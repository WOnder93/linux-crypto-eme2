/*
 * EME2: Encrypt-mix-encrypt-v2 mode
 * As defined in IEEE Std 1619.2-2010
 *
 * Copyright (c) 2015 Ondrej Mosnacek <omosnacek@gmail.com>
 *
 * Based on ecb.c and xts.c
 * Copyright (c) 2007 Rik Snel <rsnel@cube.dyndns.org>
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <crypto/algapi.h>
#include <crypto/internal/skcipher.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#include "eme2.h"
#include "eme2_test.h"
#include <crypto/gf128mul.h>
#include <crypto/scatterwalk.h>

/* the size of auxiliary buffer (must be a multiple of EME2_BLOCK_SIZE): */
#define EME2_AUX_BUFFER_SIZE PAGE_SIZE

struct bufwalk {
    int out;
    unsigned int bufsize;
    unsigned int bytesleft;
    void *mapped;
    struct scatter_walk sg_walk;
};

static inline void bufwalk_start(
        struct bufwalk *walk, int out, unsigned int bufsize,
        struct scatterlist *sg, unsigned int nbytes)
{
    walk->out = out;
    walk->bufsize = bufsize;
    walk->bytesleft = nbytes;
    scatterwalk_start(&walk->sg_walk, sg);

    walk->mapped = scatterwalk_map(&walk->sg_walk) - walk->sg_walk.offset;
}

enum {
    BUFWALK_SKIP,
    BUFWALK_READ,
    BUFWALK_WRITE,
};

static inline unsigned int bufwalk_next(
        struct bufwalk *walk, int action, void *buffer)
{
    unsigned int size = walk->bytesleft >= walk->bufsize
            ? walk->bufsize : walk->bytesleft;
    unsigned int chunk, left = size;

    walk->bytesleft -= size;
    while (left != 0) {
        chunk = scatterwalk_clamp(&walk->sg_walk, left);
        switch(action) {
        case BUFWALK_READ:
            memcpy((u8 *)buffer + size - left,
                   walk->mapped + walk->sg_walk.offset,
                   chunk);
            break;
        case BUFWALK_WRITE:
            memcpy(walk->mapped + walk->sg_walk.offset,
                   (u8 *)buffer + size - left,
                   chunk);
            break;
        }

        scatterwalk_advance(&walk->sg_walk, chunk);
        left -= chunk;
        if (left + walk->bytesleft == 0) {
            scatterwalk_unmap(walk->mapped);
            scatterwalk_done(&walk->sg_walk, walk->out, 0);
        } else if (scatterwalk_pagelen(&walk->sg_walk) == 0) {
            scatterwalk_unmap(walk->mapped);
            scatterwalk_done(&walk->sg_walk, walk->out, 1);
            walk->mapped = scatterwalk_map(&walk->sg_walk)
                    - walk->sg_walk.offset;
        }
    }
    return size;
}

static inline unsigned int bufwalk_skip_next(struct bufwalk *walk)
{
    return bufwalk_next(walk, BUFWALK_SKIP, NULL);
}

static inline unsigned int bufwalk_read_next(
        struct bufwalk *walk, void *buffer)
{
    return bufwalk_next(walk, BUFWALK_READ, buffer);
}

static inline void bufwalk_write_next(struct bufwalk *walk, void *buffer)
{
    bufwalk_next(walk, BUFWALK_WRITE, buffer);
}

typedef void (*eme2_crypt_fn)(struct crypto_cipher *, u8 *, const u8 *);
typedef int  (*eme2_crypt_ecb_fn)(struct ablkcipher_request *req);

struct eme2_req_ctx {
    struct ablkcipher_request* parent;

    eme2_crypt_fn crypt_fn;
    eme2_crypt_ecb_fn crypt_ecb_fn;

    struct bufwalk wsrc, wdst;
    unsigned int j, size;

    be128 l, mp, ccc1, m, m1;

    struct scatterlist buffer_sg[1];
    u8 buffer[EME2_AUX_BUFFER_SIZE] __aligned(8);

    struct ablkcipher_request ecb_req CRYPTO_MINALIGN_ATTR;
};

struct eme2_ctx {
   struct crypto_cipher *child;    /* the underlying cipher */
   struct crypto_ablkcipher *child_ecb;
                                   /* the underlying cipher in ECB mode */
   be128 key_ad;                   /* K_AD  - the associated data key */
   be128 key_ecb;                  /* K_ECB - the ECB pass key */
};

struct eme2_instance_ctx {
    struct crypto_spawn spawn;
    struct crypto_skcipher_spawn ecb_spawn;
};

static void eme2_req_ctx_init(
        struct eme2_req_ctx *rctx, struct ablkcipher_request *req,
        eme2_crypt_fn crypt_fn, eme2_crypt_ecb_fn crypt_ecb_fn)
{
    sg_init_one(rctx->buffer_sg, rctx->buffer, EME2_AUX_BUFFER_SIZE);

    rctx->parent = req;

    rctx->crypt_fn = crypt_fn;
    rctx->crypt_ecb_fn = crypt_ecb_fn;
}

static int setkey(struct crypto_ablkcipher *cipher,
                  const u8 *key, unsigned int keylen)
{
    struct crypto_tfm *parent = &cipher->base;

    /* the key consists of two 16-byte keys and a cipher key */
    const u8 *key_ad  = key;
    const u8 *key_ecb = key_ad  + EME2_BLOCK_SIZE;
    const u8 *key_aes = key_ecb + EME2_BLOCK_SIZE;

    unsigned int key_aes_len = keylen - 2 * EME2_BLOCK_SIZE;

    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(cipher);
    struct crypto_cipher *child = ctx->child;
    struct crypto_ablkcipher *child_ecb = ctx->child_ecb;
    u32 *flags = &parent->crt_flags;
    int err;

    if (keylen < 2 * EME2_BLOCK_SIZE) {
        /* tell the user why there was an error */
        *flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
        return -EINVAL;
    }

    /* child cipher, uses K_AES */
    crypto_cipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
    crypto_cipher_set_flags(child, crypto_tfm_get_flags(parent) &
                            CRYPTO_TFM_REQ_MASK);
    err = crypto_cipher_setkey(child, key_aes, key_aes_len);
    if (err)
        return err;

    crypto_tfm_set_flags(parent, crypto_ablkcipher_get_flags(child_ecb) &
                         CRYPTO_TFM_RES_MASK);

    crypto_ablkcipher_clear_flags(child_ecb, CRYPTO_TFM_REQ_MASK);
    crypto_ablkcipher_set_flags(child_ecb, crypto_tfm_get_flags(parent) &
                                CRYPTO_TFM_REQ_MASK);
    err = crypto_ablkcipher_setkey(child_ecb, key_aes, key_aes_len);
    if (err)
        return err;

    crypto_tfm_set_flags(parent, crypto_ablkcipher_get_flags(child_ecb) &
                         CRYPTO_TFM_RES_MASK);

    /* copy the "associated data" and "ECB pass" keys into context: */
    ctx->key_ad  = *(be128 *)key_ad;
    ctx->key_ecb = *(be128 *)key_ecb;
    return 0;
}

static inline void eme2_block_set_zero(be128 *out)
{
    /* TODO: see if this is OK (portable and stuff...): */
    out->a = 0U;
    out->b = 0U;
}

static inline void eme2_xor_padded(be128 *dst, const u8 *src,
                                   unsigned int size)
{
    crypto_xor((u8 *)dst, src, size);
    ((u8 *)dst)[size] ^= 0x80;
}

static inline void eme2_process_assoc_data_step(
        struct crypto_cipher *cipher, be128 *t_star, be128 *k_ad,
        const be128 *t)
{
    be128 tmp;
    /* K_AD = mult-by-alpha(K_AD) */
    gf128mul_x_ble(k_ad, k_ad);

    /* TT_j = AES-Enc(K_AES, K_AD xor T_j) xor K_AD */
    /* T_star = T_star xor TT_j */
    be128_xor(&tmp, k_ad, t);
    crypto_cipher_encrypt_one(cipher, (u8 *)&tmp, (u8 *)&tmp);
    be128_xor(t_star, t_star, &tmp);
    be128_xor(t_star, t_star, k_ad);
}

/* the function "H" for preprocessing the associated data */
static inline void eme2_process_assoc_data(
        const struct eme2_ctx *ctx, be128 *t_star,
        const u8 *ad, unsigned int ad_bytes)
{
    unsigned int full_blocks = ad_bytes / EME2_BLOCK_SIZE;
    unsigned int extra_bytes = ad_bytes % EME2_BLOCK_SIZE;

    const be128 *t = (const be128 *)ad;
    be128 k_ad;
    u8 last_block[EME2_BLOCK_SIZE];
    unsigned int j;

    /* special case for no associated data: */
    if (ad_bytes == 0) {
        /* T_star = AES-Enc(K_AES, K_AD) */
        crypto_cipher_encrypt_one(ctx->child,
                    (u8 *)t_star, (const u8 *)&ctx->key_ad);
        return;
    }

    eme2_block_set_zero(t_star);

    k_ad = ctx->key_ad;
    for (j = 0; j < full_blocks; j++) {
        eme2_process_assoc_data_step(ctx->child, t_star, &k_ad, &t[j]);
    }

    if (extra_bytes != 0) {
        /* pad the last block: */
        memset(last_block, 0, EME2_BLOCK_SIZE);
        memcpy(last_block, &t[full_blocks], extra_bytes);
        last_block[extra_bytes] = 0x80;

        /* one more mult-by-alpha is required for padded block: */
        /* K_AD = mult-by-alpha(K_AD) */
        gf128mul_x_ble(&k_ad, &k_ad);

        eme2_process_assoc_data_step(ctx->child, t_star, &k_ad,
                                     (be128 *)last_block);
    }
}

static int eme2_err_is_bad(struct ablkcipher_request *req, int err)
{
    switch (err) {
    case 0:
    case -EINPROGRESS:
        return 0;
    case -EBUSY:
        return !(req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG);
    default:
        return 1;
    }
}

static int eme2_loop1_start(struct eme2_req_ctx *rctx);
static int eme2_loop1_continue(struct eme2_req_ctx *rctx);
static int eme2_loop1_finish(struct eme2_req_ctx *rctx,
                             unsigned int avail, u8 *cursor);

static int eme2_loop2_start(struct eme2_req_ctx *rctx);
static int eme2_loop2_continue(struct eme2_req_ctx *rctx);
static int eme2_loop2_finish(struct eme2_req_ctx *rctx);

static void eme2_loop1_continue_cb(struct crypto_async_request *subreq, int err)
{
    struct eme2_req_ctx *rctx = subreq->data;
    struct ablkcipher_request *req = rctx->parent;

    switch (err) {
    case 0:
    case -EINPROGRESS:
        return;
    default:
        ablkcipher_request_complete(req, err);
        return;
    }

    err = eme2_loop1_continue(rctx);
    if (eme2_err_is_bad(req, err)) {
        ablkcipher_request_complete(req, err);
    }
}
static void eme2_loop2_continue_cb(struct crypto_async_request *subreq, int err)
{
    struct eme2_req_ctx *rctx = subreq->data;
    struct ablkcipher_request *req = rctx->parent;

    switch (err) {
    case 0:
    case -EINPROGRESS:
        return;
    default:
        ablkcipher_request_complete(req, err);
        return;
    }

    err = eme2_loop2_continue(rctx);
    if (eme2_err_is_bad(req, err)) {
        ablkcipher_request_complete(req, err);
    }
}

static int eme2_crypt_start(struct eme2_req_ctx *rctx, unsigned int ivsize)
{
    struct ablkcipher_request *req = rctx->parent;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);

    struct ablkcipher_request *subreq = &rctx->ecb_req;

    /* input must be at least one block: */
    if (unlikely(req->nbytes < EME2_BLOCK_SIZE)) {
        /* TODO: see if this is the right error code to use here */
        /* (xts.c uses just BUG_ON... */
        return req->nbytes == 0 ? 0 : -EINVAL;
    }

    /* init both MP and CCC_1 to T_star: */
    eme2_process_assoc_data(ctx, &rctx->mp, req->info, ivsize);
    rctx->ccc1 = rctx->mp;

    /* L = K_ECB */
    rctx->l = ctx->key_ecb;

    bufwalk_start(&rctx->wsrc, 0, EME2_AUX_BUFFER_SIZE, req->src, req->nbytes);
    bufwalk_start(&rctx->wdst, 1, EME2_AUX_BUFFER_SIZE, req->dst, req->nbytes);

    ablkcipher_request_set_tfm(subreq, ctx->child_ecb);
    return eme2_loop1_start(rctx);
}

static int eme2_loop1_start(struct eme2_req_ctx *rctx)
{
    struct ablkcipher_request *subreq = &rctx->ecb_req;

    unsigned int avail;
    u8 *cursor;
    int err;

    rctx->size = bufwalk_read_next(&rctx->wsrc, rctx->buffer);

    avail = rctx->size;
    cursor = (u8 *)rctx->buffer;

    if (unlikely(rctx->size < EME2_BLOCK_SIZE)) {
        return eme2_loop1_finish(rctx, avail, cursor);
    }
    do {
        /* P_j' = L xor P_j */
        be128_xor((be128 *)cursor, &rctx->l, (be128 *)cursor);

        /* L = mult-by-alpha(L) */
        gf128mul_x_ble(&rctx->l, &rctx->l);

        avail -= EME2_BLOCK_SIZE;
        cursor += EME2_BLOCK_SIZE;
    } while (avail >= EME2_BLOCK_SIZE);

    ablkcipher_request_set_crypt(
                subreq, rctx->buffer_sg, rctx->buffer_sg,
                rctx->size - avail, NULL);
    ablkcipher_request_set_callback(
                subreq, rctx->parent->base.flags,
                &eme2_loop1_continue_cb, rctx);
    err = rctx->crypt_ecb_fn(subreq);
    if (err != 0) {
        return err;
    }
    return eme2_loop1_continue(rctx);
}

static int eme2_loop1_continue(struct eme2_req_ctx *rctx)
{
    unsigned int avail;
    u8 *cursor;

    avail = rctx->size;
    cursor = (u8 *)rctx->buffer;
    while (avail >= EME2_BLOCK_SIZE) {
        /* MP = MP xor PPP_j */
        be128_xor(&rctx->mp, &rctx->mp, (be128 *)cursor);

        avail -= EME2_BLOCK_SIZE;
        cursor += EME2_BLOCK_SIZE;
    }
    if (likely(avail == 0))
        bufwalk_write_next(&rctx->wdst, rctx->buffer);

    if (likely(rctx->wsrc.bytesleft != 0))
        return eme2_loop1_start(rctx);

    return eme2_loop1_finish(rctx, avail, cursor);
}

static int eme2_loop1_finish(struct eme2_req_ctx *rctx,
                             unsigned int avail, u8 *cursor)
{
    struct ablkcipher_request *req = rctx->parent;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);

    be128 mc;

    if (unlikely(avail != 0)) {
        /* MP = MP xor PPP_m */
        eme2_xor_padded(&rctx->mp, cursor, avail);

        /* MM = AES-Enc(K_AES, MP) */
        rctx->crypt_fn(ctx->child, (u8 *)&mc, (u8 *)&rctx->mp);

        /* C_m = P_m xor MM [truncated] */
        crypto_xor(cursor, (u8 *)&mc, avail);

        bufwalk_write_next(&rctx->wdst, rctx->buffer);

        /* CCC_1 = CCC_1 xor CCC_m */
        eme2_xor_padded(&rctx->ccc1, cursor, avail);

        /* MC = MC_1 = AES-Enc(K_AES, MM) */
        rctx->crypt_fn(ctx->child, (u8 *)&mc, (u8 *)&mc);
    } else {
        /* MC = MC_1 = AES-Enc(K_AES, MP) */
        rctx->crypt_fn(ctx->child, (u8 *)&mc, (u8 *)&rctx->mp);
    }

    /* M = M_1 = MP xor MC */
    be128_xor(&rctx->m1, &rctx->mp, &mc);
    rctx->m = rctx->m1;

    /* CCC_1 = CCC_1 xor MC */
    be128_xor(&rctx->ccc1, &rctx->ccc1, &mc);

    /* L = K_ECB */
    rctx->l = ctx->key_ecb;

    bufwalk_start(&rctx->wsrc, 0, EME2_AUX_BUFFER_SIZE,
                  req->dst, req->nbytes - avail);
    bufwalk_start(&rctx->wdst, 1, EME2_AUX_BUFFER_SIZE,
                  req->dst, req->nbytes - avail);

    rctx->j = 0;
    return eme2_loop2_start(rctx);
}

static int eme2_loop2_start(struct eme2_req_ctx *rctx)
{
    struct ablkcipher_request *subreq = &rctx->ecb_req;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(rctx->parent);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);
    int err;

    be128 mp, mc;
    unsigned int avail, j = rctx->j;
    u8 *cursor;

    rctx->size = bufwalk_read_next(&rctx->wsrc, rctx->buffer);
    if (unlikely(rctx->size < EME2_BLOCK_SIZE)) {
        return eme2_loop2_finish(rctx);
    }

    avail = rctx->size;
    cursor = (u8 *)rctx->buffer;
    do {
        /* skip the first block: */
        if (likely(j != 0)) {
            if (likely(j % 128 != 0)) {
                /* M = mult-by-alpha(M) */
                gf128mul_x_ble(&rctx->m, &rctx->m);

                /* CCC_j = PPP_j xor M */
                be128_xor((be128 *)cursor, (be128 *)cursor, &rctx->m);
            } else {
                /* MP = PPP_j xor M_1 */
                be128_xor(&mp, (be128 *)cursor, &rctx->m1);
                /* MC = AES-Enc(K_AES, MP) */
                rctx->crypt_fn(ctx->child, (u8 *)&mc, (u8 *)&mp);
                /* M = MP xor MC */
                be128_xor(&rctx->m, &mp, &mc);
                /* CCC_j = MC xor M_1 */
                be128_xor((be128 *)cursor, &mc, &rctx->m1);
            }
            /* CCC_1 = CCC_1 xor CCC_j */
            be128_xor(&rctx->ccc1, &rctx->ccc1, (be128 *)cursor);
        }

        ++j;
        avail -= EME2_BLOCK_SIZE;
        cursor += EME2_BLOCK_SIZE;
    } while (avail >= EME2_BLOCK_SIZE);
    rctx->j = j;

    ablkcipher_request_set_crypt(
                subreq, rctx->buffer_sg, rctx->buffer_sg, rctx->size, NULL);
    ablkcipher_request_set_callback(
                subreq, rctx->parent->base.flags,
                &eme2_loop2_continue_cb, rctx);
    err = rctx->crypt_ecb_fn(subreq);
    if (err != 0) {
        return err;
    }
    return eme2_loop2_continue(rctx);
}

static int eme2_loop2_continue(struct eme2_req_ctx *rctx)
{
    unsigned int avail;
    u8 *cursor;

    avail = rctx->size;
    cursor = (u8 *)rctx->buffer;
    while (avail >= EME2_BLOCK_SIZE) {
        /* C_j = C_j' xor L */
        /* L = mult-by-alpha(L) */
        be128_xor((be128 *)cursor, (be128 *)cursor, &rctx->l);
        gf128mul_x_ble(&rctx->l, &rctx->l);

        avail -= EME2_BLOCK_SIZE;
        cursor += EME2_BLOCK_SIZE;
    }
    bufwalk_write_next(&rctx->wdst, rctx->buffer);

    if (likely(rctx->wsrc.bytesleft != 0))
        return eme2_loop2_start(rctx);

    return eme2_loop2_finish(rctx);
}

static int eme2_loop2_finish(struct eme2_req_ctx *rctx)
{
    struct ablkcipher_request *req = rctx->parent;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);

    /* (re)write CCC_1, which we skipped before: */
    rctx->crypt_fn(ctx->child, (u8 *)&rctx->ccc1, (u8 *)&rctx->ccc1);
    be128_xor(&rctx->ccc1, &rctx->ccc1, &ctx->key_ecb);

    bufwalk_start(&rctx->wdst, 1, EME2_BLOCK_SIZE, req->dst, EME2_BLOCK_SIZE);
    bufwalk_write_next(&rctx->wdst, &rctx->ccc1);

    return 0;
}

int eme2_encrypt(struct ablkcipher_request *req, unsigned int ivsize)
{
    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    unsigned long align = crypto_ablkcipher_alignmask(tfm);
    struct eme2_req_ctx *rctx =
            (void *)PTR_ALIGN((u8 *)ablkcipher_request_ctx(req), align + 1);

    eme2_req_ctx_init(rctx, req, *crypto_cipher_encrypt_one,
                      &crypto_ablkcipher_encrypt);
    return eme2_crypt_start(rctx, ivsize);
}
EXPORT_SYMBOL_GPL(eme2_encrypt);

int eme2_decrypt(struct ablkcipher_request *req, unsigned int ivsize)
{
    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    unsigned long align = crypto_ablkcipher_alignmask(tfm);
    struct eme2_req_ctx *rctx =
            (void *)PTR_ALIGN((u8 *)ablkcipher_request_ctx(req), align + 1);

    eme2_req_ctx_init(rctx, req, *crypto_cipher_decrypt_one,
                      &crypto_ablkcipher_decrypt);
    return eme2_crypt_start(rctx, ivsize);
}
EXPORT_SYMBOL_GPL(eme2_decrypt);


static int encrypt(struct ablkcipher_request *req)
{
    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    unsigned long align = crypto_ablkcipher_alignmask(tfm);
    struct eme2_req_ctx *rctx =
            (void *)PTR_ALIGN((u8 *)ablkcipher_request_ctx(req), align + 1);

    eme2_req_ctx_init(rctx, req, *crypto_cipher_encrypt_one,
                      &crypto_ablkcipher_encrypt);
    return eme2_crypt_start(rctx, crypto_ablkcipher_ivsize(tfm));
}

static int decrypt(struct ablkcipher_request *req)
{
    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    unsigned long align = crypto_ablkcipher_alignmask(tfm);
    struct eme2_req_ctx *rctx =
            (void *)PTR_ALIGN((u8 *)ablkcipher_request_ctx(req), align + 1);

    eme2_req_ctx_init(rctx, req, *crypto_cipher_decrypt_one,
                      &crypto_ablkcipher_decrypt);
    return eme2_crypt_start(rctx, crypto_ablkcipher_ivsize(tfm));
}

static int init_tfm(struct crypto_tfm *tfm)
{
    struct crypto_cipher *cipher;
    struct crypto_ablkcipher *cipher_ecb;
    struct crypto_instance *inst = (void *)tfm->__crt_alg;
    struct eme2_instance_ctx *inst_ctx = crypto_instance_ctx(inst);
    struct eme2_ctx *ctx = crypto_tfm_ctx(tfm);
    unsigned int align;

    cipher_ecb = crypto_spawn_skcipher(&inst_ctx->ecb_spawn);
    if (IS_ERR(cipher_ecb))
        return PTR_ERR(cipher_ecb);

    cipher = crypto_spawn_cipher(&inst_ctx->spawn);
    if (IS_ERR(cipher)) {
        crypto_free_ablkcipher(cipher_ecb);
        return PTR_ERR(cipher);
    }

    ctx->child = cipher;
    ctx->child_ecb = cipher_ecb;

    align = crypto_tfm_alg_alignmask(tfm);
    align &= ~(crypto_tfm_ctx_alignment() - 1);
    tfm->crt_ablkcipher.reqsize = align +
            sizeof(struct eme2_req_ctx) +
            crypto_ablkcipher_reqsize(cipher_ecb);
    return 0;
}

static void exit_tfm(struct crypto_tfm *tfm)
{
    struct eme2_ctx *ctx = crypto_tfm_ctx(tfm);
    crypto_free_cipher(ctx->child);
    crypto_free_ablkcipher(ctx->child_ecb);
    /* clear the xor keys: */
    memzero_explicit(&ctx->key_ad,  sizeof(ctx->key_ad));
    memzero_explicit(&ctx->key_ecb, sizeof(ctx->key_ecb));
}

static struct crypto_instance *alloc(struct rtattr **tb)
{
    struct crypto_instance *inst;
    struct eme2_instance_ctx *ctx;
    struct crypto_alg *alg, *ecb_alg;
    char ecb_name[CRYPTO_MAX_ALG_NAME];
    int err;

    err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_BLKCIPHER);
    if (err)
        return ERR_PTR(err);

    alg = crypto_get_attr_alg(tb, CRYPTO_ALG_TYPE_CIPHER,
                              CRYPTO_ALG_TYPE_MASK);
    if (IS_ERR(alg))
        return ERR_CAST(alg);

    /* we only support 16-byte blocks: */
    if (alg->cra_blocksize != EME2_BLOCK_SIZE)
        return ERR_PTR(-EINVAL);

    inst = kzalloc(sizeof(*inst) + sizeof(struct eme2_instance_ctx),
                   GFP_KERNEL);
    if (!inst) {
        inst = ERR_PTR(-ENOMEM);
        goto out_put_alg;
    }
    ctx = crypto_instance_ctx(inst);

    /* prepare spawn for crypto_cipher: */
    err = crypto_init_spawn(&ctx->spawn, alg, inst,
                            CRYPTO_ALG_TYPE_MASK | CRYPTO_ALG_ASYNC);
    if (err)
        goto err_free_inst;

    /* prepare spawn for ECB mode: */
    err = -ENAMETOOLONG;
    if (snprintf(ecb_name, CRYPTO_MAX_ALG_NAME, "ecb(%s)", alg->cra_name)
            >= CRYPTO_MAX_ALG_NAME)
        goto err_drop_spawn;

    crypto_set_skcipher_spawn(&ctx->ecb_spawn, inst);
    err = crypto_grab_skcipher(&ctx->ecb_spawn, ecb_name, 0, 0);
    if (err)
        goto err_drop_spawn;

    /* get the crypto_alg for the ECB mode: */
    ecb_alg = crypto_skcipher_spawn_alg(&ctx->ecb_spawn);

    err = -ENAMETOOLONG;
    if (snprintf(inst->alg.cra_name, CRYPTO_MAX_ALG_NAME, "eme2(%s)",
                 alg->cra_name) >= CRYPTO_MAX_ALG_NAME)
        goto err_drop_ecb_spawn;

    if (snprintf(inst->alg.cra_driver_name, CRYPTO_MAX_ALG_NAME,"eme2(%s,%s)",
                 alg->cra_driver_name, ecb_alg->cra_driver_name)
            >= CRYPTO_MAX_ALG_NAME)
        goto err_drop_ecb_spawn;

    inst->alg.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER |
            (ecb_alg->cra_flags & CRYPTO_ALG_ASYNC);
    inst->alg.cra_priority = ecb_alg->cra_priority;
    inst->alg.cra_blocksize = 1;

    if (alg->cra_alignmask < 7)
        inst->alg.cra_alignmask = 7;
    else
        inst->alg.cra_alignmask =
                max(alg->cra_alignmask, ecb_alg->cra_alignmask);

    inst->alg.cra_type = &crypto_ablkcipher_type;

    /* since IV size must be fixed, we arbitrarily choose one block for it: */
    inst->alg.cra_ablkcipher.ivsize = EME2_BLOCK_SIZE;

    inst->alg.cra_ablkcipher.min_keysize =
        2 * EME2_BLOCK_SIZE + alg->cra_cipher.cia_min_keysize;
    inst->alg.cra_ablkcipher.max_keysize =
        2 * EME2_BLOCK_SIZE + alg->cra_cipher.cia_max_keysize;

    inst->alg.cra_ablkcipher.setkey = setkey;
    inst->alg.cra_ablkcipher.encrypt = encrypt;
    inst->alg.cra_ablkcipher.decrypt = decrypt;

    inst->alg.cra_ctxsize = sizeof(struct eme2_ctx);

    inst->alg.cra_init = init_tfm;
    inst->alg.cra_exit = exit_tfm;

out_put_alg:
    crypto_mod_put(alg);
    return inst;

err_drop_ecb_spawn:
    crypto_drop_skcipher(&ctx->ecb_spawn);
err_drop_spawn:
    crypto_drop_spawn(&ctx->spawn);
err_free_inst:
    kzfree(inst);
    crypto_mod_put(alg);
    return ERR_PTR(err);
}

static void free(struct crypto_instance *inst)
{
    struct eme2_instance_ctx *ctx = crypto_instance_ctx(inst);
    crypto_drop_spawn(&ctx->spawn);
    crypto_drop_skcipher(&ctx->ecb_spawn);
    kzfree(inst);
}

static struct crypto_template crypto_tmpl = {
    .name = "eme2",
    .alloc = alloc,
    .free = free,
    .module = THIS_MODULE,
};

static int __init crypto_module_init(void)
{
    int err;

    printk("eme2: Loading module...\n");

    err = crypto_register_template(&crypto_tmpl);
    if (err) {
        return err;
    }
    err = eme2_run_tests();
    if (err) {
        crypto_unregister_template(&crypto_tmpl);
    }
    return err;
}

static void __exit crypto_module_exit(void)
{
    crypto_unregister_template(&crypto_tmpl);
}

module_init(crypto_module_init);
module_exit(crypto_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("EME2 block cipher mode");
MODULE_ALIAS_CRYPTO("eme2");
