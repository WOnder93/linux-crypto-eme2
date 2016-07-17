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
#include <crypto/gf128mul.h>
#include <crypto/internal/skcipher.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#include "eme2.h"
#include "eme2_test.h"
#include "blockwalk.h"

struct eme2_req_ctx;

typedef void (*eme2_crypt_fn)(struct crypto_cipher *, u8 *, const u8 *);
typedef int  (*eme2_crypt_ecb_fn)(struct ablkcipher_request *req);
typedef int  (*eme2_continue_fn)(struct eme2_req_ctx *rctx);

union eme2_block {
    be128 b128;
    u8 bytes[EME2_BLOCK_SIZE];
};

static inline void eme2_block_set_zero(union eme2_block *out)
{
    /* TODO: see if this is OK (portable and stuff...): */
    out->b128.a = 0U;
    out->b128.b = 0U;
}

static inline void eme2_block_xor(
        union eme2_block *res,
        const union eme2_block *x, const union eme2_block *y)
{
    be128_xor(&res->b128, &x->b128, &y->b128);
}

static inline void eme2_block_gf128mul(
        union eme2_block *res, const union eme2_block *x)
{
    gf128mul_x_ble(&res->b128, &x->b128);
}

struct eme2_req_ctx {
    struct ablkcipher_request* parent;

    eme2_continue_fn next;

    eme2_crypt_fn crypt_fn;
    eme2_crypt_ecb_fn crypt_ecb_fn;

    union eme2_block mp, ccc1;

    struct ablkcipher_request ecb_req CRYPTO_MINALIGN_ATTR;
};

struct eme2_ctx {
   struct crypto_cipher *child; /* the underlying cipher */
   struct crypto_ablkcipher *child_ecb;
                                /* the underlying cipher in ECB mode */
   union eme2_block key_ad;     /* K_AD  - the associated data key */
   union eme2_block key_ecb;    /* K_ECB - the ECB pass key */
};

struct eme2_instance_ctx {
    struct crypto_spawn spawn;
    struct crypto_skcipher_spawn ecb_spawn;
};

static void eme2_req_ctx_init(
        struct eme2_req_ctx *rctx, struct ablkcipher_request *req,
        eme2_crypt_fn crypt_fn, eme2_crypt_ecb_fn crypt_ecb_fn)
{
    rctx->parent = req;

    rctx->crypt_fn = crypt_fn;
    rctx->crypt_ecb_fn = crypt_ecb_fn;
}

static int setkey(struct crypto_ablkcipher *cipher,
                  const u8 *key, unsigned int keylen)
{
    struct crypto_tfm *parent = &cipher->base;

    /* the key consists of two 16-byte keys and a cipher key */
    const union eme2_block *key_ad  = (const union eme2_block *)key;
    const union eme2_block *key_ecb = key_ad + 1;
    const u8 *key_aes = (key_ecb + 1)->bytes;

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
    ctx->key_ad  = *key_ad;
    ctx->key_ecb = *key_ecb;
    return 0;
}

static inline void eme2_xor_padded(union eme2_block *dst, const u8 *src,
                                   unsigned int size)
{
    crypto_xor(dst->bytes, src, size);
    dst->bytes[size] ^= 0x80;
}

static inline void eme2_process_assoc_data_step(
        struct crypto_cipher *cipher, union eme2_block *t_star,
        union eme2_block *k_ad, const union eme2_block *t)
{
    union eme2_block tmp;
    /* K_AD = mult-by-alpha(K_AD) */
    eme2_block_gf128mul(k_ad, k_ad);

    /* TT_j = AES-Enc(K_AES, K_AD xor T_j) xor K_AD */
    /* T_star = T_star xor TT_j */
    eme2_block_xor(&tmp, k_ad, t);
    crypto_cipher_encrypt_one(cipher, tmp.bytes, tmp.bytes);
    eme2_block_xor(t_star, t_star, &tmp);
    eme2_block_xor(t_star, t_star, k_ad);
}

/* the function "H" for preprocessing the associated data */
static inline void eme2_process_assoc_data(
        const struct eme2_ctx *ctx, union eme2_block *t_star,
        const u8 *ad, unsigned int ad_bytes)
{
    unsigned int full_blocks = ad_bytes / EME2_BLOCK_SIZE;
    unsigned int extra_bytes = ad_bytes % EME2_BLOCK_SIZE;

    const union eme2_block *t = (const union eme2_block *)ad;
    union eme2_block k_ad;
    union eme2_block last_block;
    unsigned int j;

    /* special case for no associated data: */
    if (ad_bytes == 0) {
        /* T_star = AES-Enc(K_AES, K_AD) */
        crypto_cipher_encrypt_one(ctx->child, t_star->bytes, ctx->key_ad.bytes);
        return;
    }

    eme2_block_set_zero(t_star);

    k_ad = ctx->key_ad;
    for (j = 0; j < full_blocks; j++) {
        eme2_process_assoc_data_step(ctx->child, t_star, &k_ad, &t[j]);
    }

    if (extra_bytes != 0) {
        /* pad the last block: */
        eme2_block_set_zero(&last_block);
        memcpy(last_block.bytes, t[full_blocks].bytes, extra_bytes);
        last_block.bytes[extra_bytes] = 0x80;

        /* one more mult-by-alpha is required for padded block: */
        /* K_AD = mult-by-alpha(K_AD) */
        eme2_block_gf128mul(&k_ad, &k_ad);

        eme2_process_assoc_data_step(ctx->child, t_star, &k_ad, &last_block);
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

static int eme2_phase1(struct eme2_req_ctx *rctx);
static int eme2_phase2(struct eme2_req_ctx *rctx);
static int eme2_phase3(struct eme2_req_ctx *rctx);

static void eme2_callback(struct crypto_async_request *subreq, int err)
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

    err = rctx->next(rctx);
    if (err == 0 || eme2_err_is_bad(req, err)) {
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

    ablkcipher_request_set_tfm(subreq, ctx->child_ecb);
    return eme2_phase1(rctx);
}

static int eme2_phase1(struct eme2_req_ctx *rctx)
{
    struct ablkcipher_request *subreq = &rctx->ecb_req;
    struct ablkcipher_request *req = rctx->parent;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);

    struct blockwalk walk;
    unsigned int avail, reqsize = req->nbytes & EME2_BLOCK_MASK;
    union eme2_block *cursor_in, *cursor_out;
    union eme2_block buffer, l;
    int err;

    /* L = K_ECB */
    l = ctx->key_ecb;

    blockwalk_start(&walk, EME2_BLOCK_SIZE, crypto_ablkcipher_alignmask(tfm),
                    buffer.bytes, req->src, req->dst, reqsize);

    do {
        blockwalk_chunk_start(&walk);

        avail       = blockwalk_chunk_size(&walk);
        cursor_in   = blockwalk_chunk_in(&walk);
        cursor_out  = blockwalk_chunk_out(&walk);

        while (avail >= EME2_BLOCK_SIZE) {
            /* P_j' = L xor P_j */
            eme2_block_xor(cursor_out, &l, cursor_in);

            /* L = mult-by-alpha(L) */
            eme2_block_gf128mul(&l, &l);

            avail -= EME2_BLOCK_SIZE;
            ++cursor_in;
            ++cursor_out;
        }

        blockwalk_chunk_finish(&walk);
    } while (blockwalk_bytes_left(&walk));

    rctx->next = eme2_phase2;
    ablkcipher_request_set_crypt(
                subreq, req->dst, req->dst,
                reqsize, NULL);
    ablkcipher_request_set_callback(
                subreq, rctx->parent->base.flags,
                eme2_callback, rctx);
    err = rctx->crypt_ecb_fn(subreq);
    if (err != 0) {
        return err;
    }
    return eme2_phase2(rctx);
}

static int eme2_phase2(struct eme2_req_ctx *rctx)
{
    struct ablkcipher_request *subreq = &rctx->ecb_req;
    struct ablkcipher_request *req = rctx->parent;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);

    struct blockwalk walk;
    unsigned int avail, j, reqsize = req->nbytes & EME2_BLOCK_MASK;
    union eme2_block *cursor_in, *cursor_out;
    union eme2_block buffer, mc, mp, m, m1;
    int err;

    blockwalk_start(&walk, EME2_BLOCK_SIZE, crypto_ablkcipher_alignmask(tfm),
                    buffer.bytes, req->dst, req->dst, req->nbytes);

    for (;;) {
        blockwalk_chunk_start(&walk);

        avail       = blockwalk_chunk_size(&walk);
        cursor_in   = blockwalk_chunk_in(&walk);
        cursor_out  = blockwalk_chunk_out(&walk);

        while (avail >= EME2_BLOCK_SIZE) {
            /* MP = MP xor PPP_j */
            eme2_block_xor(&rctx->mp, &rctx->mp, cursor_in);

            avail -= EME2_BLOCK_SIZE;
            ++cursor_in;
            ++cursor_out;
        }

        if (unlikely(!blockwalk_bytes_left(&walk))) {
            break;
        }
        blockwalk_chunk_finish(&walk);
    }

    if (unlikely(avail != 0)) {
        /* MP = MP xor PPP_m */
        eme2_xor_padded(&rctx->mp, cursor_in->bytes, avail);

        /* MM = AES-Enc(K_AES, MP) */
        rctx->crypt_fn(ctx->child, mc.bytes, rctx->mp.bytes);

        /* C_m = P_m xor MM [truncated] */
        crypto_xor(cursor_out->bytes, mc.bytes, avail);

        /* CCC_1 = CCC_1 xor CCC_m */
        eme2_xor_padded(&rctx->ccc1, cursor_out->bytes, avail);

        /* MC = MC_1 = AES-Enc(K_AES, MM) */
        rctx->crypt_fn(ctx->child, mc.bytes, mc.bytes);
    } else {
        /* MC = MC_1 = AES-Enc(K_AES, MP) */
        rctx->crypt_fn(ctx->child, mc.bytes, rctx->mp.bytes);
    }
    blockwalk_chunk_finish(&walk);

    /* M = M_1 = MP xor MC */
    eme2_block_xor(&m1, &rctx->mp, &mc);
    m = m1;

    /* CCC_1 = CCC_1 xor MC */
    eme2_block_xor(&rctx->ccc1, &rctx->ccc1, &mc);

    /* L = K_ECB */
    j = 0;

    blockwalk_start(&walk, EME2_BLOCK_SIZE, crypto_ablkcipher_alignmask(tfm),
                    buffer.bytes, req->dst, req->dst, reqsize);
    do {
        blockwalk_chunk_start(&walk);

        avail       = blockwalk_chunk_size(&walk);
        cursor_in   = blockwalk_chunk_in(&walk);
        cursor_out  = blockwalk_chunk_out(&walk);

        /* skip the first block: */
        if (unlikely(j == 0)) {
            ++j;
            avail -= EME2_BLOCK_SIZE;
            ++cursor_in;
            ++cursor_out;
        }

        while (avail >= EME2_BLOCK_SIZE) {
            if (likely(j % 128 != 0)) {
                /* M = mult-by-alpha(M) */
                eme2_block_gf128mul(&m, &m);

                /* CCC_j = PPP_j xor M */
                eme2_block_xor(cursor_out, cursor_in, &m);
            } else {
                /* MP = PPP_j xor M_1 */
                eme2_block_xor(&mp, cursor_in, &m1);
                /* MC = AES-Enc(K_AES, MP) */
                rctx->crypt_fn(ctx->child, mc.bytes, mp.bytes);
                /* M = MP xor MC */
                eme2_block_xor(&m, &mp, &mc);
                /* CCC_j = MC xor M_1 */
                eme2_block_xor(cursor_out, &mc, &m1);
            }
            /* CCC_1 = CCC_1 xor CCC_j */
            eme2_block_xor(&rctx->ccc1, &rctx->ccc1, cursor_out);

            ++j;
            avail -= EME2_BLOCK_SIZE;
            ++cursor_in;
            ++cursor_out;
        }

        blockwalk_chunk_finish(&walk);
    } while (blockwalk_bytes_left(&walk));

    rctx->next = eme2_phase3;
    ablkcipher_request_set_crypt(
                subreq, req->dst, req->dst,
                reqsize, NULL);
    ablkcipher_request_set_callback(
                subreq, rctx->parent->base.flags,
                eme2_callback, rctx);
    err = rctx->crypt_ecb_fn(subreq);
    if (err != 0) {
        return err;
    }
    return eme2_phase3(rctx);
}

static int eme2_phase3(struct eme2_req_ctx *rctx)
{
    struct ablkcipher_request *req = rctx->parent;

    struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
    struct eme2_ctx *ctx = crypto_ablkcipher_ctx(tfm);

    struct blockwalk walk;
    unsigned int avail, reqsize = req->nbytes & EME2_BLOCK_MASK;
    union eme2_block *cursor_in, *cursor_out;
    union eme2_block buffer, l;
    int first_block = 1;

    /* L = K_ECB */
    l = ctx->key_ecb;

    blockwalk_start(&walk, EME2_BLOCK_SIZE, crypto_ablkcipher_alignmask(tfm),
                    buffer.bytes, req->src, req->dst, reqsize);

    do {
        blockwalk_chunk_start(&walk);

        avail       = blockwalk_chunk_size(&walk);
        cursor_in   = blockwalk_chunk_in(&walk);
        cursor_out  = blockwalk_chunk_out(&walk);

        if (unlikely(first_block)) {
            first_block = 0;

            /* C_1' = AES-Enc(K_AES, CCC_1) */
            rctx->crypt_fn(ctx->child, rctx->ccc1.bytes, rctx->ccc1.bytes);

            /* C_1 = C_1' xor L */
            eme2_block_xor(cursor_out, &rctx->ccc1, &l);

            /* L = mult-by-alpha(L) */
            eme2_block_gf128mul(&l, &l);

            avail -= EME2_BLOCK_SIZE;
            ++cursor_in;
            ++cursor_out;
        }

        while (avail >= EME2_BLOCK_SIZE) {
            /* C_j = C_j' xor L */
            eme2_block_xor(cursor_out, cursor_in, &l);

            /* L = mult-by-alpha(L) */
            eme2_block_gf128mul(&l, &l);

            avail -= EME2_BLOCK_SIZE;
            ++cursor_in;
            ++cursor_out;
        }

        blockwalk_chunk_finish(&walk);
    } while (blockwalk_bytes_left(&walk));

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
