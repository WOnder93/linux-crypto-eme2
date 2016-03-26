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
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#include "eme2.h"
#include "eme2_test.h"
#include <crypto/gf128mul.h>
#include <crypto/scatterwalk.h>

struct blockwalk {
    int out;
    unsigned int blocksize;
    unsigned int bytesleft;
    void *mapped;
    struct scatter_walk sg_walk;
};

static inline void blockwalk_start(
        struct blockwalk *walk, int out, unsigned int blocksize,
        struct scatterlist *sg, unsigned int nbytes)
{
    walk->out = out;
    walk->blocksize = blocksize;
    walk->bytesleft = nbytes;
    scatterwalk_start(&walk->sg_walk, sg);

    walk->mapped = scatterwalk_map(&walk->sg_walk) - walk->sg_walk.offset;
}

enum {
    BLOCKWALK_SKIP,
    BLOCKWALK_READ,
    BLOCKWALK_WRITE,
};

static inline void blockwalk_next(struct blockwalk *walk, int action,
                                  void *buffer)
{
    unsigned int size = walk->bytesleft >= walk->blocksize
            ? walk->blocksize : walk->bytesleft;
    unsigned int chunk, left = size;

    walk->bytesleft -= size;
    for (;;) {
        chunk = scatterwalk_clamp(&walk->sg_walk, left);
        switch(action) {
        case BLOCKWALK_READ:
            memcpy((u8 *)buffer + size - left,
                   walk->mapped + walk->sg_walk.offset,
                   chunk);
            break;
        case BLOCKWALK_WRITE:
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
        if (left == 0) {
            break;
        }
    }
}

static inline void blockwalk_skip_next(struct blockwalk *walk)
{
    blockwalk_next(walk, BLOCKWALK_SKIP, NULL);
}

static inline void blockwalk_read_next(struct blockwalk *walk, void *buffer)
{
    blockwalk_next(walk, BLOCKWALK_READ, buffer);
}

static inline void blockwalk_write_next(struct blockwalk *walk, void *buffer)
{
    blockwalk_next(walk, BLOCKWALK_WRITE, buffer);
}

static int setkey(struct crypto_tfm *parent, const u8 *key, unsigned int keylen)
{
    /* the key consists of two 16-byte keys and a cipher key */
    const u8 *key_ad  = key;
    const u8 *key_ecb = key_ad  + EME2_BLOCK_SIZE;
    const u8 *key_aes = key_ecb + EME2_BLOCK_SIZE;

    unsigned int key_aes_len = keylen - 2 * EME2_BLOCK_SIZE;

    struct eme2_ctx *ctx = crypto_tfm_ctx(parent);
    struct crypto_cipher *child = ctx->child;
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

    crypto_tfm_set_flags(parent, crypto_cipher_get_flags(child) &
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

static inline void eme2_xor_padded(be128 *dst, const be128 *src,
                                   unsigned int size)
{
    crypto_xor((u8 *)dst, (const u8 *)src, size);
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

static int eme2_crypt(struct eme2_ctx *ctx,
                      struct scatterlist *dst, struct scatterlist *src,
                      unsigned int nbytes, const u8 *iv, unsigned int ivsize,
                      void (*fn)(struct crypto_tfm *, u8 *, const u8 *))
{
    struct crypto_tfm *tfm = crypto_cipher_tfm(ctx->child);

    struct blockwalk wsrc, wdst;

    unsigned int j, extra_bytes = nbytes % EME2_BLOCK_SIZE;
    be128 t_star, l, mp, mc, m1, m, ccc1, tmp;

    /* input must be at least one block: */
    if (nbytes < EME2_BLOCK_SIZE) {
        /* TODO: see if this is the right error code to use here */
        /* (xts.c uses just BUG_ON... */
        return -EINVAL;
    }

    eme2_process_assoc_data(ctx, &t_star, iv, ivsize);

    /* MP = T_star xor [PPP_1 ... PPP_m] */
    mp = t_star;
    /* L = K_ECB */
    l = ctx->key_ecb;

    blockwalk_start(&wsrc, 0, EME2_BLOCK_SIZE, src, nbytes);
    blockwalk_start(&wdst, 1, EME2_BLOCK_SIZE, dst, nbytes);

    while (wsrc.bytesleft >= EME2_BLOCK_SIZE) {
        blockwalk_read_next(&wsrc, &tmp);

        /* PPP_j = AES-Enc(K_AES, L xor P_j) */
        be128_xor(&tmp, &l, &tmp);
        fn(tfm, (u8 *)&tmp, (u8 *)&tmp);
        /* MP = MP xor PPP_j */
        be128_xor(&mp, &mp, &tmp);

        blockwalk_write_next(&wdst, &tmp);

        /* L = mult-by-alpha(L) */
        gf128mul_x_ble(&l, &l);
    }

    /* CCC_1 = T_star */
    ccc1 = t_star;

    if (unlikely(extra_bytes != 0)) {
        blockwalk_read_next(&wsrc, &tmp);

        /* MP = MP xor PPP_m */
        eme2_xor_padded(&mp, &tmp, extra_bytes);

        /* MM = AES-Enc(K_AES, MP) */
        fn(tfm, (u8 *)&mc, (u8 *)&mp);

        /* C_m = P_m xor MM [truncated] */
        crypto_xor((u8 *)&tmp, (u8 *)&mc, extra_bytes);

        blockwalk_write_next(&wdst, &tmp);

        /* CCC_1 = CCC_1 xor CCC_m */
        eme2_xor_padded(&ccc1, &tmp, extra_bytes);

        /* MC = MC_1 = AES-Enc(K_AES, MM) */
        fn(tfm, (u8 *)&mc, (u8 *)&mc);
    } else {
        /* MC = MC_1 = AES-Enc(K_AES, MP) */
        fn(tfm, (u8 *)&mc, (u8 *)&mp);
    }

    /* M = M_1 = MP xor MC */
    be128_xor(&m1, &mp, &mc);
    m = m1;

    /* CCC_1 = CCC_1 xor MC */
    be128_xor(&ccc1, &ccc1, &mc);

    /* L = K_ECB */
    l = ctx->key_ecb;

    blockwalk_start(&wsrc, 0, EME2_BLOCK_SIZE, dst, nbytes - extra_bytes);
    blockwalk_start(&wdst, 1, EME2_BLOCK_SIZE, dst, nbytes - extra_bytes);

    /* skip the first block, will be written later: */
    blockwalk_skip_next(&wsrc);
    blockwalk_skip_next(&wdst);

    j = 1;
    while (wsrc.bytesleft >= EME2_BLOCK_SIZE) {
        blockwalk_read_next(&wsrc, &tmp);

        if (likely(j % 128 != 0)) {
            /* M = mult-by-alpha(M) */
            gf128mul_x_ble(&m, &m);

            /* CCC_j = PPP_j xor M */
            be128_xor(&tmp, &tmp, &m);
        } else {
            /* MP = PPP_j xor M_1 */
            be128_xor(&mp, &tmp, &m1);
            /* MC = AES-Enc(K_AES, MP) */
            fn(tfm, (u8 *)&mc, (u8 *)&mp);
            /* M = MP xor MC */
            be128_xor(&m, &mp, &mc);
            /* CCC_j = MC xor M_1 */
            be128_xor(&tmp, &mc, &m1);
        }
        /* CCC_1 = CCC_1 xor CCC_j */
        be128_xor(&ccc1, &ccc1, &tmp);

        /* multiply L before, since we start with second block and we
         * want to avoid unnecessary operation in the last iteration */

        /* L = mult-by-alpha(L) */
        /* C_j = AES-Enc(K_AES, CCC_j) xor L */
        fn(tfm, (u8 *)&tmp, (u8 *)&tmp);
        gf128mul_x_ble(&l, &l);
        be128_xor(&tmp, &tmp, &l);

        blockwalk_write_next(&wdst, &tmp);
        ++j;
    }

    /* C_1 = AES-Enc(K_AES, CCC_1) xor L */
    fn(tfm, (u8 *)&ccc1, (u8 *)&ccc1);
    be128_xor(&ccc1, &ccc1, &ctx->key_ecb);

    /* write C_1, which we skipped before: */
    blockwalk_start(&wdst, 1, EME2_BLOCK_SIZE, dst, EME2_BLOCK_SIZE);
    blockwalk_write_next(&wdst, &ccc1);
    return 0;
}

int eme2_encrypt(struct eme2_ctx *ctx,
                 struct scatterlist *dst, struct scatterlist *src,
                 unsigned int nbytes, const u8 *iv, unsigned int ivsize)
{
    return eme2_crypt(ctx, dst, src, nbytes, iv, ivsize,
                      crypto_cipher_alg(ctx->child)->cia_encrypt);
}
EXPORT_SYMBOL_GPL(eme2_encrypt);

int eme2_decrypt(struct eme2_ctx *ctx,
                 struct scatterlist *dst, struct scatterlist *src,
                 unsigned int nbytes, const u8 *iv, unsigned int ivsize)
{
    return eme2_crypt(ctx, dst, src, nbytes, iv, ivsize,
                      crypto_cipher_alg(ctx->child)->cia_decrypt);
}
EXPORT_SYMBOL_GPL(eme2_decrypt);

static int encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
           struct scatterlist *src, unsigned int nbytes)
{
    struct eme2_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
    unsigned int ivsize = crypto_blkcipher_ivsize(desc->tfm);
    return eme2_crypt(ctx, dst, src, nbytes, (const u8 *)desc->info, ivsize,
                      crypto_cipher_alg(ctx->child)->cia_encrypt);
}

static int decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
           struct scatterlist *src, unsigned int nbytes)
{
    struct eme2_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
    unsigned int ivsize = crypto_blkcipher_ivsize(desc->tfm);
    return eme2_crypt(ctx, dst, src, nbytes, (const u8 *)desc->info, ivsize,
                      crypto_cipher_alg(ctx->child)->cia_decrypt);
}

static int init_tfm(struct crypto_tfm *tfm)
{
    struct crypto_cipher *cipher;
    struct crypto_instance *inst = (void *)tfm->__crt_alg;
    struct crypto_spawn *spawn = crypto_instance_ctx(inst);
    struct eme2_ctx *ctx = crypto_tfm_ctx(tfm);
    u32 *flags = &tfm->crt_flags;

    cipher = crypto_spawn_cipher(spawn);
    if (IS_ERR(cipher))
        return PTR_ERR(cipher);

    if (crypto_cipher_blocksize(cipher) != EME2_BLOCK_SIZE) {
        *flags |= CRYPTO_TFM_RES_BAD_BLOCK_LEN;
        crypto_free_cipher(cipher);
        return -EINVAL;
    }

    ctx->child = cipher;

    return 0;
}

static void exit_tfm(struct crypto_tfm *tfm)
{
    struct eme2_ctx *ctx = crypto_tfm_ctx(tfm);
    crypto_free_cipher(ctx->child);
    /* clear the xor keys: */
    memzero_explicit(&ctx->key_ad,  sizeof(ctx->key_ad));
    memzero_explicit(&ctx->key_ecb, sizeof(ctx->key_ecb));
}

static struct crypto_instance *alloc(struct rtattr **tb)
{
    struct crypto_instance *inst;
    struct crypto_alg *alg;
    int err;

    err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_BLKCIPHER);
    if (err)
        return ERR_PTR(err);

    alg = crypto_get_attr_alg(tb, CRYPTO_ALG_TYPE_CIPHER,
                              CRYPTO_ALG_TYPE_MASK);
    if (IS_ERR(alg))
        return ERR_CAST(alg);

    inst = crypto_alloc_instance("eme2", alg);
    if (IS_ERR(inst))
        goto out_put_alg;

    inst->alg.cra_flags = CRYPTO_ALG_TYPE_BLKCIPHER;
    inst->alg.cra_priority = alg->cra_priority;
    inst->alg.cra_blocksize = 1;

    /* not sure what to do here, leaving the code from xts.c: */
    if (alg->cra_alignmask < 7)
        inst->alg.cra_alignmask = 7;
    else
        inst->alg.cra_alignmask = alg->cra_alignmask;

    inst->alg.cra_type = &crypto_blkcipher_type;

    inst->alg.cra_blkcipher.ivsize = alg->cra_blocksize;
    inst->alg.cra_blkcipher.min_keysize =
        2 * EME2_BLOCK_SIZE + alg->cra_cipher.cia_min_keysize;
    inst->alg.cra_blkcipher.max_keysize =
        2 * EME2_BLOCK_SIZE + alg->cra_cipher.cia_max_keysize;

    inst->alg.cra_ctxsize = sizeof(struct eme2_ctx);

    inst->alg.cra_init = init_tfm;
    inst->alg.cra_exit = exit_tfm;

    inst->alg.cra_blkcipher.setkey = setkey;
    inst->alg.cra_blkcipher.encrypt = encrypt;
    inst->alg.cra_blkcipher.decrypt = decrypt;

out_put_alg:
    crypto_mod_put(alg);
    return inst;
}

static void free(struct crypto_instance *inst)
{
    crypto_drop_spawn(crypto_instance_ctx(inst));
    kfree(inst);
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
    return eme2_run_tests();
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
