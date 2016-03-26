#ifndef _CRYPTO_EME2_H
#define _CRYPTO_EME2_H

#include <linux/scatterlist.h>
#include <crypto/b128ops.h>

#define EME2_BLOCK_SIZE 16

struct eme2_ctx {
    struct crypto_cipher *child;    /* the underlyiing block cipher */

    void *buffer;                   /* auxiliary buffer */
    unsigned int buffer_size;       /* aux. buffer size */

    be128 key_ad;                   /* K_AD  - the associated data key */
    be128 key_ecb;                  /* K_ECB - the ECB pass key */
};

int eme2_encrypt(struct eme2_ctx *ctx,
                 struct scatterlist *dst, struct scatterlist *src,
                 unsigned int nbytes, const u8 *iv, unsigned int ivsize);

int eme2_decrypt(struct eme2_ctx *ctx,
                 struct scatterlist *dst, struct scatterlist *src,
                 unsigned int nbytes, const u8 *iv, unsigned int ivsize);

#endif  /* _CRYPTO_EME2_H */
