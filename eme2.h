#ifndef _CRYPTO_EME2_H
#define _CRYPTO_EME2_H

#include <linux/scatterlist.h>

#define EME2_BLOCK_SIZE 16

struct eme2_ctx;

int eme2_encrypt(struct eme2_ctx *ctx,
                 struct scatterlist *dst, struct scatterlist *src,
                 unsigned int nbytes, const u8 *iv, unsigned int ivsize);

int eme2_decrypt(struct eme2_ctx *ctx,
                 struct scatterlist *dst, struct scatterlist *src,
                 unsigned int nbytes, const u8 *iv, unsigned int ivsize);

#endif  /* _CRYPTO_EME2_H */
