#ifndef _CRYPTO_EME2_H
#define _CRYPTO_EME2_H

#include <linux/crypto.h>

#define EME2_BLOCK_SIZE 16

int eme2_encrypt(struct ablkcipher_request *req, unsigned int ivsize);
int eme2_decrypt(struct ablkcipher_request *req, unsigned int ivsize);

#endif  /* _CRYPTO_EME2_H */
