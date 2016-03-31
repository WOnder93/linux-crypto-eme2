#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include "eme2_test.h"

#include "eme2_tv.h"
#include "eme2.h"

const test_case_t *cases[] = {
    &case1,
    &case2,
    &case3,
    &case4,
    &case5,
    &case6,
    &case7,
    &case8,
    &case9,
    &case10,
    &case11,
    NULL
};

static int run_test_case(const test_case_t *c, unsigned int number)
{
    int err = 0;
    int failed = 0;
    struct crypto_blkcipher *cipher = NULL;
    struct crypto_tfm *tfm;
    struct eme2_ctx *ctx;
    u8 *buffer = NULL;
    struct scatterlist sg[1];
    struct blkcipher_desc desc;

    buffer = kmalloc(c->plaintext_len, GFP_KERNEL);
    if (!buffer) {
        printk("eme2: tests: ERROR allocating buffer!\n");
        goto out;
    }

    sg_init_one(sg, buffer, c->plaintext_len);

    cipher = crypto_alloc_blkcipher("eme2(aes)", 0, 0);
    if (IS_ERR(cipher)) {
        printk("eme2: tests: ERROR allocating cipher!\n");
        err = PTR_ERR(cipher);
        cipher = NULL;
        goto out;
    }

    err = crypto_blkcipher_setkey(cipher, c->key, c->bytes_in_key);
    if (err) {
        printk("eme2: tests: ERROR setting key!\n");
        goto out;
    }

    tfm = crypto_blkcipher_tfm(cipher);
    ctx = crypto_tfm_ctx(tfm);

    memcpy(buffer, c->plaintext, c->plaintext_len);
    err = eme2_encrypt(ctx, sg, sg, c->plaintext_len,
                       c->assoc_data, c->assoc_data_len);
    if (err) {
        printk("eme2: tests: ERROR encrypting!\n");
        goto out;
    }

    if (memcmp(buffer, c->ciphertext, c->plaintext_len) != 0) {
        failed += 1;
        printk("eme2: tests: encryption-%u: Testcase failed!\n", number);
    }

    memcpy(buffer, c->ciphertext, c->plaintext_len);
    err = eme2_decrypt(ctx, sg, sg, c->plaintext_len,
                       c->assoc_data, c->assoc_data_len);
    if (err) {
        printk("eme2: tests: ERROR decrypting!\n");
        goto out;
    }

    if (memcmp(buffer, c->plaintext, c->plaintext_len) != 0) {
        failed += 1;
        printk("eme2: tests: decryption-%u: Testcase failed!\n", number);
    }

    if (c->assoc_data_len == EME2_BLOCK_SIZE) {
        desc.flags = 0;
        desc.tfm = cipher;
        crypto_blkcipher_set_iv(cipher, c->assoc_data, c->assoc_data_len);

        memcpy(buffer, c->plaintext, c->plaintext_len);

        err = crypto_blkcipher_encrypt(&desc, sg, sg, c->plaintext_len);
        if (err) {
            printk("eme2: tests: ERROR encrypting via crypto API!\n");
            goto out;
        }

        if (memcmp(buffer, c->ciphertext, c->plaintext_len) != 0) {
            failed += 1;
            printk("eme2: tests: encryption-%u-api: Testcase failed!\n", number);
        }
    }
out:
    if (buffer)
        kfree(buffer);
    if (cipher)
        crypto_free_blkcipher(cipher);
    return err < 0 ? err : failed;
}

int eme2_run_tests(void)
{
    unsigned int i = 0;
    int res, failed = 0;

    printk("eme2: tests: Running tests...\n");
    for (i = 0; cases[i] != NULL; i++) {
        printk("eme2: tests: Running testcase %u...\n", i);
        res = run_test_case(cases[i], i);
        if (res < 0) {
            return -EINVAL;
        }
        failed += res;
    }
    if (failed) {
        printk("eme2: tests: FAIL: %i tests failed!\n", failed);
    } else {
        printk("eme2: tests: OK!\n");
    }
    return 0;
}
EXPORT_SYMBOL_GPL(eme2_run_tests);
