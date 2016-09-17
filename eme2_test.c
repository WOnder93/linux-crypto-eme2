#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/completion.h>

#include "eme2_test.h"

#include "eme2_tv.h"
#include "eme2.h"

struct result {
    struct completion comp;
    int err;
};

static void result_complete(struct crypto_async_request *req, int err)
{
    struct result *res = req->data;

    if (err == -EINPROGRESS)
        return;

    res->err = err;
    complete(&res->comp);
}

static int eme2_encrypt_sync(struct ablkcipher_request *req, unsigned int ivsize)
{
    struct result res;
    int err;

    res.err = 0;
    init_completion(&res.comp);

    ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                    &result_complete, &res);
    err = eme2_encrypt(req, ivsize);
    switch (err) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        wait_for_completion(&res.comp);
        err = res.err;
        if (err == 0)
            break;
        /* fall through */
    default:
        break;
    }
    return err;
}

static int eme2_decrypt_sync(struct ablkcipher_request *req, unsigned int ivsize)
{
    struct result res;
    int err;

    res.err = 0;
    init_completion(&res.comp);

    ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                    &result_complete, &res);
    err = eme2_decrypt(req, ivsize);
    switch (err) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        wait_for_completion(&res.comp);
        err = res.err;
        if (err == 0)
            break;
        /* fall through */
    default:
        break;
    }
    return err;
}

static int run_test_case(const struct eme2_test_case *c, unsigned int number)
{
    int err = 0;
    int failed = 0;
    struct crypto_ablkcipher *cipher = NULL;
    struct ablkcipher_request *req = NULL;
    u8 *buffer = NULL;
    struct scatterlist sg[1];

    buffer = kmalloc(c->plaintext_len, GFP_KERNEL);
    if (!buffer) {
        printk("eme2: tests: ERROR allocating buffer!\n");
        goto out;
    }

    sg_init_one(sg, buffer, c->plaintext_len);

    cipher = crypto_alloc_ablkcipher("eme2(aes)", 0, 0);
    if (IS_ERR(cipher)) {
        printk("eme2: tests: ERROR allocating cipher!\n");
        err = PTR_ERR(cipher);
        cipher = NULL;
        goto out;
    }

    err = crypto_ablkcipher_setkey(cipher, c->key, c->key_len);
    if (err) {
        printk("eme2: tests: ERROR setting key!\n");
        goto out;
    }

    req = ablkcipher_request_alloc(cipher, GFP_KERNEL);
    if (IS_ERR(req)) {
        printk("eme2: tests: ERROR allocating request!\n");
        err = PTR_ERR(req);
        req = NULL;
        goto out;
    }

    ablkcipher_request_set_tfm(req, cipher);
    ablkcipher_request_set_crypt(req, sg, sg, c->plaintext_len, (u8 *)c->assoc_data);

    memcpy(buffer, c->plaintext, c->plaintext_len);

    err = eme2_encrypt_sync(req, c->assoc_data_len);
    if (err) {
        printk("eme2: tests: ERROR encrypting!\n");
        goto out;
    }

    if (memcmp(buffer, c->ciphertext, c->plaintext_len) != 0) {
        failed += 1;
        printk("eme2: tests: encryption-%u: Testcase failed!\n", number);
    }

    memcpy(buffer, c->ciphertext, c->plaintext_len);

    err = eme2_decrypt_sync(req, c->assoc_data_len);
    if (err) {
        printk("eme2: tests: ERROR decrypting!\n");
        goto out;
    }

    if (memcmp(buffer, c->plaintext, c->plaintext_len) != 0) {
        failed += 1;
        printk("eme2: tests: decryption-%u: Testcase failed!\n", number);
    }

out:
    if (buffer)
        kfree(buffer);
    if (cipher)
        crypto_free_ablkcipher(cipher);
    if (req)
        ablkcipher_request_free(req);
    return err < 0 ? err : failed;
}

int eme2_run_tests(void)
{
    unsigned int i = 0, ncases = ARRAY_SIZE(eme2_test_cases);
    int res, failed = 0;

    printk("eme2: tests: Running tests...\n");
    for (i = 0; i < ncases; i++) {
        printk("eme2: tests: Running testcase %u...\n", i);
        res = run_test_case(&eme2_test_cases[i], i);
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
