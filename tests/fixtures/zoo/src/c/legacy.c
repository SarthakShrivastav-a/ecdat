/* truth: RSA-2048 keygen (OpenSSL), AES-128 key schedule, MD5 digest, SHA-1 EVP */
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

int make_key(RSA *rsa, BIGNUM *e) {
    return RSA_generate_key_ex(rsa, 2048, e, NULL);
}

int schedule(const unsigned char *k, AES_KEY *aes) {
    return AES_set_encrypt_key(k, 128, aes);
}

void digest(const unsigned char *d, size_t n, unsigned char *out) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, d, n);
    MD5_Final(out, &ctx);
    const EVP_MD *legacy = EVP_sha1();
    (void)legacy;
}
