#ifndef LOOPING_H
#define LOOPING_H

#include <openssl/bn.h>


typedef struct PWE {
    BIGNUM *x;
    BIGNUM *y;
    int found;
} PWE;

EC_POINT* derive_pwe_looping(EC_GROUP *group, unsigned char *password,
                    unsigned char *addr1_str, unsigned char *addr2_str,
                    const BIGNUM *prime, const BIGNUM *b,
                    size_t bits);

static int kdf_length(const unsigned char *data, const char *label,
                     const unsigned char *context, size_t context_len,
                     size_t length, double divisor,
                     unsigned char *out);

static int mac_str_to_bytes(const char *mac_str, unsigned char *bytes);

void hmac256(const unsigned char *key, size_t key_len,
                   const unsigned char *data, size_t data_len,
                   unsigned char *out);

int kdf_length(const unsigned char *data, const char *label,
                     const unsigned char *context, size_t context_len,
                     size_t length, double divisor,
                     unsigned char *out);


#endif 