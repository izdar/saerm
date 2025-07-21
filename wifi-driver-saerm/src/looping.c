#include <stdio.h>
#include <string.h>
#include <math.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>

#define MAX_COUNTER 100  // Matches Python implementation

typedef struct {
    BIGNUM *x;
    BIGNUM *y;
    int found;
} PWE;

// HMAC256 function matching Python implementation
void hmac256(const unsigned char *key, size_t key_len,
                   const unsigned char *data, size_t data_len,
                   unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, &len);
}

// HMAC224 function for KDF
static void hmac224(const unsigned char *key, size_t key_len,
                   const unsigned char *data, size_t data_len,
                   unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha224(), key, key_len, data, data_len, out, &len);
}

// KDF function matching Python implementation
int kdf_length(const unsigned char *data, const char *label,
                     const unsigned char *context, size_t context_len,
                     size_t length, double divisor,
                     unsigned char *out) {
    int iterations = ceil(length / 256.0);
    size_t result_len = 0;
    
    // Prepare base hash data format
    size_t label_len = strlen(label);
    size_t hash_data_len = 2 + label_len + context_len + 2;  // 2 bytes for i, label, context, 2 bytes for length
    unsigned char *hash_data = malloc(hash_data_len);
    if (!hash_data) return 0;
    
    // Copy label and context into hash_data (after space for 2-byte i)
    memcpy(hash_data + 2, label, label_len);
    memcpy(hash_data + 2 + label_len, context, context_len);
    
    // Add length as little-endian short at the end
    hash_data[hash_data_len - 2] = length & 0xFF;
    hash_data[hash_data_len - 1] = (length >> 8) & 0xFF;
    
    for (int i = 1; i <= iterations; i++) {
        // Set i as little-endian short at start
        hash_data[0] = i & 0xFF;
        hash_data[1] = (i >> 8) & 0xFF;
        
        // Choose hash function based on length/divisor
        if (length == 224 || length == 28) {
            hmac224(data, SHA256_DIGEST_LENGTH, hash_data, hash_data_len, out + result_len);
            result_len += 28;  // SHA224 output length
        } else {
            hmac256(data, SHA256_DIGEST_LENGTH, hash_data, hash_data_len, out + result_len);
            result_len += 32;  // SHA256 output length
        }
    }
    
    free(hash_data);
    return 1;
}

// Legendre symbol calculation (a|p)
static int legendre_symbol(const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *exp = BN_new();
    BIGNUM *tmp = BN_new();
    int result = -2;  // Invalid default value
    
    // exp = (p-1)/2
    BN_sub(exp, p, BN_value_one());
    BN_rshift1(exp, exp);
    
    // tmp = a^((p-1)/2) mod p
    BN_mod_exp(tmp, a, exp, p, ctx);
    
    if (BN_is_one(tmp)) {
        result = 1;
    } else if (BN_is_zero(tmp)) {
        result = 0;
    } else {
        result = -1;
    }
    
    BN_free(exp);
    BN_free(tmp);
    return result;
}

// Convert MAC address string to bytes
static int mac_str_to_bytes(const char *mac_str, unsigned char *bytes) {
    // Remove colons and convert to bytes
    char hex[13];  // 12 chars for 6 bytes without colons + null terminator
    int j = 0;
    
    // Copy string removing colons
    for (int i = 0; mac_str[i] != '\0' && j < 12; i++) {
        if (mac_str[i] != ':') {
            hex[j++] = mac_str[i];
        }
    }
    hex[j] = '\0';
    
    // Check if we got the right number of characters
    if (strlen(hex) != 12) {
        return 0;
    }
    
    // Convert hex string to bytes
    for (int i = 0; i < 6; i++) {
        char byte_str[3] = {hex[i*2], hex[i*2+1], '\0'};
        bytes[i] = strtol(byte_str, NULL, 16);
    }
    
    return 1;
}
void PWE_free(PWE *pwe) {
    if (pwe) {
        BN_free(pwe->x);
        BN_free(pwe->y);
        free(pwe);
    }
}

EC_POINT* derive_pwe_looping(EC_GROUP *group, unsigned char *password,
                    unsigned char *addr1_str, unsigned char *addr2_str,
                    const BIGNUM *prime, const BIGNUM *b,
                    size_t bits) {
    PWE *pwe = malloc(sizeof(PWE));
    if (!pwe) return NULL;
    
    pwe->x = BN_new();
    pwe->y = BN_new();
    pwe->found = 0;
    
    // Convert MAC addresses from strings to bytes
    unsigned char addr1[6], addr2[6];
    memcpy(addr1, addr1_str, 6);
    memcpy(addr2, addr2_str, 6);
    
    
    // Create hash_pw based on MAC address ordering
    unsigned char hash_pw[12];  // 6 bytes each MAC
    if (memcmp(addr1, addr2, 6) > 0) {
        memcpy(hash_pw, addr1, 6);
        memcpy(hash_pw + 6, addr2, 6);
    } else {
        memcpy(hash_pw, addr2, 6);
        memcpy(hash_pw + 6, addr1, 6);
    }
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *y_sqr = BN_new();
    BIGNUM *three = BN_new();
    BN_set_word(three, 3);
    
    unsigned char pwd_seed[SHA256_DIGEST_LENGTH];
    unsigned char pwd_value[bits/8];
    
    for (int counter = 1; counter < MAX_COUNTER; counter++) {
        // Construct hash_data: password || counter
        size_t hash_data_len = strlen(password) + 1;
        unsigned char *hash_data = malloc(hash_data_len);
        memcpy(hash_data, password, strlen(password));
        hash_data[hash_data_len - 1] = counter & 0xFF;
        
        // Calculate pwd_seed using HMAC
        hmac256(hash_pw, 12, hash_data, hash_data_len, pwd_seed);
        
        // Calculate pwd_value using KDF
        unsigned char *p_bytes = malloc(bits/8);
        BN_bn2bin(prime, p_bytes);
        
        if (!kdf_length(pwd_seed, "SAE Hunting and Pecking", p_bytes, bits/8,
                       bits, bits, pwd_value)) {
            free(hash_data);
            free(p_bytes);
            continue;
        }
        
        free(hash_data);
        free(p_bytes);
        
        // Convert pwd_value to BIGNUM
        BN_bin2bn(pwd_value, bits/8, pwe->x);
        
        // Check if pwd_value >= prime
        if (BN_cmp(pwe->x, prime) >= 0)
            continue;
        
        // Calculate y² = (x³ - 3x + b) mod p
        // First x³
        BN_mod_mul(y_sqr, pwe->x, pwe->x, prime, ctx);
        BN_mod_mul(y_sqr, y_sqr, pwe->x, prime, ctx);
        
        // Subtract 3x
        BIGNUM *temp = BN_new();
        BN_mod_mul(temp, three, pwe->x, prime, ctx);
        BN_mod_sub(y_sqr, y_sqr, temp, prime, ctx);
        
        // Add b
        BN_mod_add(y_sqr, y_sqr, b, prime, ctx);
        
        // Check if y_sqr is quadratic residue
        if (legendre_symbol(y_sqr, prime, ctx) != 1) {
            BN_free(temp);
            continue;
        }
        
        // Calculate square root
        BN_mod_sqrt(pwe->y, y_sqr, prime, ctx);
        
        // Check if we need to negate y
        int y_bit = pwd_seed[SHA256_DIGEST_LENGTH-1] & 1;
        if ((BN_is_odd(pwe->y) ? 1 : 0) != y_bit) {
            BN_sub(pwe->y, prime, pwe->y);
        }
        
        BN_free(temp);
        pwe->found = 1;
        break;
    }
    
    BN_free(y_sqr);
    BN_free(three);
    
    EC_POINT *looping = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, looping, pwe->x, pwe->y, ctx);

    BN_CTX_free(ctx);
    BN_free(pwe->x); 
    BN_free(pwe->y);
    if(pwe) free(pwe);

    return looping;
}



// int main() {
//     // Initialize curve parameters (P-256)
//     EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
//     BIGNUM *prime = BN_new();
//     BIGNUM *a = BN_new();
//     BIGNUM *b = BN_new();
//     EC_GROUP_get_curve_GFp(group, prime, a, b, NULL);
    
//     // Example MACs and password
//     const char *addr1_str = "00:11:22:33:44:55";
//     const char *addr2_str = "aa:bb:cc:dd:ee:ff";
//     const char *password = "password123";
    
//     PWE *pwe = derive_pwe_looping(password, addr1_str, addr2_str, prime, b, 256);
    
//     if (pwe && pwe->found) {
//         char *x_hex = BN_bn2hex(pwe->x);
//         char *y_hex = BN_bn2hex(pwe->y);
//         printf("Found PWE:\nX: %s\nY: %s\n", x_hex, y_hex);
//         OPENSSL_free(x_hex);
//         OPENSSL_free(y_hex);
//     } else {
//         printf("Failed to find valid PWE\n");
//     }
    
//     // Cleanup
//     PWE_free(pwe);
//     BN_free(prime);
//     BN_free(a);
//     BN_free(b);
//     EC_GROUP_free(group);
    
//     return 0;
// }