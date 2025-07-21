#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

// HKDF-Extract implementation
// PRK = HMAC-Hash(salt, IKM)
int HKDF_Extract(const unsigned char *salt, size_t salt_len,
                 const unsigned char *ikm, size_t ikm_len,
                 unsigned char *prk, size_t hash_len) {
    
    // HMAC(salt, ikm)
    if (!HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, NULL)) {
        return 0;  // Error
    }
    return 1;  // Success
}

int HKDF_Expand(const unsigned char *prk, size_t hash_len,
                const unsigned char *info, size_t info_len,
                unsigned char *okm, size_t length) {
    unsigned char counter = 0x01;
    unsigned char output_block[EVP_MAX_MD_SIZE] = {0};
    size_t output_len = 0;
    size_t where = 0;
    HMAC_CTX *hmac = HMAC_CTX_new();
    
    if (!hmac) {
        return 0;
    }
    
    while (where < length) {
        if (!HMAC_Init_ex(hmac, prk, hash_len, EVP_sha256(), NULL)) {
            HMAC_CTX_free(hmac);
            return 0;
        }
        
        if (output_len > 0) {
            if (!HMAC_Update(hmac, output_block, output_len)) {
                HMAC_CTX_free(hmac);
                return 0;
            }
        }
        
        if (info_len > 0) {
            if (!HMAC_Update(hmac, info, info_len)) {
                HMAC_CTX_free(hmac);
                return 0;
            }
        }
        
        if (!HMAC_Update(hmac, &counter, 1) ||
            !HMAC_Final(hmac, output_block, &output_len)) {
            HMAC_CTX_free(hmac);
            return 0;
        }
        
        size_t to_copy = (length - where < output_len) ? length - where : output_len;
        memcpy(okm + where, output_block, to_copy);
        where += to_copy;
        counter++;
    }
    
    HMAC_CTX_free(hmac);
    return 1;
}


// Constants for secp256r1
const int z = -10;  // Given curve-specific parameter



// Constant-time selection between two values
void CSEL(int condition, BIGNUM *result, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    if (condition) {
        BN_copy(result, a);
    } else {
        BN_copy(result, b);
    }
}

// Utility function for modular exponentiation to p-2 (modular inverse)
void mod_inverse(BIGNUM *result, const BIGNUM *x, const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *exp = BN_new();
    BN_copy(exp, p);
    BN_sub_word(exp, 2);
    BN_mod_exp(result, x, exp, p, ctx);
    BN_free(exp);
}

// Utility function for quadratic residue testing
int is_quadratic_residue(const BIGNUM *x, const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *exp = BN_new();
    BIGNUM *result = BN_new();
    int is_qr;
    
    // Calculate (p-1)/2
    BN_copy(exp, p);
    BN_sub_word(exp, 1);
    BN_rshift1(exp, exp);
    
    // Calculate x^((p-1)/2) mod p
    BN_mod_exp(result, x, exp, p, ctx);
    
    // Check if result is 0 or 1
    is_qr = BN_is_zero(result) || BN_is_one(result);
    
    BN_free(exp);
    BN_free(result);
    return is_qr;
}

int SSWU(BIGNUM *u, EC_GROUP *group, EC_POINT *result, BN_CTX *ctx) {
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *t = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *gx1 = BN_new();
    BIGNUM *gx2 = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *temp2 = BN_new();
    BIGNUM *z_bn = BN_new();
    int ret = 0;
    // Get curve parameters
    EC_GROUP_get_curve(group, p, a, b, ctx);
    
    // Convert z to BIGNUM and handle negative value correctly
    BN_set_word(z_bn, 10);
    BN_set_negative(z_bn, 1);  // Make it -10
    
    // Calculate m = (z^2 * u^4 + z * u^2) mod p
    // First u^2
    BN_mod_mul(temp, u, u, p, ctx);
    // Then u^4
    BN_mod_mul(temp2, temp, temp, p, ctx);
    // z^2 * u^4
    BIGNUM *z_squared = BN_new();
    BN_mul(z_squared, z_bn, z_bn, ctx);
    BN_mod_mul(m, z_squared, temp2, p, ctx);
    // z * u^2
    BN_mod_mul(temp2, z_bn, temp, p, ctx);
    // Add them (handle negative correctly with modulo)
    BN_mod_add(m, m, temp2, p, ctx);
    
    // Calculate t = m^(p-2) mod p if m != 0
    if (!BN_is_zero(m)) {
        BIGNUM *exp = BN_new();
        BN_copy(exp, p);
        BN_sub_word(exp, 2);
        BN_mod_exp(t, m, exp, p, ctx);
        BN_free(exp);
    } else {
        BN_zero(t);
    }
    
    // Calculate x1
    if (BN_is_zero(m)) {
        // x1 = (b * (z * a)^(p-2)) mod p
        BN_mod_mul(temp, z_bn, a, p, ctx);
        BIGNUM *exp = BN_new();
        BN_copy(exp, p);
        BN_sub_word(exp, 2);
        BN_mod_exp(temp, temp, exp, p, ctx);
        BN_mod_mul(x1, b, temp, p, ctx);
        BN_free(exp);
    } else {
        // x1 = (-b * (1 + t) * a^(p-2)) mod p
        BN_add_word(t, 1);  // 1 + t
        BIGNUM *exp = BN_new();
        BN_copy(exp, p);
        BN_sub_word(exp, 2);
        BN_mod_exp(temp, a, exp, p, ctx);
        BN_mod_mul(temp, temp, t, p, ctx);
        BN_mod_mul(temp, b, temp, p, ctx);
        BN_set_negative(temp, 1);  // Negate
        BN_mod(x1, temp, p, ctx);  // Final modulo
        BN_free(exp);
    }
    
    // Calculate gx1 = (x1^3 + a*x1 + b) mod p
    BN_mod_mul(temp, x1, x1, p, ctx);
    BN_mod_mul(temp, temp, x1, p, ctx);
    BN_mod_mul(temp2, a, x1, p, ctx);
    BN_mod_add(gx1, temp, temp2, p, ctx);
    BN_mod_add(gx1, gx1, b, p, ctx);
    
    // Calculate x2 = (z * u^2 * x1) mod p
    BN_mod_mul(temp, u, u, p, ctx);
    BN_mod_mul(temp, temp, z_bn, p, ctx);
    BN_mod_mul(x2, temp, x1, p, ctx);
    
    // Calculate gx2 = (x2^3 + a*x2 + b) mod p
    BN_mod_mul(temp, x2, x2, p, ctx);
    BN_mod_mul(temp, temp, x2, p, ctx);
    BN_mod_mul(temp2, a, x2, p, ctx);
    BN_mod_add(gx2, temp, temp2, p, ctx);
    BN_mod_add(gx2, gx2, b, p, ctx);

    // Select between (x1, gx1) and (x2, gx2) based on quadratic residue
    BIGNUM *x = BN_new();
    BIGNUM *v = BN_new();
    
    int l = is_quadratic_residue(gx1, p, ctx);
    if (l) {
        BN_copy(x, x1);
        BN_copy(v, gx1);
    } else {
        BN_copy(x, x2);
        BN_copy(v, gx2);
    }
    
    // Calculate square root of v
    // BIGNUM *y = BN_new();
    if (!BN_mod_sqrt(y, v, p, ctx)) {
        goto cleanup;
    }
    
    // Adjust y based on LSB matching with u
    if (BN_is_odd(u) != BN_is_odd(y)) {
        BN_sub(y, p, y);
    }
    // Set the point coordinates and verify it's on curve
    if (!EC_POINT_set_affine_coordinates(group, result, x, y, ctx) ||
        !EC_POINT_is_on_curve(group, result, ctx)) {
        goto cleanup;
    }
    
    ret = 1;

cleanup:
    // Clean up
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_free(t);
    BN_free(x1);
    BN_free(x2);
    BN_free(gx1);
    BN_free(gx2);
    BN_free(temp);
    BN_free(temp2);
    BN_free(z_bn);
    BN_free(z_squared);
    BN_free(x);
    BN_free(v);
    BN_free(y);
    
    return ret;
}
void print_bytes(const unsigned char* data, size_t len, const char* label) {
    printf("%s: ", label);
    for(size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}



// Main hash-to-element function
EC_POINT* hash_to_element( unsigned char *password_str,  unsigned char *ssid_str, 
                          unsigned char *identifier_str, EC_GROUP *group) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    EC_POINT *P1 = EC_POINT_new(group);
    EC_POINT *P2 = EC_POINT_new(group);
    EC_POINT *PT = EC_POINT_new(group);
    
    // Get the prime field characteristic
    EC_GROUP_get_curve(group, p, NULL, NULL, ctx);
    
    // Calculate len = olen(p) + floor(olen(p)/2)
    size_t len = BN_num_bytes(p) + (BN_num_bytes(p) / 2);
    
    // Convert strings to octets (equivalent to Python's encode())
    size_t pwd_len = strlen(password_str);
    size_t ssid_len = strlen(ssid_str);
    size_t id_len = identifier_str ? strlen(identifier_str) : 0;
    
    // Allocate memory for the octets
    unsigned char *password = (unsigned char *)malloc(pwd_len);
    unsigned char *ssid = (unsigned char *)malloc(ssid_len);
    unsigned char *identifier = id_len > 0 ? (unsigned char *)malloc(id_len) : NULL;
    
    // Copy the raw bytes
    memcpy(password, password_str, pwd_len);
    memcpy(ssid, ssid_str, ssid_len);
    
    if (identifier_str) {
        memcpy(identifier, identifier_str, id_len);
    }
    
    // Prepare input for HKDF-Extract
    size_t total_len = pwd_len + id_len;
    unsigned char *combined = malloc(total_len);
    memcpy(combined, password, pwd_len);
    if (identifier) {
        memcpy(combined + pwd_len, identifier, id_len);
    }
    // HKDF-Extract
    unsigned char pwd_seed[32];  // SHA-256 hash length
    HKDF_Extract(ssid, ssid_len,
                combined, total_len,
                pwd_seed, 32);


    // Generate u1
    unsigned char *pwd_value = malloc(len);
    HKDF_Expand(pwd_seed, 32,
                (unsigned char*)"SAE Hash to Element u1 P1", 25,
                pwd_value, len);

    
    BIGNUM *u1 = BN_new();
    BN_bin2bn(pwd_value, len, u1);
    BN_mod(u1, u1, p, ctx);
    
       // Generate u2
    HKDF_Expand(pwd_seed, 32,
                (unsigned char*)"SAE Hash to Element u2 P2", 25,
                pwd_value, len);
    
    
    // Calculate P1 = SSWU(u1)
    SSWU(u1, group, P1, ctx);
    // After converting to u1:
 
    BIGNUM *u2 = BN_new();
    BN_bin2bn(pwd_value, len, u2);
    BN_mod(u2, u2, p, ctx);
    
    // Calculate P2 = SSWU(u2)
    SSWU(u2, group, P2, ctx);

    // PT = P1 + P2
    EC_POINT_add(group, PT, P1, P2, ctx);
    

    // Clean up
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(u1);
    BN_free(u2);
    EC_POINT_free(P1);
    EC_POINT_free(P2);
    free(password);
    free(ssid);
    if (identifier) {
        free(identifier);
    }
    free(combined);
    free(pwd_value);
    
    return PT;
}

void print_point(const char* test_name, EC_GROUP *group, EC_POINT *point, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    if (EC_POINT_get_affine_coordinates(group, point, x, y, ctx)) {
        printf("%s PT.x: 0x%s\n", test_name, BN_bn2hex(x));
        printf("%s PT.y: 0x%s\n", test_name, BN_bn2hex(y));
    }
    
    BN_free(x);
    BN_free(y);
}

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

void calculate_pwe(EC_POINT* PT, unsigned char *MAC1, unsigned char *MAC2, EC_POINT *PWE, EC_GROUP* group) {
    // unsigned char addr1[6], addr2[6];
    // mac_str_to_bytes(MAC1, addr1);
    // mac_str_to_bytes(MAC2, addr2);
    unsigned char hash_data[12];
    if (memcmp(MAC1, MAC2, 6) > 0) {
        memcpy(hash_data, MAC1, 6);
        memcpy(hash_data + 6, MAC2, 6);
    } else {
        memcpy(hash_data, MAC2, 6);
        memcpy(hash_data + 6, MAC1, 6);
    }
    unsigned char key = 0x00;
    unsigned char val[32];
    unsigned int len;
    HMAC(EVP_sha256(), &key, 1, hash_data, 12, val, &len);

    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP_get_order(group, r, ctx);
    BIGNUM *v = BN_bin2bn(val, len, NULL);
    BIGNUM *r_minus_1 = BN_new();
    BN_sub(r_minus_1, r, BN_value_one());

    BN_mod(v, v, r_minus_1, ctx);
    BN_add(v, v, BN_value_one());

    EC_POINT_mul(group, PWE, NULL, PT, v, ctx);
    goto cleanup;

cleanup:
    BN_free(r); BN_CTX_free(ctx); BN_free(v); BN_free(r_minus_1);
}

// int main() {
//     BN_CTX *ctx = BN_CTX_new();
//     EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

//     // Test Case 1
//     {
//         const char* ssid = "pirwani";
//         const char* password = "correctPassword";
//         EC_POINT* PT = hash_to_element(password, 
//                                          ssid, NULL,
//                                          group);
//         // if (PT) {
//         //     print_point("Test Case 1", group, PT, ctx);
//         // } else {
//         //     printf("Test Case 1 failed\n");
//         // }

//         const char *addr1_str = "00:11:22:33:44:55";
//         const char *addr2_str = "aa:bb:cc:dd:ee:ff";

//         EC_POINT *PWE = EC_POINT_new(group);
//         calculate_pwe(PT, addr1_str, addr2_str, PWE, group);

//         if (PWE) {
//             print_point("Test Case 1", group, PWE, ctx);
//             EC_POINT_free(PWE);
//             EC_POINT_free(PT);
//         } else {
//             printf("Test Case 1 failed\n");
//         }

//     }



//    // Cleanup
//     BN_CTX_free(ctx);
//     EC_GROUP_free(group);
//     return 0;
// }