#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>

// Print a BIGNUM in both decimal and hex format
void print_bn(const char* name, const BIGNUM *value) {
    char *hex = BN_bn2hex(value);
    char *dec = BN_bn2dec(value);
    printf("%s:\n", dec);
    printf("  dec: %s\n", dec);
    printf("  hex: 0x%s\n", hex);
    OPENSSL_free(hex);
    OPENSSL_free(dec);
}

int SSWU(BIGNUM *u, EC_GROUP *group, BN_CTX *ctx, BIGNUM **result_x, BIGNUM **result_gx) {
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *t = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *gx1 = BN_new();
    BIGNUM *gx2 = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *temp2 = BN_new();
    BIGNUM *z_bn = BN_new();
    
    // Get curve parameters
    EC_GROUP_get_curve(group, p, a, b, ctx);
    
    // Convert z to BIGNUM and handle negative value correctly
    BN_set_word(z_bn, 10);
    BN_set_negative(z_bn, 1);  // Make it -10
    
    printf("=== Test Run ===\n");
    print_bn("Input u", u);
    
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
    
    print_bn("m", m);
    
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
    
    print_bn("t", t);
    
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
        BIGNUM *one_plus_t = BN_new();
        BN_copy(one_plus_t, t);
        BN_add_word(one_plus_t, 1);
        
        BIGNUM *exp = BN_new();
        BN_copy(exp, p);
        BN_sub_word(exp, 2);
        BN_mod_exp(temp, a, exp, p, ctx);
        BN_mod_mul(temp, temp, one_plus_t, p, ctx);
        BN_mod_mul(temp, b, temp, p, ctx);
        BN_set_negative(temp, 1);
        BN_mod(x1, temp, p, ctx);
        
        BN_free(exp);
        BN_free(one_plus_t);
    }
    
    print_bn("x1", x1);
    
    // Calculate gx1 = (x1^3 + a*x1 + b) mod p
    BN_mod_mul(temp, x1, x1, p, ctx);
    BN_mod_mul(temp, temp, x1, p, ctx);
    BN_mod_mul(temp2, a, x1, p, ctx);
    BN_mod_add(gx1, temp, temp2, p, ctx);
    BN_mod_add(gx1, gx1, b, p, ctx);
    
    print_bn("gx1", gx1);
    
    // Calculate x2 = (z * u^2 * x1) mod p
    BN_mod_mul(temp, u, u, p, ctx);
    BN_mod_mul(temp, temp, z_bn, p, ctx);
    BN_mod_mul(x2, temp, x1, p, ctx);
    
    print_bn("x2", x2);
    
    // Calculate gx2 = (x2^3 + a*x2 + b) mod p
    BN_mod_mul(temp, x2, x2, p, ctx);
    BN_mod_mul(temp, temp, x2, p, ctx);
    BN_mod_mul(temp2, a, x2, p, ctx);
    BN_mod_add(gx2, temp, temp2, p, ctx);
    BN_mod_add(gx2, gx2, b, p, ctx);
    
    print_bn("gx2", gx2);
    
    printf("\n");
    
    // Copy results if pointers provided
    if (result_x && result_gx) {
        *result_x = BN_dup(x1);
        *result_gx = BN_dup(gx1);
    }
    
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
    
    return 1;
}

// int main() {
//     BN_CTX *ctx = BN_CTX_new();
//     EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
//     // Test values
//     const char* test_values[] = {
//         "75BCD15",  // 123456789 in hex
//         "DEADBEEF",
//         "1234567890ABCDEF",
//         NULL
//     };
    
//     // Run tests
//     for (int i = 0; test_values[i] != NULL; i++) {
//         BIGNUM *u = BN_new();
//         BN_hex2bn(&u, test_values[i]);
        
//         BIGNUM *result_x = NULL;
//         BIGNUM *result_gx = NULL;
        
//         SSWU(u, group, ctx, &result_x, &result_gx);
        
//         BN_free(u);
//         if (result_x) BN_free(result_x);
//         if (result_gx) BN_free(result_gx);
//     }
    
//     // Clean up
//     BN_CTX_free(ctx);
//     EC_GROUP_free(group);
    
//     return 0;
// }