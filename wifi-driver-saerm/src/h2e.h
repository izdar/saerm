#ifndef HTE_H
#define HTE_H

#include <openssl/ec.h>

EC_POINT *hash_to_element(unsigned char *password_str, unsigned char *ssid_str, 
                         unsigned char *identifier_str, EC_GROUP *group);

void calculate_pwe(EC_POINT* PT, unsigned char *MAC1, unsigned char *MAC2, EC_POINT *PWE, EC_GROUP* group);

void print_point(const char* test_name, EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);

#endif