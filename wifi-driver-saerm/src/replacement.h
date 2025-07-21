#ifndef REPLACEMENT_H_
#define REPLACEMENT_H_

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    // SAE Commit frame replacements
    unsigned char *scalar;
    size_t scalar_len;
    
    unsigned char *element;
    size_t element_len;
    
    unsigned char *ac_token;
    size_t ac_token_len;
    
    // SAE Confirm frame replacements
    unsigned char *send_confirm;
    size_t send_confirm_len;
    
    unsigned char *confirm_hash;
    size_t confirm_hash_len;
    
    // EAPOL Key frame common replacements
    unsigned char *nonce;
    size_t nonce_len;
    
    unsigned char *counter;
    size_t counter_len;
    
    unsigned char *mic;
    size_t mic_len;
    
    // EAPOL Key2 specific replacements
    unsigned char *rsn_ie;
    size_t rsn_ie_len;
    
    // EAPOL Key3 specific replacements
    unsigned char *gtk;
    size_t gtk_len;
    
    // EAPOL Key4 specific replacements
    unsigned char *install_key_flag;
    size_t install_key_flag_len;
    
    unsigned char *secure_bit;
    size_t secure_bit_len;
    
} sae_replacements_t;

unsigned char *replace_placeholders(unsigned char *buf, size_t *len,  sae_replacements_t *replacements);

void print_hex( char *prefix, const uint8_t *buf, size_t len);


#endif 