#ifndef ORACLEPARSER_H
#define ORACLEPARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Error codes for different parsing stages
#define SAE_ERROR_HEADER_SHORT -1      // Not enough bytes for header
#define SAE_ERROR_TOKEN_SHORT -2       // AC token truncated
#define SAE_ERROR_SCALAR_SHORT -3      // Scalar field truncated
#define SAE_ERROR_ELEMENT_SHORT -4     // Element field truncated
#define SAE_ERROR_CONTAINER_TAG -5     // Invalid container tag
#define SAE_ERROR_CONTAINER_LEN -6     // Container length exceeds remaining data
#define SAE_ERROR_CONFIRM_SHORT -7     // Confirm fields truncated
#define SAE_ERROR_EAPOL_SHORT -8       // EAPOL fields truncated
#define SAE_ERROR_MALFORMED -9         // General malformed packet
#define SAE_ERROR_OVERFLOW -10         // Packet longer than expected
#define SAE_ERROR_MEMORY -11

// Return codes for success with specific frame type
#define SAE_COMMIT_FRAME 1
#define SAE_CONFIRM_FRAME 2
#define EAPOL_KEY1_FRAME 3
#define EAPOL_KEY2_FRAME 4
#define EAPOL_KEY3_FRAME 5
#define EAPOL_KEY4_FRAME 6

// Container tags and extensions remain the same
#define CONTAINER_TAG 0xFF
#define RG_EXTENSION 0x5C
#define PI_EXTENSION 0x21
#define AC_EXTENSION 0x5D

// #define SUCCESS 0
#define HASH_TO_ELEMENT 126
#define ANTICLOGGING_TOKEN_REQUIRED 76

// Frame sequence numbers
#define COMMIT_SEQ 1
#define CONFIRM_SEQ 2
#define EAPOL_KEY1_SEQ 3
#define EAPOL_KEY2_SEQ 4
#define EAPOL_KEY3_SEQ 5
#define EAPOL_KEY4_SEQ 6

typedef struct {
    // Fixed fields
    uint16_t algo;
    uint16_t seq;
    uint16_t status_code;
    uint16_t group_id;
    
    // Commit frame fields
    uint8_t *ac_token;
    size_t ac_token_len;
    bool ac_token_present;
    bool ac_token_is_placeholder;
    
    uint8_t *scalar;
    size_t scalar_len;
    bool scalar_present;
    bool scalar_is_placeholder;
    
    uint8_t *element;
    size_t element_len;
    bool element_present;
    bool element_is_placeholder;
    
    // Container fields
    uint8_t *password_id;
    size_t password_id_len;
    bool password_id_present;
    
    uint8_t *rejected_groups;
    size_t rejected_groups_len;
    bool rejected_groups_present;
    
    uint8_t *ac_token_container;
    size_t ac_token_container_len;
    bool ac_token_container_present;

    // Confirm frame fields
    uint8_t *send_confirm;
    size_t send_confirm_len;
    bool send_confirm_present;
    bool send_confirm_is_placeholder;
    
    uint8_t *confirm_hash;
    size_t confirm_hash_len;
    bool confirm_hash_present;
    bool confirm_hash_is_placeholder;
    
    // EAPOL Key frame fields
    uint8_t *nonce;
    size_t nonce_len;
    bool nonce_present;
    bool nonce_is_placeholder;
    
    uint8_t *counter;
    size_t counter_len;
    bool counter_present;
    bool counter_is_placeholder;
    
    uint8_t *mic;
    size_t mic_len;
    bool mic_present;
    bool mic_is_placeholder;
    
    // EAPOL Key2 specific fields
    uint8_t *rsn_ie;
    size_t rsn_ie_len;
    bool rsn_ie_present;
    bool rsn_ie_is_placeholder;
    
    // EAPOL Key3 specific fields
    uint8_t *gtk;
    size_t gtk_len;
    bool gtk_present;
    bool gtk_is_placeholder;
    
    // EAPOL Key4 specific fields
    uint8_t *install_key_flag;
    size_t install_key_flag_len;
    bool install_key_present;
    bool install_key_is_placeholder;
    
    uint8_t *secure_bit;
    size_t secure_bit_len;
    bool secure_bit_present;
    bool secure_bit_is_placeholder;
} fuzzer_frame_t;


int hex_to_bin(const char *, uint8_t *, size_t *); 

bool check_space(size_t, size_t, size_t); 

uint8_t* safe_memdup(const uint8_t *, size_t);

int parse_container(const uint8_t *, size_t, 
                    uint8_t **, size_t *, 
                    bool *, uint8_t);

void free_fuzzer_frame(fuzzer_frame_t *); 

int parse_fuzzer_frame(const uint8_t *, size_t, fuzzer_frame_t *);
#endif