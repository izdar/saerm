# include "replacement.h"

unsigned char* replace_placeholders(unsigned char *buf, size_t *len_ptr, sae_replacements_t *replacements) {
    size_t len = *len_ptr;
    // First, calculate the final size needed after all replacements
    size_t final_size = len;
    size_t i = 0;
    
    // Placeholder map definition
    static const struct {
        const char *str;
        size_t str_len;
    } ph_map[] = {
        {"<SCALAR>", 8},
        {"<ELEMENT>", 9},
        {"<AC_TOKEN>", 10},
        {"<CONFIRM_HASH>", 14},
        {"<SEND_CONFIRM_COUNTER>", 22},
        {"<NONCE>", 7},
        {"<COUNTER>", 9},
        {"<MIC>", 5},
        {"<RSN_IE>", 8},
        {"<GTK>", 5},
        {"<INSTALL_KEY>", 13},
        {"<SECURE_BIT>", 12}
    };
    
    // Create a local buffer for the send_confirm swap
    uint8_t big_endian_buf[2] = {0, 0};
    
    // Check if we need to swap send_confirm bytes
    bool swap_send_confirm = false;
    if (replacements->send_confirm && replacements->send_confirm_len == 2) {
        big_endian_buf[0] = replacements->send_confirm[1]; // MSB
        big_endian_buf[1] = replacements->send_confirm[0]; // LSB
        swap_send_confirm = true;
    }
    
    // First pass: calculate final size
    while (i < len) {
        bool found = false;
        for (int p = 0; p < sizeof(ph_map)/sizeof(ph_map[0]); p++) {
            if (i + ph_map[p].str_len <= len &&
                memcmp(buf + i, ph_map[p].str, ph_map[p].str_len) == 0) {
                
                // Get replacement length for this placeholder
                size_t replace_len = 0;
                const unsigned char *replace_data = NULL;
                
                switch(p) {
                    case 0: // SCALAR
                        replace_data = replacements->scalar;
                        replace_len = replacements->scalar_len;
                        break;
                    case 1: // ELEMENT
                        replace_data = replacements->element;
                        replace_len = replacements->element_len;
                        break;
                    case 2: // AC_TOKEN
                        replace_data = replacements->ac_token;
                        replace_len = replacements->ac_token_len;
                        break;
                    case 3: // CONFIRM_HASH
                        replace_data = replacements->confirm_hash;
                        replace_len = replacements->confirm_hash_len;
                        break;
                    case 4: // SEND_CONFIRM
                        if (swap_send_confirm) {
                            replace_data = big_endian_buf;
                            replace_len = 2;
                        } else {
                            replace_data = replacements->send_confirm;
                            replace_len = replacements->send_confirm_len;
                        }
                        break;
                    case 5: // NONCE
                        replace_data = replacements->nonce;
                        replace_len = replacements->nonce_len;
                        break;
                    case 6: // COUNTER
                        replace_data = replacements->counter;
                        replace_len = replacements->counter_len;
                        break;
                    case 7: // MIC
                        replace_data = replacements->mic;
                        replace_len = replacements->mic_len;
                        break;
                    case 8: // RSN_IE
                        replace_data = replacements->rsn_ie;
                        replace_len = replacements->rsn_ie_len;
                        break;
                    case 9: // GTK
                        replace_data = replacements->gtk;
                        replace_len = replacements->gtk_len;
                        break;
                    case 10: // INSTALL_KEY
                        replace_data = replacements->install_key_flag;
                        replace_len = replacements->install_key_flag_len;
                        break;
                    case 11: // SECURE_BIT
                        replace_data = replacements->secure_bit;
                        replace_len = replacements->secure_bit_len;
                        break;
                }
                
                size_t placeholder_len = ph_map[p].str_len;
                
                // Adjust final size based on placeholder vs replacement length difference
                if (replace_data != NULL && replace_len > 0) {
                    if (replace_len > placeholder_len) {
                        final_size += (replace_len - placeholder_len);
                    } else {
                        final_size -= (placeholder_len - replace_len);
                    }
                } else {
                    // If no replacement, placeholder is removed entirely
                    final_size -= placeholder_len;
                }
                
                i += placeholder_len;
                found = true;
                break;
            }
        }
        if (!found) {
            i++;
        }
    }
    
    // Allocate a new buffer for the result
    unsigned char *new_buf = (unsigned char*)malloc(final_size);
    if (!new_buf) {
        return NULL; // Memory allocation failed
    }
    
    // Initialize the new buffer to zero to prevent uninitialized memory issues
    memset(new_buf, 0, final_size);
    
    // Second pass: actually perform the replacements
    size_t src_pos = 0;  // Position in original buffer
    size_t dst_pos = 0;  // Position in new buffer
    
    while (src_pos < len) {
        bool found = false;
        for (int p = 0; p < sizeof(ph_map)/sizeof(ph_map[0]); p++) {
            if (src_pos + ph_map[p].str_len <= len &&
                memcmp(buf + src_pos, ph_map[p].str, ph_map[p].str_len) == 0) {
                
                // Get corresponding replacement data
                const unsigned char *replace_data = NULL;
                size_t replace_len = 0;
                
                switch(p) {
                    case 0: // SCALAR
                        replace_data = replacements->scalar;
                        replace_len = replacements->scalar_len;
                        break;
                    case 1: // ELEMENT
                        replace_data = replacements->element;
                        replace_len = replacements->element_len;
                        break;
                    case 2: // AC_TOKEN
                        replace_data = replacements->ac_token;
                        replace_len = replacements->ac_token_len;
                        break;
                    case 3: // CONFIRM_HASH
                        replace_data = replacements->confirm_hash;
                        replace_len = replacements->confirm_hash_len;
                        break;
                    case 4: // SEND_CONFIRM
                        if (swap_send_confirm) {
                            replace_data = big_endian_buf;
                            replace_len = 2;
                        } else {
                            replace_data = replacements->send_confirm;
                            replace_len = replacements->send_confirm_len;
                        }
                        break;
                    case 5: // NONCE
                        replace_data = replacements->nonce;
                        replace_len = replacements->nonce_len;
                        break;
                    case 6: // COUNTER
                        replace_data = replacements->counter;
                        replace_len = replacements->counter_len;
                        break;
                    case 7: // MIC
                        replace_data = replacements->mic;
                        replace_len = replacements->mic_len;
                        break;
                    case 8: // RSN_IE
                        replace_data = replacements->rsn_ie;
                        replace_len = replacements->rsn_ie_len;
                        break;
                    case 9: // GTK
                        replace_data = replacements->gtk;
                        replace_len = replacements->gtk_len;
                        break;
                    case 10: // INSTALL_KEY
                        replace_data = replacements->install_key_flag;
                        replace_len = replacements->install_key_flag_len;
                        break;
                    case 11: // SECURE_BIT
                        replace_data = replacements->secure_bit;
                        replace_len = replacements->secure_bit_len;
                        break;
                }
                
                size_t placeholder_len = ph_map[p].str_len;
                
                // Copy replacement data if available
                if (replace_data != NULL && replace_len > 0) {
                    memcpy(new_buf + dst_pos, replace_data, replace_len);
                    dst_pos += replace_len;
                }
                
                // Skip past the placeholder in the source
                src_pos += placeholder_len;
                
                found = true;
                break;
            }
        }
        
        if (!found) {
            // Copy regular data
            new_buf[dst_pos++] = buf[src_pos++];
        }
    }
    
    // Free the original buffer
    free(buf);
    
    // Update the length
    *len_ptr = final_size;
    
    return new_buf;
}

void print_hex( char *prefix, const uint8_t *buf, size_t len) {
    printf("%s", prefix);
    for(size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

// int main() {
//     uint8_t commit_frame[] = {
//         0x00, 0x01,             // algo
//         0x00, 0x01,             // seq (COMMIT)
//         0x00, 0x00,             // status
//         0x00, 0x13,             // group id
//         '<', 'S', 'C', 'A', 'L', 'A', 'R', '>', // scalar placeholder
//         '<', 'E', 'L', 'E', 'M', 'E', 'N', 'T', '>' // element placeholder
//     };

//     uint8_t confirm_frame[] = {
//         0x00, 0x01,             // algo
//         0x00, 0x02,             // seq (CONFIRM)
//         0x00, 0x00,             // status
//         0x00, 0x13,             // group id
//         '<', 'S', 'E', 'N', 'D', '_', 'C', 'O', 'N', 'F', 'I', 'R', 'M', '_',
//         'C', 'O', 'U', 'N', 'T', 'E', 'R', '>', // send_confirm placeholder
//         '<', 'C', 'O', 'N', 'F', 'I', 'R', 'M', '_', 'H', 'A', 'S', 'H', '>' // confirm_hash placeholder
//     };

//     uint8_t scalar_bytes[] = {0xAA, 0xBB, 0xCC, 0xDD};
//     uint8_t element_bytes[] = {0x11, 0x22, 0x33, 0x44};
//     uint8_t send_confirm_bytes[] = {0x55, 0x66, 0x77, 0x88};
//     uint8_t confirm_hash_bytes[] = {0x99, 0xAA, 0xBB, 0xCC};

//     sae_replacements_t replacements = {
//         .scalar = scalar_bytes,
//         .scalar_len = sizeof(scalar_bytes),
//         .element = element_bytes,
//         .element_len = sizeof(element_bytes),
//         .send_confirm = send_confirm_bytes,
//         .send_confirm_len = sizeof(send_confirm_bytes),
//         .confirm_hash = confirm_hash_bytes,
//         .confirm_hash_len = sizeof(confirm_hash_bytes)
//     };

//     size_t commit_len = sizeof(commit_frame);
//     size_t confirm_len = sizeof(confirm_frame);

//     printf("Testing Commit Frame:\n");
//     print_hex("Before: ", commit_frame, commit_len);
//     commit_len = replace_placeholders(commit_frame, commit_len, &replacements);
//     print_hex("After:  ", commit_frame, commit_len);
    
//     printf("\nTesting Confirm Frame:\n");
//     print_hex("Before: ", confirm_frame, confirm_len);
//     confirm_len = replace_placeholders(confirm_frame, confirm_len, &replacements);
//     print_hex("After:  ", confirm_frame, confirm_len);

//     return 0;
// }