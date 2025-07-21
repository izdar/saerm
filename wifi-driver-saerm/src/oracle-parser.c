# include "oracle-parser.h"

int hex_to_bin(const char *hex, uint8_t *bin, size_t *bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    
    *bin_len = hex_len / 2;
    
    for (size_t i = 0; i < hex_len; i += 2) {
        char hex_byte[3] = {hex[i], hex[i + 1], '\0'};
        char *end;
        bin[i/2] = (uint8_t)strtol(hex_byte, &end, 16);
        if (*end != '\0') return -1;
    }
    
    return 0;
}

bool check_space(size_t offset, size_t needed, size_t total) {
    if (offset + needed > total) {
        return false;
    }
    return true;
}

uint8_t* safe_memdup(const uint8_t *src, size_t len) {
    if (src == NULL || len == 0 || len > 1024*1024) { // Add reasonable max size
        return NULL;
    }
    uint8_t *dst = malloc(len);
    if (!dst) return NULL;
    memcpy(dst, src, len);
    return dst;
}

// void safe_allocate_and_copy(uint8_t *src, uint8_t** dest, size_t len)
// {

// }


int parse_containers(const uint8_t *data, size_t data_len, size_t *offset, fuzzer_frame_t *frame) {
    int error_encountered = 0;  // Track if we encountered any errors
    
    // Parse containers
    while (*offset < data_len) {
        // Check if there's at least one byte left for container tag
        if (!check_space(*offset, 1, data_len)) {
            // No more data - this is normal, not an error
            break;
        }
        
        // Check for container tag
        if (data[*offset] != CONTAINER_TAG) {
            // Not a container, just skip this byte
            (*offset)++;
            continue;
        }
        
        // Now we have a container tag, so check for length field
        if (!check_space(*offset, 2, data_len)) {
            // Container tag without length - this is an error
            if (!error_encountered) error_encountered = SAE_ERROR_CONTAINER_LEN;
            (*offset)++;
            continue;
        }
        
        // Get container length
        uint8_t len = data[*offset + 1];
        
        // Check if enough space for complete container
        if (!check_space(*offset, 2 + len, data_len)) {
            // Container length exceeds available data
            if (!error_encountered) error_encountered = SAE_ERROR_CONTAINER_LEN;
            (*offset)++;
            continue;
        }
        
        // Check for extension type (must have at least one byte for extension type)
        if (len < 1) {
            // Invalid container length
            if (!error_encountered) error_encountered = SAE_ERROR_CONTAINER_LEN;
            (*offset) += 2;  // Skip tag and length
            continue;
        }
        
        // Process container based on extension type
        uint8_t extension_type = data[*offset + 2];
        
        // Try password identifier container
        if (extension_type == PI_EXTENSION) {
            frame->password_id = safe_memdup(data + *offset + 3, len - 1);
            if (frame->password_id) {
                frame->password_id_len = len - 1;
                frame->password_id_present = true;
            } else {
                if (!error_encountered) error_encountered = SAE_ERROR_MEMORY;
            }
            *offset += 2 + len;
            continue;
        }
        
        // Try rejected groups container
        if (extension_type == RG_EXTENSION) {
            frame->rejected_groups = safe_memdup(data + *offset + 3, len - 1);
            if (frame->rejected_groups) {
                frame->rejected_groups_len = len - 1;
                frame->rejected_groups_present = true;
            } else {
                if (!error_encountered) error_encountered = SAE_ERROR_MEMORY;
            }
            *offset += 2 + len;
            continue;
        }
        
        // Try AC token container
        if (extension_type == AC_EXTENSION) {
            frame->ac_token_container = safe_memdup(data + *offset + 3, len - 1);
            if (frame->ac_token_container) {
                frame->ac_token_container_len = len - 1;
                frame->ac_token_container_present = true;
            } else {
                if (!error_encountered) error_encountered = SAE_ERROR_MEMORY;
            }
            *offset += 2 + len;
            continue;
        }
        
        // Unknown extension type, skip this container
        if (!error_encountered) error_encountered = SAE_ERROR_MALFORMED;
        *offset += 2 + len;
    }
    
    return error_encountered;  // Return 0 if no errors, or the error code if errors occurred
}

void free_fuzzer_frame(fuzzer_frame_t *frame) {
    if (!frame) return;
    
    if(frame->ac_token)free(frame->ac_token);
    if(frame->scalar)free(frame->scalar);
    if(frame->element)free(frame->element);
    if(frame->password_id)free(frame->password_id);
    if(frame->rejected_groups)free(frame->rejected_groups);
    if(frame->ac_token_container)free(frame->ac_token_container);
    if(frame->send_confirm)free(frame->send_confirm);
    if(frame->confirm_hash)free(frame->confirm_hash);
    
    // memset(frame, 0, sizeof(fuzzer_frame_t));
}

int parse_fuzzer_frame(const uint8_t *raw_data, size_t data_len, fuzzer_frame_t *frame) {
    size_t offset = 0;
    const uint8_t *data = raw_data;
    int ret;

    // Initialize frame with zeros
    memset(frame, 0, sizeof(fuzzer_frame_t));

    if (!check_space(offset, 8, data_len)) {
        return SAE_ERROR_HEADER_SHORT;
    }

    frame->algo = (data[offset + 1] << 8) | data[offset];
    offset += 2;
    
    frame->seq = (data[offset + 1] << 8) | data[offset];
    offset += 2;
    
    frame->status_code = (data[offset + 1] << 8) | data[offset];
    offset += 2;
    
    frame->group_id = (data[offset + 1] << 8) | data[offset];
    offset += 2;
    
    // Handle SAE frames
    if (frame->seq == COMMIT_SEQ) {
        if (check_space(offset, 10, data_len) && memcmp(data + offset, "<AC_TOKEN>", 10) == 0) {
            frame->ac_token = safe_memdup(data + offset, 10);
            if (!frame->ac_token) {
                return SAE_ERROR_MEMORY;
            }
            frame->ac_token_len = 10;
            frame->ac_token_present = true;
            frame->ac_token_is_placeholder = true;
            offset += 10;
        } else {
            frame->ac_token_present = false;
        }

        // Scalar
        if (!check_space(offset, 8, data_len)) {
            return SAE_ERROR_SCALAR_SHORT;
        }

        if (memcmp(data + offset, "<SCALAR>", 8) == 0) {
            frame->scalar = safe_memdup(data + offset, 8);
            if (!frame->scalar) {
                return SAE_ERROR_MEMORY;
            }
            frame->scalar_len = 8;
            frame->scalar_present = true;
            frame->scalar_is_placeholder = true;
            offset += 8;
        } else {
            if (!check_space(offset, 32, data_len)) {
                return SAE_ERROR_SCALAR_SHORT;
            }
            frame->scalar = safe_memdup(data + offset, 32);
            if (!frame->scalar) {
                return SAE_ERROR_MEMORY;
            }
            frame->scalar_len = 32;
            frame->scalar_present = true;
            frame->scalar_is_placeholder = false;
            offset += 32;
        }

        // Element
        if (!check_space(offset, 9, data_len)) {
            return SAE_ERROR_ELEMENT_SHORT;
        }

        if (memcmp(data + offset, "<ELEMENT>", 9) == 0) {
            frame->element = safe_memdup(data + offset, 9);
            if (!frame->element) {
                return SAE_ERROR_MEMORY;
            }
            frame->element_len = 9;
            frame->element_present = true;
            frame->element_is_placeholder = true;
            offset += 9;
        } else {
            if (!check_space(offset, 64, data_len)) {
                return SAE_ERROR_ELEMENT_SHORT;
            }
            frame->element = safe_memdup(data + offset, 64);
            if (!frame->element) {
                return SAE_ERROR_MEMORY;
            }
            frame->element_len = 64;
            frame->element_present = true;
            frame->element_is_placeholder = false;
            offset += 64;
        }

        int container_result = parse_containers(data, data_len, &offset, frame);
        
        if (container_result < 0) {
            return container_result;
        }
        
        return SAE_COMMIT_FRAME;
    } 
    else if (frame->seq == CONFIRM_SEQ) {
        if (!check_space(offset, 22, data_len)) {
            return SAE_ERROR_CONFIRM_SHORT;
        }

        if (memcmp(data + offset, "<SEND_CONFIRM_COUNTER>", 22) == 0) {
            frame->send_confirm = safe_memdup(data + offset, 22);
            if (!frame->send_confirm) {
                return SAE_ERROR_MEMORY;
            }
            frame->send_confirm_len = 22;
            frame->send_confirm_present = true;
            frame->send_confirm_is_placeholder = true;
            offset += 22;
        } else {
            if (!check_space(offset, 2, data_len)) {
                return SAE_ERROR_CONFIRM_SHORT;
            }
            frame->send_confirm = safe_memdup(data + offset, 2);
            if (!frame->send_confirm) {
                return SAE_ERROR_MEMORY;
            }
            frame->send_confirm_len = 2;
            frame->send_confirm_present = true;
            frame->send_confirm_is_placeholder = false;
            offset += 2;
        }

        if (!check_space(offset, 14, data_len)) {
            return SAE_ERROR_CONFIRM_SHORT;
        }

        if (memcmp(data + offset, "<CONFIRM_HASH>", 14) == 0) {
            frame->confirm_hash = safe_memdup(data + offset, 14);
            if (!frame->confirm_hash) {
                return SAE_ERROR_MEMORY;
            }
            frame->confirm_hash_len = 14;
            frame->confirm_hash_present = true;
            frame->confirm_hash_is_placeholder = true;
            offset += 14;
        } else {
            if (!check_space(offset, 32, data_len)) {
                return SAE_ERROR_CONFIRM_SHORT;
            }
            frame->confirm_hash = safe_memdup(data + offset, 32);
            if (!frame->confirm_hash) {
                return SAE_ERROR_MEMORY;
            }
            frame->confirm_hash_len = 32;
            frame->confirm_hash_present = true;
            frame->confirm_hash_is_placeholder = false;
            offset += 32;
        }

        return SAE_CONFIRM_FRAME;
    }

    // Handle EAPOL Key frames
    // else if (frame->seq == EAPOL_KEY1_SEQ || 
    //          frame->seq == EAPOL_KEY2_SEQ || 
    //          frame->seq == EAPOL_KEY3_SEQ || 
    //          frame->seq == EAPOL_KEY4_SEQ) {
        
    //     // Parse the Nonce
    //     if (!check_space(offset, 7, data_len)) {
    //         return SAE_ERROR_EAPOL_SHORT;
    //     }

    //     if (memcmp(data + offset, "<NONCE>", 7) == 0) {
    //         frame->nonce = safe_memdup(data + offset, 7);
    //         if (!frame->nonce) {
    //             printf("I am here 320 in oracle-parser.c\n");                
    //             free_fuzzer_frame(frame);
    //             return SAE_ERROR_MEMORY;
    //         }
    //         frame->nonce_len = 7;
    //         frame->nonce_present = true;
    //         frame->nonce_is_placeholder = true;
    //         offset += 7;
    //     } else {
    //         if (!check_space(offset, 32, data_len)) {
    //             return SAE_ERROR_EAPOL_SHORT;
    //         }
    //         frame->nonce = safe_memdup(data + offset, 32);
    //         if (!frame->nonce) {
    //             printf("I am here 334 in oracle-parser.c\n");                
    //             free_fuzzer_frame(frame);
    //             return SAE_ERROR_MEMORY;
    //         }
    //         frame->nonce_len = 32;
    //         frame->nonce_present = true;
    //         frame->nonce_is_placeholder = false;
    //         offset += 32;
    //     }

    //     // Parse the Counter
    //     if (!check_space(offset, 9, data_len)) {
    //         return SAE_ERROR_EAPOL_SHORT;
    //     }

    //     if (memcmp(data + offset, "<COUNTER>", 9) == 0) {
    //         frame->counter = safe_memdup(data + offset, 9);
    //         if (!frame->counter) {
    //             printf("I am here 352 in oracle-parser.c\n");                
    //             free_fuzzer_frame(frame);
    //             return SAE_ERROR_MEMORY;
    //         }
    //         frame->counter_len = 9;
    //         frame->counter_present = true;
    //         frame->counter_is_placeholder = true;
    //         offset += 9;
    //     } else {
    //         if (!check_space(offset, 8, data_len)) {
    //             return SAE_ERROR_EAPOL_SHORT;
    //         }
    //         frame->counter = safe_memdup(data + offset, 8);
    //         if (!frame->counter) {
    //             printf("I am here 366 in oracle-parser.c\n");                
    //             free_fuzzer_frame(frame);
    //             return SAE_ERROR_MEMORY;
    //         }
    //         frame->counter_len = 8;
    //         frame->counter_present = true;
    //         frame->counter_is_placeholder = false;
    //         offset += 8;
    //     }

    //     // Parse the MIC (Message Integrity Code)
    //     if (!check_space(offset, 5, data_len)) {
    //         return SAE_ERROR_EAPOL_SHORT;
    //     }

    //     if (memcmp(data + offset, "<MIC>", 5) == 0) {
    //         frame->mic = safe_memdup(data + offset, 5);
    //         if (!frame->mic) {
    //             printf("I am here 384 in oracle-parser.c\n");                
    //             free_fuzzer_frame(frame);
    //             return SAE_ERROR_MEMORY;
    //         }
    //         frame->mic_len = 5;
    //         frame->mic_present = true;
    //         frame->mic_is_placeholder = true;
    //         offset += 5;
    //     } else {
    //         if (!check_space(offset, 16, data_len)) {
    //             return SAE_ERROR_EAPOL_SHORT;
    //         }
    //         frame->mic = safe_memdup(data + offset, 16);
    //         if (!frame->mic) {
    //             printf("I am here 398 in oracle-parser.c\n");                
    //             free_fuzzer_frame(frame);
    //             return SAE_ERROR_MEMORY;
    //         }
    //         frame->mic_len = 16;
    //         frame->mic_present = true;
    //         frame->mic_is_placeholder = false;
    //         offset += 16;
    //     }

    //     // Add specific handling for each EAPOL Key frame type
    //     if (frame->seq == EAPOL_KEY1_SEQ) {
    //         // Key frame 1 specific fields or flags if needed
    //         return EAPOL_KEY1_FRAME;
    //     }
    //     else if (frame->seq == EAPOL_KEY2_SEQ) {
    //         // Parse RSN IE if present
    //         if (check_space(offset, 7, data_len) && memcmp(data + offset, "<RSN_IE>", 7) == 0) {
    //             frame->rsn_ie = safe_memdup(data + offset, 7);
    //             if (!frame->rsn_ie) {
    //                 printf("I am here 418 in oracle-parser.c\n");                
    //                 free_fuzzer_frame(frame);
    //                 return SAE_ERROR_MEMORY;
    //             }
    //             frame->rsn_ie_len = 7;
    //             frame->rsn_ie_present = true;
    //             frame->rsn_ie_is_placeholder = true;
    //             offset += 7;
    //         } else if (check_space(offset, 2, data_len)) {
    //             // RSN IE with real length
    //             uint16_t ie_len = (data[offset] << 8) | data[offset + 1];
    //             if (check_space(offset, 2 + ie_len, data_len)) {
    //                 frame->rsn_ie = safe_memdup(data + offset + 2, ie_len);
    //                 if (!frame->rsn_ie) {
    //                     printf("I am here 432 in oracle-parser.c\n");                
    //                     free_fuzzer_frame(frame);
    //                     return SAE_ERROR_MEMORY;
    //                 }
    //                 frame->rsn_ie_len = ie_len;
    //                 frame->rsn_ie_present = true;
    //                 frame->rsn_ie_is_placeholder = false;
    //                 offset += 2 + ie_len;
    //             }
    //         }
    //         return EAPOL_KEY2_FRAME;
    //     }
    //     else if (frame->seq == EAPOL_KEY3_SEQ) {
    //         // Parse GTK (Group Temporal Key) if present
    //         if (check_space(offset, 5, data_len) && memcmp(data + offset, "<GTK>", 5) == 0) {
    //             frame->gtk = safe_memdup(data + offset, 5);
    //             if (!frame->gtk) {
    //                 printf("I am here 449 in oracle-parser.c\n");                
    //                 free_fuzzer_frame(frame);
    //                 return SAE_ERROR_MEMORY;
    //             }
    //             frame->gtk_len = 5;
    //             frame->gtk_present = true;
    //             frame->gtk_is_placeholder = true;
    //             offset += 5;
    //         } else if (check_space(offset, 2, data_len)) {
    //             // GTK with real length
    //             uint16_t gtk_len = (data[offset] << 8) | data[offset + 1];
    //             if (check_space(offset, 2 + gtk_len, data_len)) {
    //                 frame->gtk = safe_memdup(data + offset + 2, gtk_len);
    //                 if (!frame->gtk) {
    //                     printf("I am here 463 in oracle-parser.c\n");                
    //                     free_fuzzer_frame(frame);
    //                     return SAE_ERROR_MEMORY;
    //                 }
    //                 frame->gtk_len = gtk_len;
    //                 frame->gtk_present = true;
    //                 frame->gtk_is_placeholder = false;
    //                 offset += 2 + gtk_len;
    //             }
    //         }
    //         return EAPOL_KEY3_FRAME;
    //     }
    //     else if (frame->seq == EAPOL_KEY4_SEQ) {
    //         // Parse any Key4-specific data if present
    //         if (check_space(offset, 12, data_len) && memcmp(data + offset, "<INSTALL_KEY>", 12) == 0) {
    //             frame->install_key_flag = safe_memdup(data + offset, 12);
    //             if (!frame->install_key_flag) {
    //                 printf("I am here 480 in oracle-parser.c\n");                
    //                 free_fuzzer_frame(frame);
    //                 return SAE_ERROR_MEMORY;
    //             }
    //             frame->install_key_flag_len = 12;
    //             frame->install_key_present = true;
    //             frame->install_key_is_placeholder = true;
    //             offset += 12;
    //         } else if (check_space(offset, 1, data_len)) {
    //             // Single byte flag (0 or 1)
    //             frame->install_key_flag = safe_memdup(data + offset, 1);
    //             if (!frame->install_key_flag) {
    //                 printf("I am here 492 in oracle-parser.c\n");                
    //                 free_fuzzer_frame(frame);
    //                 return SAE_ERROR_MEMORY;
    //             }
    //             frame->install_key_flag_len = 1;
    //             frame->install_key_present = true;
    //             frame->install_key_is_placeholder = false;
    //             offset += 1;
    //         }
            
    //         // Parse secure bit flag
    //         if (check_space(offset, 11, data_len) && memcmp(data + offset, "<SECURE_BIT>", 11) == 0) {
    //             frame->secure_bit = safe_memdup(data + offset, 11);
    //             if (!frame->secure_bit) {
    //                 printf("I am here 505 in oracle-parser.c\n");                
    //                 free_fuzzer_frame(frame);
    //                 return SAE_ERROR_MEMORY;
    //             }
    //             frame->secure_bit_len = 11;
    //             frame->secure_bit_present = true;
    //             frame->secure_bit_is_placeholder = true;
    //             offset += 11;
    //         } else if (check_space(offset, 1, data_len)) {
    //             // Single byte flag (0 or 1)
    //             frame->secure_bit = safe_memdup(data + offset, 1);
    //             if (!frame->secure_bit) {
    //                 printf("I am here 517 in oracle-parser.c\n");                
    //                 free_fuzzer_frame(frame);
    //                 return SAE_ERROR_MEMORY;
    //             }
    //             frame->secure_bit_len = 1;
    //             frame->secure_bit_present = true;
    //             frame->secure_bit_is_placeholder = false;
    //             offset += 1;
    //         }
            
    //         return EAPOL_KEY4_FRAME;
    //     }
    // }

    return SAE_ERROR_MALFORMED;
}