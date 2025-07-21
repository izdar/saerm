# include "wrapper.h" 

void SENDWRAPPER::DEAUTH_MESSAGE
(
    sae_context &sae_ctx, 
    connectState * connection
)
{
    send_deauth_frame
    (
        connection->getSocket(), 
        (unsigned char*)connection->destMAC, 
        (unsigned char*)connection->sourceMAC, 
        (unsigned char *)connection->sourceMAC
    ) ; 
    sleep(0.002);
}

void SENDWRAPPER::COMMIT_MESSAGE
(   sae_context &sae_ctx, 
    connectState *connection, 
    sae_frame_t &response, 
    PWEs& pwe, 
    sae_response & AP_ctx 
)
{
    sae_ctx.pwe = pwe.h2e_PWE ; 
    generate_sae_commit(&sae_ctx) ;
    send_sae_commit(connection->getSocket(), &sae_ctx, connection->sourceMAC) ; 
    receive_frames(connection->getSocket(), (unsigned char*) connection->destMAC, &response, SAE_COMMIT) ; 
    int ret = parse_sae_frame(&response, &AP_ctx) ; 
    // if (response.type == TIMEOUT){
    //     WarningMessages::WarningWithoutCrashPositive(response.type == TIMEOUT, "COMMIT timed out"); 
    //     return ;
    // }
    WarningMessages::WarningWithoutCrashPositive(ret < 0, "Got weird vibes"); 
    if(ret > 0)
    {
        sae_ctx.areKeysSet = true ; 
        calculate_kck_and_pmk(&sae_ctx, &AP_ctx); 
        cout << "keys set" << endl ;
        
    }
}


void SENDWRAPPER::SEND_PROBE_REQUEST
(
    sae_context &sae_ctx, 
    sae_response & AP_ctx, 
    connectState * connection, 
    sae_frame_t&response
)
{
    struct assoc_params params ; 
    params.sockfd = connection->getSocket();
    params.own_mac = connection->sourceMAC ; 
    params.pmk = sae_ctx.pmk ; 
    params.pmkid = sae_ctx.pmk_id ; 
    params.timeout_ms = 1000 ; 
    params.ssid = (char *)malloc(connection->getSSID().length() + 1) ;
    params.ifname = (char *)malloc(connection->getIFaceName().length() + 1) ; 

    strcpy(params.ssid, connection->getSSID().c_str());
    strcpy(params.ifname, connection->getIFaceName().c_str());

    struct probe_info ap_info;
    int ret = probe_request_respose(&params);
    WarningMessages::WarningWithoutCrashPositive(ret >=0, "I could not associate");
    if(params.ssid)free(params.ssid);
    if(params.ifname)free(params.ifname); 
}

void SENDWRAPPER::ASSOCIATION_MESSAGE
(
    sae_context &sae_ctx, 
    sae_response & AP_ctx, 
    connectState * connection, 
    sae_frame_t& response
)
{
    struct assoc_params params ; 
    params.sockfd = connection->getSocket();
    params.own_mac = connection->sourceMAC ; 
    params.pmk = sae_ctx.pmk ; 
    params.pmkid = sae_ctx.pmk_id ; 
    params.timeout_ms = 1000 ; 
    params.ssid = (char *)malloc(connection->getSSID().length() + 1) ;
    params.ifname = (char *)malloc(connection->getIFaceName().length() + 1) ; 

    strcpy(params.ssid, connection->getSSID().c_str());
    strcpy(params.ifname, connection->getIFaceName().c_str());

    struct probe_info ap_info;
    int ret = perform_sae_association(&params, &ap_info, &response);
    if (!ret) response.type = ASSOC_RESPONSE;
    WarningMessages::WarningWithoutCrashPositive(ret >=0, "I could not associate");
    if(params.ssid)free(params.ssid);
    if(params.ifname)free(params.ifname); 
}

int SENDWRAPPER::TEST_CRASH
(
    sae_context &sae_ctx, 
    sae_response & AP_ctx, 
    connectState * connection, 
    sae_frame_t&response
) {
    struct assoc_params params ; 
    params.sockfd = connection->getSocket();
    params.own_mac = connection->sourceMAC ; 
    params.pmk = sae_ctx.pmk ; 
    params.pmkid = sae_ctx.pmk_id ; 
    params.timeout_ms = 1000 ; 
    params.ssid = (char *)malloc(connection->getSSID().length() + 1) ;
    params.ifname = (char *)malloc(connection->getIFaceName().length() + 1) ; 

    strcpy(params.ssid, connection->getSSID().c_str());
    strcpy(params.ifname, connection->getIFaceName().c_str());

    for (int i = 0; i < 3 ; ++i) {
        struct probe_info ap_info;
        sae_frame_t frame_data;
        send_probe_request(params.sockfd, params.ifname, params.ssid, params.own_mac);
        memset(&frame_data, 0, sizeof(frame_data));
        frame_data.type = ASSOCIATION;
        frame_data.data = (uint8_t *)&ap_info;
        frame_data.data_len = sizeof(struct probe_info);

        receive_frames(params.sockfd, params.own_mac, &frame_data, OTHER);
        if (frame_data.type == ASSOCIATION){
            if(params.ssid)free(params.ssid);
            if(params.ifname)free(params.ifname); 
            return 0;
        }
    }
    if(params.ssid)free(params.ssid);
    if(params.ifname)free(params.ifname); 
    return -1 ;
}


void generateNewZeroKeys
(
    sae_context &sae_ctx, 
    sae_response &AP_PARAMS
)
{
    memset(sae_ctx.pmk, 0, 32) ;
    memset(sae_ctx.kck, 0, 32) ;
    sae_ctx.areKeysSet = true ; 
        
    BN_zero(AP_PARAMS.scalar);     
    
    EC_POINT_set_to_infinity(AP_PARAMS.group, AP_PARAMS.element) ;
    AP_PARAMS.isZeroElement = true ;
}


void SENDWRAPPER::CONFIRM_MESSAGE
(
    sae_context &sae_ctx, 
    sae_response & AP_ctx, 
    connectState * connection, 
    sae_frame_t&response, 
    PWEs& pwe 
)
{
    if(!sae_ctx.areKeysSet){
        generateNewZeroKeys(sae_ctx, AP_ctx) ; 
        sae_ctx.pwe = pwe.h2e_PWE ; 
        generate_sae_commit(&sae_ctx) ; 
        
    }
    generate_sae_confirm(&sae_ctx, &AP_ctx);
    int ret = send_sae_confirm(connection->getSocket(), &sae_ctx, connection->sourceMAC); 
    // if (response.type == TIMEOUT){
    //     WarningMessages::WarningWithoutCrashPositive(response.type == TIMEOUT, "CONFIRM timed out"); 
    //     return ;
    // }
    WarningMessages::WarningWithoutCrashPositive(ret < 0, "sending confirm failed.."); 
    receive_frames(connection->getSocket(), connection->destMAC, &response, SAE_CONFIRM);
    ret = parse_sae_frame(&response, &AP_ctx) ;  
    if (ret < 0) {
        WarningMessages::WarningWithoutCrashPositive(ret < 0, "Confirm ERROR"); 
    }
} 

void create_replace_fields
(
    sae_replacements_t &fieldHandler, 
    sae_context &sae_ctx, 
    sae_response &AP_ctx, 
    fuzzer_frame_t &parsingHandler 
)
{
    // Clear the replacement structure to ensure all pointers are NULL initially
    memset(&fieldHandler, 0, sizeof(sae_replacements_t));
    printf("sequence no: %d\n", parsingHandler.seq);
    // Handle SAE frame replacements
    if (parsingHandler.seq == 1 || parsingHandler.seq == 2) {
        // Scalar replacement
        printf("replacing commit, trying scalar\n");
        fieldHandler.scalar = (unsigned char*) malloc(32);
        if (fieldHandler.scalar) {
            unsigned char scalar_buf[32];
            BN_bn2binpad(sae_ctx.scalar, scalar_buf, 32);
            memcpy(fieldHandler.scalar, scalar_buf, 32);
            fieldHandler.scalar_len = 32;
        }
        
        // Element replacement
        fieldHandler.element = (unsigned char*) malloc(64);
        if (fieldHandler.element) {
            fieldHandler.element_len = 64;
            unsigned char tempBuff[65];
            WarningMessages::PositiveConditionMsg(sae_ctx.element != NULL, "For some weird reason sae_ctx element is null");
            WarningMessages::PositiveConditionMsg(sae_ctx.group != NULL, "For some weirder reason the sae_ctx group is NULL. :-) ");
            size_t elementLen = EC_POINT_point2oct(sae_ctx.group, sae_ctx.element,
                POINT_CONVERSION_UNCOMPRESSED,
                tempBuff, 65, NULL);
            cout << "ELEMENT LEN: " << elementLen << endl;
            WarningMessages::PositiveConditionMsg(elementLen == 65, "Something wrong with elementLen");
            memcpy(fieldHandler.element, tempBuff + 1, 64);
        }
        
        // AC Token replacement
        if (sae_ctx.ac_token_set) {
            size_t token_len = (parsingHandler.status_code == 126) ? 35 : 32;
            fieldHandler.ac_token = (unsigned char*) malloc(token_len);
            if (fieldHandler.ac_token) {
                fieldHandler.ac_token_len = token_len;
                memcpy(fieldHandler.ac_token, sae_ctx.ac_token, fieldHandler.ac_token_len);
            }
        }
        
        // Send confirm replacement
        fieldHandler.send_confirm = (unsigned char*) malloc(2);
        if (fieldHandler.send_confirm) {
            uint8_t msb = (sae_ctx.send_confirm & 0xFF00) >> 8;  // Most significant byte
            uint8_t lsb = sae_ctx.send_confirm & 0x00FF;         // Least significant byte
            fieldHandler.send_confirm[0] = (unsigned char) msb;  // Big endian: MSB first
            fieldHandler.send_confirm[1] = (unsigned char) lsb;  // then LSB
            fieldHandler.send_confirm_len = 2;
        }
        // Confirm hash replacement
        fieldHandler.confirm_hash = (unsigned char*) malloc(32);
        if (fieldHandler.confirm_hash) {
            memcpy(fieldHandler.confirm_hash, sae_ctx.confirm, 32);
            fieldHandler.confirm_hash_len = 32;
        }
    }
    
    // Handle EAPOL frame replacements
    if (parsingHandler.seq >= EAPOL_KEY1_SEQ && parsingHandler.seq <= EAPOL_KEY4_SEQ) {
        // Nonce replacement
        if (sae_ctx.nonce != NULL) {
            fieldHandler.nonce = (unsigned char*) malloc(32);
            if (fieldHandler.nonce) {
                memcpy(fieldHandler.nonce, sae_ctx.nonce, 32);
                fieldHandler.nonce_len = 32;
            }
        }
        
        // Counter replacement
        fieldHandler.counter = (unsigned char*) malloc(8);
        if (fieldHandler.counter) {
            uint64_t counter = sae_ctx.eapol_replay_counter;
            for (int i = 0; i < 8; i++) {
                fieldHandler.counter[7-i] = (counter >> (i * 8)) & 0xFF;
            }
            fieldHandler.counter_len = 8;
        }
        
        // Handle Key2 specific replacements - RSN IE
        if (parsingHandler.seq == EAPOL_KEY2_SEQ) {
            // Sample RSN IE with a fixed length of 20 bytes
            fieldHandler.rsn_ie = (unsigned char*) malloc(20);
            if (fieldHandler.rsn_ie) {
                // In a real implementation, this would be filled with actual RSN IE data
                // For example: 30 14 01 00 00 0F AC 04 01 00 00 0F AC 04 01 00 00 0F AC 02
                // This is a placeholder - fill with sample RSN IE
                static const unsigned char rsn_ie_example[20] = {
                    0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 
                    0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02
                };
                memcpy(fieldHandler.rsn_ie, rsn_ie_example, 20);
                fieldHandler.rsn_ie_len = 20;
            }
        }
        
        // Handle Key3 specific replacements - GTK
        if (parsingHandler.seq == EAPOL_KEY3_SEQ) {
            // GTK with a fixed length of 16 bytes
            fieldHandler.gtk = (unsigned char*) malloc(16);
            if (fieldHandler.gtk) {
                // In a real implementation, this would be filled with actual GTK data
                // For this example, we're using a simple pattern
                for (int i = 0; i < 16; i++) {
                    fieldHandler.gtk[i] = i + 1;
                }
                fieldHandler.gtk_len = 16;
            }
        }
        
        // Handle Key4 specific replacements - Install key flag and Secure bit
        if (parsingHandler.seq == EAPOL_KEY4_SEQ) {
            // Install key flag (1 byte)
            fieldHandler.install_key_flag = (unsigned char*) malloc(1);
            if (fieldHandler.install_key_flag) {
                fieldHandler.install_key_flag[0] = 0x01; // Install key flag enabled
                fieldHandler.install_key_flag_len = 1;
            }
            
            // Secure bit flag (1 byte)
            fieldHandler.secure_bit = (unsigned char*) malloc(1);
            if (fieldHandler.secure_bit) {
                fieldHandler.secure_bit[0] = 0x01; // Secure bit enabled
                fieldHandler.secure_bit_len = 1;
            }
        }
        
        // MIC calculation and replacement - only if we have eapol_kck
        // This needs to be done LAST after all other fields are set
        // if (sae_ctx.eapol_kck != NULL) {
        //     fieldHandler.mic = (unsigned char*) malloc(16);
        //     if (fieldHandler.mic) {
        //         if (!sae_ctx.ptk_set) {
        //             // In a real implementation, MIC would be calculated based on the entire EAPOL frame
        //             // For this example we're setting zeros, but in practice this would call a function 
        //             // to calculate the appropriate MIC using sae_ctx.eapol_kck
        //             memset(fieldHandler.mic, 0, 16);
        //             fieldHandler.mic_len = 16;
        //         } else {
        //             // Build a frame for MIC calculation using the current fieldHandler values
        //             // The MIC field in this frame will be set to zeros
        //             unsigned char *data = NULL;
        //             size_t data_len = 0;
                    
        //             // Build the frame without making assumptions about its format
        //             // Simply copying the available data from fieldHandler
        //             build_eapol_frame_for_mic(&data, &data_len, &fieldHandler, parsingHandler.seq);
                    
        //             if (data != NULL && data_len > 0) {
        //                 // Compute the MIC using the KCK portion of the PTK
        //                 compute_mic(sae_ctx.eapol_kck, data, data_len, fieldHandler.mic);
                        
        //                 // Free the temporary frame data
        //                 free(data);
        //             } else {
        //                 // If frame building failed, use zeros as fallback
        //                 memset(fieldHandler.mic, 0, 16);
        //             }
                    
        //             fieldHandler.mic_len = 16;
        //         }
        //     }
        // }
    }
}

void set_containers(fuzzer_frame_t &parsingHandler, sae_context &sae_ctx) {
    // For password_id container
    if (parsingHandler.password_id_present && parsingHandler.password_id && parsingHandler.password_id_len > 0) {
        // Set container fields
        sae_ctx.pi_container.tag = CONTAINER_TAG;
        sae_ctx.pi_container.extension = PI_EXTENSION;
        sae_ctx.pi_container.length = parsingHandler.password_id_len;
        sae_ctx.pi_container.size = parsingHandler.password_id_len - 1; // Size is length minus 1
        
        // Allocate memory ensuring it's enough for how it will be used
        // Since calculate_kck_and_pmk multiplies by sizeof(uint16_t)
        size_t alloc_size = sae_ctx.pi_container.size * sizeof(uint16_t);
        sae_ctx.pi_container.value = (unsigned char *)malloc(alloc_size);
        
        if (sae_ctx.pi_container.value) {
            // Initialize memory to zero first
            memset(sae_ctx.pi_container.value, 0, alloc_size);
            // Copy values
            memcpy(sae_ctx.pi_container.value, parsingHandler.password_id, sae_ctx.pi_container.size);
        } else {
            sae_ctx.pi_container.size = 0;
            sae_ctx.pi_container.length = 0;
        }
    } else {
        sae_ctx.pi_container.value = NULL;
        sae_ctx.pi_container.size = 0;
        sae_ctx.pi_container.length = 0;
    }
    
    // For rejected_groups container
    if (parsingHandler.rejected_groups_present && parsingHandler.rejected_groups && parsingHandler.rejected_groups_len > 0) {
        // Set container fields
        sae_ctx.rg_container.tag = CONTAINER_TAG;
        sae_ctx.rg_container.extension = RG_EXTENSION;
        sae_ctx.rg_container.length = parsingHandler.rejected_groups_len;
        sae_ctx.rg_container.size = parsingHandler.rejected_groups_len - 1; // Size is length minus 1
        
        // Allocate memory ensuring it's enough for how it will be used
        size_t alloc_size = sae_ctx.rg_container.size * sizeof(uint16_t);
        sae_ctx.rg_container.value = (unsigned char *)malloc(alloc_size);
        
        if (sae_ctx.rg_container.value) {
            // Initialize memory to zero first
            memset(sae_ctx.rg_container.value, 0, alloc_size);
            // Copy values
            memcpy(sae_ctx.rg_container.value, parsingHandler.rejected_groups, sae_ctx.rg_container.size);
        } else {
            sae_ctx.rg_container.size = 0;
            sae_ctx.rg_container.length = 0;
        }
    } else {
        sae_ctx.rg_container.value = NULL;
        sae_ctx.rg_container.size = 0;
        sae_ctx.rg_container.length = 0;
    }
}

void SENDWRAPPER::RAW_PACKET
(
    sae_context &sae_ctx, 
    sae_response &AP_ctx, 
    connectState *connection, 
    sae_frame_t &response, 
    PWEs& pwe, 
    fuzzer_frame_t &parsingHandler, 
    sae_replacements_t &fieldHandler, 
    std::string &rawPacketToSend,
    int &parse_error_code
)
{
    size_t LEN = rawPacketToSend.length()/2 ;
    printf("RAW_LEN: %u\n",LEN);
    unsigned char * binData = (unsigned char*) malloc(sizeof(unsigned char) * (LEN)); 
    ManipulationUtility::string_to_unsigned_char(rawPacketToSend, binData) ;
    parse_error_code = parse_fuzzer_frame(binData, LEN, &parsingHandler) ; 
    set_containers(parsingHandler, sae_ctx);
    if(parsingHandler.status_code == 0){
        sae_ctx.pwe = pwe.loop_PWE ; 
    }
    else{
        sae_ctx.pwe = pwe.h2e_PWE ; 
    }
    if(!sae_ctx.areKeysSet){
        generateNewZeroKeys(sae_ctx, AP_ctx) ; 
    }
    generate_sae_commit(&sae_ctx) ; 
    generate_sae_confirm(&sae_ctx, &AP_ctx) ; 
    create_replace_fields(fieldHandler, sae_ctx, AP_ctx, parsingHandler) ; 
    binData = replace_placeholders(binData, &LEN, &fieldHandler) ; 
    send_sae_frame(connection->getSocket(), (unsigned char*)connection->destMAC, (unsigned char*)connection->sourceMAC
, (unsigned char*)connection->destMAC, parsingHandler.seq, parsingHandler.status_code, binData, LEN) ; 
    
    sae_frame_type_t request_type;
    if (parsingHandler.seq == 1 && parsingHandler.algo == 3) request_type = SAE_COMMIT;
    else if (parsingHandler.seq == 2 && parsingHandler.algo == 3) request_type = SAE_CONFIRM;
    else request_type = OTHER;
    
    receive_frames(connection->getSocket(), (unsigned char*)connection->destMAC, &response, request_type);
    // if (response.type == TIMEOUT){
    //     WarningMessages::WarningWithoutCrashPositive(response.type == TIMEOUT, "RAW_PACKET timed out"); 
    //     free(binData) ; 
    //     return ;
    // }
    
    parse_sae_frame(&response, &AP_ctx) ; 
    // (fieldHandler.scalar);
    // free(fieldHandler.element) ; 
    // if(fieldHandler.ac_token) free(fieldHandler.ac_token); 
    // free(fieldHandler.confirm_hash) ; 
    // free(fieldHandler.send_confirm) ; 


    // free_fuzzer_frame(&parsingHandler);
    
    
    free(binData) ; 
} 

