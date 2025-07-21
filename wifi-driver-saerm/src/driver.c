#include "driver.h"

int send_sae_commit(int sockfd, struct sae_context *sae_ctx,  unsigned char *our_mac) {
    unsigned char commit_frame[512] = {0};
    size_t pos = 0;
    
    // Authentication Algorithm (SAE)
    commit_frame[pos++] = 0x03;  // SAE
    commit_frame[pos++] = 0x00;
    
    // Authentication Transaction Sequence (1 for commit)
    commit_frame[pos++] = 0x01;
    commit_frame[pos++] = 0x00;
    
    // Status Code (0 = success)
    commit_frame[pos++] = 0x7e;
    commit_frame[pos++] = 0x00;
    
    // // Finite Cyclic Group (19 for P256)
    commit_frame[pos++] = 19;
    commit_frame[pos++] = 0;
    
    // Scalar
    unsigned char scalar_buf[32];
    BN_bn2binpad(sae_ctx->scalar, scalar_buf, 32);
    memcpy(commit_frame + pos, scalar_buf, 32);
    pos += 32;
    
    // Element (x,y coordinates)
    unsigned char element_buf[65];
    size_t element_len = EC_POINT_point2oct(sae_ctx->group, (EC_POINT *)sae_ctx->element,
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          element_buf, 65, NULL);
    // Skip 0x04 prefix
    memcpy(commit_frame + pos, element_buf + 1, element_len - 1);
    pos += element_len - 1;
    // BN_CTX *ctx = BN_CTX_new();
    // printf("here\n");
    // print_point("element: ", sae_ctx->group, (EC_POINT *)sae_ctx->element, ctx);
    // BN_CTX_free(ctx);
    if (sae_ctx->pi_container.size) {
        memcpy(commit_frame + pos, &sae_ctx->pi_container.tag, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        uint8_t length = sae_ctx->pi_container.length + (2 * sae_ctx->pi_container.size); 
        memcpy(commit_frame + pos, &length, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        memcpy(commit_frame + pos, &sae_ctx->pi_container.extension, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        
        if (sae_ctx->pi_container.value) {
            memcpy(commit_frame + pos, sae_ctx->pi_container.value, sae_ctx->pi_container.size * 2);
            pos += sae_ctx->pi_container.size * 2;
        }
    }

    if (sae_ctx->rg_container.size) {
        memcpy(commit_frame + pos, &sae_ctx->rg_container.tag, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        uint8_t length = sae_ctx->rg_container.length + (2 * sae_ctx->rg_container.size); 
        memcpy(commit_frame + pos, &length, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        memcpy(commit_frame + pos, &sae_ctx->rg_container.extension, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        
        if (sae_ctx->rg_container.value) {
            memcpy(commit_frame + pos, sae_ctx->rg_container.value, sae_ctx->rg_container.size * 2);
            pos += sae_ctx->rg_container.size * 2;
        }
    }

    return send_sae_frame(sockfd, sae_ctx->mac, our_mac, sae_ctx->mac, 0, 126, commit_frame, pos);
}

int send_sae_confirm(int sockfd, struct sae_context *sae_ctx,  unsigned char *our_mac) {
    unsigned char confirm_frame[512] = {0};
    size_t pos = 0;
    
    // Authentication Algorithm (SAE)
    confirm_frame[pos++] = 0x03;  // SAE
    confirm_frame[pos++] = 0x00;
    
    // Authentication Transaction Sequence (2 for confirm)
    confirm_frame[pos++] = 0x02;
    confirm_frame[pos++] = 0x00;
    
    // Status Code (0 = success)
    confirm_frame[pos++] = 0x00;
    confirm_frame[pos++] = 0x00;
    
    confirm_frame[pos++] = sae_ctx->send_confirm & 0xFF;         // Low byte (LSB)
    confirm_frame[pos++] = (sae_ctx->send_confirm >> 8) & 0xFF;  // High byte (MSB)

    // Scalar
    memcpy(confirm_frame + pos, sae_ctx->confirm, 32);
    pos += 32;

    return send_sae_frame(sockfd, sae_ctx->mac, our_mac, sae_ctx->mac, 0, 0, confirm_frame, pos);
}

int parse_sae_frame(sae_frame_t *response, struct sae_response *ap) {
    if (response->type == TIMEOUT || !response->data) {
        return -5 ;
    }
    size_t pos = 4;
    
    switch (response->type) {
        case SAE_COMMIT:
            ap->status = (response->data + pos)[0];
            if (ap->status == 1) return -4;
            if (ap->status != 0 && ap->status != 0x7e) return -1;
            pos = pos + 2;
            uint16_t group = (response->data + pos)[0];
            ap->group_id = group;
            if (group == 0x13){
                ap->group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            }
            else{
                // HANDLE OTHER EC GROUPS
            }
            pos += 2;
            if (ap->status == 76) {
                // AC TOKEN PARSER HERE
                // ap->ac_token = malloc(response->data_len - pos);
                memcpy(ap->ac_token, response->data + pos, response->data_len - pos);
                return -2;
            }
            else if (ap->status == 77) {
                return -3;
            }
            
            BN_bin2bn(response->data + pos, 32, ap->scalar);

            pos = pos + 32;
            BIGNUM *x = BN_new();
            BIGNUM *y = BN_new();
            BN_bin2bn(response->data + pos, 32, x);
            pos = pos + 32;
            BN_bin2bn(response->data + pos, 32, y);
            BN_CTX *ctx = BN_CTX_new();
            EC_POINT_set_affine_coordinates(ap->group, ap->element, x, y, ctx);
            BN_CTX_free(ctx);
            BN_free(x);
            BN_free(y);
            ap->didWeReceiveCommit = true ;
            ap->isZeroElement = false ;
            return 1;
        case SAE_CONFIRM:
            uint16_t status;
            memcpy(&status, response + pos, 2);
            ap->status = htole16(status);
            if (!ap->status) return -2;
            if (ap->status != 0) return -1;
            pos = pos + 2;
            uint16_t send_confirm;
            memcpy(&send_confirm, response + pos, 2);
            pos = pos + 2;
            ap->send_confirm = htole16(send_confirm);
            memcpy(ap->confirm, response + pos, 32);
            printf("made it here\n");
            return 2;
        case ASSOCIATION:
            return 3;
    }

}

int parse_eapol_frame(sae_frame_t *response, struct sae_response *ap) {
    size_t pos = 11;
    uint64_t replay_counter;
    switch(response->type) {
        case EAPOL_KEY_1:
            memcpy(&replay_counter, response->data + pos, 8);
            ap->eapol_replay_counter = be64toh(replay_counter);
            pos += 8;
            ap->nonce = malloc(32);
            memcpy(ap->nonce, response->data + pos, 32);
            return 1;
        case EAPOL_KEY_3:
            memcpy(&replay_counter, response->data + pos, 8);
            ap->eapol_replay_counter = be64toh(replay_counter);
            return 3;
    }
}

void generate_sae_commit(struct sae_context *sae_ctx) {
    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP_get_order(sae_ctx->group, r, ctx);
    BN_rand_range(sae_ctx->rand, r);
    BN_rand_range(sae_ctx->mask, r);
    BN_add(sae_ctx->rand, sae_ctx->rand, BN_value_one());
    BN_add(sae_ctx->mask, sae_ctx->mask, BN_value_one());
    BN_mod_add(sae_ctx->scalar, sae_ctx->rand, sae_ctx->mask, r, ctx);
    EC_POINT_mul(sae_ctx->group, (EC_POINT *)sae_ctx->element, NULL, sae_ctx->pwe, sae_ctx->mask, ctx);
    EC_POINT_invert(sae_ctx->group, (EC_POINT *)sae_ctx->element, ctx);
    BN_free(r);
    BN_CTX_free(ctx);
}


void debug_break(int x)
{
    // #ifdef DEBUG
        assert(x);
    // #endif 
}

void debug_message(char *x){
    // #ifdef DEBUG 
        printf("[DEBUG MESSAGE]: %s\n",x);
        fflush(stdout);
    // #endif 
}


void calculate_kck_and_pmk(struct sae_context *sae_ctx, struct sae_response *ap_ctx) {
    unsigned char *salt;
    size_t salt_len;
    debug_break(sae_ctx != NULL);
    debug_break(sae_ctx != NULL);
    debug_break(ap_ctx != NULL);
    if (!(sae_ctx->rg_container.size)) {
        salt = malloc(sizeof(unsigned char) * 32) ; //calloc(32, 1);
        memset(salt,0,32) ;
        salt_len = 32;
    }
    else {
        salt = malloc(sae_ctx->rg_container.size * sizeof(uint16_t));
        salt_len = sae_ctx->rg_container.size * sizeof(uint16_t);
        memcpy(salt, sae_ctx->rg_container.value, sae_ctx->rg_container.size * sizeof(uint16_t));
    }
    if(!sae_ctx->group)debug_break(0); 
    EC_POINT *k = EC_POINT_new(sae_ctx->group);
    debug_break(k != NULL);
    BN_CTX *ctx = BN_CTX_new();
    debug_break(ctx != NULL) ; 
 

    debug_break(ap_ctx->scalar != NULL);
    debug_break(ap_ctx->element != NULL);
    debug_break(sae_ctx->pwe != NULL);
    debug_break(sae_ctx->rand != NULL);
    debug_break(sae_ctx->group != NULL);

    EC_POINT_mul(sae_ctx->group, k, NULL, sae_ctx->pwe, ap_ctx->scalar, ctx);

    EC_POINT_add(sae_ctx->group, k, k, ap_ctx->element, ctx);

    EC_POINT_mul(sae_ctx->group, k, NULL, k, sae_ctx->rand, ctx);

    BIGNUM *x = BN_new();
    debug_break(x != NULL);
    BIGNUM *y = BN_new();
    debug_break(y != NULL);
    EC_POINT_get_affine_coordinates(sae_ctx->group, k, x, y, ctx);
    unsigned char buffer[32];
    int len = 32;


    BN_bn2binpad(x, buffer, 32);


    unsigned char* keyseed = (unsigned char*) malloc(sizeof(unsigned char) * 32);

    debug_break(keyseed != NULL);

    hmac256(salt, salt_len, buffer, len, keyseed);


    BIGNUM *scalar_sum = BN_new();
    debug_break(scalar_sum != NULL);
    BIGNUM* prime_order = BN_new();
    debug_break(prime_order != NULL);
    EC_GROUP_get_order(sae_ctx->group, prime_order, ctx);
    BN_mod_add(scalar_sum, sae_ctx->scalar, ap_ctx->scalar, prime_order, ctx);
    unsigned char context[32];
    BN_bn2binpad(scalar_sum, context, 32);
    unsigned char* kck_and_pmk = malloc(64);
    debug_break(kck_and_pmk != NULL);
    kdf_length(keyseed, "SAE KCK and PMK", context, 32, 512, 256, kck_and_pmk);

    if(sae_ctx->kck == NULL) debug_break(0); 
    memcpy(sae_ctx->kck, kck_and_pmk, 32);
    if(sae_ctx->pmk == NULL) debug_break(0);
    memcpy(sae_ctx->pmk, kck_and_pmk + 32, 32);
    if(sae_ctx->pmk_id==NULL) assert(0) ; 
    memcpy(sae_ctx->pmk_id, context, 16);

    sae_ctx->areKeysSet = true ; 

 
    if(ctx) BN_CTX_free(ctx);
    if(x) BN_free(x);
    if(y) BN_free(y);
    if(keyseed) free(keyseed);
    if(kck_and_pmk)free(kck_and_pmk);
    if(k)EC_POINT_free(k);
    if(salt) free(salt);
    if(scalar_sum) BN_free(scalar_sum);

}

int generate_sae_confirm(struct sae_context *sae_ctx, struct sae_response *ap_ctx) {
    size_t data_len = sizeof(uint16_t) + 32 + 64 + 32 + 64 ;
    unsigned char *data = malloc(data_len);

    size_t pos = 0;
    uint16_t send_confirm = htole16(sae_ctx->send_confirm);
    memcpy(data, &send_confirm, sizeof(uint16_t));
    pos += 2;

    BN_bn2binpad(sae_ctx->scalar, data + pos, 32);

    pos += 32;


    unsigned char element_buf[65];
    size_t element_len = EC_POINT_point2oct(sae_ctx->group, (EC_POINT *)sae_ctx->element,
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          element_buf, 65, NULL);
    memcpy(data + pos, element_buf + 1, 64);

    pos += 64;

    BN_bn2binpad(ap_ctx->scalar, data + pos, 32);
    pos += 32;
    if (ap_ctx->isZeroElement == false) {
        unsigned char ap_element_buf[65];
        element_len = EC_POINT_point2oct(ap_ctx->group, ap_ctx->element,
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            ap_element_buf, 65, NULL);
        printf("POSSIBLE ZERO ELEMENT: ");
        for (int i = 0; i < 64 ; i++) {
            printf("%02x ", ap_element_buf[i + 1]);
        }
        printf("\n");
        memcpy(data + pos, ap_element_buf + 1, 64);
    }
    else {
        unsigned char ap_element_buf[1];
        element_len = EC_POINT_point2oct(ap_ctx->group, ap_ctx->element,
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            ap_element_buf, 1, NULL);
        printf("POSSIBLE ZERO ELEMENT: ");
        for (int i = 0; i < element_len ; i++) {
            printf("%02x ", ap_element_buf[i]);
        }
        printf("\n");
        memcpy(data + pos, ap_element_buf, element_len);

    }

    hmac256(sae_ctx->kck, 32, data, data_len, sae_ctx->confirm);
    
    free(data);
    return 0;
}



int generate_ptk(struct sae_context *sae_ctx, struct sae_response *ap_ctx, unsigned char* our_mac) {
    unsigned char hash_macs[12];
    if (memcmp(our_mac, sae_ctx->mac, 6) < 0) {
        memcpy(hash_macs, our_mac, 6);
        memcpy(hash_macs + 6, sae_ctx->mac, 6);
    } else {
        memcpy(hash_macs, sae_ctx->mac, 6);
        memcpy(hash_macs + 6, our_mac, 6);
    }
    unsigned char hash_nonces[64];
    if (memcmp(sae_ctx->nonce, ap_ctx->nonce, 32) < 0) {
        memcpy(hash_nonces, sae_ctx->nonce, 32);
        memcpy(hash_nonces + 32, ap_ctx->nonce, 32);
    } else {
        memcpy(hash_nonces, ap_ctx->nonce, 32);
        memcpy(hash_nonces + 32, sae_ctx->nonce, 32);
    }


    unsigned char hash_data[76];
    memcpy(hash_data, hash_macs, 12);
    memcpy(hash_data + 12, hash_nonces, 64);

    kdf_length(sae_ctx->pmk, "Pairwise key expansion", hash_data, 76, 384, 256.0, sae_ctx->ptk);

    memcpy(sae_ctx->eapol_kck, sae_ctx->ptk, 16);
    sae_ctx->ptk_set = true;
    return 0;
}

void initialize_sae_context(EC_GROUP *group, unsigned char *ssid, unsigned char *mac, sae_context* sae_ctx) {
    sae_ctx->group = group;
    sae_ctx->rand = BN_new();
    sae_ctx->mask = BN_new();
    sae_ctx->scalar = BN_new();
    sae_ctx->element = EC_POINT_new(sae_ctx->group);
    sae_ctx->confirm = malloc(sizeof(unsigned char) * 32);
    // sae_ctx->pwe = EC_POINT_new(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    sae_ctx->pwe = NULL ;
    sae_ctx->send_confirm = 1;
    sae_ctx->ssid = (unsigned char*) malloc(sizeof(unsigned char) * (strlen(ssid) +1)) ; 
    strcpy(sae_ctx->ssid, ssid) ; 
    //sae_ctx->ssid = ssid;
    sae_ctx->areKeysSet = false; 
    sae_ctx->kck = malloc(sizeof(unsigned char) * 32);
    sae_ctx->pmk = malloc(sizeof(unsigned char) * 32);
    sae_ctx->pmk_id = malloc(sizeof(unsigned char) * 16);
    sae_ctx->ptk = malloc(sizeof(unsigned char) * 48);
    sae_ctx->eapol_kck = malloc(sizeof(unsigned char) * 16);
    memset(sae_ctx->kck, 0, 32);
    memset(sae_ctx->pmk, 0, 32);
    memset(sae_ctx->pmk_id, 0, 16);
    memset(sae_ctx->ptk, 0, 48);
    memset(sae_ctx->eapol_kck, 0, 16);
    sae_ctx->ptk_set = false;
    // AP testing MAC
    // hostapd testing MAC
    // sae_ctx->mac = { 0x02; 0x00; 0x00; 0x00; 0x02; 0x00 };
    sae_ctx->eapol_replay_counter = 0;
    sae_ctx->nonce = malloc(32);
    sae_ctx->ac_token_set = false;
    sae_ctx->password = (unsigned char*) malloc(sizeof(unsigned char) * (strlen("correctPassword") +1)) ; 
    strcpy(sae_ctx->password, "correctPassword");
    sae_ctx->freq = 2437;
    sae_ctx->rg_container.tag = 0xff;
    sae_ctx->rg_container.length = 1;
    sae_ctx->rg_container.extension = 0x5c;
    sae_ctx->rg_container.size = 0;
    sae_ctx->rg_container.value = NULL;
    sae_ctx->pi_container.tag = 0xff;
    sae_ctx->pi_container.length = 1;
    sae_ctx->pi_container.extension = 0x21;
    sae_ctx->pi_container.size = 0;
    sae_ctx->pi_container.value = NULL;
    sae_ctx->ac_container.tag = 0xff;
    sae_ctx->ac_container.length = 1;
    sae_ctx->ac_container.extension = 0x5d;
    sae_ctx->ac_container.size = 0;
    sae_ctx->ac_container.value = NULL;
    memcpy(&sae_ctx->mac, mac, 6);
    // memcpy(sae_ctx.ssid, ssid, strlen(ssid) - 1);
}

// int main(int argc, char *argv[]) {
//     unsigned char dst[6] = { 0xc8,0x7f,0x54,0x24,0xa0,0x7c};
//     sae_context sae_ctx;
//     initialize_sae_context(argv[2], dst, &sae_ctx);
//     // sae_ctx.rg_container.value = malloc(sizeof(uint16_t));
//     // uint16_t rejected_group = 0x14;
//     // memcpy(sae_ctx.rg_container.value, &rejected_group, 2);
//     // sae_ctx.rg_container.size = 1;

//     // sae_ctx.pi_container.value = malloc(sizeof(uint16_t));
//     // uint16_t password_identifier = 0x14bf;
//     // memcpy(sae_ctx.pi_container.value, &password_identifier, sizeof(uint16_t));
//     // sae_ctx.pi_container.size = 1;


//     unsigned char our_mac[6] = { 0x00, 0x1c, 0x50, 0x0e, 0x46, 0x30 };
//     // unsigned char our_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00 };


//     EC_POINT *PT = hash_to_element(sae_ctx.password, sae_ctx.ssid, NULL, sae_ctx.group);
//     sae_ctx.pwe = EC_POINT_new(sae_ctx.group);

//     BN_CTX *ctx = BN_CTX_new();


//     calculate_pwe(PT, sae_ctx.mac, our_mac, sae_ctx.pwe, sae_ctx.group);

//     // Generate and send commit
//     generate_sae_commit(&sae_ctx);

//     if (initialize_interfaces(argv[3], argv[4]) != 0) {
//         fprintf(stderr, "Failed to initialize interfaces\n");
//         return 1;
//     }


//     int sockfd = create_monitor_socket(argv[4]);
//     sae_frame_t *response = malloc(sizeof(sae_frame_t));



//     struct sae_response *AP_PARAMS = malloc(sizeof(struct sae_response));

//     send_sae_commit(sockfd, &sae_ctx, our_mac);
//     receive_frames(sockfd, sae_ctx.mac, response);

//     int ret = parse_sae_frame(response, AP_PARAMS);
    
//     calculate_kck_and_pmk(&sae_ctx, AP_PARAMS);
//     generate_sae_confirm(&sae_ctx, AP_PARAMS);

//     send_sae_confirm(sockfd, &sae_ctx, our_mac);
//     receive_frames(sockfd, sae_ctx.mac, response);

//     ret = parse_sae_frame(response, AP_PARAMS);

//     struct assoc_params params = {
//         .sockfd = sockfd,
//         .ifname = argv[4],
//         .ssid = sae_ctx.ssid,
//         .own_mac = our_mac,
//         .pmk = sae_ctx.pmk,
//         .pmkid = sae_ctx.pmk_id,
//         .timeout_ms = 5000
//     };
//     struct probe_info ap_info;
//     ret = perform_sae_association(&params, &ap_info);

//     if (ret < 0) {
//         perror("FAILED TO ASSOCIATE");
//         return -1;
//     }

//     AP_PARAMS->nonce = malloc(32);
//     receive_frames(sockfd, sae_ctx.mac, response);

//     parse_eapol_frame(response,AP_PARAMS);

//     sae_ctx.eapol_replay_counter = AP_PARAMS->eapol_replay_counter;

//     generate_ptk(&sae_ctx, AP_PARAMS, our_mac);

//     send_eapol_msg_2(sockfd, our_mac, sae_ctx.mac, sae_ctx.nonce, sae_ctx.eapol_replay_counter, sae_ctx.eapol_kck, sae_ctx.pmk_id);

//     receive_frames(sockfd, sae_ctx.mac, response);

//     parse_eapol_frame(response, AP_PARAMS);

//     sae_ctx.eapol_replay_counter = AP_PARAMS->eapol_replay_counter;

//     send_eapol_msg_4(sockfd, our_mac, sae_ctx.mac, sae_ctx.eapol_replay_counter, sae_ctx.eapol_kck);

//     send_deauth_frame(sockfd, our_mac, sae_ctx.mac, our_mac);

// finish:
//     if(response->data)free(response->data);
//     if(PT) EC_POINT_free(PT);
//     if(response)free(response);
//     if(AP_PARAMS->scalar)BN_free(AP_PARAMS->scalar);
//     if(AP_PARAMS->element)EC_POINT_free(AP_PARAMS->element);
//     if(AP_PARAMS->group)EC_GROUP_free(AP_PARAMS->group);
//     if(sae_ctx.pwe)EC_POINT_free(sae_ctx.pwe);
//     if(sae_ctx.group)EC_GROUP_free(sae_ctx.group);
//     if(sae_ctx.scalar)BN_free(sae_ctx.scalar);
//     if(sae_ctx.rand)BN_free(sae_ctx.rand);
//     if(sae_ctx.mask)BN_free(sae_ctx.mask);
//     if(sae_ctx.element)EC_POINT_free(sae_ctx.element);
//     if(sae_ctx.rg_container.value) free(sae_ctx.rg_container.value);
//     if(sae_ctx.ac_token) free(sae_ctx.ac_token);
//     if(sae_ctx.pi_container.value) free(sae_ctx.pi_container.value);
//     if(sae_ctx.kck)free(sae_ctx.kck);
//     if(sae_ctx.pmk)free(sae_ctx.pmk);
//     if(sae_ctx.pmk_id)free(sae_ctx.pmk_id);
//     if(AP_PARAMS) free(AP_PARAMS);
    
//     return 0;
// }