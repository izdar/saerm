#ifndef DRIVER_H
#define DRIVER_H

#include <stdio.h>
#include <stdbool.h> 
#include <string.h>
#include <sys/ioctl.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <endian.h>
#include <assert.h>
#include "looping.h"
#include "h2e.h"
#include "sendFrame.h"
#include "sae_assoc.h"
#include "frame_structs.h"

#define KEYSEED_SIZE 32

struct container {
    uint8_t tag;
    uint8_t extension;
    uint8_t length;
    unsigned char *value;
    size_t size;
}__attribute__((packed));

typedef struct sae_context {
    EC_GROUP *group;
    BIGNUM *rand;
    BIGNUM *mask;
    BIGNUM *scalar;
    EC_POINT *element;

    EC_POINT *pwe;

    unsigned char *pmk;
    bool areKeysSet;
    unsigned char *kck;
    unsigned char *pmk_id;
    unsigned char *ptk;
    unsigned char *eapol_kck;
    bool ptk_set;

    uint16_t send_confirm;
    unsigned char *confirm;

    unsigned char *ssid;
    unsigned char *password;

    struct container rg_container;
    struct container pi_container;
    struct container ac_container;

    unsigned char* ac_token;
    bool ac_token_set;

    unsigned char *nonce;
    uint64_t eapol_replay_counter;

    unsigned char mac[6];
    int freq;
} sae_context;


typedef struct sae_response {
    BIGNUM *scalar;
    EC_POINT *element;
    uint16_t send_confirm;
    unsigned char confirm[32];
    unsigned char* ac_token;
    uint16_t status;
    EC_GROUP* group;
    int group_id;
    bool didWeReceiveCommit ; 
    bool isZeroElement;
    uint64_t eapol_replay_counter;
    unsigned char *nonce;
}sae_response;

int send_sae_commit(int sockfd, struct sae_context *sae_ctx,  unsigned char *our_mac);
int send_sae_confirm(int sockfd, struct sae_context *sae_ctx,  unsigned char *our_mac);
int parse_sae_frame(sae_frame_t *response, struct sae_response *ap);
int parse_eapol_frame(sae_frame_t *response, struct sae_response *ap);
void generate_sae_commit(struct sae_context *sae_ctx);
void calculate_kck_and_pmk(struct sae_context *sae_ctx, struct sae_response *ap_ctx);
int generate_sae_confirm(struct sae_context *sae_ctx, struct sae_response *ap_ctx);
int generate_ptk(struct sae_context *sae_ctx, struct sae_response *ap_ctx, unsigned char* our_mac);
void initialize_sae_context(EC_GROUP *group, unsigned char *ssid, unsigned char *mac, sae_context *sae_ctx);

#endif