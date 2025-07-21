// sae_assoc.h
#ifndef SAE_ASSOC_H
#define SAE_ASSOC_H
#include "frame_structs.h"

struct assoc_params {
    int sockfd;
    char *ifname;
    char *ssid;
    uint8_t *own_mac;
    uint8_t *pmk;
    uint8_t *pmkid;
    int timeout_ms;
};
int probe_request_respose(struct assoc_params *params);
int perform_sae_association(struct assoc_params *params, struct probe_info *ap_info_out, sae_frame_t *response);
int send_probe_request(int sockfd, const char *ifname, const char *ssid, const uint8_t *own_mac);
#endif