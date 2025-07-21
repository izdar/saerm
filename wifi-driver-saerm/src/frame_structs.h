// frame_structs.h
#ifndef FRAME_STRUCTS_H
#define FRAME_STRUCTS_H

// #include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/ec.h>

// enum packetType {COMMIT, CONFIRM, RAW, ASSOCIATION_REQUEST} ; 
// typedef enum packetType packetType ; 


struct probe_info {
    uint8_t bssid[6];
    uint8_t ssid[32];
    uint8_t ssid_len;
    uint16_t capability;
    uint8_t rates[8];
    uint8_t rates_len;
    uint8_t rsn_ie[256];
    uint8_t rsn_ie_len;
};


struct radiotap_header {
    uint8_t version;     // Version 0
    uint8_t pad;
    uint16_t len;        // Length of entire radiotap header including data
    uint32_t present;    // Present flags
} __attribute__((packed));

struct radiotap_data {
    uint8_t flags;       // Flags - aligned to 8 bits
    uint8_t rate;        // Rate - aligned to 8 bits
    uint16_t chan_freq;  // Channel frequency - aligned to 16 bits
    uint16_t chan_flags; // Channel flags - aligned to 16 bits
    uint16_t tx_flags;   // TX flags - aligned to 16 bits
} __attribute__((packed));

struct radiotap {
    struct radiotap_header header;
    struct radiotap_data data;
} __attribute__((packed));

struct frame_control {
    uint8_t protocol_version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t to_ds:1;
    uint8_t from_ds:1;
    uint8_t more_frag:1;
    uint8_t retry:1;
    uint8_t power_mgmt:1;
    uint8_t more_data:1;
    uint8_t protected_frame:1;
    uint8_t order:1;
} __attribute__((packed));

struct ieee80211_header {
    struct frame_control frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed));

struct eapol_key {
    uint8_t protocol_version;
    uint8_t packet_type;
    uint16_t packet_length;
    uint8_t descriptor_type;
    uint16_t key_info;
    uint16_t key_length;
    uint64_t replay_counter;
    uint8_t key_nonce[32];
    uint8_t key_iv[16];
    uint8_t key_rsc[8];
    uint8_t key_id[8];
    uint8_t key_mic[16];
    uint16_t key_data_length;
    unsigned char key_data[];
} __attribute__((packed));

struct eapol_frame {
    struct radiotap_header rt;
    struct ieee80211_header mac_header;
    uint8_t llc[8];  // LLC header with EAPOL ethertype
    struct eapol_key eapol;
} __attribute__((packed));

struct complete_frame {
    // public: 
    struct radiotap rt;
    struct ieee80211_header mac_header;
    uint8_t variable[1024];
} __attribute__((packed));


typedef enum sae_frame_type_t{
    SAE_COMMIT,
    SAE_CONFIRM,
    ASSOCIATION,
    ASSOC_RESPONSE,
    EAPOL_KEY_1,
    EAPOL_KEY_3,
    TIMEOUT,
    OTHER
} sae_frame_type_t;

typedef struct sae_frame_t{
    sae_frame_type_t type;
    unsigned char *data;
    size_t data_len;
} sae_frame_t;


#endif