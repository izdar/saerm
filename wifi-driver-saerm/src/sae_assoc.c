#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>      // Added for errno and error codes
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/select.h> // Added for select()
#include "sae_assoc.h"

#include "sendFrame.h"
#include "frame_structs.h"
#include "sae_assoc.h"

// Keep all the previous struct definitions and #defines...
#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_STYPE_PROBE_REQ 0x0040
#define IEEE80211_STYPE_PROBE_RESP 0x0050
#define IEEE80211_STYPE_ASSOC_REQ 0x0000

#define WLAN_EID_SSID 0
#define WLAN_EID_SUPP_RATES 1
#define WLAN_EID_RSN 48
#define WLAN_EID_HT_CAP 45
#define WLAN_EID_VHT_CAP 191
#define WLAN_EID_EXT_CAPS 127

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed));



int send_probe_request(int sockfd, const char *ifname, const char *ssid, const uint8_t *own_mac) {
    struct complete_frame frame;
    memset(&frame, 0, sizeof(frame));
    uint8_t *pos;
    
    // Setup radiotap header
    setup_radiotap(&frame.rt);
    
    // Setup 802.11 header
    frame.mac_header.frame_control.protocol_version = 0;
    frame.mac_header.frame_control.type = 0;        // Management frame
    frame.mac_header.frame_control.subtype = 4;     // Probe Request
    frame.mac_header.frame_control.to_ds = 0;
    frame.mac_header.frame_control.from_ds = 0;
    frame.mac_header.frame_control.more_frag = 0;
    frame.mac_header.frame_control.retry = 0;
    frame.mac_header.frame_control.power_mgmt = 0;
    frame.mac_header.frame_control.more_data = 0;
    frame.mac_header.frame_control.protected_frame = 0;
    frame.mac_header.frame_control.order = 0;
    
    frame.mac_header.duration = 0;
    memset(frame.mac_header.addr1, 0xff, 6);        // Destination: Broadcast
    memcpy(frame.mac_header.addr2, own_mac, 6);     // Source: Your MAC
    memset(frame.mac_header.addr3, 0xff, 6);        // BSSID: Broadcast
    frame.mac_header.seq_ctrl = 0;
    
    // Add variable fields (SSID and Supported Rates)
    pos = frame.variable;
    
    // SSID IE
    *pos++ = 0;  // SSID IE ID
    *pos++ = strlen(ssid);
    memcpy(pos, ssid, strlen(ssid));
    pos += strlen(ssid);
    
    // Supported Rates IE
    *pos++ = 1;  // Supported Rates IE ID
    *pos++ = 8;  // Length
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x8c, 0x98, 0xb0, 0x00};
    memcpy(pos, rates, 8);
    pos += 8;
    
    size_t total_len = sizeof(frame.rt) + sizeof(frame.mac_header) + (pos - frame.variable);
    
    // printf("Sending probe request for SSID: %s\n", ssid);
    return send(sockfd, &frame, total_len, 0);
}

static int parse_probe_response(uint8_t *buf, size_t len, struct probe_info *info) {
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)buf;
    uint8_t *pos = buf + sizeof(*hdr);
    uint8_t *end = buf + len;

    // Skip fixed parameters (timestamp, beacon interval, capability)
    pos += 10;

    while (pos + 2 <= end) {
        uint8_t id = *pos++;
        uint8_t ie_len = *pos++;
        
        if (pos + ie_len > end)
            break;

        switch (id) {
            case WLAN_EID_SSID:
                if (ie_len <= 32) {
                    memcpy(info->ssid, pos, ie_len);
                    info->ssid_len = ie_len;
                }
                break;
                
            case WLAN_EID_SUPP_RATES:
                if (ie_len <= 8) {
                    memcpy(info->rates, pos, ie_len);
                    info->rates_len = ie_len;
                }
                break;
                
            case WLAN_EID_RSN:
                if (ie_len <= 254) {
                    info->rsn_ie[0] = WLAN_EID_RSN;
                    info->rsn_ie[1] = ie_len;
                    memcpy(info->rsn_ie + 2, pos, ie_len);
                    info->rsn_ie_len = ie_len + 2;
                }
                break;
        }
        pos += ie_len;
    }

    return 0;
}

static int send_assoc_request(int sock, const char *ifname, 
                            struct probe_info *ap_info,
                            uint8_t *own_mac,
                            uint8_t *pmk, uint8_t *pmkid) {
    struct complete_frame frame;
    memset(&frame, 0, sizeof(frame));
    uint8_t *pos;

    // Setup radiotap header
    setup_radiotap(&frame.rt);

    // Setup 802.11 header
    frame.mac_header.frame_control.protocol_version = 0;
    frame.mac_header.frame_control.type = 0;        // Management frame
    frame.mac_header.frame_control.subtype = 0;     // Association Request
    frame.mac_header.frame_control.to_ds = 0;
    frame.mac_header.frame_control.from_ds = 0;
    frame.mac_header.frame_control.more_frag = 0;
    frame.mac_header.frame_control.retry = 0;
    frame.mac_header.frame_control.power_mgmt = 0;
    frame.mac_header.frame_control.more_data = 0;
    frame.mac_header.frame_control.protected_frame = 0;
    frame.mac_header.frame_control.order = 0;

    frame.mac_header.duration = 0;
    memcpy(frame.mac_header.addr1, ap_info->bssid, 6);  // Destination
    memcpy(frame.mac_header.addr2, own_mac, 6);         // Source
    memcpy(frame.mac_header.addr3, ap_info->bssid, 6);  // BSSID
    frame.mac_header.seq_ctrl = 0;

    // Start filling variable portion
    pos = frame.variable;

    // Capability Information
    memcpy(pos, &ap_info->capability, 2);
    pos += 2;

    // Listen Interval
    uint16_t listen_int = htole16(100);
    memcpy(pos, &listen_int, 2);
    pos += 2;

    // SSID
    *pos++ = WLAN_EID_SSID;
    *pos++ = ap_info->ssid_len;
    memcpy(pos, ap_info->ssid, ap_info->ssid_len);
    pos += ap_info->ssid_len;

    // Supported Rates
    *pos++ = WLAN_EID_SUPP_RATES;
    *pos++ = ap_info->rates_len;
    memcpy(pos, ap_info->rates, ap_info->rates_len);
    pos += ap_info->rates_len;

    // RSN IE
    *pos++ = WLAN_EID_RSN;
    pos++;  // Length will be filled later
    uint8_t *rsn_start = pos;

    // Version
    uint16_t version = htole16(1);
    memcpy(pos, &version, 2);
    pos += 2;

    // Group cipher suite (CCMP)
    uint8_t ccmp_suite[4] = {0x00, 0x0f, 0xac, 0x04};
    memcpy(pos, ccmp_suite, 4);
    pos += 4;

    // Pairwise cipher suite count
    uint16_t suite_count = htole16(1);
    memcpy(pos, &suite_count, 2);
    pos += 2;

    // Pairwise cipher suite (CCMP)
    memcpy(pos, ccmp_suite, 4);
    pos += 4;

    // AKM suite count
    memcpy(pos, &suite_count, 2);
    pos += 2;

    // AKM suite (SAE)
    uint8_t sae_suite[4] = {0x00, 0x0f, 0xac, 0x08};
    memcpy(pos, sae_suite, 4);
    pos += 4;

    // RSN Capabilities
    uint16_t rsn_cap = 0;
    rsn_cap |= (1 << 6);  // MFPR bit
    rsn_cap |= (1 << 7);  // MFPC bit
    rsn_cap = htole16(rsn_cap);  // Convert to little-endian
    memcpy(pos, &rsn_cap, 2);
    pos += 2;

    if (pmkid) {
        // PMKID Count
        uint16_t pmkid_count = htole16(1);
        memcpy(pos, &pmkid_count, 2);
        pos += 2;

        // PMKID
        memcpy(pos, pmkid, 16);
        pos += 16;
        uint8_t bip_suite[4] = {0x00, 0x0f, 0xac, 0x06};  // AES-CMAC-128
        memcpy(pos, bip_suite, 4);
        pos += 4;
    }

    // Fill in RSN IE length
    *(rsn_start - 1) = pos - rsn_start;

    // HT Capabilities
    *pos++ = WLAN_EID_HT_CAP;
    *pos++ = 26;  // Length
    uint8_t ht_cap[26] = {
        0x6f, 0x01, // HT Capabilities Info
        0x01, // A-MPDU Parameters
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Supported MCS Set
        0x00, 0x00, // HT Extended Capabilities
        0x00, 0x00, // Transmit Beamforming Capabilities
        0x00  // ASEL Capabilities
    };
    memcpy(pos, ht_cap, 26);
    pos += 26;

    // Extended Capabilities
    *pos++ = WLAN_EID_EXT_CAPS;
    *pos++ = 10;  // Length
    uint8_t ext_cap[10] = {0};
    ext_cap[0] |= 0x01;  // 20/40 BSS coexistence management support
    memcpy(pos, ext_cap, 10);
    pos += 10;

    // RSNX
    *pos++ = 0xf4;  // Extension Element ID
    *pos++ = 0x01;  // Length
    *pos++ = 0x20;  // Data

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(ifname);
    sll.sll_protocol = htons(ETH_P_ALL);

    size_t total_len = sizeof(frame.rt) + sizeof(frame.mac_header) + (pos - frame.variable);
    return sendto(sock, &frame, total_len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

int probe_request_respose(struct assoc_params *params) {
    struct probe_info ap_info = {0};
    sae_frame_t frame_data = {0};  // Zero initialize the entire structure

    // Input validation
    if (!params || !params->ifname || !params->ssid || 
        !params->own_mac || 
        params->sockfd < 0) {
        errno = EINVAL;
        return -1;
    }

    // Send probe request
    if (send_probe_request(params->sockfd, params->ifname, params->ssid, params->own_mac) < 0) {
        perror("Failed to send probe request");
        return -1;
    }

    // Setup receive structure for probe response
    frame_data.type = ASSOCIATION;
    frame_data.data = NULL;  // Start with NULL, let receive_frames allocate memory
    frame_data.data_len = 0;

    // Receive probe response
    printf("sent probe response.. waiting.\n");
    receive_frames(params->sockfd, params->own_mac, &frame_data, OTHER);
    printf("received probe response.. associating.\n");
    return 0;
}

int perform_sae_association(struct assoc_params *params, struct probe_info *ap_info_out, sae_frame_t *response) {
    struct probe_info ap_info = {0};
    sae_frame_t frame_data = {0};  // Zero initialize the entire structure

    // Input validation
    if (!params || !params->ifname || !params->ssid || 
        !params->own_mac || 
        params->sockfd < 0) {
        errno = EINVAL;
        return -1;
    }

    // Send probe request
    if (send_probe_request(params->sockfd, params->ifname, params->ssid, params->own_mac) < 0) {
        perror("Failed to send probe request");
        return -1;
    }

    // Setup receive structure for probe response
    frame_data.type = ASSOCIATION;
    frame_data.data = NULL;  // Start with NULL, let receive_frames allocate memory
    frame_data.data_len = 0;

    // Receive probe response
    printf("sent probe response.. waiting.\n");
    receive_frames(params->sockfd, params->own_mac, &frame_data, OTHER);
    printf("received probe response.. associating.\n");
    
    // If we received data, copy it to our local ap_info
    if (frame_data.data && frame_data.type == ASSOCIATION) {
        printf("Copying probe data from allocated memory to local structure\n");
        memcpy(&ap_info, frame_data.data, sizeof(struct probe_info));
        free(frame_data.data);  // Free the allocated memory
        frame_data.data = NULL;  // Set to NULL for next receive_frames call
    } else {
        printf("Did not receive valid probe response\n");
        if (frame_data.data) {
            free(frame_data.data);
            frame_data.data = NULL;
        }
        return -1;
    }

    // Verify we have a valid BSSID
    if (memcmp(ap_info.bssid, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
        printf("No valid BSSID received in probe response\n");
        return -1;
    }

    // Send association request with the ap_info
    if (send_assoc_request(params->sockfd, params->ifname, &ap_info, 
                         params->own_mac, params->pmk, params->pmkid) < 0) {
        return -1;
    }

    // Wait for association response
    frame_data.type = ASSOC_RESPONSE;
    frame_data.data = NULL;  // Always start with NULL
    frame_data.data_len = 0;
    
    receive_frames(params->sockfd, ap_info.bssid, &frame_data, ASSOCIATION);
    
    if (!frame_data.data || frame_data.type == TIMEOUT) {
        printf("no association response.. continuing.\n");
        if (frame_data.data) {
            free(frame_data.data);
        }
        return -1;
    }
    
    if (frame_data.type != ASSOC_RESPONSE) {
        printf("Did not receive association response\n");
        if (frame_data.data) {
            free(frame_data.data);
        }
        return -1;
    }
    response->type = ASSOC_RESPONSE;
    // Copy probe info to output
    if (ap_info_out) {
        memcpy(ap_info_out, &ap_info, sizeof(ap_info));
    }

    // Clean up any remaining allocated memory before returning
    if (frame_data.data) {
        free(frame_data.data);
        frame_data.data = NULL;
    }

    return 0;
}