#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <endian.h>
#include <openssl/cmac.h>

#include "sendFrame.h"
#include "frame_structs.h"

// Radiotap header field masks
#define RT_FIELD_PRESENT_FLAGS      (1 << 1)
#define RT_FIELD_PRESENT_RATE      (1 << 2)
#define RT_FIELD_PRESENT_CHANNEL   (1 << 3)
#define RT_FIELD_PRESENT_TX_FLAGS  (1 << 15)

// Radiotap flags
#define RT_FLAGS_NONE              0x00
#define RT_FLAGS_CFP               0x01
#define RT_FLAGS_SHORT_PREAMBLE    0x02
#define RT_FLAGS_WEP_ENC          0x04
#define RT_FLAGS_FRAGMENT         0x08

// Channel flags
#define RT_CHN_FLAG_TURBO         0x0010
#define RT_CHN_FLAG_CCK           0x0020
#define RT_CHN_FLAG_OFDM          0x0040
#define RT_CHN_FLAG_2GHZ          0x0080
#define RT_CHN_FLAG_5GHZ          0x0100


void setup_radiotap(struct radiotap *rt) {
    // Zero out the entire structure first to avoid uninitialized memory
    memset(rt, 0, sizeof(struct radiotap));
    
    // Set header fields
    rt->header.version = 0;
    rt->header.pad = 0;
    rt->header.len = sizeof(struct radiotap); // Total size of header plus data
    
    // Set present flags for the fields we're including
    // Assuming we want to include flags, rate, channel info, and tx flags
    rt->header.present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 15);
    
    // Set data fields
    rt->data.flags = 0;  // No special flags
    rt->data.rate = 0;   // Rate in 500kbps units
    rt->data.chan_freq = 0; // Channel frequency
    rt->data.chan_flags = 0; // Channel flags
    rt->data.tx_flags = 0;  // TX flags
}

int run_command(const char *cmd, char *const args[]) {
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return -1;
    }
    
    if (pid == 0) {  // Child process
        execvp(cmd, args);
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } else {  // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return -1;
    }
}

int initialize_interfaces(const char *phy_if, const char *mon_if) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return -1;
    }

    char cmd[512];

    // start_virtual_interface(phy, iface)
    snprintf(cmd, sizeof(cmd), "sudo iw %s interface add %s type monitor", phy_if, mon_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to add monitor interface\n");
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "sudo ifconfig %s up", mon_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to bring up monitor interface\n");
        return -1;
    }

    // set_ap_mode(phy) - Always put it down first
    snprintf(cmd, sizeof(cmd), "sudo ifconfig %s down", phy_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to bring down interface %s\n", phy_if);
        return -1;
    }

    // Set type to __ap
    snprintf(cmd, sizeof(cmd), "sudo iw %s set type __ap", phy_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to set interface type to __ap\n");
        return -1;
    }

    // Bring interface back up (up=True in set_ap_mode)
    snprintf(cmd, sizeof(cmd), "sudo ifconfig %s up", phy_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to bring up physical interface\n");
        return -1;
    }

    // start_ap(phy, 6) - Start AP on channel 6
    snprintf(cmd, sizeof(cmd), 
        "sudo iw dev %s ap start fakeAP 2437 20 1000 1 head 80000000000000000000c4e984dbfb7bc4e984dbfb7b0000000000000000000064000000", 
        phy_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to start AP\n");
        // Don't return -1 here since Python code doesn't fail on this
    }

    // Final ifconfig up (like the Python code does after ap start)
    snprintf(cmd, sizeof(cmd), "sudo ifconfig %s up", phy_if);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed final ifconfig up\n");
    }

    printf("Interface initialization complete\n");
    return 0;
}

int create_monitor_socket(const char *ifname) {
    int sockfd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    int flags = fcntl(sockfd, F_GETFL, 0); 
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
    
    // struct timeval tv;
    // tv.tv_sec = 2;
    // tv.tv_usec = 0;
    // if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(struct timeval)) < 0) {
    //     perror("setsockopt failed");
    //     close(sockfd);  // Close socket on error
    //     return -1;      // Return -1, not void
    // }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        close(sockfd);
        return -1;
    }
    
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

int send_deauth_frame(int sockfd, const uint8_t *dest_mac, const uint8_t *src_mac, const uint8_t *bssid) {
    struct complete_frame frame;
    memset(&frame, 0, sizeof(frame));
    
    setup_radiotap(&frame.rt);
    
    frame.mac_header.frame_control.protocol_version = 0;
    frame.mac_header.frame_control.type = 0;        // Management frame
    frame.mac_header.frame_control.subtype = 12;    // Deauthentication frame
    frame.mac_header.frame_control.to_ds = 0;
    frame.mac_header.frame_control.from_ds = 0;
    frame.mac_header.frame_control.more_frag = 0;
    frame.mac_header.frame_control.retry = 0;
    frame.mac_header.frame_control.power_mgmt = 0;
    frame.mac_header.frame_control.more_data = 0;
    frame.mac_header.frame_control.protected_frame = 0;
    frame.mac_header.frame_control.order = 0;
    
    frame.mac_header.duration = 0;
    memcpy(frame.mac_header.addr1, dest_mac, 6);    // Destination MAC
    memcpy(frame.mac_header.addr2, src_mac, 6);     // Source MAC
    memcpy(frame.mac_header.addr3, bssid, 6);       // BSSID
    frame.mac_header.seq_ctrl = 0;
    
    // Add reason code 3 (Station leaving) to variable data
    frame.variable[0] = 3;  // Reason code (lower byte)
    frame.variable[1] = 0;  // Reason code (upper byte)
    
    size_t frame_len = sizeof(frame.rt) + sizeof(frame.mac_header) + 2; // +2 for reason code
    
    if (send(sockfd, &frame, frame_len, 0) < 0) {
        perror("Failed to send deauth frame");
        return -1;
    }
    
    return 0;
}

int send_sae_frame(int sockfd, const uint8_t *dest_mac, const uint8_t *src_mac, 
    const uint8_t *bssid, uint16_t seq, uint16_t status,
    const uint8_t *variable_data, size_t variable_len) {
    // Calculate minimum frame size needed
    size_t min_frame_size = sizeof(struct radiotap) + 
                sizeof(struct ieee80211_header) + 
                variable_len;

    // Allocate memory and zero-initialize it
    uint8_t *frame_buffer = (uint8_t *)calloc(1, min_frame_size);
    if (!frame_buffer) {
    perror("Failed to allocate memory for frame");
    return -1;
    }

    // Get pointers to different parts of the frame
    struct radiotap *rt = (struct radiotap *)frame_buffer;
    struct ieee80211_header *mac = (struct ieee80211_header *)(frame_buffer + sizeof(struct radiotap));
    uint8_t *variable = frame_buffer + sizeof(struct radiotap) + sizeof(struct ieee80211_header);

    // Initialize radiotap header
    setup_radiotap(rt);

    // Initialize MAC header
    memset(mac, 0, sizeof(struct ieee80211_header));

    mac->frame_control.protocol_version = 0;
    mac->frame_control.type = 0;        // Management frame
    mac->frame_control.subtype = 11;    // Authentication frame
    mac->frame_control.to_ds = 0;
    mac->frame_control.from_ds = 0;
    mac->frame_control.more_frag = 0;
    mac->frame_control.retry = 0;
    mac->frame_control.power_mgmt = 0;
    mac->frame_control.more_data = 0;
    mac->frame_control.protected_frame = 0;
    mac->frame_control.order = 0;

    mac->duration = 0;

    // Copy addresses with NULL checks
    if (dest_mac) memcpy(mac->addr1, dest_mac, 6);
    if (src_mac) memcpy(mac->addr2, src_mac, 6);
    if (bssid) memcpy(mac->addr3, bssid, 6);

    mac->seq_ctrl = 0;

    // Copy variable data
    if (variable_data && variable_len > 0) {
    memcpy(variable, variable_data, variable_len);
    }

    // Send frame
    int result = send(sockfd, frame_buffer, min_frame_size, 0);

    // Clean up
    free(frame_buffer);

    if (result < 0) {
    perror("Failed to send frame");
    return -1;
    }

    return 0;
}

bool receive_beacon_frame(unsigned char *mac_address, int sock_fd) {
    unsigned char buffer[2048];
    
    // Receive a frame
    ssize_t packet_len = recv(sock_fd, buffer, sizeof(buffer), 0);
    if (packet_len < 0) {
        perror("Error receiving packet");
        return false;
    }
    
    // Check if it's a beacon frame (frame type 0x08)
    unsigned char frame_control = buffer[0];
    if ((frame_control & 0xFC) != (0x08 << 2)) {
        return false;  // Not a beacon frame
    }
    
    // Check if the source MAC matches our target
    if (memcmp(&buffer[10], mac_address, 6) == 0) {
        return true;  // Found a beacon frame from the specified MAC
    }
    
    return false;
}

int process_received_frame(const uint8_t *buffer, ssize_t len, char* dst, sae_frame_t *data) {
    if (len < sizeof(struct radiotap_header)) {
        data->type = TIMEOUT;
        data->data_len = 0;
        return 0;
    }
    
    const struct radiotap_header *rt_header = (const struct radiotap_header *)buffer;
    
    if (len < rt_header->len) {
        return 0;
    }
    
    const uint8_t *frame = buffer + rt_header->len;
    const struct ieee80211_header *mac_header = (const struct ieee80211_header *)frame;
    
    // Extract frame control fields
    uint8_t type = mac_header->frame_control.type;
    uint8_t subtype = mac_header->frame_control.subtype;
    // printf("%d %d\n",type, subtype);

    
    if (type == 0 && subtype == 1 && !memcmp(mac_header->addr2, dst, 6)) {
        data->type = ASSOC_RESPONSE;
        const uint8_t *assoc_resp = frame + sizeof(struct ieee80211_header);
        data->data_len = len - (assoc_resp - buffer);
        data->data = malloc(data->data_len);
        if (data->data == NULL) {
            perror("Memory allocation failed");
            return 0;
        }
        memcpy(data->data, assoc_resp, data->data_len);
        return 1;
    }


    // Add EAPOL Key message detection
    if (type == 2 && subtype == 8 && !memcmp(mac_header->addr2, dst, 6)) {  // Data frame
        const uint8_t *data_start = frame + sizeof(struct ieee80211_header);
        data_start += 8;
        // Check for EAPOL ethertype (0x888e)
        if (data_start[0] == 0x88 && data_start[1] == 0x8e) {
            const struct eapol_key *eapol = (const struct eapol_key *)(data_start + 2);
            uint16_t key_info = ntohs(eapol->key_info);

            // Check if it's EAPOL-Key message 1 (Key MIC not set, Key ACK set)
            if ((key_info == 0x0088)) {
                data->type = EAPOL_KEY_1;
                data->data_len = len - (data_start - buffer);
                data->data = malloc(data->data_len);
                if (data->data == NULL) {
                    perror("Memory allocation failed");
                    return 0;
                }
                memcpy(data->data, data_start, data->data_len);
                return 1;
            }
            
            // Check if it's EAPOL-Key message 3 (Key MIC set, Key ACK set, Encrypted)
            if ((key_info & 0x0008) && (key_info & 0x0100) && (key_info & 0x0040)) {
                data->type = EAPOL_KEY_3;
                data->data_len = len - (data_start - buffer);
                data->data = malloc(data->data_len);
                if (data->data == NULL) {
                    perror("Memory allocation failed");
                    return 0;
                }
                memcpy(data->data, data_start, data->data_len);
                return 1;
            }
        }
    }
    // Check for probe response (type 0, subtype 5)
    if (type == 0 && subtype == 5 && !memcmp(mac_header->addr1, dst, 6)) {
        // Allocate memory for probe_info if not already allocated
        if (data->data == NULL) {
            data->data = malloc(sizeof(struct probe_info));
            if (data->data == NULL) {
                perror("Memory allocation failed");
                return 0;  // Early return on malloc failure
            }
            
            // Initialize only after successful allocation
            struct probe_info *probe_data = (struct probe_info *)data->data;
            printf("Initializing new probe_info structure...\n");
            memset(probe_data, 0, sizeof(struct probe_info));
        } else {
            // Check if this is a pointer to stack memory from perform_sae_association
            // We need to use a safer approach than comparing with a local stack variable
            // Instead, we'll just be careful with the existing pointer
            
            // Safe to clear existing dynamically allocated memory
            printf("Clearing existing probe_info structure...\n");
            // Only clear memory if it's properly allocated
            if (data->data_len >= sizeof(struct probe_info)) {
                memset(data->data, 0, sizeof(struct probe_info));
            } else {
                // Reallocate to ensure proper size
                free(data->data);
                data->data = malloc(sizeof(struct probe_info));
                if (data->data == NULL) {
                    perror("Memory allocation failed");
                    return 0;
                }
                memset(data->data, 0, sizeof(struct probe_info));
            }
        }
        
        // Get proper pointer to probe_data structure
        struct probe_info *probe_data = (struct probe_info *)data->data;
        
        // Copy BSSID from the correct field in the header
        memcpy(probe_data->bssid, mac_header->addr3, 6);
        printf("BSSID captured: %02x:%02x:%02x:%02x:%02x:%02x\n", 
               probe_data->bssid[0], probe_data->bssid[1], probe_data->bssid[2], 
               probe_data->bssid[3], probe_data->bssid[4], probe_data->bssid[5]);
        
        // Make sure we have enough data for fixed parameters (24 bytes header + 12 bytes fixed params)
        if (len < sizeof(struct ieee80211_header) + 12) {
            printf("Probe response too short for fixed parameters\n");
            return 0;
        }
        
        const uint8_t *probe_body = frame + sizeof(struct ieee80211_header);
        
        // Copy capability info from fixed parameters
        memcpy(&probe_data->capability, probe_body + 10, 2);
        
        // Parse IEs
        const uint8_t *ie = probe_body + 12;
        const uint8_t *end = buffer + len;
        
        printf("Starting to parse IEs...\n");
        while (ie + 2 <= end) {
            uint8_t id = ie[0];
            uint8_t ie_len = ie[1];
            
            // Ensure we have the complete IE
            if (ie + 2 + ie_len > end) {
                printf("Incomplete IE (id=%d, len=%d), stopping parsing\n", id, ie_len);
                break;
            }
            
            switch (id) {
                case 0: // SSID
                    if (ie_len <= 32) {
                        memcpy(probe_data->ssid, ie + 2, ie_len);
                        probe_data->ssid_len = ie_len;
                        printf("Found SSID: ");
                        for (int i = 0; i < ie_len; i++) {
                            printf("%c", isprint(probe_data->ssid[i]) ? probe_data->ssid[i] : '.');
                        }
                        printf(" (len=%d)\n", ie_len);
                    } else {
                        printf("SSID too long (%d), ignoring\n", ie_len);
                    }
                    break;
                    
                case 1: // Supported rates
                    if (ie_len <= 8) {
                        memcpy(probe_data->rates, ie + 2, ie_len);
                        probe_data->rates_len = ie_len;
                        printf("Found %d supported rates\n", ie_len);
                    } else {
                        printf("Too many rates (%d), truncating to 8\n", ie_len);
                        memcpy(probe_data->rates, ie + 2, 8);
                        probe_data->rates_len = 8;
                    }
                    break;
                    
                case 48: // RSN
                    if (ie_len <= 254) {
                        probe_data->rsn_ie[0] = 48;
                        probe_data->rsn_ie[1] = ie_len;
                        memcpy(probe_data->rsn_ie + 2, ie + 2, ie_len);
                        probe_data->rsn_ie_len = ie_len + 2;
                        printf("Found RSN IE (len=%d)\n", ie_len);
                    } else {
                        printf("RSN IE too long (%d), ignoring\n", ie_len);
                    }
                    break;
                    
                default:
                    // Skip other IEs
                    break;
            }
            
            ie += 2 + ie_len;
        }
        
        // Final validation check
        if (memcmp(probe_data->bssid, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
            printf("Error: BSSID is all zeros after parsing\n");
            return 0;
        }
        
        if (probe_data->ssid_len == 0) {
            printf("Warning: No SSID found in probe response\n");
        }
        
        printf("Probe response parsing complete\n");
        data->type = ASSOCIATION;
        data->data_len = sizeof(struct probe_info);
        return 1;
    }    
    // Original authentication frame handling
    if (type == 0 && subtype == 11 && !memcmp(mac_header->addr2, dst, 6)) {
        const uint8_t *variable = (const uint8_t *)(mac_header + 1);
        uint16_t seq;
        memcpy(&seq, variable + 2, 2);

        if (seq & 0x0001) {
            data->type = SAE_COMMIT;
        }
        else {
            data->type = SAE_CONFIRM;
        }
        
        size_t variable_len = len - (variable - buffer);
        data->data_len = variable_len;

        printf("DEBUG: sendFrame.c Line 435 LEN : %u\n",data->data_len) ; 
        
        data->data = malloc(data->data_len);
        if (data->data == NULL) {
            perror("Memory allocation failed");
            return 0;
        }

        memcpy(data->data, variable, variable_len);
        printf("DEBUG: sendFrame.c Line 446 DONE FRAME COPY, RETURNING\n") ; 
        return 1;
    }
    return 0;
}

void receive_frames(int sockfd, unsigned char* dst, sae_frame_t *data, sae_frame_type_t request_type) {
    uint8_t buffer[2500] = {0};  // Initialize buffer to zero
    ssize_t len;
    // struct timeval tv;
    
    // if (!dst || !data || !data->data) {  // Add pointer validation
    //     printf("Invalid parameters in receive_frames\n");
    //     return;
    // }

    // Set socket timeout
    // tv.tv_sec = 2;
    // tv.tv_usec = 0;
    // if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    //     perror("setsockopt failed");
    //     return;
    // }

    int count = 0;
    while (count++ < 10) {  // Limit the number of iterations
        memset(buffer, 0, sizeof(buffer));  // Clear buffer before each receive
        len = recv(sockfd, buffer, sizeof(buffer), 0);
        // printf("sendFrame.c Line 471 LEN = %u\n",len) ; 
        
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                data->type = TIMEOUT;
                return;  // Timeout occurred
            }
            perror("Frame reception failed");
            continue;
        }

        if (len == 0) {  // Connection closed
            printf("Connection closed by peer\n");
            return;
        }

        if (len > sizeof(buffer)) {  // Sanity check
            printf("Received frame too large\n");
            continue;
        }

        // Validate frame before processing
        if (!process_received_frame(buffer, len, dst, data)) {
            continue;
        }

        // Check for valid frame type
        if ((data->type == SAE_COMMIT && request_type == SAE_COMMIT) || (data->type == SAE_CONFIRM && request_type == SAE_CONFIRM) || 
            data->type == EAPOL_KEY_1 || data->type == EAPOL_KEY_3 || 
            data->type == ASSOCIATION || data->type == ASSOC_RESPONSE) {
            return;
        }
    }
    data->type = TIMEOUT;
}


int compute_mic(unsigned char *key, unsigned char *data, size_t data_len, unsigned char *mic_out) {
    CMAC_CTX *ctx = CMAC_CTX_new();
    size_t mic_len;
    
    if (!ctx) return -1;
    
    // Use AES-128-CMAC as per standard (first 16 bytes of KCK)
    if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    
    if (!CMAC_Update(ctx, data, data_len)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    
    if (!CMAC_Final(ctx, mic_out, &mic_len)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    
    CMAC_CTX_free(ctx);
    return 0;
}

int send_eapol_msg_2(int sockfd,
                     const unsigned char *own_mac, 
                     const unsigned char *ap_mac, 
                     const unsigned char *snonce, 
                     uint64_t replay_counter,
                     const unsigned char *kck,
                     const unsigned char *pmkid) {
    // Calculate total size needed for the eapol_key structure
    size_t key_data_len = 47;  // 44 + 3 for RSNX
    size_t eapol_key_size = sizeof(struct eapol_key) + key_data_len;
    
    // Allocate frame with exact size needed
    struct eapol_frame *frame = malloc(sizeof(struct eapol_frame) - sizeof(struct eapol_key) + eapol_key_size);
    if (!frame) return -1;
    
    memset(frame, 0, sizeof(struct eapol_frame) - sizeof(struct eapol_key) + eapol_key_size);
    
    // Rest of the code remains same until key_data handling
    frame->rt.version = 0;
    frame->rt.len = sizeof(struct radiotap_header);
    
    frame->mac_header.frame_control.type = 2;
    frame->mac_header.frame_control.subtype = 0;
    frame->mac_header.frame_control.to_ds = 1;
    frame->mac_header.duration = 0;
    memcpy(frame->mac_header.addr1, ap_mac, 6);
    memcpy(frame->mac_header.addr2, own_mac, 6);
    memcpy(frame->mac_header.addr3, ap_mac, 6);
    
    static const uint8_t llc_snap_header[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
    memcpy(frame->llc, llc_snap_header, 8);
    
    frame->eapol.protocol_version = 2;
    frame->eapol.packet_type = 3;
    frame->eapol.packet_length = htons(sizeof(struct eapol_key) - 4 + key_data_len);
    
    frame->eapol.descriptor_type = 2;
    frame->eapol.key_info = htons(0x0108);
    frame->eapol.key_length = htons(16);
    
    uint64_t counter_be = htobe64(replay_counter);
    memcpy(&frame->eapol.replay_counter, &counter_be, 8);
    
    memcpy(frame->eapol.key_nonce, snonce, 32);
    memset(frame->eapol.key_iv, 0, 16);
    memset(frame->eapol.key_rsc, 0, 8);
    memset(frame->eapol.key_id, 0, 8);
    memset(frame->eapol.key_mic, 0, 16);

    // Construct key data
    unsigned char key_data[24] = {
        0x30, 0x2a, 0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x08,
        0xc0, 0x00,
        0x01, 0x00
    };

    // Build complete key data
    memcpy(frame->eapol.key_data, key_data, 24);
    memcpy(frame->eapol.key_data + 24, pmkid, 16);
    unsigned char gm_suite[4] = {0x00, 0x0f, 0xac, 0x06};
    memcpy(frame->eapol.key_data + 40, gm_suite, 4);
    unsigned char rsnx[3] = {0xf4, 0x01, 0x20};
    memcpy(frame->eapol.key_data + 44, rsnx, 3);

    frame->eapol.key_data_length = htons(key_data_len);

    // Calculate MIC
    uint8_t mic[16];
    size_t eapol_len = 95;  // Size of EAPOL-Key header without key_data
    size_t total_len = eapol_len + key_data_len + 4;  // Add key_data length + EAPOL header

    if (compute_mic(kck, (uint8_t *)&frame->eapol, total_len, mic) != 0) {
        free(frame);
        return -1;
    }

    memcpy(frame->eapol.key_mic, mic, 16);
    
    // Send frame
    size_t frame_len = sizeof(struct radiotap_header) + 
                      sizeof(struct ieee80211_header) + 
                      8 +  // LLC header
                      eapol_len + key_data_len + 4;  // EAPOL + key_data + header

    send(sockfd, frame, frame_len, 0);
    
    free(frame);
    return 0;
}
int send_eapol_msg_4(int sockfd,
                     const unsigned char *own_mac, 
                     const unsigned char *ap_mac,
                     uint64_t replay_counter,
                     const unsigned char *kck) {
    struct eapol_frame frame;
    memset(&frame, 0, sizeof(frame));
    
    // Setup radiotap header
    frame.rt.version = 0;
    frame.rt.len = sizeof(struct radiotap_header);
    
    // Setup 802.11 header
    frame.mac_header.frame_control.type = 2;     // Data frame
    frame.mac_header.frame_control.subtype = 0;
    frame.mac_header.frame_control.to_ds = 1;
    frame.mac_header.duration = 0;
    memcpy(frame.mac_header.addr1, ap_mac, 6);   // Destination (AP)
    memcpy(frame.mac_header.addr2, own_mac, 6);  // Source
    memcpy(frame.mac_header.addr3, ap_mac, 6);   // BSSID
    
    // LLC/SNAP header
    static const uint8_t llc_snap_header[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
    memcpy(frame.llc, llc_snap_header, 8);
    
    // EAPOL header and key
    frame.eapol.protocol_version = 2;
    frame.eapol.packet_type = 3;      // EAPOL-Key
    frame.eapol.packet_length = htons(sizeof(struct eapol_key) - 4);
    
    // EAPOL-Key header
    frame.eapol.descriptor_type = 2;
    frame.eapol.key_info = htons(0x0308);  // Msg 4 flags: MIC + Secure + Key Type
    frame.eapol.key_length = htons(16);
    
    uint64_t counter_be = htobe64(replay_counter);
    memcpy(&frame.eapol.replay_counter, &counter_be, 8);
    
    // Zero out all other fields
    memset(frame.eapol.key_nonce, 0, 32);
    memset(frame.eapol.key_iv, 0, 16);
    memset(frame.eapol.key_rsc, 0, 8);
    memset(frame.eapol.key_id, 0, 8);
    memset(frame.eapol.key_mic, 0, 16);
    frame.eapol.key_data_length = 0;  // No key data in message 4
    
    // Calculate MIC
    uint8_t mic[16];
    size_t eapol_len = 95;  // Size of EAPOL-Key header without key_data
    size_t total_len = eapol_len + 4;  // Add EAPOL header length
    if (compute_mic(kck, (uint8_t *)&frame.eapol, total_len, mic) != 0) {
        return -1;
    }
    
    // Copy MIC into frame
    memcpy(frame.eapol.key_mic, mic, 16);
    
    // Send frame
    size_t frame_len = sizeof(struct radiotap_header) + 
                      sizeof(struct ieee80211_header) + 
                      8 +  // LLC header
                      eapol_len + 4;  // EAPOL header + data
    
    send(sockfd, &frame, frame_len, 0);
    
    return 0;
}

// int main(int argc, char *argv[]) {
//     if (argc != 3) {
//         fprintf(stderr, "Usage: %s <physical_interface> <monitor_interface>\n", argv[0]);
//         fprintf(stderr, "Example: %s wlx001c500e4631 wlan0\n", argv[0]);
//         return 1;
//     }
    
//     if (initialize_interfaces(argv[1], argv[2]) != 0) {
//         fprintf(stderr, "Failed to initialize interfaces\n");
//         return 1;
//     }
    
//     int sockfd = create_monitor_socket(argv[2]);
//     if (sockfd < 0) {
//         return 1;
//     }
//     // Example usage for SAE commit message
//     uint8_t dest_mac[6] = {0xC8, 0xE3, 0x06, 0x90, 0x3A, 0xE6};  // Broadcast
//     uint8_t src_mac[6] = {0x23, 0xCC, 0x22, 0x33, 0x44, 0x55};   // Example source
//     uint8_t bssid[6] = {0x23, 0xCC, 0x22, 0x33, 0x44, 0x55};     // Example BSSID
    
//     // Example SAE commit message data (you would replace this with actual SAE data)
//     uint8_t sae_data[] = {
//         0x13, 0x00,    // Group ID (19 for ECC group)
//         0x01, 0x00,    // Scalar
//         // ... more SAE-specific data ...
//     };
//     // sleep(5000);
//     // Send example SAE commit frame (sequence 1)
//     if (send_sae_frame(sockfd, dest_mac, src_mac, bssid, 1, 0, sae_data, sizeof(sae_data)) < 0) {
//         close(sockfd);
//         return 1;
//     }
    
//     // Start receiving frames
//     receive_frames(sockfd);
    
//     close(sockfd);
//     return 0;
// }