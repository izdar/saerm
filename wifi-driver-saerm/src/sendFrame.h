#ifndef SENDFRAME_H
#define SENDFRAME_H

# include "frame_structs.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

int create_monitor_socket(const char *ifname);
int send_deauth_frame(int sockfd, const uint8_t *dest_mac, const uint8_t *src_mac, const uint8_t *bssid);
int send_sae_frame(int sockfd, const uint8_t *dest_mac, const uint8_t *src_mac, 
                  const uint8_t *bssid, uint16_t seq, uint16_t status,
                  const uint8_t *variable_data, size_t variable_len);
// void process_received_frame(const uint8_t *buffer, size_t len);
int initialize_interfaces(const char *phy_if, const char *mon_if);
int send_eapol_msg_2(int sockfd,
                     const unsigned char *own_mac, 
                     const unsigned char *ap_mac, 
                     const unsigned char *snonce, 
                     uint64_t replay_counter,
                     const unsigned char *kck,
                     const unsigned char *pmkid);
int send_eapol_msg_4(int sockfd,
                     const unsigned char *own_mac, 
                     const unsigned char *ap_mac,
                     uint64_t replay_counter,
                     const unsigned char *kck);

                     int process_received_frame(const uint8_t *buffer, ssize_t len, char* dst, sae_frame_t *data);
void receive_frames(int sockfd, unsigned char* dst, sae_frame_t *data, sae_frame_type_t request_type); ;
int compute_mic(unsigned char *key, unsigned char *data, size_t data_len, unsigned char *mic_out);
int receive_frames_probe_response(int sockfd, unsigned char* dst, sae_frame_t *data) ;
bool receive_beacon_frame(unsigned char *mac_address, int sock_fd);


#endif 