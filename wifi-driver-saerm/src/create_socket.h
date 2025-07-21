#ifndef CREATE_SOCKET_H_
#define CREATE_SOCKET_H_
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

int run_command(const char *cmd, char *const args[]);
int initialize_interfaces(const char *phy_if, const char *mon_if);
int create_monitor_socket(const char *ifname);

#endif