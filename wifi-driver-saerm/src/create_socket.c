#include "create_socket.h"

int sockfd = -1 ;

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
    char *ifconfig_down[] = {"sudo ifconfig", (char *)phy_if, "down", NULL};
    char *iw_add_if[] = {"sudo iw", (char *)phy_if, "interface", "add", (char *)mon_if, "type", "monitor", NULL};
    char *iw_set_type[] = {"sudo iw", (char *)phy_if, "set", "type", "__ap", NULL};
    char *ifconfig_phy_up[] = {"sudo ifconfig", (char *)phy_if, "up", NULL};
    char *ifconfig_mon_up[] = {"sudo ifconfig", (char *)mon_if, "up", NULL};
    char *iw_set_channel[] = {"sudo iw", (char *)mon_if, "set", "channel", "6", NULL};
    char *iw_start_ap[] = {
        "sudo iw", (char *)phy_if, "ap", "start", "fakeAP", "2437", "20", "1000", "1", "head",
        "80000000000000000000c4e984dbfb7bc4e984dbfb7b0000000000000000000064000000",
        NULL
    };

    // printf("Initializing interfaces...\n");

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return -1;
    }


    // printf("Adding monitor interface...\n");
    if (run_command("iw", iw_add_if) != 0) {
        fprintf(stderr, "Failed to add monitor interface\n");
        return -1;
    }

    // printf("Bringing up monitor interface...\n");
    if (run_command("ifconfig", ifconfig_mon_up) != 0) {
        fprintf(stderr, "Failed to bring up monitor interface\n");
        return -1;
    }

    // printf("Setting channel...\n");
    // if (run_command("iw", iw_set_channel) != 0) {
    //     fprintf(stderr, "Failed to set channel\n");
    //     return -1;
    // }

    // printf("Bringing down physical interface...\n");
    if (run_command("ifconfig", ifconfig_down) != 0) {
        fprintf(stderr, "Failed to bring down interface %s\n", phy_if);
        return -1;
    }

    // printf("Setting interface type...\n");
    if (run_command("iw", iw_set_type) != 0) {
        fprintf(stderr, "Failed to set interface type\n");
        return -1;
    }

    // printf("Bringing up physical interface...\n");
    if (run_command("ifconfig", ifconfig_phy_up) != 0) {
        fprintf(stderr, "Failed to bring up physical interface\n");
        return -1;
    }

    // printf("Starting AP...\n");
    if (run_command("iw", iw_start_ap) != 0) {
        fprintf(stderr, "Warning: Failed to start AP (this might be expected)\n");
    }



    // printf("Interface initialization complete\n");
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
    // if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*)&tv, sizeof(struct timeval)) < 0) {
    //     perror("setsockopt failed");
    //     return;
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

void handle_sigint(int sig) {
    printf("\nCaught SIGINT (Ctrl+C), exiting gracefully...\n");
    if (sockfd != -1){
        close(sockfd);
    }
    exit(0);
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("ARGV err: create_socket phy iface\n");
        return -1;
    }
    initialize_interfaces(argv[1], argv[2]);
    sockfd = create_monitor_socket(argv[2]);
    FILE *file = fopen("sockfd.txt", "w");
    fprintf(file, "%d\n", sockfd);
    fclose(file);
    signal(SIGINT, handle_sigint);
    while (1) {
        sleep(10) ;
    }
    return 0;
}