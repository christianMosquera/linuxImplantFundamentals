#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#define IP_VERSION AF_INET
#define IPV4_LOOPBACK_ADDR "127.0.0.1"
#define IPV6_LOOPBACK_ADDR "::1"
#define CORRECT_IP_VERSION "192.168.1.237" // not real ip

#define DEBUG

#ifdef DEBUG
    #define LOG(fmt, ...) syslog(LOG_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#else
    #define LOG(fmt, ...)
#endif

void capterror(pcap_t *caps, char *message);

void signal_handler(int sig);

void *smalloc(size_t size);

void check_for_correct_ip();

void check_for_antivirus();

#endif