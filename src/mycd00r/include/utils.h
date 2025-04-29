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

#ifdef DEBUG
    #define LOG(fmt, ...) syslog(LOG_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#else
    #define LOG(fmt, ...)
#endif

void capterror(pcap_t *caps, char *message);

void signal_handler(int sig);

void *smalloc(size_t size);

#endif