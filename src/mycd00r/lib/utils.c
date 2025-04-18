#include "utils.h"

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

void uninstall_program() {
    
}