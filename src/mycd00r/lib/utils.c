#include "utils.h"

void capterror(pcap_t *caps, char *message) {
    pcap_perror(caps,message);
    exit (-1);
}

void signal_handler(int sig) {
    /* the ugly way ... */
    LOG("Exiting daemon\n");
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

void xor_encrypt_decrypt(char *data, size_t length, char key) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key;
    }
}