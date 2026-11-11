#include "scanner.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

volatile sig_atomic_t pingLoop = 1;

static double diff_ms(const struct timespec* a, const struct timespec* b)
{
    return (b -> tv_sec - a -> tv_sec) * 1000.0 + (b -> tv_nsec - a -> tv_nsec) / 1000000.0;
}

unsigned short checksum(void* b, int len)
{
	unsigned short* buf = b;
	unsigned int sum = 0;

	for(; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return (unsigned short)~sum;
	}




void intHandler(int dummy)
{
    (void)dummy;
	pingLoop = 0;
}


char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
    struct hostent *host_entity = gethostbyname(addr_host);
    if (host_entity == NULL)
        return NULL;

    char *ip = malloc(NI_MAXHOST);
    if (!ip) return NULL;

    struct in_addr *a = (struct in_addr *)host_entity->h_addr_list[0];
    strcpy(ip, inet_ntoa(*a));

    memset(addr_con, 0, sizeof(*addr_con));
    addr_con->sin_family = host_entity->h_addrtype;
    addr_con->sin_port   = htons(PORT_NO);
    addr_con->sin_addr   = *a;
    return ip;
}



char *reverse_dns_lookup(char *ip_addr)
{
    struct sockaddr_in temp_addr;
    char buf[NI_MAXHOST];

    memset(&temp_addr, 0, sizeof(temp_addr));
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr(ip_addr);

    if (getnameinfo((struct sockaddr *)&temp_addr, sizeof(temp_addr),
                    buf, sizeof(buf), NULL, 0, NI_NAMEREQD))
    {
        fprintf(stderr, "\n\033[31m===Could not resolve reverse lookup of hostname===\033[0m\n");
        return NULL;
    }
    return strdup(buf);
}



long double send_ping(int sockfd, struct sockaddr_in *ping_addr,
                      char *rev_host, char *ping_ip, char *ping_dom)
{
    int ttl_val = 64, received = 0;
    int sent = 0;
    long double total_ms = 0;
    struct ping_pkt pckt;
    struct timespec t_start, t_end;
    struct timeval tv_out = { .tv_sec = RECV_TIMEOUT, .tv_usec = 0 };

    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
    {
        fprintf(stderr, "\n\033[31m===TTL failed!===\033[0m\n");
        return -1.0L;

    }


    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) != 0)
    {
        fprintf(stderr, "\n\033[31m===Could not set receive timeout! ===\033[0m\n");
        return -1.0L;
    }

   for (int j = 0; pingLoop; j++)
   {
       unsigned short seq = (unsigned short)(j + 1);

       memset(&pckt, 0, sizeof(pckt));
       pckt.hdr.type = ICMP_ECHO;
       pckt.hdr.un.echo.id = htons(getpid() & 0xFFFF);
       pckt.hdr.un.echo.sequence = htons(seq);

       size_t i;
       for (i = 0; i < sizeof(pckt.msg) - 1; i++)
           pckt.msg[i] = i + '0';
       pckt.msg[i] = 0;

       pckt.hdr.checksum = 0;
       pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
        
        if ( j > 0 ) 
        {
            struct timespec ts;
            ts.tv_sec = PING_SLEEP_RATE / 1000000;
            ts.tv_nsec = (PING_SLEEP_RATE % 1000000) * 1000L;
            nanosleep(&ts, NULL);

            if (!pingLoop)
                break;
        }
        


        clock_gettime(CLOCK_MONOTONIC, &t_start);
        if (sendto(sockfd, &pckt, sizeof(pckt), 0,
                   (struct sockaddr *)ping_addr, sizeof(*ping_addr)) <= 0)
        {
            fprintf(stderr, "\n\033[31m===Failed to Send the Packet!===\033[0m\n");
            continue;
        }

        sent++;

     for(;;){
         
        unsigned char rbuf[1024];
        struct sockaddr_in r_addr;
        socklen_t addr_len = sizeof(r_addr);
        
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        if(diff_ms(&t_start, &t_end) >= RECV_TIMEOUT * 1000.0){
            fprintf(stderr, "\n\033[31m===Failed to Receive Packet!===\033[0m\n");
            break;
        }


        ssize_t n = recvfrom(sockfd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&r_addr, &addr_len);



        if (n <= 0) {

            if ( errno == EINTR && !pingLoop)
                break;

            fprintf(stderr, "\n\033[31m===Failed to Receive Packet!===\033[0m\n");
            break;
        }



        clock_gettime(CLOCK_MONOTONIC, &t_end);


        struct iphdr *ip = (struct iphdr *)rbuf;
        size_t ip_len = ip->ihl * 4;
        if (ip_len < sizeof(struct iphdr) || n < (ssize_t)(ip_len + sizeof(struct icmphdr))) 
            continue;



        struct icmphdr *icmp = (struct icmphdr *)(rbuf + ip_len);
        if (icmp->type != ICMP_ECHOREPLY || icmp->code != 0)
            continue;
        if (icmp ->un.echo.id != htons(getpid() & 0xFFFF))
            continue;
        if (icmp->un.echo.sequence != htons(seq))
            continue;
        if (r_addr.sin_addr.s_addr != ping_addr -> sin_addr.s_addr)
            continue;




        double rtt = diff_ms(&t_start, &t_end);
        total_ms += rtt;
        received++;


        printf("%zd bytes from %s (h: %s) (%s) msg_seq = %d ttl = %d rtt = %.2f ms.\n",
                (ssize_t)(n - (ssize_t)ip_len), ping_dom,
                rev_host ? rev_host : "unknown",
                ping_ip, seq, ip->ttl, rtt);

        break;
     }

    }
    
   printf("\n-- %s ping statistics --\n" "%d packets transmiteed, %d received, %.0f%% packet loss\n", ping_dom, sent, received, sent ? 100.0 * (sent - received) / sent : 0.0); 

    return received ? total_ms / received : -1.0;
}




long double ping(char *host)
{
    struct sockaddr_in addr_con;
    char *ip_addr = dns_lookup(host, &addr_con);
    if (ip_addr == NULL) {
        fprintf(stderr, "\033[31m===Could not Find The DNS!===\033[0m\n");
        return -1.0;
    }

    char *reverse_hostname = reverse_dns_lookup(ip_addr);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("[-]Unable to open socket (need root / CAP_NET_RAW)");
        free(ip_addr);
        free(reverse_hostname);
        return -1.0;
    }


    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = intHandler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);


    long double result = send_ping(sockfd, &addr_con, reverse_hostname, ip_addr, host);

    close(sockfd);
    free(ip_addr);
    free(reverse_hostname);
    return result;
}
