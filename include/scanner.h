#ifndef SCANNER_H
#define SCANNER_H

#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> 
#include <signal.h>
#include <time.h> 

#define PING_PKT_S 64 
#define PORT_NO 0 
#define PING_SLEEP_RATE 1000000
#define RECV_TIMEOUT 1 

extern volatile sig_atomic_t pingLoop;

struct ping_pkt
{
	struct icmphdr hdr;
	char msg[PING_PKT_S - sizeof(struct icmphdr)];
};

unsigned short checksum(void* b, int len);
void intHandler(int dummy);
char* dns_lookup(char* addr_host, struct sockaddr_in* addr_con);
char* reverse_dns_lookup(char* ip_addr);


long double send_ping(int sockfd, struct sockaddr_in *ping_addr, char* rev_host, char* ping_ip, char* ping_dom);


long double ping(char* host);


#endif
