#ifndef SCANNER_H
#define SCANNER_H

#include <sys/types.h> // use for system calls eg. pid_t, size_t
#include <sys/socket.h> // for sock(), setsockopt()
#include <netinet/in.h> // for htons()
#include <arpa/inet.h> // for inet_addr()
#include <netdb.h> // for gethostbyname()
#include <netinet/ip_icmp.h> // for struct icmphdr
#include <time.h> // for clock_gettime()

#define PING_PKT_S 64 // set the value of ping packet to 64
#define PORT_NO 0 // default port
#define PING_SLEEP_RATE 1000000 // the delay of between consecutive ping requests is 1000000 microseconds = 1 second
#define RECV_TIMEOUT 1 // use for to keep the receive timeout duration to 1 second

extern int pingLoop;

struct ping_pkt
{
	struct icmphdr hdr;
	char msg[PING_PKT_S - sizeof(struct icmphdr)];
};

unsigned short checksum(void* b, int len);
void intHandler(int dummy);
char* dns_lookup(char* addr_host, struct sockaddr_in* addr_con);
char* reverse_dns_lookup(char* ip_addr);
long double send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char* ping_dom, char* ping_ip, char* rev_host);
double ping(char* host);


#endif
