#include "scanner.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>

unsigned short checksum(void* b, int len)
{
	unsigned short* buf = b;
	ubsigned int sum = 0;

	for(; len >; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return (unsigned short)~sum;
	}




void intHandler(int dummy)
{
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
    long double total_ms = 0;
    struct ping_pkt pckt;
    struct timespec t_start, t_end;
    struct timeval tv_out = { .tv_sec = RECV_TIMEOUT, .tv_usec = 0 };

    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        fprintf(stderr, "\n\033[31m===TTL failed!===\033[0m\n");
        return -1;
    }
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

    for (int j = 0; j < 3; j++)
    {
        memset(&pckt, 0, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = htons(getpid() & 0xFFFF);
        pckt.hdr.un.echo.sequence = htons(j);

        size_t i;
        for (i = 0; i < sizeof(pckt.msg) - 1; i++)
            pckt.msg[i] = i + '0';
        pckt.msg[i] = 0;

        pckt.hdr.checksum = 0;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        usleep(PING_SLEEP_RATE);

        clock_gettime(CLOCK_MONOTONIC, &t_start);
        if (sendto(sockfd, &pckt, sizeof(pckt), 0,
                   (struct sockaddr *)ping_addr, sizeof(*ping_addr)) <= 0)
        {
            fprintf(stderr, "\n\033[31m===Failed to Send the Packet!===\033[0m\n");
            continue;
        }

       
        unsigned char rbuf[1024];
        struct sockaddr_in r_addr;
        socklen_t addr_len = sizeof(r_addr);

        ssize_t n = recvfrom(sockfd, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr *)&r_addr, &addr_len);
        if (n <= 0) {
            fprintf(stderr, "\n\033[31m===Failed to Receive Packet!===\033[0m\n");
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &t_end);

        struct iphdr *ip = (struct iphdr *)rbuf;
        size_t ip_len = ip->ihl * 4;
        if (n < (ssize_t)(ip_len + sizeof(struct icmphdr))) continue;

        struct icmphdr *icmp = (struct icmphdr *)(rbuf + ip_len);
        if (icmp->type != ICMP_ECHOREPLY || icmp->code != 0)
            continue;

        double rtt = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
                     (t_end.tv_nsec - t_start.tv_nsec) / 1000000.0;
        total_ms += rtt;
        received++;

        fprintf(stderr, "%d bytes from %s (h: %s) (%s) msg_seq = %d ttl = %d rtt = %.2f ms.\n",
                PING_PKT_S, ping_dom, rev_host ? rev_host : "unknown",
                ping_ip, j + 1, ttl_val, rtt);
    }

    return received ? total_ms / received : 0;
}




long double ping(char* host)
{
	int sockfd;
	char *ip_addr, *reverse_hostname;
	struct sockaddr_in addr_con;
	int addrlen =sizeof(addr_con);
	long double result;

	ip_addr = dns_lookup(host, &addr_con);
	if(ip_addr == NULL)
	{
		fprintf(stderr, "\033[31m===Could not Find The DNS!===\033[0m\n");
		return 0;
	}

	reverse_hostname = reverse_dns_lookup(ip_addr);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0)
	{
		printf("[-]Unable to Open The Socket!!!\n");
		return 0;
	}

	result = send_ping(sockfd, &addr_con, reverse_hostname, ip_addr, host);

	close(sockfd);
	free(ip_addr);
	free(reverse_hostname);

	return result;
}
