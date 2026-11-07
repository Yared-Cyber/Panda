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



char* reverse_dns_lookup(char* ip_addr)
{
	struct sockaddr_in temp_addr;
	socklen_t len;
	char buf[NI_MAXHOST], *ret_buf;

	temp_addr.sin_family = AF_INET;
	temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
	len = sizeof(struct sockaddr_in);

	if (getnameinfo((struct sockaddr* )& temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMERQD))
	{
		fprintf(stderr, "\n\033[31m===Could not Reslove Reverse lookup of hostname===\033[0m\n");
		return 	NULL;
	}

	ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char));
	strcpy(ret_buf, buf);
	return ret_buf;
}


long double send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char* ping_dom, char* ping_ip, char* rev_host)
{
	int ttl_val = 64, msg_count = 0, i, addr_len, flag = 1, msg_received_count = 0;

	struct ping_pkt pckt;
	struct sockaddr_in r_addr;
	struct timespec time_start, time_end, tfs, tfe;
	long double rtt_msec = 0, total_msec = 0, rtt_msecs[5], avg_rtt;
	struct timeval tv_out;
	tv_out.tv_sec = RECV_TIMEOUT;
	tv_out.tv_usec = 0;


	clock_gettime(CLOCK_MONOTONIC, &tfs);

	if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
	{
		fprintf(stderr, "\n\033[31m===TTL failed!===\033[0m\n");
		return -1;
	}

	setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);

	for(int j = 0; j < 3; j++)
	{
		flag = 1;
		bzero(&pckt, sizeof(pckt));

		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = getpid();

		for ( i = 0; i < sizeof(pckt.msg) - 1; i++)
			pckt.msg[i] = i + '0';

		pckt.msg[i] = 0;
		pckt.hdr.un.echo.sequence = msg_count++;
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

		usleep(PING_SLEEP_RATE);

		clock_gettime(CLOCK_MONOTONIC, &time_start);
		if( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0)
		{
			fprintf(stderr, "\n\033[31m===Failed to Send the Packet!===\033[0m\n");
			flag = 0;
		}

		addr_len = sizeof(r_addr);

		if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count)
		{
			fprintf(stderr, "\n\033[31m===Failed to Receive Packet!===\033[0m\n");
		}

		else 
		{
			clock_gettime(CLOCK_MONOTONIC, &time_end);

			double rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + (time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;

			rtt_msecs[j] = rtt_msec;

			if(flag)
			{
				if(!(pckt.hdr.type == ICMP_ECHOREPLY && pckt.hdr.code == 0))
				{
					return 0;
				}

				else
				{
					fprintf(stderr, "%d bytes from %s (h: %s) (%s) msg_seq = %d ttl = %d rrt = %.2f ms.\n", PING_PKT_S, ping_dom, rev_host, ping_ip, msg_count, ttl_val, (double)rtt_msec);

					msg_received_count++;
				}
			}
		}
	}

		return (rtt_msecs[0] + rtt_msecs[1] + rtt_msecs[2]) / 3;
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
