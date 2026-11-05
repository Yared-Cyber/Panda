#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <sys/types.h> // use for system calls eg. pid_t, size_t
#include <sys/socket.h> // for sock(), setsockopt()
#include <netinet/in.h> // for htons()
#include <arpa/inet.h> // for inet_addr()
#include <netdb.h> // for gethostbyname()
#include <unistd.h> // for close()
#include <string.h> // for bzero, strcpy()
#include <stdlib.h> // for exit()
#include <netinet/ip_icmp.h> // for struct icmphdr
#include <time.h> // for clock_gettime()
#include <fcntl.h> // for file descriptor flag
#include <signal.h> // for singal()

#define PING_PKT 64 // set the value of ping packet to 64
#define PORT_NO 0 // defult port
#define PING_SLEEP_RATE 1000000 // the delay of between consecutive ping requests is 1000000 microseconds = 1 second
#define RECV_TIMEOUT 1 // use for to keep the receive timeout duration to 1 second

int pingLoop;



#endif
