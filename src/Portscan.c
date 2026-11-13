#include "Portsacn.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

struct port_info {
	unisined short port;
	const char* service;
}

static const struct port_info PORTS[] = {
    {21,    "ftp"},
    {22,    "ssh"},
    {23,    "telnet"},
    {25,    "smtp"},
    {53,    "dns"},
    {80,    "http"},
    {110,   "pop3"},
    {111,   "rpcbind"},
    {135,   "msrpc"},
    {139,   "netbios-ssn"},
    {143,   "imap"},
    {443,   "https"},
    {445,   "smb"},
    {465,   "smtps"},
    {587,   "submission"},
    {993,   "imaps"},
    {995,   "pop3s"},
    {1433,  "mssql"},
    {1521,  "oracle"},
    {2049,  "nfs"},
    {3306,  "mysql"},
    {3389,  "rdp"},
    {5432,  "postgresql"},
    {5900,  "vnc"},
    {6379,  "redis"},
    {8080,  "http-alt"},
    {8443,  "https-alt"},
    {27017, "mongodb"}
};

#define NUM_PORTS ((int)(sizeof(PORTS) / sizeof(PORTS[0])))

enum {
    PORT_UNKNOWN,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED
};



static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}



static int set_nonblocking (int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) return -1;

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
