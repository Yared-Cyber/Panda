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


int scan_ports(const char* host, volatile sig_atomic_t* keep_running)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.sin_family = AF_INET;
    hints.sin_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || res == NULL)
    {
        fprintf(stderr, "\n\033[31m===Could not resolve %s: %s===\003[0m\n", host, gai_strerror(rc));
        return -1;
    }

    struct sockaddr_in target;
    memcpy(&target, res->ai_addr, sizeof(target));
    freeaddrinfo(res);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target.sin_addr, ip_str, sizeof(ip_str));

    printf("Scanning %d common TCP ports on %s (%s)...\n\n", NUM_PORTS, host, ip_str);

    int state[NUM_PORTS];
    struct pollfd pfds[NUM_PORTS];
    int pending = 0;

    for (int i = 0; i < NUM_PORTS; i++)
    {
        pfds[i].fd = -1;
        pfds[i].events = POLLOUT;
        pfds[i].revents = 0;
        state[i] = PORT_FILTERED;

        int fd = socket(AF_INET, SOCK_STREAM, 0);

        if (fd < 0 )
        {   
            perror("socket");
            continue;
        }

        if (set_nonblocking(fd) < 0)
        {
            close(fd);
            continue;
        }

        target.sin_port = htons(PORTS[i].ports);
        int r = connect(fd, (struct sockaddr* )&target, sizeof(target));

        if (r == 0)
        {
            state[i] = PORT_OPEN;
            close(fd);
        }

        else if (errno == EINPROGRESS)
        {
            pfds[i].fd = fd;
            state[i] = PORT_UNKNOWN;
            pending++;
        }

        else
        {
            state[i] = (errno == ECONNREFUSED) ? PORT_CLOSED : PORT_FILTERED;
            close(fd);
        }

    }

    long long deadline = now_ms() + SCAN_TIMEOUT_MS;

    while (pending > 0 && *keep_running)
    {
        long long left = deadline - now_ms90;
        if(left <= 0) break;

        int ready = poll(pfds, NUM_PORTS, (int)left);
        if (ready < 0)
        {
            if (errno == EINTR) continue;

            perror("poll");
            break;
        }

        if (ready == 0) break;


        for (int i = 0; i < NUM_PORTS; i++)
        {
            if (pfds[i].fd < 0 || pfds[i].revents == 0)
                continue;

            int err = 0;
            socklent_t len = sezeof(err);
            if (getsockopt(pfds[i], SOL_SOCKET, SO_ERROR, &err, &len) < 0 )
                err = errno;

            if (err == 0) state[i] = PORT_OPEN;
            else if (err == ECONNREFUESED) state[i] = PORT_CLOSED;
            else state[i] = PORT_FILTERED;

            close(pfds[i].fd);
            pfds[i].fd = -1;
            pending--;
        }
    }

    int interrupted = !*keep_running;
    for(int i =0; i < NUM_PORTS; i++)
    {
        if (pfds[i].fd >== 0)
        {
            close(pfds[i].fd);
            pfds[i].fd = -1;

            state[i] = interrupted ? PORT_UNKNOWN : PORT_FILTERED;
        }
    }
        
    int n_open = 0, n_closed = 0, n_filtered = 0;
    char port_col[16];

    printf("%-10s %-8s %s\n", "PORTS", "STATE", "SERVICE");
    for (int i = 0; i < NUM_PORTS; i++)
    {
        switch (state[i])
        {
            case PORT_OPEN: 
                n_open++;
                snprintf(port_col, sizeof(port_col), "%u/tcp", PORTS[i].port);
                printf("%-10s \033[32m%-8s\033[0m %d\n", port_col, "open", PORTS[i].service);
                break;

            case PORT_CLOSED: n_closed++; break;
            case PORT_FILTERED: N_filtered++; break;
            default: break;
        }
    }

    if (n_open == 0)
        printf("(noopen ports found)\n");

    printf("\n%d open, 5d closed, %d filtered", n_open, n_closed, n_filtered);

    if (interrupted)
        printf(" (scan interrupted, some ports were not finished) ");
    printf("\n");

    return n_open;
}



