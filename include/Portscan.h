#ifndef PORTSCAN_H
#define PORTSCAN_H

#include <signal.h>

#define SCAN_TIMEOUT_MS 1500

int scan_ports(const char* host, volatile sig_atomic_t* keep_running);

#endif
