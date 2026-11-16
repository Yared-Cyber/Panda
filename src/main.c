#include <stdio.h>
#include <signal.h>

#include "scanner.h"
#include "Portscan.h"
#include "tui.h"

extern volatile sig_atomic_t pingLoop;


static void on_sigint(int sig){
	(void)sig;
	pingLoop = 0;
}




int main(int argc, char* argv[]){
	if (argc != 2){
		fprintf(stderr, "Usage: %s <hostname or IPV4 address>\n", argv[0]); 
		return 1;
	}

	char* host = argv[1];

	tui_logo();

	int mode = tui_menu(host);
	if (mode == TUI_QUIT) return 0;

	signal(SIGINT, on_sigint);

	int exit_code = 0;

	if (mode == TUI_PING || mode == TUI_BOTH){
		tui_section(mode == TUI_BOTH ? "Step 1: ping" : "Ping");

		if (mode == TUI_BOTH)
			printf("Pinging %s (press ctrl+c to stop pinging and start the port scan)\n\n", host);
		else 
			printf("Pinging %s (press ctrl+c to stop)\n\n", host);

		long double avg_rtt = ping(host);

		if (avg_rtt < 0){
			if (mode == TUI_BOTH)
				printf("\nNo ping replies. The host may be down or blocking ICMP, scanning anyway.\n");
			else {
				printf("\nNo ping replies. The host may be down or blocking ICMP.\n");
				exit_code = 1;
			}
		}
		else
			printf("\nAverage RTT: %.2Lf ms\n", avg_rtt);
	}
 
	if (mode == TUI_PORTSCAN || mode == TUI_BOTH){
		pingLoop = 1;   
 
		tui_section(mode == TUI_BOTH ? "Step 2: port scan" : "Port scan");
 
		int open_ports = scan_ports(host, &pingLoop);
		if (open_ports < 0)
			exit_code = 1;
	}
 
	return exit_code;
}
