#include <stdio.h>
#include <signal.h>

#include "scanner.h"
#include "Portscan.h"

extern volatile sig_atomic_t pingLoop;


int main(int argc, char* argv[]){
	if (argc != 2){
		fprintf(stderr, "Usage: %s <hostname or IPV4 address>\n", argv[0]); 
		return 1;
	}

	char* host = argv[1];
	
	printf("=== step 1: ping %s (press ctrl+c to stop pinging and start the port scan) ===\n\n", host);

	long double avg_rtt = ping(host);

	if (avg_rtt < 0)
		printf("\nNo ping replies. The host may be down or blocking ICMP, scanning anyway.\n");
	else
		printf("\nAverage RTT: %.2Lf ms\n", avg_rtt);

	pingLoop = 1;

	printf("\n=== step 2: port scan ===\n");

	int open_ports = scan_ports(host, &pingLoop);


	return open_ports < 0 ? 1 : 0;
}
