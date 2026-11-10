#include <stdio.h>
#include "scanner.h"

int main(int argc, char* argv[]){
	if (argc != 2){
		fprintf(stderr, "sudo %s <host>", argv[1]);
		return 1;
	}

	long double avg = ping(argv[1]);

	if(avg < 0)
		printf ("ping failed\n");
	else 
		printf("average rtt: %.2Lf ms\n", avg);

	return avg < 0;
}
