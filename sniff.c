#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#define BUF_SIZE 65536

int rawsocket = 0;

int menu(); // menu function
int packet_chaptuer();


int main () {
	packet_chaptuer();
}



int menu() {
	int choosen = 0;
	printf("Choose options");
	printf("----------------");
	printf(" 1. start capture");
	printf(" 2. setting filter");
	scanf(" >>> %d", &choosen);
	return choosen;
} 

int packet_chaptuer(){
	struct sockaddr addr;
	int addrLen = sizeof(addr);
	int buf_len = 0;
	unsigned char* buf = (unsigned char*) malloc(BUF_SIZE);

	rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (rawsocket < 0){
		printf("end chahptuer: sock open error\n");
		return -1;
	}
	while(1){
		buf_len = recvfrom(rawsocket, buf, 65536, 0, &addr, (socklen_t *)&addrLen);
		if (buf_len < 0){
	
			printf("end chaptuer: recvfrom error");
			return -1;
		}
		buf[buf_len] = 0;

		printf(buf);
		printf("\n");
		printf("catch\n");
	}
	
}

