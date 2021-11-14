#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>


#define BUF_SIZE 65536

int scok = 0;

int menu(); // menu function
int packet_chaptuer();


int main () {
	int choosen = 0;
	choosen = menu();
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
	int packet = 0;
	
	unsigned char* buf = (unsigned char*) malloc(BUF_SIZE);

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock < 0){
		printf("end chahptuer: sock open error\n");
		reutrn -1;
	}
	
	packet = recvfrom(sock, buf, 65536, 0, %addr, (socklen_t *)&addrLen);
	
	if (packet < 0){
		printf("end capttuer: recv error \n");
		return -1;
	}


}

