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
#include <signal.h>
#include <sys/stat.h>
#include <netinet/ip_icmp.h>
#include <dirent.h>
#include <fcntl.h>
#define BUF_SIZE 65536

#define ICMP = 1
#define TCP = 6
#define UDP = 17
#define DNS = 53
#define HTTP = 80

char is_chap = 1;

int rawsocket = 0;
char filter_protocol[3];
char *filter_socrce_ip[4];
char *filter_dest_ip[4];
int menu(); // menu function
int packet_chaptuer();
FILE *log_fp;

struct sockaddr_in source, dest;

int main () {
	packet_chaptuer();
}



int menu() {
	int choosen = 0;
	printf("Choose options\n");
	printf("----------------\n");
	printf(" 1. start capture\n");
	printf(" 2. setting filter\n");
	printf(" 3. clear data\n");
	scanf(" >>> %d", &choosen);
	return choosen;
} 

int packet_chaptuer(){
	struct sockaddr addr;
	int addrLen = sizeof(addr);
	int buf_len = 0;
	unsigned char* buf = (unsigned char*) malloc(BUF_SIZE);
	char temp[10];
	unsigned short i_header_len = 0;
	int protocol = 0;
	int s_port = 0;
	int d_port = 0;
	char * protocol_name[10];
	int p_len = 0;
	unsigned char *data;
	int rest_data = 0;

	rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (rawsocket < 0){
		printf("end chahptuer: sock open error\n");
		return -1;
	}

	while(is_chap){

		memset(buf, 0, BUF_SIZE);
		i_header_len = 0;
		protocol = 0;
		s_port = 0;
		d_port = 0;
		p_len = 0;
		protocol_name = "";
		p_len = 0;
		buf_len = recvfrom(rawsocket, buf, 65536, 0, &addr, (socklen_t *)&addrLen);
		if (buf_len < 0){
	
			printf("end chaptuer: recvfrom error");
			return -1;
		}
		buf[buf_len] = 0;
		
		// link header remove
		struct ethhdr *e_header = (struct ethhdr)(buf);
		
		// ip header remove
		struct iphdr *i_header = (struct iphdr*)(buf + sizeof(struct ethhdr));
		i_header_len = i_header->ihl * 4;
		memset(&source, 0, sizeof(source));
		memset(&dest, 0, sizeof(dest));
		source.sin_addr.s_addr = i_header->saddr;
		dest.sin_addr.s_addr = i_header->daddr;
		protocol = (unsigned int)ip->protocol;
		data = (buf + i_header_len + sizeof(struct ethhdr));
		rest_data = buf_len - (i_header_len + sizeof(struct ethhdr));
		
		switch (protocol){
		
			case ICMP:
				struct icmp *icmp = (struct icmp*)(buf + sizeof(struct ethhdr) + i_header_len);
				struct ih_idseq *ih_idseq = (struct ih_idseq*)(buf + i_header_len + sizeof(struct ethhdr) + i_header_len);
				strcpy(protocol_name, "ICPM");
				s_port = ntohs(i_header->saddr);
				d_port = ntohs(i_header->daddr);
				data = (buffer + i_header_len + sizeof(struct ethhdr) + sizeof(struct icmp));
				rest_data = buf_len - (i_header_len + sizeof(struct ethhdr) + sizeof(struct icmp));

			case TCP:
				struct tcphdr *t_header = (struct tcphdr*)(buf + sizeof(struct ethhdr) + i_header_len);
				strcpy(protocol_name, "TCP");
				s_port = ntohs(t_header->source);
				d_port = ntohs(t_header->dest);
				data = (buffer + i_header_len + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				rest_data = buf_len - (i_header_len + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			
			case UDP:
				struct tcphdr *u_header = (struct usphdr*)(buf + sizeof(struct ethhdr) + i_header_len);
				strcpy(protocol_name, "UDP");
				s_port = ntohs(u_header->source);
				d_port = ntohs(u_header->dest);
				data = (buffer + i_header_len + sizeof(struct ethhdr) + sizeof(struct udphdr));
				rest_data = buf_len - (i_header_len + sizeof(struct ethhdr) + sizeof(struct udphdr));
			
			default:
				sprintf(protocol_name, "%d", protocol);
		}
		
		mkdir("./logdir", 0755);
		
		char filename[100];
		char frame[10];
		
		// chosse packet
		if (!(
			(strcmp("HTTP", protocol_name) == 0) ||
			(strcmp("ICMP", protocol_name) == 0) ||
			(strcmp("DNS", protocol_name) == 0) ||
			(strcmp("https-tls", protocol_name) == 0)
			)){
			continue;
		}

		sprintf(filename: "./logdir/%s_%s_%s_%s.txt", frame, inet_ntoa(source.sin_addr, inet_ntoa(dest.sin_addr), protocol_name);
		
		log_fp = fopen(&filename, "w")
		
		
	}
			
}

void print_ethernet_header(struct ethhdr *eth, FILE *fp){
	fprintf(fp, "\n======== Ethernet Header ========\n");
	fprintf(fp, "S_address %.2X %.2X %.2X %.2X %.2X %.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(fp, "D_address %.2X %.2X %.2X %.2X %.2X %.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}

void print_ip_header(struct iphdr * i_header, FILE *fp){
	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));

	source.sin_addr.s_addr = i_header->saddr;
	dest.sin_addr.s_addr = i_header->daddr;

	fprintf(fp, "\n======== IP Hearder ========\n");	
	fprintf(fp, " -version: %d\n", (unsigned int)i_header->version);	
	fprintf(fp, " -ihl: %d (bytes)\n", (unsigned int)i_header->ihl);	
	fprintf(fp, " -type of service: %d\n", (unsigned int)i_header->tos);	
	fprintf(fp, " -lenght: %d\n", ntohs(i_header->tot_len));	
	fprintf(fp, " -ID: %d\n", ntohs(i_header->id));	
	fprintf(fp, " -ttl: %d\n", (unsigned int)i_header->ttl);
	fprintf(fp, " -protocol: %d\n", (unsigned int)i_header->protocol);	
	fprintf(fp, " -checksum: %d\n", (unsigned int)i_header->check);	
	fprintf(fp, " -S_IP: %s\n", inet_ntoa(source.sin_addr));	
	fprintf(fp, " -D_IP: %s\n", inet_ntoa(dest.sin_addr));
}

void print_icmp_header(struct icmp * icmp_header, struct ih_idseq *ih_idseq, FILE * fp){
	fprintf(fp, "\n======== ICMP Header ========\n");
	fprintf(fp, " -type: %d\n", (unsigned int)icmp_header->icmp_type);
	fprintf(fp, " -code: %d\n", (unsigned int)icmp_header->icmp_code);
	fprintf(fp, " -checksum: %d\n", (unsigned int)icmp_header->icmp_cksum);
	fprintf(fp, " -ID: %d\n", ih_idseq->icd_id);
	fprintf(fp, " -seq number: %d\n", ih_idseq->icd_seq);
}

void print_tcp_header(struct tcphdr * tcp_header, FILE * fp){

	fprintf(fp, "\n======== TCP Header ========\n");
	fprintf(fp, " -s_port: %d\n", ntohs(tcp_header->source));
	fprintf(fp, " -d_port: %d\n", ntohs(tcp_header->dest));
	fprintf(fp, " -seq number: %d", tcp_header->seq);
	fprintf(fp, " -ack number: %d", tcp_header->ack_seq);
}

void print_udp_header(struct udphdr * udp_header, FILE * fp){

	fprintf(fp, "\n======== UDP Header ========\n");
	fprintf(fp, " -s_port: %d\n", ntohs(udp_header->source));
	fprintf(fp, " -d_port: %d\n", ntohs(udp_header->dest));
	fprintf(fp, " -seq number: %d", udp_header->seq);
	fprintf(fp, " -ack number: %d", udp_header->ack_seq);
}

void print_data(unsigned char *data, int rest_data){

	fprintf("\n======== Data ========\n");
	
	for (int i = 1; i < rest_data; i ++){
		if (('!' < data[i]) && (data[i] < 'z')){
			fprintf(fp, "%c", data[i]);
		} else {
			fprintf(fp, "%c", '.');
		}

		if(i % 16 == 0){
			fprintf(fp, "\n");
		}
	}

	fprintf(fp, "\n");
}

