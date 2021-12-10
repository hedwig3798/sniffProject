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
#include <linux/if_ether.h>
#include <sys/stat.h>
#include <dirent.h>

#define BUF_SIZE 65536

#define ICMP 1
#define TCP 6
#define UDP 17
#define DNS 53
#define HTTP 80
#define HTTPS 443
void print_ethernet_header(struct ethhdr *eth, FILE *fp);
void print_ip_header(struct iphdr * i_header, FILE *fp);
void print_icmp_header(struct icmp * icmp_header, struct ih_idseq *ih_idseq, FILE * fp);
void print_tcp_header(struct tcphdr * tcp_header, FILE * fp);
void print_udp_header(struct udphdr * udp_header, FILE * fp);
void print_data(unsigned char *data, int rest_data, FILE * fp);

void reset_log_data();

void tokenizer(char * str);

void end_program();
void set_filter();
void search_packet();
void print_packet();
void close_handler();

char result[4][100];

char is_chap = 1;
int num_packet = 0;
int rawsocket = 0;
char filter_protocol[3];
char filter_source_ip[4];
char filter_dest_ip[4];

int menu(); // menu function
int packet_chaptuer();
FILE *log_fp;

struct sigaction act;

struct sockaddr_in source, dest;

int main () {
	int choose;

	while(1){
		choose = menu();
		printf("%d \n", choose);
		switch (choose){
			case 1:
				packet_chaptuer();
				break;

			case 2:
				set_filter();
				break;

			case 3:
				search_packet();
				break;

			case 4:
				print_packet();
				break;

			case 5:
				reset_log_data();
				break;

			case 6:
				end_program();
				return 0;
		}
	}
}



int menu() {
	int choosen = 0;
	printf("Choose options\n");
	printf("----------------\n");
	printf(" 1. start capture\n");
	printf(" 2. setting filter\n");
	printf(" 3. search packet\n");
	printf(" 4. print packet");
	printf(" 5. clear data\n");
	printf(" 6. end program\n");
	scanf("%d", &choosen);
	getchar();
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
	char protocol_name[10];
	int p_len = 0;
	unsigned char *data;
	int rest_data = 0;
	
	act.sa_handler = close_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, 0);

	rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (rawsocket < 0){
		printf("\nend chahptuer: sock open error\n");
		return -1;
	}

	while(is_chap){

		memset(buf, 0, BUF_SIZE);
		i_header_len = 0;
		protocol = 0;
		s_port = 0;
		d_port = 0;
		p_len = 0;
		strcpy(protocol_name, "");
		p_len = 0;
		buf_len = recvfrom(rawsocket, buf, 65536, 0, &addr, (socklen_t *)&addrLen);
		if (buf_len < 0){
	
			printf("\nend chaptuer: recvfrom error\n");
			return -1;
		}
		buf[buf_len] = 0;
		
		// link header remove
		struct ethhdr *e_header = (struct ethhdr *)(buf);
		// ip header remove
		struct iphdr *i_header = (struct iphdr*)(buf + sizeof(struct ethhdr));
		i_header_len = i_header->ihl * 4;
		memset(&source, 0, sizeof(source));
		memset(&dest, 0, sizeof(dest));
		source.sin_addr.s_addr = i_header->saddr;
		dest.sin_addr.s_addr = i_header->daddr;
		protocol = (unsigned int)i_header->protocol;
		data = (buf + i_header_len + sizeof(struct ethhdr));
		rest_data = buf_len - (i_header_len + sizeof(struct ethhdr));
		
		
		if (protocol == ICMP){
			struct icmp *icmp = (struct icmp*)(buf + sizeof(struct ethhdr) + i_header_len);
			struct ih_idseq *ih_idseq = (struct ih_idseq*)(buf + i_header_len + sizeof(struct ethhdr) + sizeof(struct ih_idseq));
			strcpy(protocol_name, "ICPM");
			s_port = ntohs(i_header->saddr);
			d_port = ntohs(i_header->daddr);
			data = (buf + i_header_len + sizeof(struct ethhdr) + sizeof(struct icmp));
			rest_data = buf_len - (i_header_len + sizeof(struct ethhdr) + sizeof(struct icmp));
		}
		else if(protocol == TCP){
			struct tcphdr *t_header = (struct tcphdr*)(buf + sizeof(struct ethhdr) + i_header_len);
			strcpy(protocol_name, "TCP");
			s_port = ntohs(t_header->source);
			d_port = ntohs(t_header->dest);
			data = (buf + i_header_len + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			rest_data = buf_len - (i_header_len + sizeof(struct ethhdr) + sizeof(struct tcphdr));
		}
		else if (protocol == UDP){
			struct udphdr *u_header = (struct udphdr*)(buf + sizeof(struct ethhdr) + i_header_len);
			strcpy(protocol_name, "UDP");
			s_port = ntohs(u_header->source);
			d_port = ntohs(u_header->dest);
			data = (buf + i_header_len + sizeof(struct ethhdr) + sizeof(struct udphdr));
			rest_data = buf_len - (i_header_len + sizeof(struct ethhdr) + sizeof(struct udphdr));
		}
		else{
			sprintf(protocol_name, "%d", protocol);
		}
	
		// analize HTTP, DNS. HTTPS by port
		if ((DNS == s_port) || (DNS == d_port)){
			strcpy(protocol_name, "DNS");
		}
		else if ((HTTP == s_port) || (HTTP == d_port)){
			strcpy(protocol_name, "HTTP");
		}
		else if ((HTTPS == s_port) || (HTTPS == d_port)){
			strcpy(protocol_name, "http-tls");
		}
		
		

		// if http -> dave http data
		if (strcmp(protocol_name, "HTTP") == 0){
			struct http_header* http_header = (struct http_header*)(buf + sizeof(struct ethhdr) + i_header_len + sizeof(struct tcphdr));
			int http_size = rest_data;
		}

		mkdir("./logdir", 0755);
		
		char filename[100];
		char frame[10];
		
		// chosse packet -> change after
		if (!(
			(strcmp("HTTP", protocol_name) == 0) ||
			(strcmp("ICMP", protocol_name) == 0) ||
			(strcmp("DNS", protocol_name) == 0) ||
			(strcmp("https-tls", protocol_name) == 0)
			)){
			continue;
		}

		if (num_packet < 10){
			sprintf(frame, "000%d", num_packet);
		}
		else if (10 <= num_packet && num_packet < 100){
			sprintf(frame, "00%d", num_packet);
		}
		else if (100 <= num_packet && num_packet < 1000){
			sprintf(frame, "0%d", num_packet);
		}
		else if (1000 <= num_packet && num_packet < 10000){
			sprintf(frame, "%d", num_packet);
		}
		else if (num_packet >= 10000){
			is_chap = 0;
			printf("packet save buffer id full. end chapture\n");
		}

		sprintf(filename, "./logdir/%s_%s_%s_%s.txt", frame, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), protocol_name);
		log_fp = fopen(filename, "w");
		print_ethernet_header(e_header, log_fp);
		print_ip_header(i_header, log_fp);
		

		if (protocol == ICMP){
			
			struct icmp *icmp = (struct icmp*)(buf + sizeof(struct ethhdr) + i_header_len);
			struct ih_idseq *ih_idseq = (struct ih_idseq*)(buf + i_header_len + sizeof(struct ethhdr) + sizeof(struct ih_idseq));
			print_icmp_header(icmp, ih_idseq, log_fp);
		}
		else if (protocol == TCP){
			
			struct tcphdr *t_header = (struct tcphdr*)(buf + sizeof(struct ethhdr) + i_header_len);
			print_tcp_header(t_header, log_fp);
		}
		else if (protocol == UDP){
			
			struct udphdr *u_header = (struct udphdr*)(buf + sizeof(struct ethhdr) + i_header_len);
			print_udp_header(u_header, log_fp);
		}

		print_data(data, rest_data, log_fp);
		
		
		printf("Source %s\t", inet_ntoa(source.sin_addr));
		printf("Dest %s\t", inet_ntoa(dest.sin_addr));
		printf("Protocol %s\n", protocol_name);
		
		num_packet ++;
		

		fclose(log_fp);
	}

	free(buf);
	
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
	fprintf(fp, " -UDP len: %d", udp_header->len);
	fprintf(fp, " -checksum: %d", udp_header->check);
}

void print_data(unsigned char *data, int rest_data, FILE * fp){

	fprintf(fp, "\n======== Data ========\n");
	
	for (int i = 1; i < rest_data; i ++){
		if (('!' < data[i]) && (data[i] < '~')){
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


void reset_log_data(){
	rmdir("./logdir", 1);
}


void tokenizer(char * str){
	char * temp = (char*)malloc(sizeof(str) + 1);
	char * ptr;
	int i = 0;
	strcpy(temp, str);
	
	memset(result, 0, sizeof(result));

	ptr = strtok(temp, "_");

	while (ptr != NULL){
		strcpy(result[i], ptr);
		i ++;
		ptr = strtok(NULL, "_");
	}
}

void end_program(){
	reset_log_data();
}

void init_filter(){
	strcpy(filter_source_ip, "");
	strcpy(filter_dest_ip, "");
	strcpy(filter_protocol, "");
}

void set_filter(){
	
	init_filter();

	printf("\n input source ip: ");
	scanf("%s", filter_source_ip);
	printf("\n input dest ip  : ");
	scanf("%s", filter_dest_ip);
	printf("\n input protocol : ");
	scanf("%s", filter_protocol);

	printf("\nfilter set %s, %s, %s\n", filter_source_ip, filter_dest_ip, filter_protocol);
	
}
void search_packet(){
	const char * path = "./logdir";
	DIR * direc;
	struct dirent * dir_entry;


	if (
			(strcmp(filter_source_ip, "") == 0) &&
			(strcmp(filter_dest_ip, "") == 0) &&
			(strcmp(filter_protocol, "") == 0)
		){
		printf("please set filter first\n");
	}

	direc = opendir(path);
	while(dir_entry = readdir(direc)){
		tokenizer(dir_entry->d_name);

		if((strcmp(result[1], filter_source_ip) == 0)){
			printf("%s\n", dir_entry->d_name);
		}
		else if ((strcmp(result[2], filter_dest_ip) == 0)){
			printf("%s\n", dir_entry->d_name);
		}
		else if ((strcmp(result[3], filter_protocol) == 0)){
			printf("%s\n", dir_entry->d_name);
		}
		
	}


}

void print_packet(){
	int num;
	char frame[10];


	printf("input packet number: ");
	scanf("%d", &num);

	if (num < 10){
		sprintf(frame, "000%d", num);
	}
	else if (10 <= num && num < 100){
		sprintf(frame, "00%d", num);
	}
	else if (100 <= num && num < 1000){
		sprintf(frame, "0%d", num);
	}
	else if (1000 <= num && num < 10000){
		sprintf(frame, "%d", num);
	}

	const char * path = "./logdir";
	DIR * direc;
	struct dirent * dir_entry;
	char file_name[100];
	direc = opendir(path);
	strcpy(file_name, "");
	while(dir_entry = readdir(direc)){
		tokenizer(dir_entry->d_name);

		if((strcmp(result[0], frame) == 0)){
			printf("%s\n", dir_entry->d_name);
			strcpy(file_name, dir_entry->d_name);
			break;
		}

		if (strcmp(file_name, "") == 0){
			printf("cannot find file\n");
			return;
		}
	}	

	char real_file[100];
	
	strcpy(real_file, path);

	sprintf(real_file, "%s", file_name);
				
		
	char temp[10000] = {0, };
	FILE * fp;
	fp = fopen(real_file, "r");

	fread(temp, sizeof(temp), 1, fp);

	
	fclose(fp);


}

void close_handler(){
	printf("\nChapture end\n");
	is_chap = 0;
}
