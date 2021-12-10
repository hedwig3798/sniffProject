#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
//디렉토리 생성 라이브러리
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
//시스템 관련 헤더
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/ip_icmp.h>
#include "dns.h"

#define BUFFER_SIZE 65536
#define PATH_MAX 512

#define ICMP 1
#define TCP 6
#define UDP 17
#define DNS 53
#define HTTP 80

typedef struct http_header{
	unsigned char http_first[3000];
}http_header;

int rawsocket;
int packet_num = 0;
int remaining_data = 0;
int max_file;
FILE *log_file;
FILE *log_file_dir;
FILE *read_file = NULL;
char filter[80];
char filter2[80]; // source ip
char filter3[80]; // dest ip
char file_token[4][40];
char file_list[10000][100];


struct sockaddr_in source, dest;
struct sigaction act;
struct http_header *hh;

int packet_handler(void);
int packet_analyze(char *filter);
int packet_list();


void close_handler(void){
	printf("\n=====Pcap End=====\n");

//	fclose(log_file);
	close(rawsocket);
}

void print_ethernet_header(struct ethhdr *eth, FILE *fp);
void print_ip_header(struct iphdr * i_header, FILE *fp);
void print_icmp_header(struct icmp * icmp_header, struct ih_idseq *ih_idseq, FILE * fp);
void print_tcp_header(struct tcphdr * tcp_header, FILE * fp);
void print_udp_header(struct udphdr * udp_header, FILE * fp);
void print_data(unsigned char *data, int rest_data, FILE * fp);

void print_menu();
void tokenizer(char str[1024]);

void make_logdir();
void delete_logdir();
void get_logdir();
int rmdirs(const char *path, int force);
int list_view(char *filters);


int associate_file(int ch, int flag){


	if(0 <= ch && ch <= packet_num){
		tokenizer(file_list[ch]);
		printf("연관 필터 적용 : %s \n", file_token[1]);
		strcpy(filter2 ,file_token[1]);
		}
	else{
		printf("입력값 재확인  \n");
	}
}


int file_select(const struct dirent *entry)
{
	char temp_filter[80] = "";
	strcpy(temp_filter, entry->d_name);

	if(strstr(temp_filter, filter) && (strstr(temp_filter, filter2)))
	{
		return 1;
	}
	else{
		return 0;
	}
}

void file_read(int ch)
{
	read_file = NULL;
	char dir_path[120] = "./logdir/";
	char path[120]; 
	strcpy(path, file_list[ch]);
	strcat(dir_path, path);

	read_file = fopen(dir_path,"r");
	printf("입력 확인 %d \n", ch);
	printf("실행 파일  %s \n", dir_path);

	if(read_file != NULL)
	{
		char strTemp[4096];
		char *pStr;

		while( !feof(read_file))
		{
			pStr = fgets(strTemp, sizeof(strTemp), read_file);
			printf("%s", strTemp);
		}
		fclose(read_file);
	}
	else
	{
		printf("read_file Error \n");
	}

}

void packetSelect(){
	int input = 0;
	printf("분석할  패킷의 프레임 번호 : ");
	scanf(" %d", &input);
	getchar();

	if(input > packet_num || input < 0){
		printf("잘못된 입력 \n");
		return;
	}

	file_read(input);
}

int main(int argc, char *argv[])
{
	int input, end_flag = 0;
	socklen_t len;

	while(!end_flag){

		print_menu();
		printf("\ninput : ");
		scanf("%d", &input);
		int count = 0;
	
		switch(input){
			case 1:
				packet_handler();
				break;
			case 2:

				packet_analyze("");
				list_view("");
				break;
			case 3: 
				packetSelect();
				break;
			case 4: 
				printf("\nfilter input : ");
				scanf("%s", filter);
				printf("filter set...\n");
				break;
			case 5: 
				printf("연관 프레임 번호를 입력하세요 : ");
				scanf(" %d", &input);
				getchar();

				associate_file(input, 0);
				break;
			case 6: 
				strcpy(filter,"");
				strcpy(filter2,"");
				printf("filter reset...\n");
				break;
			case 7: 
				delete_logdir();
				exit(1);
				break;
			default:
				printf("Check your input\n");
				break;
		}

	}

	return 0;
}


void make_logdir()
{
	char path[] = {"./logdir"};
	mkdir(path, 0755);
}


void delete_logdir()
{
	char path[] = {"./logdir"};
	int result = rmdirs(path, 1);

	if(result == -1){
		printf("delete_logdir Error\n");
	}
}


int rmdirs(const char *path, int force)
{
	DIR * dir_ptr = NULL;
	struct dirent *file = NULL;
	struct stat buf;
	char filename[1024];


	if((dir_ptr = opendir(path)) == NULL){
		return unlink(path);
	}


	while((file = readdir(dir_ptr))!=NULL){

		if(strcmp(file->d_name,".")==0 || strcmp(file->d_name,"..")==0){
			continue;
		}


		sprintf(filename, "%s/%s", path, file->d_name);


		if(lstat(filename,&buf)==-1){
			continue;
		}


		if(S_ISDIR(buf.st_mode)){

			if(rmdirs(filename, force) == -1 && !force){
				return -1;
			}
		}

		else if(S_ISREG(buf.st_mode) || S_ISLNK(buf.st_mode)){
			if(unlink(filename)==-1&&!force){
				return -1;
			}
			printf("파일삭제 %s \n", file->d_name);
		}
	}

	closedir(dir_ptr);
	return rmdir(path);
}


void get_logdir()
{
	log_file_dir = fopen("logdir_list.txt", "w");
    	DIR *dir = opendir("logdir");
    	if(dir == NULL)
    	{
        	printf("failed open\n");
    	}
 
    	struct dirent *de=NULL;
 
    	while((de = readdir(dir))!=NULL)
    	{

        	fprintf(log_file_dir, "%s\n",de->d_name);
    	}
    	closedir(dir);
	fclose(log_file_dir);
} 

int packet_handler(){
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

int packet_analyze(char *filters){
	struct dirent **namelist;
	int plus = 0;
	int count = 0;
	int idx;

	const char *path = "./logdir";

	// NULL 로 변경, 얜 전체 다 매핑 시키는 용도로 쓸 꺼다. 
	if((count = scandir(path, &namelist, NULL, alphasort)) == -1){
		fprintf(stderr, "%s direntory scan error\n", path);
		return -1;
	}

	// .이나 ..을 계산에서 제외시키기 위함이다.
	if(strcmp(filter,"")==0 && strcmp(filter2,"")==0){
		plus = 2;
	}
	else{
		plus = 2;
	}

	for(idx = plus; idx < count; idx++){
		//파일의 이름 출력
		//printf("%s\n", namelist[idx]->d_name);
		strcpy(file_list[idx - plus], namelist[idx]->d_name);
	}

	printf("반환된 count : %d\n", count);

	//file_list에 데이터 저장, 디버깅 완료

	for(idx = 0; idx < count; idx++){
		free(namelist[idx]);
	}

	free(namelist);

	return 0;

}

int list_view(char *filters){
	struct dirent **namelist;
	int plus = 0;
	int count = 0;
	int idx;

	const char *path = "./logdir";

	printf("Filter : %s // %s  \n", filter, filter2);	

	if((count = scandir(path, &namelist, file_select, alphasort)) == -1){
		fprintf(stderr, "%s direntory scan error\n", path);
		return -1;
	}

	// .이나 ..을 계산에서 제외시키기 위함이다.
	if(strcmp(filter,"")==0 && strcmp(filter2,"")==0){
		plus = 2;
	}


	for(idx = plus; idx < count; idx++){
		//파일의 이름 출력
		printf("%s\n", namelist[idx]->d_name);
	}

	printf("반환된 count : %d\n", count);

	//file_list에 데이터 저장, 디버깅 완료

	for(idx = 0; idx < count; idx++){
		free(namelist[idx]);
	}

	free(namelist);

	return count;

}


void print_menu(){
	printf("\n=====Program Menu=====\n");
	printf("1.Capture Start \n");
	printf("2.List View \n");
	printf("3.Select Packet\n");
	printf("4.set Filter \n");
	printf("5.set associate Filter \n");
	printf("6.reset Filter \n");
	printf("7.exit \n");
}

void tokenizer(char str[1024]){
	char temp[1024];
	char *ptr;
	int i = 0;

	strcpy(temp, str);
	ptr = strtok(temp, "_");
	
	while(ptr != NULL){
		strcpy(file_token[i], ptr);
		i++;
		ptr = strtok(NULL, "_");
	}
}
