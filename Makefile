CC = gcc
CFLAGES = -g -Wall
all : sniffer

sniffer : sniff.c
	$(CC) $(CFLAGES) sniff.c -o sniffer
