#ifndef __UDP_SOCK_H__ 
#define __UDP_SOCK_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>


int udp_connect(const char* IP, int port, int* s, struct sockaddr_in* si_other);

int udp_send(int* s, const char* buf, int buflen, struct sockaddr_in* si_other, int* slen);

//void udp_send(int, 
#endif
