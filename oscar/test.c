#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "udp_sock.h"

#define BUFLEN 512

void str_part_1(char* res, struct aes_data_t* data);
void str_part_2(char* res, struct aes_data_t* data);

void main(){

  struct aes_data_t fake;

  memset(fake.username, '\0', 16);
  strcat(fake.username, "fabien");
  fake.timestamp = (int)time(NULL);
  fake.ip = 0;

  struct in_addr inp;
  
  inet_aton("192.168.0.1", &inp);
  fake.ip = (int)inp.s_addr;
  fake.port = 23000;
  fake.protocol = 0;
  memset(fake.md5sum, '\0', 32);

  printf("username : %s\n", fake.username);
  printf("timestamp : %d\n", fake.timestamp);
  printf("ip : %d\n", fake.ip);
  printf("port : %d\n", fake.port);
  printf("protocol : %d\n", fake.protocol);

  struct sockaddr_in si_other;
  int s, i, slen=sizeof(si_other);
  char buf[BUFLEN];
  memset(buf, '\0', 512);
  
  printf("> %d\n",
	 udp_connect("127.0.0.1", 8888, &s, &si_other));

  strcat(buf, "SPA");

  int complete_size = sizeof(struct aes_data_t)+0;
  
  memcpy(buf, &fake, sizeof(struct aes_data_t));
  for(i = 0; i < complete_size; i++){
    printf("%x:", buf[i]);
  }

  printf("\n%d\n", i);

  printf(">> %d\n",
	 sendto(s, buf, complete_size,
		0, (const struct sockaddr*)&si_other, slen));

  
  
  
  
}
