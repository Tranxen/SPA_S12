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
#include "../md5.h"
#include "encrypt.h"

#define BUFLEN 512

void str_part_1(char* res, struct aes_data_t* data);
void str_part_2(char* res, struct aes_data_t* data);

int main(){

  struct aes_data_t fake;

  memset(fake.username, '\0', 16);
  strcat(fake.username, "fabien");
  fake.timestamp = (int)time(NULL);
  fake.ip_src = 0;
  fake.ip_dst = 0;

  struct in_addr inp;
  
  inet_aton("127.0.0.1", &inp);
  fake.ip_src = (int)inp.s_addr;

  inet_aton("192.168.0.1", &inp);
  fake.ip_dst = (int)inp.s_addr;
  
  fake.port = 23000;
  fake.protocol = 0;
  memset(fake.md5sum, '\0', 32);
  md5_hash_from_string("bruno", fake.md5sum);

  printf("username : %s\n", fake.username);
  printf("timestamp : %d\n", fake.timestamp);
  printf("ip src: %d\n", fake.ip_src);
  printf("ip dst: %d\n", fake.ip_dst);
  printf("port : %d\n", fake.port);
  printf("protocol : %d\n", fake.protocol);
  printf("md5sum : %s\n", fake.md5sum);
  
  struct sockaddr_in si_other;
  int s, i, slen=sizeof(si_other);
  char buf[BUFLEN];
  memset(buf, '\0', 512);
  
  printf("> %d\n",
	 udp_connect("127.0.0.1", 8888, &s, &si_other));

  strcat(buf, "SPA");

  int complete_size = sizeof(struct aes_data_t)+0;
  
  memcpy(buf, &fake, sizeof(struct aes_data_t));

  //  char *buf_encrypted = encrypt("fabien brillant",
				

  for(i = 0; i < complete_size; i++){
    printf("%x:", buf[i]);
  }

  printf("\n%d\n", i);

  printf(">> %d\n",
	 sendto(s, buf, complete_size,
		0, (const struct sockaddr*)&si_other, slen));

  
  
  
  
}
