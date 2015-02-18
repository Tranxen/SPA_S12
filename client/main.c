// include de common.h
#include "udp_packet.h"
#include <time.h>
#include "../util.h"
#include "../md5.h"

// struct aes_data_t{

//   char username[16];
//   unsigned int timestamp;
//   unsigned int ip_src;
//   unsigned int ip_dest;
//   unsigned short port;
//   char protocol;
//   char md5sum[32];

// };

#ifndef DEBUG
#define DEBUG 0
#endif
	

#define TCP 0
#define UDP 1

int main() {
	char ip_addr_str[] = "127.0.0.1";
	char dest_port_str[] = "7777";

	//char payload[] = "SPACOOOLL";

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat(spa.username, "Superman");

	spa.timestamp = (int)time(NULL);

	struct in_addr inp;

	inet_aton("127.0.0.1", &inp);
	spa.ip_src = (int)inp.s_addr;

  	inet_aton("127.0.0.1", &inp);
	spa.ip_dest = (int)inp.s_addr;

	spa.port = 22;
	spa.protocol = TCP;


	int payload_len = sizeof(struct aes_data_t) - sizeof(char) * 32;
	char *str_buff = NULL;
	str_buff = malloc(payload_len);
	memcpy(str_buff, &spa, payload_len);
	memset(spa.md5sum, '\0', 32);
	md5_hash_from_string(str_buff, spa.md5sum);

	if (DEBUG) {
		printf(">>> %s\n", str_buff);
		printf(">>> %s\n", spa.md5sum);
	}

	int len = sizeof(struct aes_data_t);
	char *buffer = NULL;
	buffer = malloc(len);
	memcpy(buffer, &spa, len);

	if (DEBUG) {
		int i;
		for(i = 0; i < len; i++){
		    printf("%x:", buffer[i]);
		}
		printf("\n%d\n", i);
	}

	send_udp_packet(ip_addr_str, dest_port_str, buffer);

	free(buffer);


	return 0;
}