// include de common.h
#include "udp_packet.h"
#include <time.h>
#include "../util.h"
#include "../md5.h"

// struct aes_data_t{

//   char username[16];
//   unsigned int timestamp;
//   unsigned int ip;
//   unsigned short port;
//   char protocol;
//   char md5sum[32];

// };
int main() {


	char input[] = "Coucou";
	char output[2*MD5_DIGEST_LENGTH+1];
	md5_hash_from_string(input, output);
    printf("%s\n", output);

	return 0;

	char ip_addr_str[] = "127.0.0.1";
	char dest_port_str[] = "7777";

	//char payload[] = "SPACOOOLL";

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat(spa.username, "Superman");

	spa.timestamp = (int)time(NULL);

	struct in_addr inp;
  	inet_aton("127.0.0.1", &inp);
	spa.ip = (int)inp.s_addr;
	spa.port = 22;
	spa.protocol = 0;

	memset(spa.md5sum, '\0', 32);
	strcat(spa.md5sum, "2eqkjhcizuedjksj");

	int len = sizeof(struct aes_data_t);
	char *buffer = NULL;
	buffer = malloc(len);
	memcpy(buffer, &spa, len);
int i;
for(i = 0; i < len; i++){
    printf("%x:", buffer[i]);
}

printf("\n%d\n", i);

	send_udp_packet(ip_addr_str, dest_port_str, buffer);

	free(buffer);


	return 0;
}