// include de common.h
#include "../common.h"
#include "udp_packet.h"
#include <time.h>
#include "../util.h"

// struct aes_data_t{

//   char username[16];
//   unsigned int timestamp;
//   unsigned int ip;
//   unsigned short port;
//   char protocol;
//   char md5sum[32];

// };

int main() {

	char ip_addr_str[] = "127.0.0.1";
	char dest_port_str[] = "7777";

	//char payload[] = "SPACOOOLL";

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat(spa.username, "Superman");

	spa.timestamp = (unsigned)time(NULL);

	spa.ip = ip_to_int("127.0.0.1");
	spa.port = 22;
	spa.protocol = '0';

	memset(spa.md5sum, '\0', 32);
	strcat(spa.md5sum, "2eqkjhcizuedjksj");

	int len = sizeof(struct aes_data_t);
	char *buffer = NULL;
	buffer = malloc(len);
	memcpy(buffer, &spa, len);

	send_udp_packet(ip_addr_str, dest_port_str, buffer);

	free(buffer);


	return 0;
}