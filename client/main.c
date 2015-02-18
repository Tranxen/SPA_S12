
#include "udp_packet.h"
#include <time.h>
#include "../util.h"
#include "../md5.h"
#include "encrypt.h"


#ifndef DEBUG
#define DEBUG 0
#endif
	

#define TCP 0
#define UDP 1

int rand_range(int min_n, int max_n) {
    return rand() % (max_n - min_n + 1) + min_n;
}

int main(int argc, char *argv[]) {

	srand(time(NULL));


	if (argc != 2) {
		printf("Usage : %s IP\n", argv[0]);
		return 0;
	}

	char key[] = "superKey1234";

	char *ip_addr_str = argv[1];

	int dest_port = rand_range(1, 49151);

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat(spa.username, "Superman");

	spa.timestamp = (int)time(NULL);

	struct in_addr inp;

	inet_aton("127.0.0.1", &inp);
	spa.ip_src = (int)inp.s_addr;

  	inet_aton("192.168.1.77", &inp);
	spa.ip_dst = (int)inp.s_addr;

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

	char *encrypted = NULL;
	encrypted = malloc(16);
	encrypted = encrypt(key, buffer);

	if (DEBUG) {
		printf("Encrypted : \n%s\n", encrypted);
	}


	send_udp_packet(ip_addr_str, dest_port, encrypted);

	free(buffer);
	free(encrypted);


	return 0;
}