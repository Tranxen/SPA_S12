
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

	char key[] = "fabien brillant";

	char *ip_addr_str = argv[1];

	int dest_port = rand_range(1, 49151);

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat(spa.username, "Supermanoooooob");

	spa.timestamp = (int)time(NULL);

	struct in_addr inp;

	inet_aton("127.0.0.1", &inp);
	spa.ip_src = (int)inp.s_addr;

  	inet_aton("192.168.1.77", &inp);
	spa.ip_dst = (int)inp.s_addr;

	spa.port = 22;
	spa.protocol = TCP;


	int payload_len = sizeof(struct aes_data_t) - sizeof(char) * 32;
	char *payload = NULL;
	payload = malloc(payload_len);

	memcpy(payload, &spa, payload_len);
	memset(spa.md5sum, '\0', payload_len);
	md5_hash_from_string(payload, spa.md5sum);

	char *cipher_text = encrypt(key, (char*)&spa, sizeof(struct aes_data_t));

	send_udp_packet(ip_addr_str, dest_port, cipher_text);

	return 0;
}