
#include "udp_packet.h"
#include <time.h>
#include "../util.h"
#include "../md5.h"
#include "encrypt.h"
#include <string.h>


#ifndef DEBUG
#define DEBUG 0
#endif
	

#define TCP 0
#define UDP 1

int rand_range(int min_n, int max_n) {
    return rand() % (max_n - min_n + 1) + min_n;
}

void lower(char *str1) {
	while(*str1!='\0') {
		if(*str1<91&&*str1>64)
			*str1=*str1+32;
		str1++;                                                        
	}
}

int main(int argc, char *argv[]) {

	srand(time(NULL));

	if (argc != 6) {
		printf("Usage : %s username ip ip_requested port_requested tcp/udp\n", argv[0]);
		printf("example : %s toto 127.0.0.1 192.168.1.1 22 tcp\n", argv[0]);
		return 0;
	}

	char key[] = "fabien brillant";

	char *username = argv[1];
	char *ip_addr_str = argv[2];
	char *ip_requested = argv[3];
	int port_requested = atoi(argv[4]);
	char *protocol_requested_str = argv[5];
	lower(protocol_requested_str);
	int protocol_requested;

	if (strcmp(protocol_requested_str, "tcp") == 0)
		protocol_requested = TCP;
	else if (strcmp(protocol_requested_str, "udp") == 0)
		protocol_requested = UDP;

	int dest_port = rand_range(1, 49151);

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat(spa.username, username);

	spa.timestamp = (int)time(NULL);

	struct in_addr inp;

	inet_aton("127.0.0.1", &inp);
	spa.ip_src = (int)inp.s_addr; // Must be dynamic

  	inet_aton(ip_requested, &inp);
	spa.ip_dst = (int)inp.s_addr;

	spa.port = port_requested;
	spa.protocol = protocol_requested;


	int payload_len = sizeof(struct aes_data_t) - sizeof(char) * 32;
	char payload[payload_len];
	memset(payload, '\0', payload_len);
	memcpy(payload, &spa, payload_len);

	memset(spa.md5sum, '\0', sizeof(spa.md5sum));
	md5_hash_from_string(payload, spa.md5sum);

	char *cipher_text = encrypt(key, (char*)&spa, sizeof(struct aes_data_t));

	send_udp_packet(ip_addr_str, dest_port, cipher_text);

	return 0;
}