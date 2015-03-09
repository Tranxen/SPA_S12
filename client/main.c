#include "network_util.h"
#include <time.h>
#include "../util.h"
#include "../md5.h"
#include "encrypt.h"
#include <string.h>
#include "counter.h"
#include "../server/secret.h"


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

	if (argc < 6) {
		printf("Usage : %s username ip ip_requested port_requested tcp/udp [-i interface]\n", argv[0]);
		printf("example : %s toto 127.0.0.1 192.168.1.1 22 tcp\n", argv[0]);
		return 0;
	}


	char *username = argv[1];
	char *ip_addr_str = argv[2];
	char *ip_requested = argv[3];
	int port_requested = atoi(argv[4]);
	char *protocol_requested_str = argv[5];
	lower(protocol_requested_str);
	int protocol_requested;
	char *interface = NULL;

	int c;

	while ((c = getopt (argc, argv, "i:")) != -1) {
		switch (c) {
			case 'i':
				interface = optarg;
				break;
			case '?':
				if (optopt == 'i')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
          			fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        		else
          			fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
		}
	}

	char key[] = "fabien brillant";





	if (strcmp(protocol_requested_str, "tcp") == 0)
		protocol_requested = TCP;
	else if (strcmp(protocol_requested_str, "udp") == 0)
		protocol_requested = UDP;

	int dest_port = rand_range(1, 49151);

	struct aes_data_t spa;

	memset(spa.username, '\0', 16);
	strcat((char*)spa.username, username);

	spa.timestamp = (int)time(NULL);

	struct in_addr inp;

	inet_aton(get_ip_addr(interface), &inp);
	spa.ip_src = (int)inp.s_addr;

  	inet_aton(ip_requested, &inp);
	spa.ip_dst = (int)inp.s_addr;

	spa.port = port_requested;
	spa.protocol = protocol_requested;

	rand_string((char*)spa.random, 16);

	int payload_len = sizeof(struct aes_data_t) - sizeof(char) * 32;
	char payload[payload_len];
	memset(payload, '\0', payload_len);
	memcpy(payload, &spa, payload_len);

	memset(spa.md5sum, '\0', sizeof(spa.md5sum));
	md5_hash_from_string(payload, payload_len, (char*)spa.md5sum);


    // Load seed and counter for user
    printf("Loading client seed and counter\n");
    struct client_entry_t client;
    load("client.secret", &client);
    printf("Seed : %s\n", client.seed);
    printf("Counter : %d\n", (int)client.counter);

    char buff[128];
    char hotp_res[9] = {0}; // 8digis + \0

    hotp(client.seed, strlen(client.seed), client.counter, 8, buff, hotp_res, 9);

    printf("HOTP = %s\n", hotp_res);


	char *cipher_text = encrypt(key, (char*)&spa, sizeof(struct aes_data_t));

	send_udp_packet(interface, ip_addr_str, dest_port, cipher_text);

	return 0;
}
