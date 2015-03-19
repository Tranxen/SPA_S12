#include "network_util.h"
#include <time.h>
#include "../util.h"
#include "../md5.h"
#include "encrypt.h"
#include <string.h>
#include "counter.h"
#include "../server/secret.h"

#define APP_PORT 7777

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
    printf("Usage : %s username ip ip_requested port_requested tcp/udp [-d delay] [-i interface]\n", argv[0]);
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
  int delay;

  int c;

  while ((c = getopt (argc, argv, "i:d:")) != -1) {
    switch (c) {
    case 'i':
      interface = optarg;
      break;
    case 'd':
      delay = atoi(optarg);
      break;
    case '?':
      if (optopt == 'i')
	   fprintf (stderr, "Option -%c requires an argument.\n", optopt);
      else if (optopt == 'd')
        fprintf (stderr, "Option -%c requires an argument.\n", optopt);
      else if (isprint (optopt))
	fprintf (stderr, "Unknown option `-%c'.\n", optopt);
      else
	fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
    }
  }


  if (strcmp(protocol_requested_str, "tcp") == 0)
    protocol_requested = TCP;
  else if (strcmp(protocol_requested_str, "udp") == 0)
    protocol_requested = UDP;

  int dest_port = APP_PORT;//rand_range(1, 49151);

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

  spa.opentime = delay;

  rand_string((char*)spa.random, 16);

  printf("RANDOM = %s\n", spa.random);

  int payload_len = sizeof(struct aes_data_t) - sizeof(char) * 32;
  char payload[payload_len];
  memset(payload, '\0', payload_len);
  memcpy(payload, &spa, payload_len);

  memset(spa.md5sum, '\0', sizeof(spa.md5sum));
  md5_hash_from_string(payload, payload_len, (char*)spa.md5sum);

  printf("from (%d)=>\n", payload_len);
  fflush(stdout);
  fwrite(payload, sizeof(char), payload_len, stdout);
  fflush(stdout);
  printf("\n\nmd5(client) = %s\n", (char*)spa.md5sum);

  // Load seed and counter for user
  printf("Loading client seed and counter\n");
  char file[] = "client.secret";
  struct client_entry_t client;
  load(file, &client);
  printf("Seed : %s\n", client.seed);
  printf("Counter : %d\n", (int)client.counter);

  char buff[128];
  char OTP[9] = {0}; // 8digis + \0

  hotp(client.seed, strlen(client.seed), client.counter, 8, buff, OTP, 9);

  printf("HOTP = %s\n", OTP);

  int ii=0;

  printf("====>non cripte:\n");

  char fabtest22[sizeof(struct aes_data_t)];

  memcpy(fabtest22, (char*)&spa, sizeof(struct aes_data_t));

  for(ii = 0; ii < sizeof(struct aes_data_t); ii++){

      printf("%d : %x\n", ii, fabtest22[ii]);

  }

  char *cipher_text = encrypt(OTP, (char*)&spa, sizeof(struct aes_data_t));

  char fabtest[255];

  memset(fabtest, '\0', 255);

  //strncat(fabtest, cipher_text, 255);



  /*
  printf("====>data:\n");
  for(ii = 0; ii < 96; ii++){

    printf("%d : %x\n", ii, cipher_text[ii]);

  }
  */

  //printf("\n\n");


  /*  fwrite(cipher_text,
	 sizeof(char), 96,
	 stdout);
  */


  send_udp_packet(interface, ip_addr_str, dest_port, cipher_text);

  update_counter(file, client);

  return 0;
}
