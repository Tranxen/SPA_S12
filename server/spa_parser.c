#include "../common.h"
#include "spa_parser.h"
#include <stdio.h>
#include <stdlib.h>

static struct aes_data_t* _spa = NULL;

void spa_init(){

  _spa = malloc(sizeof(struct aes_data_t));

}

int spa_parser(char* data, int size){

  if(size != sizeof(struct aes_data_t)){
    printf("ERREUR : taille du paquet SPA non valide\n");
    printf("\t - %d instead of %d\n", size, sizeof(struct aes_data_t));
    return -1;
  }
  
  if(_spa == NULL)
    spa_init();

  _spa = (struct aes_data_t*)(data);

  int i = 0;

  printf("--\n");
    
  printf("username : %s\n", _spa->username);
  printf("timestamp : %d\n", _spa->timestamp);
  char str_ip[16];

  conv_ip_int_to_str(_spa->ip, &str_ip);
  
  printf("ip : %s\n", str_ip);
  printf("port : %d\n", _spa->port);
  printf("protocol : %d (%s)\n",
	 _spa->protocol,
	 (_spa->protocol == 0) ? "TCP" : "UDP");
  printf("md5sum : %s\n", _spa->md5sum);
  	 
  return 0;

}
