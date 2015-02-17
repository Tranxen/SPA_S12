#include "../common.h"
#include "spa_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

char* IPCLIENT ="182.168.2.2";
typedef struct {
  char* proto;
  char* IPserveur;
  char* IPclient;
  int dport;
} args_iptables_struct;


static struct aes_data_t* _spa = NULL;

void *changeiptables(void* args)
{
  args_iptables_struct *argums = args;
  char * regle;
  sprintf(regle, "iptables -A FORWARD -p %s -d %s -s %s -dport %s -m state --state NEW -j ACCEPT", argums->proto, argums->IPserveur, argums->IPclient, argums->dport);
  system(regle);

  sleep(30);
  sprintf(regle, "iptables -D FORWARD -p %s -d %s -s %s -dport %s -m state --state NEW -j ACCEPT", argums->proto, argums->IPserveur, argums->IPclient, argums->dport);
  system(regle);
}


void spa_init(){

  _spa = malloc(sizeof(struct aes_data_t));

}

int spa_parser(char* data, int size){

  if(size != sizeof(struct aes_data_t)){
    printf("ERREUR : taille du paquet SPA non valide\n");
    printf("\t - %d instead of %d\n", size, sizeof(struct aes_data_t));
    return -1;
  }
  
  /*  if(_spa == NULL)
    spa_init();
  */
  
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

  /*
  pthread_t threadIptables;
  args_iptables_struct*args = malloc(sizeof *args);
  args->proto = (_spa->protocol == 0) ? "TCP" : "UDP";
  args->IPserveur = str_ip;
  args->IPclient = IPCLIENT;
  args->dport = _spa->port;

  pthread_create (& threadIptables, NULL, changeiptables, args);
  */  

  return 0;

}
