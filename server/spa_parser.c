#include "../common.h"
#include "../md5.h"
#include "spa_parser.h"
#include "decrypt.h"
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

  char* decrypted_spa = decrypt("fabien brillant", data, sizeof(struct aes_data_t));
  
  _spa = (struct aes_data_t*)(decrypted_spa);

  int i = 0;

  printf("--\n");
    
  printf("username : %s\n", _spa->username);
  printf("timestamp : %d\n", _spa->timestamp);
  char str_ip[16];

  conv_ip_int_to_str(_spa->ip_src, &str_ip);
  printf("ip src: %s\n", str_ip);
  conv_ip_int_to_str(_spa->ip_dst, &str_ip);
  printf("ip dest: %s\n", str_ip);
  printf("port : %d\n", _spa->port);
  printf("protocol : %d (%s)\n",
   _spa->protocol,
   (_spa->protocol == 0) ? "TCP" : "UDP");

  char tosum[32];
  char verify_md5[32];
  memcpy(tosum, decrypted_spa, 32);
  md5_hash_from_string(tosum, verify_md5);
  printf("md5sum : %s\n", _spa->md5sum);
  
  if(strcmp(_spa->md5sum, verify_md5) == 0){
    printf("MD5 CORRECTE\n");

    // APPEL DU CODE DE 20/100
    
  }
<<<<<<< HEAD
  else{
    printf("MD5 INCORRECTE\n");
  }

  for (i = 0; i < 32; i++){

    printf("%c - %c : %s\n", _spa->md5sum[i], verify_md5[i], (_spa->md5sum[i] == verify_md5[i]) ? "[OK]" : "[ER]");

  }
=======
  else printf("MD5 INCORRECTE\n");
>>>>>>> 0542f8c7f65eb727b68e386b0cb8dde2802e943b

  
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
