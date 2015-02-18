#include "../common.h"
#include "../md5.h"
#include "spa_parser.h"
#include "decrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define OPTD_IP_CHECK 0x1
#define OPTD_SIZE_CHECK 0x2
#define OPTD_MD5_CHECK 0x4
#define OPTD_USELESS_1 0x8
#define OPTD_USELESS_2 0x10

#define OPT_DEBUG (0x4 | 0x8) //FAUT PAS OUBLIER LES ()

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

int spa_parser(char* data, int size, int pkt_ip_src){

  printf("\nOPT_DEBUG = %x\n", OPT_DEBUG);
  
  if(size != sizeof(struct aes_data_t)){
    printf("ERREUR : taille du paquet SPA non valide\n");
    printf("\t - %d instead of %d\n", size, sizeof(struct aes_data_t));
    return -1;
  }

  char* decrypted_spa = decrypt("fabien brillant", data, sizeof(struct aes_data_t));
  
  _spa = (struct aes_data_t*)(decrypted_spa);

  printf("OPT_DEBUG : %d\n", OPT_DEBUG);
  printf("OPTD_IP : %d\n", OPTD_IP_CHECK);
  printf("RES : %d\n", 0x06 & 0x01);
  
  if((OPT_DEBUG & OPTD_IP_CHECK) != 0 &&
     _spa->ip_src != pkt_ip_src){
    printf("ERREUR : l'ip source du paquet ne correspond pas à l'ip contenu dans spa\n");
    
    return -1;
  }
  
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


  if(OPT_DEBUG & OPTD_MD5_CHECK){
    printf("md5sum : %s\n", _spa->md5sum);
    if(strncmp(_spa->md5sum, verify_md5, 32) == 0){
      printf("MD5 CORRECTE\n");

      // APPEL DU CODE DE 20/100
    
    }
    else{
      printf("MD5 INCORRECTE\n");
      for (i = 0; i < 32; i++){
	printf("%c - %c : %s\n", _spa->md5sum[i], verify_md5[i], (_spa->md5sum[i] == verify_md5[i]) ? "[OK]" : "[ER]");
      }
    
    }
  }
    
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
