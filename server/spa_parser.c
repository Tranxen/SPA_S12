#include "../common.h"
#include "../md5.h"
#include "spa_parser.h"
#include "decrypt.h"
#include "antireplay.h"
#include "secret.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define OPTD_IP_CHECK 0x1
#define OPTD_SIZE_CHECK 0x2
#define OPTD_MD5_CHECK 0x4
#define OPTD_REPLAY_CHECK 0x8
#define OPTD_USELESS_2 0x10

#define OPT_DEBUG (0x1 | 0x4 | 0x8) //FAUT PAS OUBLIER LES ()

char* IPCLIENT ="182.168.2.2";
typedef struct {
  char proto[4];
  char IPserveur[33];
  char IPclient[33];
  int dport;
  char md5sum[32];
  uint16_t opentime;
} args_iptables_struct;


static struct aes_data_t* _spa = NULL;

void *changeiptables(void* args)
{
  args_iptables_struct *argums = args;

  char regle[1000];

  sprintf(regle, "iptables -A FORWARD -p %s -d %s -s %s --dport %d -m state --state NEW -j ACCEPT",
      argums->proto, argums->IPserveur, argums->IPclient, argums->dport);
  system(regle);

  // entre 1 et 180 sec
  if(argums->opentime > 0 && argums->opentime < 180)
    sleep(argums->opentime);
  else  
    sleep(30);
  
  sprintf(regle, "iptables -D FORWARD -p %s -d %s -s %s --dport %d -m state --state NEW -j ACCEPT",
   argums->proto, argums->IPserveur, argums->IPclient, argums->dport);
  system(regle);

  del_check_4_replay(argums->md5sum);

  free(argums);
  
}


void spa_init(){

  clientry_read("test.fdp");

}

int spa_parser(char* data, int size, int pkt_ip_src){

  printf("\nOPT_DEBUG = %x\n", OPT_DEBUG);

  //  if(size != sizeof(struct aes_data_t)){
  //printf("ERREUR : taille du paquet SPA non valide\n");
    printf("\t - %d instead of %d\n", size, sizeof(struct aes_data_t));
    //}

  
  // =========== CODE RELOU ================

  char str_ip0[16]; memset(str_ip0, '\0', 16);
  conv_ip_int_to_str(pkt_ip_src, str_ip0);
  
  int counter = clientry_get_counter(str_ip0);

  if(counter < 0){
    printf("Erreur : impossible de trouver une correspondance pour cette ip (%s)\n", str_ip0);
    return -1;    
  }

  char hotp_res[9]; //8 digits + \0
  memset(hotp_res, '\0', 9);

  char seed[16];
  clientry_get_seed(seed, str_ip0);

  char stupid[128];
    
  hotp(seed, strlen(seed), counter, 8, stupid, hotp_res, 9);
  // appel de la fonction hotp pour obtenir hotp_res

  printf("NEW KEY : %s\n", hotp_res);


  /*fwrite(data, sizeof(char), 96,
	 stdout);
  */
  
  char* decrypted_spa = decrypt(hotp_res,
				data,
				96);
				
  // =======================================
  
  int ii = 0;
  printf("====>non cripte:\n");
  for(ii = 0; ii < sizeof(struct aes_data_t); ii++){
    
    printf("%d : %x\n", ii, decrypted_spa[ii]);
    
  }
  printf("\n\n");
  

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
  printf("opentime : %d\n", _spa->opentime);
  printf("random : %s\n", _spa->random);

  const int md5less = sizeof(struct aes_data_t) - sizeof(uint8_t) * 32;

  char tosum[md5less];
  char verify_md5[32];

  memset(tosum, '\0', md5less);
  memset(verify_md5, '\0', 32);
  
  memcpy(tosum, decrypted_spa, md5less);

  printf("++++++++++++++++++\n");
  ii = 0;
  for(ii = 0; ii < md5less; ii++){
    printf("%d : %c\n", ii, tosum[ii]);
  }
  
  md5_hash_from_string(decrypted_spa, md5less, verify_md5);

  // SI PAQUET INVALIDE => TEJ ICI !

  if(OPT_DEBUG & OPTD_MD5_CHECK){
    printf("md5sum(recv) : %s\n", _spa->md5sum);
    printf("from (%d) =>\n", md5less);

    fflush(stdout);
    fwrite(decrypted_spa, sizeof(char), md5less, stdout);
    fflush(stdout);
    
    printf("\n\nmd5sum(calc) : %s\n", verify_md5);
    if(strncmp(_spa->md5sum, verify_md5, 32) == 0){
      printf("MD5 CORRECTE\n");

      int current_time = (int)time(NULL);

      if(abs(current_time - _spa->timestamp) > 240){
	printf("date pérminée\n");
	return -1;
      }

      if(add_check_4_replay(_spa->md5sum) == -1){
	return -1;
      }

      // APPEL DU CODE DE 20/100

    }
    else{
      printf("MD5 INCORRECTE\n");
      for (i = 0; i < md5less; i++){
  printf("%c - %c : %s\n", _spa->md5sum[i], verify_md5[i], (_spa->md5sum[i] == verify_md5[i]) ? "[OK]" : "[ER]");
      }

    }
  }

  clientry_inc_counter(str_ip0); // si tout va bien on incrémente le compteur
 
  pthread_t threadIptables;
  args_iptables_struct *args = malloc(sizeof *args);
  //args->proto =  ? "TCP" : "UDP";
  if (_spa->protocol == 0)
  strcpy(args->proto, "TCP");
  else
  strcpy(args->proto, "UDP");

  //args->IPserveur = str_ip;
  //printf("HERE : %s\n", ip_dest_server);
  conv_ip_int_to_str(_spa->ip_dst, args->IPserveur);
  //strcpy(args->IPserveur, ip_dest_server);
  //args->IPserveur = ip_dest_server;
  //strcpy(args->IPclient, IPCLIENT);
  conv_ip_int_to_str(_spa->ip_src, args->IPclient);
  //args->IPclient = IPCLIENT;
  args->dport = _spa->port;

  args->opentime = _spa->opentime;
  
  pthread_create (& threadIptables, NULL, changeiptables, args);


  return 0;

}
