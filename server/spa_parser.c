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

#define OPT_DEBUG (0x1 | 0x4 | 0x8)

#define MAX_TIME_OBSOLET 30 // en seconde
#define MAX_ENTRIES 1000

typedef struct {
  char proto[4];
  char IPserveur[33];
  char IPclient[33];
  int dport;
  char md5sum[32];
  uint16_t opentime;
} args_iptables_struct;


static struct aes_data_t* _spa = NULL;
pthread_mutex_t lock1;
pthread_mutex_t lock2;



void *changeiptables(void* args)
{
  pthread_mutex_lock(&lock1);

  args_iptables_struct *argums = args;

  char regle[MAX_ENTRIES];

  if(add_check_4_replay(argums->md5sum) == -1){
    return;
  }
  
  sprintf(regle, "iptables -A FORWARD -p %s -d %s -s %s --dport %d -m state --state NEW -j ACCEPT",
      argums->proto, argums->IPserveur, argums->IPclient, argums->dport);
  system(regle);

  pthread_mutex_unlock(&lock1);

  // entre 1 et 180 sec
  if(argums->opentime > 0 && argums->opentime < 180)
    sleep(argums->opentime);
  else  
    sleep(30);

  pthread_mutex_lock(&lock2);
  
  sprintf(regle, "iptables -D FORWARD -p %s -d %s -s %s --dport %d -m state --state NEW -j ACCEPT",
   argums->proto, argums->IPserveur, argums->IPclient, argums->dport);
  system(regle);

  del_check_4_replay(argums->md5sum);
  
  free(argums);

  pthread_mutex_unlock(&lock2);
  
}


void spa_init(){

  clientry_read("server.secret");

  if(pthread_mutex_init(&lock1, NULL) != 0)
    {
      printf("\n mutex 1 init failed\n");
      exit(-1);
    }

  
  if(pthread_mutex_init(&lock2, NULL) != 0)
    {
      printf("\n mutex 2 init failed\n");
      exit(-1);
    }

}

int spa_parser(char* data, int size, int pkt_ip_src){

  // ==============================

  // Récupération de la valeur du
  // compteur HOTP pour un client donné

  // ==============================
  
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

  // ==============================

  // appel de la fonction hotp pour
  // obtenir une nouvelle clé (hotp_res)
  // +
  // Dechiffrement du paquet SPA
  // avec la nouvelle clé
  
  // ==============================
  
  hotp(seed, strlen(seed), counter, hotp_res, 9);

  printf("NEW KEY : %s\n", hotp_res);

  // 96 correspond à la taille du packet SPA chiffré
  char* decrypted_spa = decrypt(hotp_res,
				data,
				96);
				
  // ==============================
  
  _spa = (struct aes_data_t*)(decrypted_spa);

  // ==============================

  // Vérification du MD5sum
  // md5less : taile de la structure
  // SPA sans le md5
  
  // ==============================

 
  const int md5less = sizeof(struct aes_data_t) - sizeof(uint8_t) * 32;
  char verify_md5[32];
  memset(verify_md5, '\0', 32);
  md5_hash_from_string(decrypted_spa,
		       md5less,
		       verify_md5);


  if(OPT_DEBUG & OPTD_MD5_CHECK){

    if(strncmp(_spa->md5sum, verify_md5, 32) != 0){
      printf("MD5 INCORRECTE\n");
      printf("md5sum(calc) : %s\n", verify_md5);
      printf("md5sum(recv) : %s\n", _spa->md5sum);
      free(decrypted_spa);
      return -1;
    }
    else{
      printf("MD5 CORRECTE\n");
    }
  }
 
  // ==============================

  // Vérification anti-usurpation

  // ==============================
  
  if((OPT_DEBUG & OPTD_IP_CHECK) != 0 &&
     _spa->ip_src != pkt_ip_src){
    printf("ERREUR : l'ip source du paquet ne correspond pas à l'ip contenu dans le paquet spa\n");
    // Ca va être bien avec les NATs...
    free(decrypted_spa);
    return -1;
  }

  // ==============================

  // Vérification anti-rejeu

  // ==============================

  int current_time = (int)time(NULL);

  // 30 sec : temps max authorisé entre 2 timestamp
  if(abs(current_time - _spa->timestamp) > MAX_TIME_OBSOLET){
    printf("date pérminée\n");
    free(decrypted_spa);
    return -1;
  }
  
  
  int i = 0;

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

 
  // Tout va bien, on incrémente le compteur HOTP
  clientry_inc_counter(str_ip0); 
 
  pthread_t threadIptables;
  args_iptables_struct *args = malloc(sizeof *args);

  if (_spa->protocol == 0)
    strcpy(args->proto, "TCP");
  else
    strcpy(args->proto, "UDP");
  
  conv_ip_int_to_str(_spa->ip_dst, args->IPserveur);
  conv_ip_int_to_str(_spa->ip_src, args->IPclient);
  args->dport = _spa->port;
  args->opentime = _spa->opentime;
  strncpy(args->md5sum, _spa->md5sum,32);
  
 
  pthread_create (& threadIptables, NULL, changeiptables, args);

  free(decrypted_spa);
  
  return 0;

}
