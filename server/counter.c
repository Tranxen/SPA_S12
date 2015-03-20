#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "counter.h"

#define MAX_ENTRY 128

static struct client_entry_t clientry[MAX_ENTRY];
static int nb_entry = 0;

void clientry_read(const char* file){
  
  FILE* fdp = fopen(file, "r");
  
  if(!fdp){printf("%s not found\n", file); exit(-1);}

  char ip[16]; memset(ip, '\0', 16);
  char seed[16]; memset(seed, '\0', 16);
  int counter = 0;

  nb_entry = 0;
  
  while(fscanf(fdp, "%s / %s / %d\n", ip, seed, &counter) != EOF){
    
    memset(clientry[nb_entry].ip, '\0', 16);
    memset(clientry[nb_entry].seed, '\0', 16);
    strcat(clientry[nb_entry].ip, ip);
    strcat(clientry[nb_entry].seed, seed);
    clientry[nb_entry].counter = counter;

    nb_entry++;
    if(nb_entry > MAX_ENTRY - 1){
      printf("Nombre d'entrée trop grande\n");
      exit(-1);
    }
  }

  printf("%d entries written\n", nb_entry);

  int a = 0;

  for ( a ; a < nb_entry; a++){

    printf("%s/%s/%d\n",
	   clientry[a].ip,
	   clientry[a].seed,
	   clientry[a].counter);
	   

  }
  
  fclose(fdp);

}

int get_index_from_ip(char* ip){

  int i = 0;

  for (i ; i < nb_entry; i++){

    if(strncmp(ip, clientry[i].ip, 16) == 0)
      return i;
  }

  return -1;

}

int clientry_get_counter(char* ip){

  int a = get_index_from_ip(ip);
  if(a < 0) return -1;

  return clientry[a].counter;

}

int clientry_get_seed(char* seed, char* ip){

  memset(seed, '\0', 16);
  int a = get_index_from_ip(ip);
  if(a < 0) return -1;

  strcat(seed, clientry[a].seed);

  return 0;
}

void clientry_inc_counter(char* ip){

 int a = get_index_from_ip(ip);
 if(a < 0) {printf("exit -1\n"); exit(-1);}

 clientry[a].counter++;  

}

