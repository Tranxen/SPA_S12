#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "txlist.h"

static item* lst = NULL;
static int list_count = 0;

#define MAX_ENTRIES 1000

// retire une entrée dans le cache (appellée
// lorsque le bail arrive à expiration)

void del_check_4_replay(char* spa_md5){

  item *currP, *prevP;

  prevP = NULL;
  
  for (currP = lst; currP != NULL; prevP = currP, currP = currP->next) {

    if (strncmp(currP->data,spa_md5, 32) == 0) { 

      if (prevP == NULL) {
	lst = currP->next;
      } else {
	prevP->next = currP->next;
      }

      free(currP);
      list_count--;
      printf("Hash : ");
      fwrite(spa_md5, sizeof(char), 32, stdout);
      printf(" expired : %d entries left\n", list_count);
      return;
    }
  }

}

// ajoute une entrée dans le cache (appellée
// lorsqu'un client a envoyé un paquet SPA valide

int add_check_4_replay(char* spa_md5){

  if(list_count > MAX_ENTRIES){

    printf("ERREUR : Trop d'ajouts dans le cache\n");
    return -1;

  }
  
  if(!lst){
    lst = (item *)malloc(sizeof(item));
    lst->next = NULL;
  }
  
  item * curr;
  curr = lst->next;

  while(curr) {

    if(strncmp(spa_md5, curr->data, 32) == 0){
      printf("ERREUR : HASH déjà existant => REJEU !!!\n");
      return -1;
    }
    
    curr = curr->next ;
  }

  list_add(lst, spa_md5);
  list_count++;

  printf("Hash : ");
  fwrite(spa_md5, sizeof(char), 32, stdout);
  printf(" added : %d entries left\n", list_count);
    
  return 0;
}

