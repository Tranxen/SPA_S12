#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "txlist.h"

static item* lst = NULL;

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

      return;
    }
  }


}

int add_check_4_replay(char* spa_md5){

  if(!lst){
    lst = (item *)malloc(sizeof(item));
    lst->next = NULL;
  }
  
  // verif

  item * curr;
  curr = lst->next;

  while(curr) {

    if(strncmp(spa_md5, curr->data, 32) == 0){
      printf("HASH déjà existant => REJEU !!!\n");
      return -1;
    }
    
    curr = curr->next ;
  }

  // add
  printf("add\n");
  list_add(lst, spa_md5);

  return 0;
}

/*
int main(int argc, char** argv){

  printf("lol\n");

  add_check_4_replay("fabienbgfabienbgfabienbgfabienba");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbb");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbc");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbd");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbe");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbf");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbg");

  if(!lst->next){

    printf("Eh non lol, la liste est toujours vide\n");

  }

  item * curr;
  curr = lst->next;

  while(curr) {

    write(1, curr->data, 32);
    printf("\n");

    curr = curr->next ;
  }
  
  printf("------------ test deletion -------------\n");

  //item * pp = lst;
  del_check_4_replay("fabienbgfabienbgfabienbgfabienbc");
  del_check_4_replay("fabienbgfabienbgfabienbgfabienbe");
  del_check_4_replay("fabienbgfabienbgfabienbgfabienba");
  del_check_4_replay("fabienbgfabienbgfabienbgfabienbg");
    

  printf("----------- draw ------------\n");

  curr = lst->next;
  //curr = lst;

  while(curr) {

    write(1, curr->data, 32);
    printf("\n");

    curr = curr->next ;
  }
 

}

*/
