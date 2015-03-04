#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "txlist.h"

static item* lst = NULL;

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

  add_check_4_replay("fabienbgfabienbgfabienbgfabienbg");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbj");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbi");
  add_check_4_replay("fabienbgfabienbgfabienbgfabienbj");

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
  

}
*/
