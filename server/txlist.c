#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include "txlist.h"

void list_add(item* lst, char* data){

  if(lst == NULL){
    printf("ERREUR : ajout impossible sur une liste NULL\n");
    exit(-1);
  }
  
  item* cell=malloc(sizeof(item));
  
  strncpy(cell->data,data,32);
  

  if(lst->next == NULL){
    cell->next = NULL;
    lst->next = cell;
  }
  else{
    
    cell->next = lst->next;
    lst->next = cell;

  }

}

void list_del(item* lst, char* data){

  item * curr;

  if(lst == NULL){
    printf("ERREUR : suppression impossible sur une liste NULL\n");
    exit(-1);
  }

  curr = lst;

  while(curr){

    if((curr->next) && strcmp(curr->next->data, data) == 0){

      item * to_del = curr->next;
      curr->next = curr->next->next;
      //curr = NULL;
      free(to_del);
      to_del = NULL;

    }
    else
      curr = curr->next;
  }

}

void list_destroy(item* lst){


  item* next;

  while(lst != NULL){
    next =lst->next;
    free(lst);
    lst=next;
  }

  printf("LIST DESTROYED\n");

}

