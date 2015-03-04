#ifndef DEF_TXLIST
#define DEF_TXLIST

#include<stdlib.h>
#include<stdio.h>

#define DATA_LENGTH 32

struct list_el {
  char data[DATA_LENGTH];
  struct list_el * next;
};

typedef struct list_el item;

void list_add(item* lst, char* md5);

void list_del(item* lst, char* md5);

void list_destroy(item* lst);

void list_debug(item* lst);

#endif
