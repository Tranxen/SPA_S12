#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "counter.h"


void load(const char* file, struct client_entry_t* client) {

    FILE* fd = fopen(file, "r");

    if (!fd){
        printf("Cannot open %s\n", file);
        exit(-1);
    }

    char seed[16] = {0};
    memset(seed, '\0', 16);
    int counter = 0;

    if (fscanf(fd, "%s / %d\n", seed, &counter) == 2) {
        strcpy(client->seed, seed);
        client->counter = counter;
    } else {
       printf("Wrong format\n");
       exit(-1);
    }

    fclose(fd);
}

void update_counter(const char* file, struct client_entry_t client) {
    //TOOD

  FILE* fd = fopen(file, "w+");

  if(!fd){printf("??\n");exit(-1);}
  
  fprintf(fd, "%s / %d\n", client.seed, ++client.counter);

  fclose(fd);
  
}
