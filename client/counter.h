#ifndef SECRET_H_
#define SECRET_H_

struct client_entry_t {

  char seed[16];
  u_long counter;

};


void load(const char* file, struct client_entry_t* client);

void update_counter(const char* file, struct client_entry_t client);

#endif