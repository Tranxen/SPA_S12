

struct client_entry_t{

  char ip[16];
  char seed[16];
  u_long counter;

};


void clientry_read(const char* file);

int clientry_get_counter(char* userip);

void clientry_inc_counter(char* userip);

