#include "util.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

// convertie une ip sous forme de int
// en ip sous forme de chaine de caractères

inline void conv_ip_int_to_str(int ip, char* str){

  memset(str, '\0', 16);
  
  sprintf(str, "%d.%d.%d.%d",
	  ip & 0xFF,
	  ip >> 8 & 0xFF,
	  ip >> 16 & 0xFF,
	  ip >> 24 & 0xFF);
}

// convertie une ip sous forme de chaine de caractères
// en ip sous forme d'un int

inline void conv_ip_str_to_int(int* ip, char* str){

  struct in_addr inp;
  inet_aton(str, &inp);
  *ip = (int)inp.s_addr;

}

//genere une chaine de caractères aléatoire

inline void rand_string(char *str, size_t size) {

  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (size) {
        --size;
        size_t n;
        for (n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
}
