#include "util.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

inline void conv_ip_int_to_str(int ip, char* str){

  memset(str, '\0', 16);
  
  sprintf(str, "%d.%d.%d.%d",
	  ip & 0xFF,
	  ip >> 8 & 0xFF,
	  ip >> 16 & 0xFF,
	  ip >> 24 & 0xFF);
}

inline void conv_ip_str_to_int(int* ip, char* str){

  struct in_addr inp;
  inet_aton(str, &inp);
  *ip = (int)inp.s_addr;

};
