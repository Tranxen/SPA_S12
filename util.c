
#include "util.h"
#include <string.h>
#include <stdio.h>

void conv_ip_int_to_str(int ip, char* str){

  memset(str, '\0', 16);
  
  sprintf(str, "%d.%d.%d.%d",
	  ip & 0xFF,
	  ip >> 8 & 0xFF,
	  ip >> 16 & 0xFF,
	  ip >> 24 & 0xFF);
}
