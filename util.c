
#include "util.h"
#include <string.h>
#include <stdio.h>
//#include <openssl/md5.h>

void conv_ip_int_to_str(int ip, char* str){

  memset(str, '\0', 16);
  
  sprintf(str, "%d.%d.%d.%d",
	  ip & 0xFF,
	  ip >> 8 & 0xFF,
	  ip >> 16 & 0xFF,
	  ip >> 24 & 0xFF);
}

/*
void md5_hash_from_string (char *string, char *hash)
{
  int i;
  char unsigned md5[MD5_DIGEST_LENGTH] = {0};

  MD5((const unsigned char *)string, strlen(string), md5);

  for (i=0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(hash + 2*i, "%02x", md5[i]);
  }
}

*/
