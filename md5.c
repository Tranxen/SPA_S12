#include "md5.h"

// calcul le md5sum de la chaine passé en paramètre

void md5_hash_from_string (char *string, int size, char *hash)
{
  int i;
  char unsigned md5[MD5_DIGEST_LENGTH] = {0};

  MD5((const unsigned char *)string, size-1, md5);

  for (i=0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(hash + 2*i, "%02x", md5[i]);
  }
}
