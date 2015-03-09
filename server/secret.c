//#include "otptool.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>


#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>



/* Powers of ten */
static const int    powers10[] = { 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000 };

/*
 * Generate an OTP using the algorithm specified in RFC 4226,
 */

void
hotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf10, char *buf16, size_t buflen)
{
  const int max10 = sizeof(powers10) / sizeof(*powers10);
  //printf("max10 : %d (%d)/(%d)\n", max10, sizeof(powers10), sizeof(*powers10));
  const int max16 = 8;
  const EVP_MD *sha1_md = EVP_sha1();
  u_char hash[EVP_MAX_MD_SIZE];
  u_int hash_len;
  u_char tosign[8];
  int offset;
  int value;
  int i;

  /* Encode counter */
  for (i = sizeof(tosign) - 1; i >= 0; i--) {
    tosign[i] = counter & 0xff;
    counter >>= 8;
  }

  /* Compute HMAC */
  HMAC(sha1_md, key, keylen, tosign, sizeof(tosign), hash, &hash_len);

  /* Extract selected bytes to get 32 bit integer value */
  offset = hash[hash_len - 1] & 0x0f;
  value = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
    | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

  /* Sanity check max # digits */
  if (ndigits < 1)
    ndigits = 1;
  
  if (buf10 != NULL) {
    snprintf(buf10, buflen, "%0*d", ndigits < max10 ? ndigits : max10,
	     ndigits < max10 ? value % powers10[ndigits - 1] : value);
  }
  
  /* Generate hexadecimal digits */
  if (buf16 != NULL) {
    snprintf(buf16, buflen, "%0*x", ndigits < max16 ? ndigits : max16,
	     ndigits < max16 ? (value & ((1 << (4 * ndigits)) - 1)) : value);
  }
}

/*
int main(int argc, char** argv){

  u_char seed[] = "nique ta mere\0";
  int seed_len = strlen(seed);

  u_char bufdec[32];memset(bufdec, '\0', 32);
  u_char bufhex[32];memset(bufhex, '\0', 32);

  int i = 0;

  for (i ; i < 10; i++){
  
    hotp(seed, seed_len, i, 16, bufdec, bufhex, 16);

    printf("-----------------------------\n");
    printf("dec : %s\n", bufdec);
    printf("hex : %s\n", bufhex);
    
  }
  
  return 0;

}
*/
