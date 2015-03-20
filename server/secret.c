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



/*
 * Generate an OTP using the algorithm specified in RFC 4226,
 */

void
hotp(const u_char *key, size_t keylen, u_long counter, char *buf, size_t buflen)
{
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

  /* Generate hexadecimal digits */
  if (buf != NULL) {
    snprintf(buf, buflen, "%08x", value);
  }
}

