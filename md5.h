#ifndef MD5_H
#define MD5_H

#include <stdio.h>
#include <openssl/md5.h>
#include <string.h>

void md5_hash_from_string (char *string, int size, char *hash);


#endif