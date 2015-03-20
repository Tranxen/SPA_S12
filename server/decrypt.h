#ifndef COUNTER_H_
#define COUNTER_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

char* decrypt(char* key, char* ciphertext, int ciphertext_len);

#endif
