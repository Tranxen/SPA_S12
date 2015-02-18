#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

char * encrypt (char* key, char* text, int ciphertext_len);

#endif
