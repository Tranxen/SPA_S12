#include "decrypt.h"

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init_de(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];

  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  return 0;
}

/*                                                                          
 * Decrypt *len bytes of ciphertext                                         
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext */

  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

char* decrypt(char* key, char* ciphertext, int ciphertext_len){
  EVP_CIPHER_CTX de;
  unsigned int salt[] = {12345, 54321};
  unsigned char* key_data;
  unsigned char* plaintext;
  int key_data_len;
  int text_len;
  key_data = (unsigned char*) key;
  key_data_len = strlen (key);

  if (aes_init_de(key_data, key_data_len, (unsigned char*)&salt, &de)) {
    printf("Couldn't initialize AES cypher\n");
    exit(EXIT_FAILURE);
  }
  //text_len = strlen(ciphertext)+1;
  text_len = ciphertext_len;
  plaintext = aes_decrypt(&de, (unsigned char *)ciphertext, &text_len);
  /*printf("cipher text : %s\n", ciphertext);
  printf("key : %s\n", key);
  printf("plain text : %s\n", plaintext);
  */
  return(char*) plaintext;
}
