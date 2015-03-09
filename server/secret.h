#ifndef SECRET_H_
#define SECRET_H_

void hotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf10, char *buf16, size_t buflen);

#endif
