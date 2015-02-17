
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

unsigned int ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            /* We insist on stopping at "." if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return 0;
            }
        }
        if (n >= 256) {
            return 0;
        }
        v *= 256;
        v += n;
    }
    return v;
}