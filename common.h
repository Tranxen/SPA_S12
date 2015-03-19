#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#pragma pack()

struct aes_data_t{

  uint8_t 	username[16];
  uint32_t 	timestamp;
  uint32_t 	ip_src;
  uint32_t 	ip_dst;
  uint32_t 	port;
  uint8_t 	protocol;
  uint16_t 	opentime; // en seconde
  uint8_t 	random[16];
  uint8_t 	md5sum[32];
    
};

#endif
