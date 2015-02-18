

struct aes_data_t{

  char username[16];
  unsigned int timestamp;
  unsigned int ip_src;
  unsigned int ip_dst;
  unsigned short port;
  char protocol;
  char md5sum[32];

};

struct udp_data_t{

  char header[3];
  struct aes_data_t data;

};
