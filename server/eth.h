#ifndef ETH_H_
#define ETH_H_

#define ETH_HDR_LENGTH 14

typedef struct eth_hdr{
  u_char eth_address_src[6];
  u_char eth_adress_dst[6];
  u_short eth_type;
}* eth_hdr_t;

void eth_pkt_process(u_char *,const struct pcap_pkthdr *, const u_char *);


#endif
