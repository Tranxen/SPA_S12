#ifndef IPV4_H_
#define IPV4_H_

typedef struct ipv4_hdr{
  u_char ip_hdr_len :4;
  u_char ip_version :4;
  u_char ip_tos;
  u_short total_length;
  u_short ip_id;
  u_short ip_offset_frag_1 :5;
  u_char flag_mf :1;
  u_char flag_df :1;
  u_char reserved :1;
  u_short ip_offset_frag_2 :8;
  u_char ip_ttl;
  u_char ip_protocol;
  u_short ip_hdr_chksum;
  u_int ip_src;
  u_int ip_dst;
}* ipv4_hdr_t;

void ipv4_pkt_process(u_char *,const struct pcap_pkthdr *, const u_char *,long);

#endif
