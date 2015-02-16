#ifndef UDP_H_
#define UDP_H_

typedef struct udp_hdr {
	u_short src_port;
	u_short dst_port;
	u_short length;
	u_short checksum;
}*udp_hdr_t;

void udp_pkt_process(u_char *,const struct pcap_pkthdr *, const u_char *,int);

#endif
