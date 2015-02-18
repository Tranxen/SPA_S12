#include <pcap/pcap.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "eth.h"
#include "ipv4.h"
#include "udp.h"
#include "../common.h"

#define PACKET_READ_LENGTH 64

#define DEBUG_PKT 0

static void signal_handler(int);
static void pkt_process(u_char *, const struct pcap_pkthdr *,
		const u_char *);

pcap_t *capture_handle;


struct eth_hdr* e1 = NULL;
struct ipv4_hdr* e2 = NULL;
struct udp_hdr* e3 = NULL;

static int pckt_id = 0;

static void close_app(){
  fprintf(stdout,"\n------ CLOSE APP CALLED --------\n");
  pcap_breakloop(capture_handle);

  //Ex2 protocol_metrics_print(metrics);
  //session_list_print(session_list);
}

static void signal_handler(int signal) {
	switch (signal) {
	case SIGINT:
		close_app();
		break;
	case SIGTERM:
		close_app();
		break;
	default:
		fprintf(stderr, "UNKNOWN SIGNAL\n");
		exit(EXIT_FAILURE);
	}
}

bpf_u_int32 total_len = 0;
int total_pkt = 0;

static void 
pkt_process(u_char *param, const struct pcap_pkthdr *pkt_hdr,
		const u_char *pkt_data) {
  //eth_pkt_process(param,pkt_hdr,pkt_data);
  
  total_pkt++;
  total_len += pkt_hdr->len;

  int offset1 = 0;
  int offset2 = 0;
  int offset3 = 0;
  int i = 0;

  //struct eth_hdr* e1 = malloc(sizeof(struct eth_hdr));
  e1 = (struct eth_hdr*)(pkt_data);

  offset1 = sizeof(struct eth_hdr);
  //struct ipv4_hdr* e2 = malloc(sizeof(struct ipv4_hdr));
  e2 = (struct ipv4_hdr*)(pkt_data + offset1);

  offset2 = offset1 + sizeof(struct ipv4_hdr);
  e3 = (struct udp_hdr*)(pkt_data + offset2);

  offset3 = offset2 + sizeof(struct udp_hdr);
  
  if(e2->ip_protocol != 17){
    //printf("not a UDP packet => don't care\n");
    return;
  }
  
  // ========== LECTURE ETHERNET ===============

  /* DEBUG STRUCT ETHERNET */

  printf("\n==== %d ====\n", pckt_id); pckt_id++;


  printf("DEBUG RAW eth_hdr : ");
  for(i = 0; i < 14; i++){
    printf("%x:", pkt_data[i]);
  }
  printf("\n");

  if(DEBUG_PKT >= 1){
    printf("\tmac src : ");
    for(i = 0; i < 6; i++){
      printf("%x:", e1->eth_address_src[i]);
    }
    printf("\n");
    printf("\tmac dst : ");
    for(i = 0; i < 6; i++){
      printf("%x:", e1->eth_adress_dst[i]);
    }
    printf("\n");
    printf("\ttype : %x\n", e1->eth_type);
  }
  
  // =========== LECTURE IP =======================

  printf("DEBUG RAW ipv4_hdr : ");
  for(i = offset1; i < offset1 + sizeof(struct ipv4_hdr); i++){
    printf("%x:", pkt_data[i]);
  }
  printf("\n");

  if(DEBUG_PKT >= 1){
  
    printf("\thdrlen : %x\n", e2->ip_hdr_len);
    printf("\tip_version : %x\n", e2->ip_version);
    printf("\tip_tos : %x\n", e2->ip_tos);
    printf("\ttotal_length : %d\n", ntohs(e2->total_length)); // inversion d'octet sur u_short...
    printf("\ttp_id : %x\n", htons(e2->ip_id));
    printf("\tip_ttl : %d\n", e2->ip_ttl);
    printf("\tip_protocol : %x (%d)\n", e2->ip_protocol, e2->ip_protocol);

  }

  printf("\tip src : %d.%d.%d.%d\n",
	 e2->ip_src & 0xFF,
	 e2->ip_src >> 8 & 0xFF,
	 e2->ip_src >> 16 & 0xFF,
	 e2->ip_src >> 24 & 0xFF);

  printf("\tip dst : %d.%d.%d.%d\n",
	 e2->ip_dst & 0xFF,
	 e2->ip_dst >> 8 & 0xFF,
	 e2->ip_dst >> 16 & 0xFF,
	 e2->ip_dst >> 24 & 0xFF);

  
  // =========== LECTURE UDP =======================
  
  printf("DEBUG RAW udp_hdr : ");
  for(i = offset2; i < offset2 + sizeof(struct udp_hdr); i++){
    printf("%x:", pkt_data[i]);
  }
  printf("\n");

  if(DEBUG_PKT >= 1){
    printf("\tsrc port : %d\n", ntohs(e3->src_port));
    printf("\tdst port : %d\n", ntohs(e3->dst_port));
    printf("\tlength   : %d\n", ntohs(e3->length));
    printf("\tchecksum : %x\n", ntohs(e3->checksum));
  }
  
  // ============ LECTURE DATA =====================

  int data_length = ntohs(e3->length) - sizeof(struct udp_hdr);
  printf("\tdata len : %d\n", data_length);

  /*
  char* data_raw = NULL;
  data_raw = malloc(sizeof(char)*data_length);
  memset(data_raw, '\0', data_length);
  */


  printf("DEBUG RAW DATA (hex) : ");
  for(i = offset3; i < offset3 + data_length; i++){
    printf("%x:", pkt_data[i]);
  }
  printf("\n");

  if(DEBUG_PKT >= 1){
  printf("DEBUG RAW DATA (ascii) : ");
  for(i = offset3; i < offset3 + data_length; i++){
    printf("%c", pkt_data[i]);
  }
  printf("\n");
  }
  
  if(data_length == sizeof(struct aes_data_t)){ //Attention 60 octet pour spa non crypté, 64 sinon
    spa_parser(pkt_data+offset3, data_length, e2->ip_src);
  }
  
}


void 
listen_interface(char *device_name){
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  capture_handle = pcap_create(device_name, pcap_errbuf);
  pcap_set_snaplen(capture_handle, PACKET_READ_LENGTH);
  pcap_set_timeout(capture_handle, 1000);
  pcap_set_promisc(capture_handle, 1);
  
  fprintf(stdout,"\n------- LISTENING %s ----------\n",device_name);

  if (pcap_activate(capture_handle) != EXIT_SUCCESS) {
    fprintf(stderr, "pcap_activate failed : %s line: %d\n%s\n",
	    __FILE__, __LINE__, pcap_geterr(capture_handle));
    return;
  }

  /*int res_pcap_loop = pcap_loop(capture_handle, -1, pkt_process,
				(u_char *) session_list);
  */
  
  int res_pcap_loop = pcap_loop(capture_handle, -1, pkt_process, NULL);
  
  switch (res_pcap_loop) {
  case 0:
    fprintf(stderr, "packet count reached\n");
    break;
  case -1:
    fprintf(stderr, "An error occurred while reading the packet\n");
    break;
  case -2:
    fprintf(
	    stderr,
	    "pcap_breakloop called\n");
    break;
  }
  

  pcap_close(capture_handle);
  fprintf(stderr, "capture thread ended\n");
 }

int
main(int argc, char *argv[]){
  int i = 1;
  char * device_name = NULL;

  u_short test = 0x08;

  printf("-> %x\n", test);
  
  /*  e1 = malloc(sizeof(struct eth_hdr));
  e2 = malloc(sizeof(struct ipv4_hdr));
  e3 = malloc(sizeof(struct udp_hdr));
  */
  
  //Ex2 metrics = protocol_metrics_create();
  //session_list = session_list_create();

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
 
  if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface")
      == 0) {
     device_name = argv[i + 1];
  }
  
  listen_interface(device_name);

  printf("\nTotal nb pkt : %d, total len : %d o\n\n", total_pkt, total_len);

  //Ex2 protocol_metrics_destroy(metrics);
  //session_list_destroy(session_list);

  /*  free(e1);
  free(e2);
  free(e3);
  */
  return EXIT_SUCCESS;
}
