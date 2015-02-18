#include "udp_packet.h"

void send_udp_packet(char* ip_dest, int port_dest, char* payload) {

	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE];
	u_int32_t ip_addr;
	uint16_t  dest_port;
    int bytes_written;
    int payload_size = sizeof(struct aes_data_t);

	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* Generating a random id */

    libnet_seed_prand (l);


    ip_addr = libnet_name2addr4(l, ip_dest, LIBNET_DONT_RESOLVE);

    if ( ip_addr == -1 ) {
            fprintf(stderr, "Error converting IP address.\n");
            libnet_destroy(l);
            exit(EXIT_FAILURE);
    }

    //sscanf (port_dest, "%" SCNd16 "\n", &dest_port); /* Cast to uint16_t */
    dest_port = (uint16_t)port_dest;

    /* Building UDP header */
    libnet_ptag_t udp;
    udp = libnet_build_udp(libnet_get_prand (LIBNET_PRu16),    /* random source port */
                    dest_port,                 		           /* dest. port */
                    LIBNET_UDP_H + payload_size,               /* total length */ 
                    0,           					           /* autofill checksum */ 
                    (u_int8_t*)payload, 			           /* payload */
                    payload_size, 					           /* payload length */
                    l, 								           /* libnet context */
                    0); 							           /* build new protocol tag */
    if (udp == -1) {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
      	libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Building IP header */
    if ( libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + sizeof(payload) , IPPROTO_UDP, ip_addr, l) == -1 )
    {
            fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(l));
            libnet_destroy(l);
            exit(EXIT_FAILURE);
    }


    bytes_written = libnet_write(l);
    if ( bytes_written != -1 )
        printf("%d bytes written.\n", bytes_written);
    else
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));


	libnet_destroy(l);
}