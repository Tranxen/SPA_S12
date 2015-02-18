#ifndef UDP_PACKET_H
#define UDP_PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <inttypes.h>
#include "../common.h"

char* get_ip_addr(char* device);
void send_udp_packet(char* device, char* ip_dest, int port_dest, char* payload);

#endif