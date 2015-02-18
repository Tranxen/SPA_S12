#ifndef UDP_PACKET_H
#define UDP_PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <inttypes.h>
#include "../common.h"

void send_udp_packet(char* ip_dest, int port_dest, char* payload);

#endif