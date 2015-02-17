// include de common.h
#include "udp_packet.h"

int main() {

	char ip_addr_str[] = "127.0.0.1";
	char dest_port_str[] = "7777";

	char payload[] = "SPACOOOLL";

	send_udp_packet(ip_addr_str, dest_port_str, payload);

	return 0;
}