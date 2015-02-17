#include "udp_sock.h"

void diep(char *s)
{
  perror(s);
  exit(1);
}


int udp_connect(const char* IP, int port, int* s, struct sockaddr_in* si_other){

    if ((*s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1){
	printf("ECHEC\n");
	diep("socket");
	return -1;
    }

    memset((char *) si_other, 0, sizeof(*si_other));
    si_other->sin_family = AF_INET;
    si_other->sin_port = htons(port);

    if (inet_aton(IP, &si_other->sin_addr)==0) {
	fprintf(stderr, "inet_aton() failed\n");
	printf("connexion %s : %d [ECHEC]\n", IP, port);
	exit(1);
    }

    printf("connexion %s : %d [OK]\n", IP, port);
    return 0;

}



int udp_send(int* s, const char* buf, int buflen ,struct sockaddr_in* si_other, int* slen){

    if (sendto(*s, buf, buflen, 0, (const struct sockaddr*)si_other, *slen)==-1)
	diep("sendto()");
    else
	printf("send %s", buf);

    return 0;

}
