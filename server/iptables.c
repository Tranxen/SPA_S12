#include <unistd.h>
#include <stdio.h>

void changeiptables(char* proto, char* IPserveur, char* IPclient, char* dport, char* sport)
{
  char * regle;
  sprintf(regle, "iptables -A FORWARD -p %s -d %s -s %s -dport %s -sport %s -m state --state NEW -j ACCEPT", proto, IPserveur, IPclient, dport, sport);
  system(regle);

  sleep(30);
  sprintf(regle, "iptables -D FORWARD -p %s -d %s -s %s -dport %s -sport %s -m state --state NEW -j ACCEPT", proto, IPserveur, IPclient, dport, sport);
  system(regle);
}
