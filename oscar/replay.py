#! /usr/bin/python

from scapy.all import *
import sys


packetCount = 0

def customAction(packet):
    global packetCount
    packetCount += 1

    print "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)

    packet.show()

    sys.exit(1)
    

#sniff(filter="udp and port 7777",prn=customAction)

raw = "\x12e\xaf'~\xff_9\xf4\x9dn\x89R\xbd/v~u\nZ2!\xe7u\x1a\x004\xb6<\xfaqf3\t\xb2\x91\xa6/\xc0?m\xd0V\x1a\x06\xff\xb7\xc3\xfb\x167\xad\xadIM?\x180\xb1\x97)\xf3\x1a!"

"""
raw correspond to 
username : toto
timestamp : 1424271490
ip src: 10.0.2.15
ip dest: 192.168.1.1
port : 22
protocol : 0 (TCP)
md5sum : f71dbe52628a3f83a77ab494817525c6
"""

send(IP(dst="127.0.0.1",src="111.111.111.111")/UDP(dport=7777)/raw)