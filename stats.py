#!/usr/bin/env python
#Imports
import logging, sys, imp
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from collections import Counter
from scapy.all import *

packets = rdpcap(sys.argv[1])
#Lists containing packet information
datalist = []
srclist = []
dstlist = []
#Initialized value counts
dnscount = 0
httpcount = 0
nxcount = 0
valcount = 0

#Iterate through packets and find DNS packets
for packet in packets:
    if DNS in packet:
        dnscount += 1
#Iterate through packets for port 80(http)
for packet in packets:
    if (packet.haslayer(TCP) and packet[TCP].sport == 80) or (packet.haslayer(TCP) and packet[TCP].dport == 80):
        httpcount += 1

for packet in packets:
    #Look for DNS packets that return NX records
    if packet.haslayer(DNS) and packet[DNS].rcode == 3:
        nxcount += 1
    #Look for DNS packets that return A records
    elif packet.haslayer(DNS) and packet[DNS].rcode == 0:
        valcount += 1
'''
print 'Domain\t\t\t\t\t\t Response Code'
for packet in packets:
    if packet.haslayer(DNS):
        print '%s\t\t\t\t\t\t%s' %(packet[DNSQR].qname,packet[DNS].rcode)
'''

'''
  Retrieve src and destination IP addresses and store in a collection.Counter object
  Additional information such as port may be added at a later point. Scapy should be used to retrieve IP layer info.
'''
#Create two lists. One for src and one dst IP addresses.
for packet in packets:
    srclist.append(packet[IP].src)
    dstlist.append(packet[IP].dst)

#Add IP addresses to a Counter object for occurrence counts
srcdata = collections.Counter(srclist)
dstdata = collections.Counter(dstlist)

print 'Top Talkers'
print '\nSrcIP:\t\t\tOcc.'
for s in srcdata.most_common():
    print '%s\t\t%s' %(s[0],s[1])
print '\nDstIP:\t\t\tOcc.'
for d in dstdata.most_common():
    print '%s\t\t%s' %(d[0],d[1])

print '\n\nTraffic Statistics for %s' % sys.argv[1]
print 'HTTP:\t\t\t%s' % httpcount
print 'DNS:\t\t\t%s' % dnscount
print 'Non-Existent Domains:\t%s' % nxcount
print 'Valid Domains:\t\t%s' % valcount
