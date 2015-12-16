#!/usr/bin/env python

#Imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from collections import Counter
from scapy.all import *

#Initializations
file = 'DGA.pcap'
packets = rdpcap(file)
#Packet information lists
datalist = []

#Retrieve all DNS packets
print 'Non-Existent Domain Name'
print '------------------------'
for packet in packets:
    if packet.haslayer(DNS) and packet[DNS].rcode == 3:
        print packet[DNSQR].qname#.strip('sbx08571.alphaga.wayport.net.')

print '\nExistent Domain Name'
print '------------------------'
for packet in packets:
    if packet.haslayer(DNS) and packet[DNS].rcode == 0:
        print packet[DNSQR].qname#.strip('sbx08571.alphaga.wayport.net.')
