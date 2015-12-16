#!/usr/bin/env python
#Imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from collections import Counter
from scapy.all import *
import optparse

#File Metadata
pcap = ''
datalist = []
slist = []
dlist = []
#Data Bags
proto = collections.Counter()
domname = collections.Counter()

#Gather Protocol Counts
def statsByProto():
	stats = []
	for p in packets:
		if p.haslayer(TCP):
			stats.append(p[TCP].dport)
		elif p.haslayer(UDP):
			stats.append(p[UDP].dport)
		else:
			continue
	proto = collections.Counter(stats)

#Gather stats by host
#Track ports for unique IP address
def statsByHost():
	hostdict = {}

	for p in packets:
		ports = []
		if p.haslayer(TCP):
			hostdict = p[IP].src
				if p[TCP].dport != 0:
					ports.append(p[TCP].dport)
		elif p.haslayer(UDP):
			hostdict = p[IP].src
				if p[UDP].dport != 0:
					ports.append(p[UDP].dport)
		else:
			continue
#Gather number of DNS Requests
def statsByDomain():
	domains = []
	for p in packets:
		if p.haslayer(DNS) and p[UDP].dport == 53:
			domains.append(p[DNSQR].qname)
		else:
			continue
	domname = collections.Counter(domains)

#Main Method
def main():


if __name__=="__main__":main()
