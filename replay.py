#!/usr/bin/env python

'''
Script replays traffic from a given PCAP
'''

import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def replay(file):

	pkts = rdpcap(file)
	for pkt in pkts:
		sendp(pkt)

def main():

	if len(sys.argv) < 2:
		sys.exit("Usage: Please provide packet capture.")
	else:
		replay(sys.argv[1])

if __name__=='__main__':
	main()
