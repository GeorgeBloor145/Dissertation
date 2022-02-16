### WEEEEEE

from scapy.all import *


def pcap_processing():

    pcap = rdpcap('fuzz-2006-06-26-2594.pcap')
    ips = set((p[IP].src) for p in PcapReader('fuzz-2006-06-26-2594.pcap') if IP in p)
    for i in ips:
        print(i)

pcap_processing()

