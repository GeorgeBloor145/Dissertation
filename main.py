### WEEEEEE

from scapy.all import *
import requests

def pcap_processing():


    ips = set((p[IP].src) for p in PcapReader('fuzz-2006-06-26-2594.pcap') if IP in p)
    return ips

def geolocation_api_request():
    IPADDR = pcap_processing()
    #print(IPADDR)
    for current_ip in IPADDR:
        print(current_ip)
        r = requests.get('http://pro.ip-api.com/csv/{}?key=0OjtyiZRQbFHXYW'.format(current_ip))

        print(r.text)



        


#pcap_processing()

geolocation_api_request()
