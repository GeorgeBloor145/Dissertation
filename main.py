### WEEEEEE

from scapy.all import *
import requests

def pcap_processing():

    pcap = rdpcap('fuzz-2006-06-26-2594.pcap')
    ips = set((p[IP].src) for p in PcapReader('fuzz-2006-06-26-2594.pcap') if IP in p)
    for i in ips:
        print(i)

def geolocation_api_request():
    r = requests.get('http://ip-api.com/csv/94.3.90.21?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query')
    print(r.text)

    for i in range(len(r.text)):
        


#pcap_processing()

geolocation_api_request()
