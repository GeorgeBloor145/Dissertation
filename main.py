### WEEEEEE

from scapy.all import *
import requests
import IP2Location
import os

### Global Vars
database = IP2Location.IP2Location(os.path.join("data", "/home/george/Documents/Dissertation/IP2LOCATION-LITE-DB11.IPV6.BIN/IP2LOCATION-LITE-DB11.IPV6.BIN"))
geolocationips = {}

###
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

def ip2location():
    IPADDR = pcap_processing()

    for current_ip in IPADDR:
        rec = database.get_all(current_ip)
        current = geolocationips.get(current_ip,{'country': rec.country_short, 'region': rec.region, 'city': rec.city, 'latitude': rec.latitude, 'longitude': rec.longitude})
        geolocationips[current_ip] = current

    print(geolocationips)



#pcap_processing()

#geolocation_api_request()
ip2location()