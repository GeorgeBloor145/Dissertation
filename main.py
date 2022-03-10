### WEEEEEE

from scapy.all import *
import requests
import IP2Location
import os
from ipwhois import IPWhois
import json
import logging
import country_converter as coco


### Global Vars
database = IP2Location.IP2Location(os.path.join("data", "/home/george/Documents/Dissertation/IP2LOCATION-LITE-DB11.IPV6.BIN/IP2LOCATION-LITE-DB11.IPV6.BIN"))
geolocationips = {}
cc = coco.country_converter
###
def pcap_processing():


    ips = set((p[IP].src) for p in PcapReader('/home/george/Documents/Dissertation/fuzz-2006-06-26-2594.pcap') if IP in p)
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
    failed = 0

    for current_ip in IPADDR:
        number = current_ip[0] + current_ip[1] + current_ip[2] + current_ip[3] + current_ip[4] + current_ip[5] + current_ip[6]


        if number == "192.168":
            print("THE IP ADDRESS {} is in a private range, lookup FAILED".format(current_ip))
            failed = failed + 1


        else:
            match = ""
            whoislookup = whois(current_ip)
            print(whoislookup)
            rec = database.get_all(current_ip)
            if whoislookup == rec.country_short:
                print("MATCH 1")
                match = "True"
            else:
                match = "False"
            current = geolocationips.get(current_ip,{'country_long': rec.country_long, 'country_short': rec.country_short, 'region': rec.region, 'city': rec.city, 'latitude': rec.latitude, 'longitude': rec.longitude, 'whois': whoislookup, 'match': match})
            # if current['whois'] == current['country_short']:
            #             #     print("MATCH")
            #             #     current['match'].append("true")
            #             # else:
            #             #     current['match'].append("false")

            geolocationips[current_ip] = current



    #print("")
    print(geolocationips)
    #print("")
    print("The number of failed lookups were: {}".format(failed))
    return geolocationips, failed



def whois(passed_ip):
    #print("BRRRRRR {}".format(passed_ip))


    try:
        obj = IPWhois(passed_ip)

        res = obj.lookup_rdap()
        print(res)
       # print(res['asn_country_code'])
        return res['asn_country_code']
    except:
        print("ERROR LOOKING UP IP: {} LIKELY A PRIVATE ADDRESS".format(passed_ip))


        # except Exception as e:
        #     print(str(e))
        #     logging.warning("WHOIS LOOKUP FAILED: " + str(e))
        #
        #     return {'query': current_ip, "error": 'Error: WHOIS Lookup Failed'}
        #     continue

#pcap_processing()

#geolocation_api_request()
#ip2location()

#whois()