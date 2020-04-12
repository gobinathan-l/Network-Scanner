#!/usr/bin/env python
# For ?? Errors [https://forum.stationx.net/t/ether-arp-who-has-says/3904/2]
# pip uninstall scapy
# pip uninstall scapy-http
# pip install scapy==2.4.2
# pip install scapy-http==1.8.2
# scapy.ls(scapy.*()) [To list all the Fields is the method]

import scapy.all as scapy

def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request # The '/' appends the arp_request to the arp_broadcast.
#    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1) # The srp allows to send packet with custom Ether part. [s for send and r for recieve]
    # The send'n'recieve functions return a couple of two lists.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # To get only the answered machines list.
    print("IP Address \t\t\t\t Mac Address\n---------------------------------------------------------")
    for element in answered_list:
        if len(element[1].psrc) == 11:
            print(element[1].psrc + "\t\t\t\t" + element[1].hwsrc)  # The answered list contains packets sent and answer.
        if len(element[1].psrc) == 13:
            print(element[1].psrc + "\t\t\t\t" + element[1].hwsrc)  # The answered list contains packets sent and answer.
        print("---------------------------------------------------------")
#    print(answered_list.summary())
#    arp_request_broadcast.show()
#    print(arp_request_broadcast.summary())
#    arp_request_broadcast.show()                      # The show() Method shows the Contents of the ARP Packet

arp_scan("192.168.1.1/24")
