#!/usr/bin/env python
import scapy.all as scapy
import argparse

# arp este un protocal in care stiu ip-ul unui divice si
# print-un semnal de brodcast in retea aflu adresa mac a device-ului respectiv


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # arp packet object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # set the destination mac to the broadcast mac
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()

    # send the packet and receive message
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for elem in answered_list:
        clients_list.append({"ip": elem[1].psrc, "mac": elem[1].hwsrc})

    return clients_list


def print_scan_result(scan_results_list):
    print('IP\t\t\tMac Address\n-----------------------------------------')
    for elem in scan_results_list:
        print(elem["ip"] + '\t\t' + elem["mac"])


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target ip addresses for scanning")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info")
    return options


# to get the ip address type route -n in terminal
arg = get_arguments()
scan_result = scan(arg.target)
print_scan_result(scan_result)
