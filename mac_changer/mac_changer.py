#!/urs/bin/env python

#ifconfig - to view network interfaces

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        parser.error("[-] Please specify a MAC, use --help for more info")
    return options


def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_rez = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))

    if mac_address_search_rez:
        return mac_address_search_rez.group(0)
    else:
        print("[-] Could not read the MAC address")

arguments = get_arguments()
current_mac = get_current_mac(arguments.interface)
print("[+] Current MAC: " + str(current_mac))
change_mac(arguments.interface, arguments.new_mac)
current_mac = get_current_mac(arguments.interface)

if arguments.new_mac == current_mac:
    print("[+] MAC was successfully changed to: " + str(current_mac))
else:
    print()