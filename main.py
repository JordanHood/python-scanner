import socket
import subprocess
import argparse
import sys
def system_call(command):
    return subprocess.getoutput([command])

# grab the host gateway
def get_gateway_address():
    return system_call("route -n get default | grep 'gateway' | awk '{print $2}'")

# using nmap to populate the ARP-tables
def populate_arp_tables(gatewayAddress):
    return system_call("nmap -T5 -sn {}-255".format(gatewayAddress))

# scan the populated arp table and filter results that aren't `incomplete` 
def get_arp_table():
    return system_call("arp -a -n | grep -v incomplete | awk '{print $2}' | grep -E -o '[0-9.]+'")

def port_scan(ipAddress):
    return system_call("nmap {}".format(ipAddress))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan","-s",  help="Scan the local network for all available devices", action="store_true")
    parser.add_argument("--port","-p", help="Scan a device on the local network for all availabile ports")
    args=parser.parse_args()
    if args.scan:
        gatewayAddress = get_gateway_address()
        populate_arp_tables(gatewayAddress)
        print(get_arp_table())
    elif args.port:
        print(port_scan(args.port))
    else:
        parser.print_help()
        sys.exit(1)