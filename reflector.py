#!/usr/bin/env python3
# Imports here
import argparse
from scapy.all import *

# accept input args
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP

def get_input_args():
    """
        Process input args from the user.
    """
    parser = argparse.ArgumentParser(f"The goal of this project is to create a “reflector” which will \
            relaunch attacks sent to a given IP address and ethernet address to the IP address that sent the attack.")

    parser.add_argument('--interface', required=True, type=str, default="",
                        help='The interface on which all Communication will occur.')
    parser.add_argument('--victim-ip', required=True, type=str, default="", help='IP of victim.')
    parser.add_argument('--victim-ethernet', required=True, type=str, default="",
                        help='Ethernet Address of the victim.')
    parser.add_argument('--reflector-ip', required=True, type=str, default="", help='The reflector IP address')
    parser.add_argument('--reflector-ethernet', required=True, type=str, default="",
                        help='The reflector Ethernet Address.')

    # extrac incase we need it
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="store_true")
    group.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    return args

def remove_checksum(pkt):
    del pkt.chksum
    if pkt.haslayer(TCP):
        del pkt[TCP].chksum
    if pkt.haslayer(UDP):
        del pkt[UDP].chksum
    if pkt.haslayer(ICMP):
        del pkt[ICMP].chksum
    return pkt

class Reflector:

    def __init__(self, int_face, v_ip, v_eth, r_ip, r_eth):
        self.int_face = int_face
        self.v_ip = v_ip
        self.v_eth = v_eth
        self.r_ip = r_ip
        self.r_eth = r_eth
        sniff(prn=self.main_pkt_checker, iface=self.int_face)

    def main_pkt_checker(self, pkt):
        print(pkt.summary())
        new_pkt = None

        # # Handle APR
        if ARP in pkt and pkt[ARP].pdst == self.v_ip:
            new_pkt = self.send_arp_from_victim(pkt)

        if ARP in pkt and pkt[ARP].pdst == self.r_ip:
            new_pkt = self.send_arp_from_reflector(pkt)

        if IP in pkt and pkt[IP].dst == self.v_ip:
            new_pkt = self.send_from_reflector(pkt)

        if IP in pkt and pkt[IP].dst == self.r_ip:
            new_pkt = self.send_from_victim(pkt)

        if new_pkt is not None:
            sendp(new_pkt, iface=self.int_face)

    def send_arp_from_victim(self, pkt):
        # set pkt src as reflector
        # print("---------ORIGINAL PKT------------")
        # pkt.show()
        # print("----------send_arp_from_victim-----------")

        p = pkt.copy()
        p[ARP].op = 2  # casue we are saying is at.

        p[Ether].dst = pkt[ARP].hwsrc
        p[ARP].pdst = pkt[ARP].psrc  # attack was the src
        p[ARP].hwdst = pkt[ARP].hwsrc  # attack was the src

        p[Ether].src = self.v_eth
        p[ARP].psrc = self.v_ip
        p[ARP].hwsrc = self.v_eth

        # p.show2()
        return p

    def send_arp_from_reflector(self, pkt):
        # set pkt src as reflector
        # print("---------ORIGINAL PKT------------")
        # pkt.show()
        # print("----------send_arp_from_victim-----------")

        p = pkt.copy()

        p.op = 2  # casue we are saying is at.
        p[Ether].dst = pkt[ARP].hwsrc
        p[ARP].pdst = pkt[ARP].psrc  # attack was the src
        p[ARP].hwdst = pkt[ARP].hwsrc  # attack was the src

        p[Ether].src = self.r_eth
        p[ARP].psrc = self.r_ip
        p[ARP].hwsrc = self.r_eth

        # p.show2()
        return p

    def send_from_reflector(self, pkt):
        p = pkt.copy()
        print("Check sum : ", p.chksum)
        p = remove_checksum(p)

        p[IP].src = self.r_ip
        p[Ether].src = self.r_eth

        p[IP].dst = pkt[IP].src
        p[Ether].dst = pkt[Ether].src  # attack was the src

        p.show2()
        return p

    def send_from_victim(self, pkt):
        p = pkt.copy()
        print("Check sum : ", p.chksum)
        p = remove_checksum(p)

        # set src and dst
        p[IP].src = self.v_ip
        p[Ether].src = self.v_eth

        p[IP].dst = pkt[IP].src
        p[Ether].dst = pkt[Ether].src  # attack was the src

        p.show2()
        return p



# def arp_monitor_callback(pkt):
#     if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
#         return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")

def main():
    my_args = get_input_args()
    my_reflector = Reflector(
        my_args.interface,
        my_args.victim_ip,
        my_args.victim_ethernet,
        my_args.reflector_ip,
        my_args.reflector_ethernet)


# Call to main function to run the program
if __name__ == "__main__":
    main()
