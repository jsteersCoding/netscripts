#!/usr/bin/python3

import sys
from scapy.all import *

"""
Setup and Run instructions:

Install package:
* pip install --pre scapy[complete]

Run script (script runs infinitely):
* sudo python3 spoof_source_ip_address.py

Observe overwrite:
* sudo tcpdump -i <interface_name> -s 65535 -nn 'net <subnet>' -w <pcap>
* sudo tcpdump -nn -r <pcap>
# 10:11:07.141385 IP <source_ip>.39072 > <destination_ip>.80: Flags [S], seq 2270559729, win 64240, options [mss 1460,sackOK,TS val 2483010714 ecr 0,nop,wscale 7], length 0
# 10:11:07.141507 IP <source_ip>.80 > <destination_ip>.39072: Flags [R.], seq 0, ack 2270559730, win 0, length 0
* sudo tcpdump -nn -i <interface_name> 'host <source_ip>'
# 11:23:44.123456 IP <source_ip> > <destination_ip>: ICMP echo reply, id 18867, seq 872, length 64

Kill process if no sniff count is provided (infinite packets):
# ps aux | grep "sudo python3 spoof_source_ip_address.py" | grep -v grep | awk {'print $2'} | sudo xargs kill -9

Send packets:
* ping <destination_address> # ICMP
# 1 packets transmitted, 1 received, 0% packet loss, time 0ms
# rtt min/avg/max/mdev = 0.234/0.234/0.234/0.000 ms

* nmap -sP <destination_address> -oX -
# <host><status state="up" reason="conn-refused" reason_ttl="0"/>
# <address addr="<destination_address>" addrtype="ipv4"/>
"""

interface="<interface_name>"
srcIP="<source_ip>"

def changeSourceIP(packet):
    if IP in packet:
        packet[IP].src = srcIP
        sendp(packet, iface=interface, verbose=True)
while 1:
    sniff(prn=changeSourceIP,iface=interface) # add count for num of packets to sniff (e.g. count=2)
