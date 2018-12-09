from scapy.all import* 
import pcapy
import sys
import argparse
import socket
import fcntl
import struct
import base64
import re


count = 0
FTP_user=""
FTP_pass=""

import Nikto_Scan
import Xmas_Scan
import Fin_Scan
import HttpBasicAuth
import FTPAuth
import Null_Scan


def packetcallback(packet):
  try:
    if TCP in packet:
      ip_address = packet[IP].src
      Null_Scan.NULL_SCAN(packet, ip_address)
      Fin_Scan.FIN_SCAN(packet, ip_address)
      Nikto_Scan.NIKTO_SCAN(packet, ip_address)
      Xmas_Scan.XMAS_SCAN(packet, ip_address)
    if packet[TCP].dport == 80:
      ip_address = packet[IP].src
      HttpBasicAuth.OPEN_PASSWORD_SCAN(packet, ip_address)
    if (packet.haslayer(TCP)):
        if(packet[TCP].sport==21 or packet[TCP].dport==21):
            ip_address = packet[IP].dst
            FTPAuth.pass_FTP(packet, ip_address)
  except:
    pass




parser = argparse.ArgumentParser(
    description='A network sniffer that identifies basic vulnerabilities'
)
parser.add_argument('-i', dest='interface', help="Network interface to sniff on", default='eth0')

parser.add_argument('-r', dest='pcapfile', help="A PCAP file to read")
args = parser.parse_args()
if args.pcapfile:
  try:
    print "Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile}
    w = rdpcap(args.pcapfile)#sniff(offline = args.pcapfile, prn=packetcallback)
    for pkt in w:
        packetcallback(pkt)
  except:
    print "Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile}
else:
  print "Sniffing on %(interface)s... " % {"interface" : args.interface}
  try:
    sniff(iface= args.interface, prn = packetcallback)
  except pcapy.PcapError:
    print "Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface}
  except:
    print "Sorry, can\'t read network traffic. Are you root?"

