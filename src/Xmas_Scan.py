from scapy.all import*
import pcapy
import sys
import argparse
import socket
import fcntl
import struct
import base64
import re

from alarm import count

def XMAS_SCAN(packet, ip_address):
  global count

  CWR = 0x80
  ACK = 0x10
  URG = 0x20
  ECE = 0x40
  SYN = 0x02
  FIN = 0x01
  RST = 0x04
  PSH = 0x08
  flags = packet[TCP].flags
  if not(flags & CWR) and not (flags & ACK) and (flags & URG) and not(flags & ECE) and not(flags & SYN) and (flags & FIN) and not(flags & RST) and (flags & PSH):
    count += 1
    print 'ALERT #' + str(count) + ': XMAS scan is detected from ' + ip_address + ' (TCP)!'

