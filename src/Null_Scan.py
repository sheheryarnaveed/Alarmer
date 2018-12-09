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

def NULL_SCAN(packet, ip_address):
  global count
  flags = packet[TCP].flags
  if flags == 0:
    count += 1
    print 'ALERT #' + str(count) + ': NULL scan is detected from ' + ip_address + ' (TCP)!'
  return 0
