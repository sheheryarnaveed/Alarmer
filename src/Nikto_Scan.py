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

def NIKTO_SCAN(packet, ip_address):
    global count
    HTTP_PAC=str(packet)
    if HTTP_PAC.find('GET') != -1:
      http = "\n".join(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
      if http is not None:
          if http.find('Nikto') != -1:
              count += 1
              print 'ALERT #' + str(count) + ': Nikto scan is detected from ' + ip_address + ' (HTTP)!'
