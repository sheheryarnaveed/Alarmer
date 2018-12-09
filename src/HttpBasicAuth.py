from scapy.all import*
import pcapy
import sys
import argparse
import socket
import fcntl
import base64
import re

from alarm import count

def OPEN_PASSWORD_SCAN(packet, ip_address):
    global count

    Packet_string = str(packet)
    if Packet_string.find('HTTP') != -1:
        data = str(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
        if data.find('Authorization: Basic') != -1:
            double_dash = re.search('Authorization: Basic(.+?)==', data)
            single_dash = re.search('Authorization: Basic(.+?)=', data)

            if double_dash:
                count += 1
                new_credentials = ""
                credentials = ""
                credentials += double_dash.group(1)

                for c in credentials:
                    if c == "'":
                      for a in credentials:
                          if(a == "'"):
                            break
                          else:
                            new_credentials +=a
                      credentials = new_credentials
                      break
                credentials += '=='
                credentials = base64.b64decode(credentials)
                user = ""
                passw = ""
                m = 0
                for i in credentials:
                    if i==":":
                        m = 1
                    if(m==0):
                        user+=i
                    else:
                        if(i!=":"):
                            passw+=i

                print 'ALERT #' + str(count) + ': Username and password sent in-the-clear from ' + ip_address + ' (HTTP) (username:'+ user +',' +' password:'+ passw+')!'
            elif single_dash:
                count += 1
                new_credentials = ""
                credentials = ""
                credentials += single_dash.group(1)
                for c in credentials:
                    if c == "'":
                      for a in credentials:
                          if(a == "'"):
                            break
                          else:
                            new_credentials +=a
                      credentials = new_credentials
                      break
                credentials += '='
                credentials = base64.b64decode(credentials)
                user = ""
                passw = ""
                m = 0
                for i in credentials:
                    if i==":":
                        m = 1
                    if(m==0):
                        user+=i
                    else:
                        if(i!=":"):
                            passw+=i
                print 'ALERT #' + str(count) + ': Username and password sent in-the-clear from ' + ip_address + ' (HTTP) (username:'+ user +',' +' password:'+ passw+')!'

