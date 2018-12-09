from scapy.all import*
import pcapy
import sys
import argparse
import socket
import fcntl
import struct
import base64
import re

from alarm import count, FTP_user, FTP_pass

def pass_FTP(packet, ip_address):
    global count
    global FTP_pass
    global FTP_user
    data = str(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))

    if data.find('USER') != -1:
        k = 0
        sample  = data
        for i in sample:
            if(i==" "):
                k = 1
            if(k==1 and i != " "):
                if (i=='"'):
                    break
                FTP_user+= i

    elif 'PASS' in data:
        k = 0
        sample  = data
        for i in sample:
            if(i==" "):
                k = 1
            if(k==1 and i != " "):
                if (i=='"'):
                    break
                FTP_pass+= i
    else:
        if(data.find('230') != -1):
            count += 1
            print 'ALERT #' + str(count) + ': Username and password sent in-the-clear from ' + ip_address + ' (FTP) (username:'+ FTP_user +',' +' password:'+ FTP_pass+')!'

