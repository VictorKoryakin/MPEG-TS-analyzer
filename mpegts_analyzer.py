#!/usr/bin/python3
# coding: utf8
#Simple Analyzer v1.03 22.03.2018
#The autor of the program, Victor Koryakin
#

import socket
import struct
import time
import os
import threading    #DON'T USED
import math
import sys    #DON'T USED
import subprocess    
import argparse

binfolder=os.path.split(__file__)[0]+'/'  #���������� ��� �������� � ������� ����� ���� ��

#������ ������� �������
parser = argparse.ArgumentParser()    #������� ������

parser.add_argument("-m", "--multicast", help="IP multicast address")   #��������� ��������� ������� ����� �������
parser.add_argument("-p", "--port", type=int, help="IP multicast port (integer)")
parser.add_argument("-z", "--zabbix", help="Zabbix server ip address")
parser.add_argument("-s", "--server", help="Hostname in zabbix system")
parser.add_argument("-k", "--key", help="Key for the data element in zabbix")
parser.add_argument("-t", "--timeN", type=int, help="The value of the period of analysis")
args = parser.parse_args()   #���������� � �����������
print(args)
if args.multicast : mcast_grp=args.multicast   #������ ��������� ��������� ����� �������
if args.port : mcast_port=args.port
if args.timeN : timeN=args.timeN
if args.zabbix : zabbix_ip=args.zabbix
if args.server : host_name=args.server
if args.key : key=args.key

cc_reset_timer=3600   #������ ������ ������ ��

print('Start parametrs: ' + mcast_grp +':'+ str(mcast_port)  )          #DON'T USED

#��������� ����� ��� ������������� �����������
addrinfo = socket.getaddrinfo(mcast_grp, None)[0]
sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

sec=2    #����� �������� �������� ������, ������
usec=0    #����� �������� �������� ������, �����������
timeval = struct.pack('ll', sec, usec)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)    #������ ��������� (����� �������� �������� ������) ������

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((mcast_grp, mcast_port))
group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])

mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)  #����� ����� �������� ����� ����������� �� ����������, � ���������� igmp ������

#0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
#0000000000000000000000000000000000000000000000000000000000000000000
#0000000000000000000000000000000000000000000000000000
# ������� �������  TS-������
def TSreader(d, data, tslenght=188) :         #  d{ pid : countCC, errCC, Npackets, �������}
    for j in range(0,math.floor(len(data)/tslenght)):   # ����������� �� ���� ts-������� � �������� eth-������
        if data[j*tslenght]==71 :  # ���������� ��� ������ ���� � ������ ��� ���� �������������
            pid=int.from_bytes(data[(1+j*tslenght):(3+j*tslenght)], byteorder='big')&8191  #���������� ��� ��������� ������
            cc=data[3+j*tslenght]&15  #���������� CC ��������� ������
            if d.get(pid) :   #�����������: ���� ������ ��� ��� ���� � ��������, ��
                if cc - d[pid][0] == 1 or cc - d[pid][0] ==-15 or cc==d[pid][0] :   #���� ������� �������� �� �� ������� ������ ����������� !!! cc==d[pid][0] - ��� �����������, ��  �� ���������� ������ ��� ����� ��������
                    d[pid][0]=cc  #���������� ����� �������� �������� ��
                else :            #���� ���� ������ ��, ��
                    d[pid][1]=d[pid][1]+1  #����������� ������� ������ �� �������
                    d[pid][0]=cc  #���������� ����� �������� �������� ��
                d[pid][2]=d[pid][2]+1      #���������� ����� �������� �������� �������
            else :    #���� ������� ���� ���  � ��������, ��
                d[pid]=[cc,0,1]
        else :
            print('byaka v potoke')
    return [d]
#0000000000000000000000000000000000000000000000000000
#0000000000000000000000000000000000000000000000000000000000000000000
#0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

#rezFile=binfolder + 'status' + '.txt'
#rezFile = open(rezFile,'w') #��������� ���� � ������� �� ������
i=0  #������� ����������� �������
d={}   #���������������� ������� � ������� ����� ������������ ������� ����������
rezult=[0,0,0]    #��������� ������� ����� ���������� � ������� [CC,bitrate,�������� �������]
speed_8191=0      #������ ������� �������� ��� �������� ���������� ����.
t=time.time()   #������ ��� ����������� �������� (�������� ������ 30 ������ �� �������)
tt=time.time()   #������ ���������� ������ (�������� ��� � ���)
flagrate=1     #���� ������� ��������
while True :   #�������� ����
    try:
        data, sender = sock.recvfrom(1500)  #������ �� ��� �� 1500 ����
    except socket.error as serr:            #���� ����� �� �������� ��������� �����, �� ���������� ������� ���������� � ������� ��������
        if flagrate==1 :
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate -o ' + str(0), shell=True  )
            print('timeout')
        flagrate=flagrate+1     # ����������� ������� ����� �� �������
        if flagrate==30 : flagrate=1     #��� ������ ������� ������ �� 30 (30*2=60 ������) �� ��������� � ������� � ������� �������� ���������� ��������� � ������� ��������
    else :
        flagrate=1      #���� ������� ������������� �� ����� ����� ����������� �������� 1
        while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's    �.�. ������� ��������� ���� � ����� ������, �������� �����
        # ��������� ������� ������ ������� TS-������
        d=TSreader(d, data)[0]       #�������� ������� ��������� ������ � �������� ����� �������� ������� d
        if time.time()-t > timeN :   #���������, ���� ���� ���������� ���������, ��
            rezult=[0,0,0]    #���������� ��������� ��� �������
            for keys in d.keys() :    #����������� �� ���� ����� (������� �������)
                speed=math.floor(d[keys][2]*188*7/timeN)     #���������� �������� �� ����������� PID-�
                d[keys][2]=0       #� �������� ������� ������� � �������� �������
                if len(d[keys]) == 3 :    #���� � ������� ��� ��� ���������  � �������� (��������3), ��  ��������� ���������� �������� �������� � �������
                    d[keys].append(speed)
                else :
                    d[keys][3]=speed
                if keys < 8191 :         #���� ����� ���� �� ��������� �� ��������� ��� ������
                    rezult[0]=rezult[0] + d[keys][1]    #��������� ������ �� ���� PID
                else :     # � ���� �� ���������� ��������� ���, �� ��������� ��� ��������
                    speed_8191=d[keys][3]  #��������� �������� ���������� ����
                rezult[1]=rezult[1] + speed    #��������� ������� �� ���� PID
            rezult[2]=rezult[1] - speed_8191    #���������� �������� �������� ����� �� ����� �������� ���������� ����
            t=time.time()
            print(rezult)
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'cc -o ' + str(rezult[0]), shell=True )
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate -o ' + str(rezult[1]), shell=True  )
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate_useful -o ' + str(rezult[2]), shell=True  )
            #print('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'cc -o ' + str(rezult[0])  )
            #print('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate -o ' + str(rezult[1])  )
            print('----')
        if time.time()-tt > cc_reset_timer :    #���� ������ ��� ���, �� ���������� ������� ������ � �������
            tt=time.time()
            for keys in d.keys() :    #����������� �� ���� ����� (������� �������)
                d[keys][1]=0    #�������� ����������� � ������� ������



