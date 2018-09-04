#!/usr/bin/python3
# coding: utf8
#Simple Analyzer v1.03 22.03.2018
#The autor of the program, Victor Koryakin

import socket
import struct
import time
import os
import threading    #DON'T USED
import math
import sys    #DON'T USED
import subprocess    
import argparse

binfolder=os.path.split(__file__)[0]+'/'  #DON'T USED
parser = argparse.ArgumentParser()    #создаем парсер
parser.add_argument("-m", "--multicast", help="IP multicast address")   #добавляем параметры которые будем вводить
parser.add_argument("-p", "--port", type=int, help="IP multicast port (integer)")
parser.add_argument("-z", "--zabbix", help="Zabbix server ip address")
parser.add_argument("-s", "--server", help="Hostname in zabbix system")
parser.add_argument("-k", "--key", help="Key for the data element in zabbix")
parser.add_argument("-t", "--timeN", type=int, help="The value of the period of analysis")
args = parser.parse_args()   #переменная с аргументами
print(args)
if args.multicast : mcast_grp=args.multicast   #задаем отдельные аргументы приих наличии
if args.port : mcast_port=args.port
if args.timeN : timeN=args.timeN
if args.zabbix : zabbix_ip=args.zabbix
if args.server : host_name=args.server
if args.key : key=args.key

cc_reset_timer=3600   #период сброса ошибок СС

print('Start parametrs: ' + mcast_grp +':'+ str(mcast_port)  )          #DON'T USED

addrinfo = socket.getaddrinfo(mcast_grp, None)[0]
sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
sec=2    #время ожидания входного пакета, секунд
usec=0    #время ожидания входного пакета, микросекунд
timeval = struct.pack('ll', sec, usec)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)    
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((mcast_grp, mcast_port))
group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])

mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)  

# Функция анализа  TS-пакета
def TSreader(d, data, tslenght=188) :         #  d{ pid : countCC, errCC, Npackets, битрейт}
    for j in range(0,math.floor(len(data)/tslenght)):   # пробегаемся по всем ts-пакетам в принятом eth-пакете
        if data[j*tslenght]==71 :  # убеждаемся что первый байт в пакете это байт синхронизации
            pid=int.from_bytes(data[(1+j*tslenght):(3+j*tslenght)], byteorder='big')&8191  #определяем пид принятого пакета
            cc=data[3+j*tslenght]&15  #определяем CC принятого пакета
            if d.get(pid) :   #анализируем: если данный пид уже есть в слловаре, то
                if cc - d[pid][0] == 1 or cc - d[pid][0] ==-15 or cc==d[pid][0] :   #если текущее значение СС на единицу больше предыдущего !!! cc==d[pid][0] - это неправильно, но  со сплайсером только так можно работать
                    d[pid][0]=cc  #запоминаем новое значение счетчика СС
                else :            #если есть ошибка СС, то
                    d[pid][1]=d[pid][1]+1  #увеличиваем счетчик ошибок на единицу
                    d[pid][0]=cc  #запоминаем новое значение счетчика СС
                d[pid][2]=d[pid][2]+1      #запоминаем новое значение счетчика пакетов
            else :    #если данного пида нет  в слловаре, то
                d[pid]=[cc,0,1]
        else :
            print('byaka v potoke')
    return [d]

#rezFile=binfolder + 'status' + '.txt'
#rezFile = open(rezFile,'w') #открываем файл с данными на запись
i=0  #счетчик прочитанных пакетов
d={}   #инициализировали словарь в который будут записываться текущие результаты
rezult=[0,0,0]    #результат который будем отправлять в заббикс [CC,bitrate,полезный битрейт]
speed_8191=0      #задаем нулевое значение для скорости последнего пида.
t=time.time()   #таймер для определения битрейта (примерно каждые 30 секунд ил иминуту)
tt=time.time()   #период накопления ошибок (примерно раз в час)
flagrate=1     #флаг наличия битрейта
while True :   #основной цикл
    try:
        data, sender = sock.recvfrom(1500)  #читаем за раз до 1500 байт
    except socket.error as serr:            #если долго не приходит ожидаемый пакет, то отправляем забиксу информацию о нулевом битрейте
        if flagrate==1 :
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate -o ' + str(0), shell=True  )
            print('timeout')
        flagrate=flagrate+1     # увеличиваем зачение флага на единицу
        if flagrate==30 : flagrate=1     #как только счетчик дойдет до 30 (30*2=60 секунд) он сбросится к единице и забиксу повторно отправится сообщение о нулевом битрейте
    else :
        flagrate=1      #если битрейт восстановится то флагу снова присваиваем значение 1
        while data[-1:] == '\0': data = data[:-1]   
        # Процедура анализа пакета анализа TS-пакета
        d=TSreader(d, data)[0]       #вызываем функцию обработки пакета и получаем новое значение словаря d
        if time.time()-t > timeN :   #проверяем, если пора обработать результат, то
            rezult=[0,0,0]    #сбрасываем результат для забикса
            for keys in d.keys() :    #пробегаемся по всем пидам (записям словаря)
                speed=math.floor(d[keys][2]*188*7/timeN)     #определили скорость по конкретному PID-у
                d[keys][2]=0       #и сбросили счетчик пакетов в основном словаре
                if len(d[keys]) == 3 :    #если в словаре ещё нет инфрмации  о битрейте (столбец№3), то  добавлеем полученное значение скорости в словарь
                    d[keys].append(speed)
                else :
                    d[keys][3]=speed
                if keys < 8191 :         #если номер пида не последний то учитываем его ошибки
                    rezult[0]=rezult[0] + d[keys][1]    #суммируем ошибки по всем PID
                else :     # а если мы анализиуем последний пид, то посчитаем его скорость
                    speed_8191=d[keys][3]  #посчитали скорость последнего пида
                rezult[1]=rezult[1] + speed    #суммируем битрейт по всем PID
            rezult[2]=rezult[1] - speed_8191    #определили полезную скорость вычтя из общей скорость последнего пида
            t=time.time()
            print(rezult)
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'cc -o ' + str(rezult[0]), shell=True )
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate -o ' + str(rezult[1]), shell=True  )
            processsender=subprocess.Popen('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate_useful -o ' + str(rezult[2]), shell=True  )
            #print('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'cc -o ' + str(rezult[0])  )
            #print('zabbix_sender -z ' + zabbix_ip + ' -s "' + host_name + '" -k ' + key + 'rate -o ' + str(rezult[1])  )
            print('----')
        if time.time()-tt > cc_reset_timer :    #если прошёл уже час, то сбрасываем счетчик ошибок 
            tt=time.time()
            for keys in d.keys() :    #пробегаемся по всем пидам 
                d[keys][1]=0    #обнуляем накопленные ошибки
