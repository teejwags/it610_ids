#Some code adapted from www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension
#Some code adapted from www.w3schools.com/python
import socket
from struct import *
import datetime
import pcapy
import netifaces
import mysql.connector
import datetime

def main():
    print("Monitoring on interface enp0s3")
    cap = pcapy.open_live("enp0s3",65536,1,0)
    while True:
        (header, packet) = cap.next()
        parsed = parse_packet(packet)
        if('srcIP' in parsed and parsed['srcIP'] != netifaces.ifaddresses('enp0s3')[netifaces.AF_INET][0]['addr']):
            db_action(parsed)

def eth_addr(a):
    b = a.hex()
    c = ""
    for i in range(0, 12, 2):
        c+=b[i:i+2]
        if(i != 10): 
            c+=":"
    return c

def parse_packet(packet):
    now = datetime.datetime.now()
    returninfo={'timestamp':now.replace(hour=now.hour-5).strftime("%Y/%m/%d %H:%M:%S.%f")}
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH',eth_header)
    eth_protocol = socket.ntohs(eth[2])
    returninfo['srcMAC']=eth_addr(packet[6:12])

    if(eth_protocol==8):
        ip_header = packet[eth_length:20+eth_length]
        iph=unpack('!BBHHHBBH4s4s',ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        returninfo['srcIP']=str(s_addr)
        d_addr = socket.inet_ntoa(iph[9])

        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
            tcph=unpack('!HHLLBBHHH',tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            returninfo['srcPort']=source_port
            returninfo['destPort']=dest_port
            h_size=eth_length+iph_length+tcph_length * 4
            data_size=len(packet)-h_size
            data=packet[h_size:]
            returninfo['payload']= data.decode(encoding='utf-8',errors='ignore')

        elif protocol==1:
            u=iph_length +eth_length
            icmph_length = 4
            icmp_header=packet[u:u+4]
            icmph=unpack('!BBH',icmp_header)
            icmp_type=icmph[0]
            code=icmph[1]
            checksum=icmph[2]
            h_size=eth_length+iph_length+icmph_length
            data_size=len(packet)-h_size
            data=packet[h_size:]
            returninfo['payload']= data.decode(encoding='utf-8',errors='ignore')

        elif protocol==17:
            u = iph_length+eth_length
            udph_length = 8
            udp_header=packet[u:u+8]
            udph=unpack('!HHHH',udp_header)
            source_port=udph[0]
            dest_port=udph[1]
            length=udph[2]
            checksum=udph[3]
            returninfo['srcPort']=source_port
            returninfo['destPort']=dest_port
            h_size=eth_length+iph_length+udph_length
            data_size=len(packet)-h_size
            data=packet[h_size:]
            returninfo['payload']= data.decode(encoding='utf-8',errors='ignore')

        else:
            print('Protocol other than TCP, UDP, or ICMP and cannot be processed.')
    return returninfo

def db_action(data):
    try:
        sentlog = False
        idsdb = mysql.connector.connect(host='localhost',user='ids',passwd=<password>,database='ids_log')
        idscursor = idsdb.cursor(prepared=True)
        sql = """SELECT * FROM ids_records WHERE source_ip=%s"""
        params = (data.get('srcIP'),)
        idscursor.execute(sql,params)
        sir = idscursor.fetchall()
        sameip = 0
        for row in sir:
            sameip += 1
        sql = """SELECT * FROM ids_records WHERE source_mac=%s"""
        params = (data.get('srcMAC'),)
        idscursor.execute(sql,params)
        smr = idscursor.fetchall()
        samemac = 0
        for row in smr:
            samemac += 1
        if(sameip == 0 or samemac == 0):
            log_info(data, "New Source Host [")
            sentlog = True
        sql = """SELECT * FROM ids_records WHERE source_ip=%s AND source_mac=%s AND payload LIKE %s"""
        compstring = data['payload'][:8] +'%' +data['payload'][-8:]
        params = (data.get('srcIP'),data.get('srcMAC'),compstring,)
        idscursor.execute(sql,params)
        spr = idscursor.fetchall()
        samepackets = 0
        for row in spr:
            samepackets += 1
        if(samepackets == 0 and sentlog == False):
            log_info(data, "Atypical Data Received [ ")
        sql = """INSERT INTO ids_records (timestamp, source_mac, source_ip, source_port, dest_port, payload) VALUES (%s, %s, %s, %s, %s, %s)"""
        params = (data.get('timestamp'),data.get('srcMAC'),data.get('srcIP'),data.get('srcPort'),data.get('destPort'),data.get('payload'),)
        idscursor.execute(sql, params)
        idsdb.commit()
    except mysql.connector.Error as error:
        print("MySQL error: ".format(error))
    finally:
        if(idsdb.is_connected()):
            idsdb.close()
            idscursor.close()
    
def log_info(data, cause):
    logfile = open("log_ids.log","a")
    logfile.write('(')
    logfile.write(data['timestamp'])
    logfile.write(') WARNING: ')
    logfile.write(cause)
    logfile.write('Source IP: ')
    logfile.write(data['srcIP'])
    logfile.write(' Source MAC: ')
    logfile.write(data['srcMAC'])
    logfile.write('] [see database record for additional details.]\n')
    logfile.close()
    print("Potentially suspicious network activity detected. Check log for details (PATH: ./log_ids.log).")

if(__name__ =="__main__"):
    main()
