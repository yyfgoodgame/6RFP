import multiprocessing
import sys  
from io import StringIO
import time

import random
import re
import string
import json

import numpy as np
from  statsmodels.sandbox.stats.runs import runstest_1samp
import math

from scapy.all import *
import ipaddress
import socket
import pyshark

def is_ipv6(address):
    try:
        ipaddress.IPv6Address(address)
        return True
    except:
        return False

def is_increase(seq):
    return seq == sorted(seq)
    
def is_cycle(sequence):
    c=0
    sequence.insert(0,0)
    for j in range(1,len(sequence)):
        if sequence[j]-sequence[j-1] < 0:
            c+=1
        if c>=3:
            return False
    return True
    

def judge(sequence):
    odd=[]
    even=[]
    seq=[]
    l=len(sequence)
    
    for i in range(l):
        if int(sequence[i]) > 0:
            seq.append(int(sequence[i]))
            if i%2 == 0:
                even.append(int(sequence[i]))
            else:
                odd.append(int(sequence[i]))
    seq_array=np.array(seq)
    seq_std=np.std(seq_array)
    seq_max=max(seq)

    if is_increase(odd) and is_increase(even) :
        if is_increase(seq) :
            return 'global'
        else:
            return 'local'
    elif is_cycle(odd) and is_cycle(even) :
        if is_cycle(seq) :
            return 'global'
        else:
            return 'local'
    elif runstest_1samp(seq,cutoff='median')[1] >= 0.05 :
        return 'random'
    else:        
        return 'other'

def get_diff(s):
    seq=[]
    for i in s:
        seq.append(int(i))
    l=len(seq)
    r=[]
    for i in range(l):
        if seq[i]>0:
            r.append((i,seq[i]))
            if len(r) >= 2:
                break
    diff=math.floor((r[1][1]-r[0][1])/(r[1][0]-r[0][0]))

    if diff==1:
        return 'one'
    else:
        return 'not one'

def big_or_small(s):
    num=-1
    for i in s:
        if int(i) > 0:
            num=int(i)
            break
    if num<65535:
        return 'small'
    else:
        return 'big'
        
def get_ipid(ipid):
    res=judge(ipid)
    length=len(ipid)
    even_list=[]
    for j in range(length//2):
        if ipid[2*j] > 0:
            even_list.append(ipid[2*j])
    
    if res == 'other':
        ipid_incre='null'
        ipid_num=big_or_small(even_list)
    elif res == 'local':
        ipid_incre=get_diff(even_list)
        ipid_num=big_or_small(even_list)
    elif res =='global':
        ipid_incre=get_diff(ipid)
        ipid_num=big_or_small(even_list)
    else:
        ipid_incre='null'
        ipid_num=big_or_small(even_list)
    
    result=dict()
    result["type"]=res
    result["incre_num"]=ipid_incre
    result["number"]=ipid_num
    
    return result
    


def send_tcp(source,addr,sport,interface):
    packet = IPv6(src=source, dst=addr)/TCP(sport=sport,dport=22, flags='S')
    firstseq=packet[TCP].seq
    response = sr1(packet, timeout=2, verbose=False,iface=interface)
    TTL=0
    Size=0
    SSH_B='null'
    if response:
        tmp_ack=response[TCP].seq
        TTL=response[IPv6].hlim
        Size=len(response)
        packet = IPv6(src=source, dst=addr)/TCP(sport=sport,dport=22, flags="A",ack=tmp_ack+1,seq=firstseq+1)
        response = sr1(packet, timeout=2, verbose=False,iface=interface)
       
        if response:
            if "Raw" in response:
                SSH_B=(response["Raw"].load).decode('utf-8')[:-2]
    
    return TTL,Size,SSH_B
        

def send_udp(local_ip,target_ip,sport,interface):
    packet = IPv6(src=local_ip, dst=target_ip)/UDP(sport=sport,dport=53)
    response = sr1(packet, timeout=2, verbose=False,iface=interface)
    TTL=0
    Size=0
    if response:
        TTL=response[IPv6].hlim
        Size=len(response)
    
    return TTL,Size

def send_icmp(source,addr, data, seq,interface):
    packet = IPv6(src=source,dst=addr, plen=len(data) + 8) / ICMPv6EchoRequest(data=data, seq=seq)
    send(packet, verbose=False,iface=interface)
    response = sniff(count=1, timeout=2,filter='src host %s and icmp6' % addr,iface=interface)
    TTL=0
    IPID=0
    
    if response:
        TTL=response[0][IPv6].hlim
        if 'IPv6 Extension Header - Fragmentation header' in response[0]:
            IPID=response[0]['IPv6 Extension Header - Fragmentation header'].id
    return TTL,IPID


def send_too_big(source,addr, data, mtu,interface):    
    base = IPv6(src=addr,dst=source, plen=len(data) + 8,tc=4,hlim=48)
    extension = ICMPv6EchoReply(data=data, seq=0)
    packet = base / extension
    p=IPv6(raw(packet))
    checksum=p['ICMPv6 Echo Reply'].cksum

    too_big_extension = ICMPv6PacketTooBig(mtu=mtu) / \
        (base / ICMPv6EchoReply(data=data[:mtu - 96], seq=0,cksum=checksum))

    base = IPv6(src=source,dst=addr)

    too_big_packet = base / too_big_extension

    send(too_big_packet, verbose=False,iface=interface)

def send_snmp(source,addr,sport,interface):
    #the payload is extracted from a snmpv3 request
    data=b'0=\x02\x01\x030\x11\x02\x04\x00\xcc\x1f\xba\x02\x03\x00\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x100\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x000\x13\x04\x00\x04\x00\xa0\r\x02\x03r\n\x95\x02\x01\x00\x02\x01\x000\x00'
    base = IPv6(src=source,dst=addr)
    packet = base / UDP(sport=sport,dport=161)/data
    response = sr1(packet, timeout=2, verbose=False,iface=interface)
    
    if response:
        return response
    else:
        return None


def random_generate_data(total_length):
    payload_length = total_length - 40
    data_length = payload_length - 8
    return ''.join(random.choices(string.ascii_letters + string.digits, k=data_length))



def packet_send(target_ips,Host_A,Host_B,interface,rounds,i):
    data = random_generate_data(1300)
    length=len(target_ips)
    result=dict()
    snmp_result=[]
    
    for j in range(length):
        target_ip=target_ips[j].split()[0]
        result[target_ip]=dict()
        
        snmp_res=send_snmp(Host_A,target_ip,30000+i,interface)
        if snmp_res != None:
            snmp_result.append(snmp_res)        
        
        TTL,Size,SSH_B=send_tcp(Host_A,target_ip,30000+i,interface)
        result[target_ip]['tcp']=dict()
        result[target_ip]['ssh']=dict()
        result[target_ip]['tcp']['ttl']=TTL
        result[target_ip]['tcp']['size']=Size
        result[target_ip]['ssh']['type']=SSH_B
        
        TTL,Size=send_udp(Host_A,target_ip,30000+i,interface)
        result[target_ip]['udp']=dict()
        result[target_ip]['udp']['ttl']=TTL
        result[target_ip]['udp']['Size']=Size
        
        result[target_ip]['icmp']=dict()
        result[target_ip]['icmp']['ttl']=0
        result[target_ip]['icmp']['ipid']=[]
        
        if is_ipv6(target_ip):   
            TTL,IPID=send_icmp(Host_A,target_ip, data,0,interface)
            TTL,IPID=send_icmp(Host_B,target_ip, data,0,interface) 

            send_too_big(Host_A,target_ip, data, 1280,interface)
            send_too_big(Host_B,target_ip, data, 1280,interface)
            
            for i in range(rounds):
                TTL,IPID=send_icmp(Host_A,target_ip, data, 2*i+1,interface)
                result[target_ip]['icmp']['ipid'].append(IPID)
                if TTL != 0:
                    result[target_ip]['icmp']['ttl']=TTL
                    
                TTL,IPID=send_icmp(Host_B,target_ip, data, 2*i+2,interface)
                result[target_ip]['icmp']['ipid'].append(IPID)
                if TTL != 0:
                    result[target_ip]['icmp']['ttl']=TTL
    
    return (result,snmp_result)
    
    
def combination(json_file,snmp_file):
    
    only_snmp=dict()
    snmp_6RFP=dict()
    only_6RFP=dict()
    
    f=open(json_file,'r',encoding='utf-8')
    tmp=json.load(f)
    f.close()
    cap=pyshark.FileCapture(snmp_file,display_filter='udp.srcport==161')     #pcap文件

    for i in cap:
        if i.ipv6.nxt == '17':
            ipadd=i.ipv6.src

            old_stdout = sys.stdout 
            captured_output = StringIO()  
            sys.stdout = captured_output  
             
            print((i.snmp)) 
              
            sys.stdout = old_stdout  
              
            output = captured_output.getvalue()  

            pattern = re.compile(r"%s(.*?)$"%'Engine Enterprise ID: ', re.MULTILINE | re.DOTALL)  
            matches = pattern.findall(output)   
            unique_matches = set(matches)
            for match in unique_matches:  
                vendor=match.rsplit(' ',1)[0]
                
            if vendor != 'Unknown' and vendor != 'net-snmp':
                if ipadd in tmp and len(tmp[ipadd]['icmp']['ipid']) >=8 :
                    snmp_6RFP[ipadd]=tmp[ipadd]
                    ipid_info=get_ipid(tmp[ipadd]['icmp']['ipid'])
                    del snmp_6RFP[ipadd]['icmp']['ipid']
                    snmp_6RFP[ipadd]['ipid']=ipid_info
                    snmp_6RFP[ipadd]['snmp']=dict()
                    snmp_6RFP[ipadd]['snmp']['vendor']=vendor
                    del tmp[ipadd]
                else:
                    only_snmp[ipadd]=dict()
                    only_snmp[ipadd]['vendor']=vendor
    
    for i in tmp:
        only_6RFP[i]=tmp[i]
        ipid_info=get_ipid(tmp[i]['icmp']['ipid'])
        del only_6RFP[i]['icmp']['ipid']
        only_6RFP[i]['ipid']=ipid_info
        
        
    
    with open('./only_snmp.json','w',encoding='utf-8') as f:
        json.dump(only_snmp, f, ensure_ascii=False, indent=4)
    with open('./snmp_6RFP.json','w',encoding='utf-8') as f:
        json.dump(snmp_6RFP, f, ensure_ascii=False, indent=4)
    with open('./only_6RFP.json','w',encoding='utf-8') as f:
        json.dump(only_6RFP, f, ensure_ascii=False, indent=4)
                
                      


def run(target_file,Host_A,Host_B,snmp_file,json_file,interface,process_number=50,rounds=15):
    f=open(json_file,'a+',encoding='utf-8')
    g = PcapWriter(snmp_file,append=True)
    json_dict=dict()
    with open(target_file, 'r', encoding='utf-8') as input_stream:
        p = multiprocessing.Pool(process_number)
        lines = input_stream.readlines()
        random.shuffle(lines)
        batch_size=len(lines)
        m=time.time()
        result=[]

        for i in range(process_number):
            t=batch_size//process_number
            if i == process_number-1:
                target_ips = lines[i*t:]
            else:
                target_ips = lines[i*t:i*t+t]
            
            result.append(p.apply_async(packet_send, args=(
                target_ips,Host_A,Host_B,interface,rounds,i)))
        p.close()
        p.join()
        n=time.time()
        print('Detecting cost %ds'%(n-m))
        
        for i in result:
            res=i.get()
            json_dict.update(res[0])
            for j in res[1]:
                g.write(j)
        json.dump(json_dict, f, ensure_ascii=False, indent=4)
        
        f.close()
        g.close()




if __name__ == '__main__':
    Host_A=''   
    Host_B=''
    target_file='./tar.txt'    #file containing ipv6 address for scanning
    interface=''               
    snmp_file=''               #file store snmp scanning result
    json_file=''               #file store 6RFP scanning result
    
    #scanning using multiprocessing
    run(target_file,Host_A,Host_B,snmp_file,json_file,interface,process_number=2,rounds=5)
    
    #analysis of snmp and 6RFP , generating only_snmp.json , snmp_6RFP.json , only_6RFP.json in current directory
    combination(json_file,snmp_file)    
    
    
    
    







