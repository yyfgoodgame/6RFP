import re
import matplotlib
import sklearn.tree
from sklearn.datasets import load_iris
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier, plot_tree ,DecisionTreeRegressor ,export_graphviz  
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
import numpy as np
import matplotlib.pyplot as plt
from itertools import groupby
import pandas
import json 
#import graphviz 
import random
from io import StringIO
import pydotplusx
import graphviz





def normalize_array_to_range(arr, min_range=0, max_range=65535):
    # Assume arr is a list of (key, value) tuples
    if not arr:
        return []

    # Find the maximum and minimum values of value
    min_value = min(value for _, value in arr)
    max_value = max(value for _, value in arr)

    # If the maximum value equals the minimum value, return the original array (or an array where all values are min_range)
    if max_value == min_value:
        return [(key, min_range) for key, value in arr]

    # Normalize the array to the range (0, 65535)

    normalized_arr = [(key, int((value - min_value) / (max_value - min_value) * (max_range - min_range) + min_range))  
                      for key, value in arr]  
      
    return normalized_arr  

def cal_runs(sarray):
    smedian=np.median(sarray)
    runtest=[]
    for i in sarray:
        if i<=smedian:
            runtest.append(0)
        else:
            runtest.append(1)
    return sum(1 for _ in groupby(runtest))

def duldiff(array):
    l=[]
    for i in range(len(array)//2):
        l.append(abs(array[2*i+1]-array[2*i]))
    return np.mean(abs(np.diff(l)))


def get_ttl(ttl):
    if ttl < 32:
        return 32
    elif ttl < 64:
        return 64
    elif ttl < 128:
        return 128
    else:
        return 255

def load_my_data(file):
    f=open(file, 'r', encoding='utf-8')
    data=[]
    label=[]
    jsoncontent=json.load(f)

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    #vendor_dict={'ciscoSystems': 1, 'Juniper': 2, 'HUAWEI': 3, 'Casa': 4, 'net-snmp': 5, 'Teracom': 6, 'Adtran': 7, 'Brocade': 8, 'Ruijie': 9, 'FS.COM': 10, 'Dell': 11, 'H3C': 12, 'Extreme': 13, 'Stale': 14, 'nVent,': 15, 'OneAccess': 16, 'Alcatel-Lucent': 17, 'Hewlett-Packard': 18,'Unknown': 19}
    vendor_dict={'HUAWEI': 1, 'Juniper': 2, 'ciscoSystems': 3, 'OneAccess': 4, 'Ruijie': 5, '3Com': 6, 'Extreme': 7, 'Brocade': 8, 'Unknown': 9, 'H3C': 10, 'Hewlett-Packard': 11, 'Casa': 12, 'Dell': 13, 'RND': 14, 'net-snmp': 15, 'Teracom': 16, 'D-Link': 17, 'FS.COM': 18, 'RiverDelta': 19, 'Hewlett': 20, 'Broadcom': 21, 'nVent,': 22, 'ACCTON': 23, 'Alcatel-Lucent': 24, 'Maipu': 25, 'Alteon': 26, 'TP-Link': 27, 'Shanghai': 28, 'Adtran': 29, 'ZyXEL': 30, 'SonicWALL,': 31, 'Furukawa': 32, 'Microsoft': 33, 'Rad': 34, 'NAG': 35, 'Beijing': 36, 'Stale': 37, 'Enterasys': 38, 'LANCOM': 39, 'Blade': 40}

    for i in jsoncontent:
        line=jsoncontent[i]
        
        #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']],line['tcp_icmp'],line['udp_icmp']]
        #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
        linelabel=vendor_dict[line['snmp']['vendor']]

        data.append(feature)
        label.append(linelabel)


    f.close()

    return data,label


def random_dic(dicts):
    dict_key_ls = list(dicts.keys())
    random.shuffle(dict_key_ls)
    new_dic = {}
    for key in dict_key_ls:
        new_dic[key] = dicts.get(key)
    return new_dic


def load_ssh_data(file):
    f=open(file, 'r', encoding='utf-8')
    data=[]
    label=[]
    data_label=[]
    jsoncontent=json.load(f)
    jsoncontent=random_dic(jsoncontent)
    cc=0
    tt=0

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    #vendor_dict={'ciscoSystems': 1, 'Juniper': 2, 'HUAWEI': 3, 'Casa': 4, 'net-snmp': 5, 'Teracom': 6, 'Adtran': 7, 'Brocade': 8, 'Ruijie': 9, 'FS.COM': 10, 'Dell': 11, 'H3C': 12, 'Extreme': 13, 'Stale': 14, 'nVent,': 15, 'OneAccess': 16, 'Alcatel-Lucent': 17, 'Hewlett-Packard': 18,'Hewlett':19,'Unknown': 20,'Alteon':21,'ZyXEL':22,'NAG':23}
    #ssh_raw={'SSH-1.99-OpenSSH_6.1': 1, 'SSH-2.0-OpenSSH_7.2 FIPS': 2, 'SSH-2.0-OpenSSH_8.8': 3, 'SSH-1.99-OpenSSH_7.3': 4, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 5, 'SSH-2.0-OpenSSH_7.4': 6, 'SSH-2.0-OpenSSH_6.4': 7, 'SSH-2.0-OpenSSH_6.9': 8, 'SSH-2.0-OpenSSH_8.0': 9, 'SSH-2.0-OpenSSH_9.0': 10, 'SSH-2.0-Adtran_4.31': 11, 'SSH-2.0-OpenSSH_5.9 FIPS': 12, 'SSH-2.0-OpenSSH_5.5 FIPS': 13, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 14, 'SSH-2.0-OpenSSH_7.1': 15, 'SSH-1.99-RGOS_SSH': 16, 'SSH-2.0-RomSShell_4.61': 17, 'SSH-2.0-OpenSSH_4.4': 18, 'SSH-1.99-SSH': 19, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 20, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 21, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 22, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 23, 'SSH-1.99-OpenSSH_6.9': 24, 'SSH-2.0-OpenSSH_5.8': 25, 'SSH-2.0-RGOS_SSH': 26, 'SSH-2.0-OpenSSH_7.5': 27, 'SSH-1.99-Cisco-1.25': 28, 'SSH-2.0-OpenSSH_6.6': 29, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 30, 'SSH-2.0-OpenSSH_6.2': 31, 'SSH-1.99-OpenSSH_6.4': 32, 'SSH-2.0-OpenSSH_6.1': 33, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 34, 'SSH-2.0-OpenSSH_7.3': 35, 'SSH-2.0-OpenSSH_6.2 FIPS': 36, 'SSH-1.99--': 37, 'SSH-2.0-RomSShell_5.40': 38, 'SSH-2.0-SSH': 39, 'SSH-2.0-Cisco-1.25': 40, 'SSH-2.0-OpenSSH_6.6.1': 41, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 42, 'SSH-2.0-OpenSSH_6.0': 43, 'SSH-2.0-OpenSSH_5.9': 44, 'SSH-2.0-OpenSSH_7.2': 45, 'SSH-2.0-ZTE_SSH.2.0': 46, 'SSH-2.0--': 47,'SSH-1.99-OpenSSH_6.0':48,'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]':49,'SSH-1.99-OpenSSH_4.4':50,'SSH-2.0-Alteon':51,'SSH-2.0-RGOS_PK3223':52,'SSH-1.99-OpenSSH_5.8':53,'SSH-1.99-OpenSSH_6.2':54,'SSH-2.0-SERVER_1.01':55}
    ssh_raw={'SSH-2.0-Cisco-1.25': 1, 'SSH-2.0-OpenSSH_7.5': 2, 'null': 3, 'SSH-2.0--': 4, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 5, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 6, 'SSH-2.0-OpenSSH_7.4': 7, 'SSH-2.0-ROSSSH': 8, 'SSH-2.0-OpenSSH_6.9': 9, 'SSH-2.0-OpenSSH_7.3': 10, 'SSH-2.0-OpenSSH_7.2': 11, 'SSH-2.0-Comware-7.1.075': 12, 'SSH-1.99-Cisco-1.25': 13, 'SSH-2.0-OpenSSH_7.2 FIPS': 14, 'SSH-2.0-OpenSSH_6.6.1': 15, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 16, 'SSH-2.0-OpenSSH_5.9': 17, 'SSH-2.0-HUAWEI-1.5': 18, 'SSH-2.0-OpenSSH_6.4': 19, 'SSH-2.0-OpenSSH_5.9 FIPS': 20, 'SSH-2.0-OpenSSH_6.0': 21, 'SSH-2.0-OpenSSH_6.2': 22, 'SSH-2.0-OpenSSH_4.4': 23, 'SSH-1.99-Comware-7.1.045': 24, 'SSH-2.0-RomSShell_5.40': 25, 'SSH-2.0-OpenSSH_6.2 FIPS': 26, 'SSH-2.0-OpenSSH_5.5 FIPS': 27, 'SSH-2.0-Comware-7.1.070': 28, 'SSH-2.0-Cisco-2.0': 29, 'SSH-2.0-Comware-7.1.059': 30, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 31, 'SSH-2.0-OpenSSH_8.0': 32, 'SSH-2.0-RGOS_SSH': 33, 'SSH-2.0-OpenSSH_5.8': 34, 'SSH-2.0-RomSShell_4.61': 35, 'SSH-2.0-OpenSSH_7.1': 36, 'SSH-2.0-OpenSSH_8.8': 37, 'SSH-2.0-SSH': 38, 'SSH-2.0-OpenSSH_6.1': 39, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 40, 'SSH-2.0-Comware-9.0.001': 41, 'SSH-2.0-OpenSSH_9.5 FreeBSD-20231004': 42, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 43, 'SSH-2.0-Adtran_4.31': 44, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 45, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719': 46, 'SSH-2.0-Dh-v39EVDB8f6LZ': 47, 'SSH-2.0-OpenSSH_9.7 FreeBSD-20240318': 48, 'SSH-1.99-OpenSSH_6.9': 49, 'SSH-1.99-RGOS_SSH': 50, 'SSH-1.99--': 51, 'SSH-2.0-SERVER_1.01': 52, 'SSH-1.99-OpenSSH_6.0': 53, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240104': 54, 'SSH-2.0-Mocana SSH 6.3': 55, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 56, 'SSH-2.0-RGOS_PK3223': 57, 'SSH-1.99-SSH': 58, 'SSH-2.0-OpenSSH_7.8 FreeBSD-20180909': 59, 'SSH-1.99-OpenSSH_7.3': 60, 'SSH-1.99-OpenSSH_6.1': 61, 'SSH-1.99-OpenSSH_6.8': 62, 'SSH-2.0-Comware-7.1.064': 63, 'SSH-1.99-OpenSSH_6.4': 64, 'SSH-1.99-Comware-7.1.075': 65, 'SSH-2.0-OpenSSH_7.7p1': 66, 'SSH-2.0-OpenSSH_6.6': 67, 'SSH-2.0-Comware-9.1.058': 68, 'SSH-2.0-WLH_rbHQLlDeyy': 69, 'SSH-1.99-OpenSSH_6.2': 70, 'SSH-2.0-OpenSSH_9.0': 71, 'SSH-1.99-OpenSSH_7.2p2': 72, 'SSH-2.0-Comware-7.1.045': 73, 'SSH-2.0-Alteon': 74, 'SSH-2.0-RGOS_SSH_1.0': 75, 'SSH-1.99-OpenSSH_5.8': 76, 'SSH-2.0-OpenSSH_3.5p1': 77, 'SSH-1.99-OpenSSH_6.6.1': 78, 'SSH-1.99-OpenSSH_4.4': 79, 'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]': 80, 'SSH-1.99-HUAWEI-1.5': 81, 'SSH-2.0-lancom': 82, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3': 83, 'SSH-2.0-dropbear': 84, 'SSH-2.0-OpenSSH_7.8': 85, 'SSH-2.0-OpenSSH_9.2p1': 86, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7': 87, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6': 88, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11': 89, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10': 90, 'SSH-2.0-OpenSSH_9.7': 91, 'SSH-2.0-ZTE_SSH.2.0': 92, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u1': 93, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2': 94, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1': 95, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1': 96, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 97, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5': 98, 'SSH-2.0-OpenSSH_9.5': 99, 'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7': 100, 'SSH-2.0-FHSSH_8.0': 101, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4': 102, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2': 103, 'SSH-2.0-OpenSSH_9.6': 104, 'SSH-2.0-OpenSSH_8.9p1': 105, 'SSH-2.0-OpenSSH_5.5': 106, 'SSH-2.0-OpenSSH_8.4p1 Debian-2~bpo10+1': 107, 'SSH-2.0-OpenSSH_9.2p1 Debian-2': 108, 'SSH-2.0-OpenSSH_8.6': 109, 'SSH-2.0-OpenSSH_9.3': 110, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u3': 111, 'SSH-2.0-OpenSSH_9.6p1 Debian-4': 112, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7': 113, 'SSH-2.0-dropbear_2020.81': 114, 'SSH-2.0-OpenSSH_7.9p1': 115, 'SSH-2.0-OpenSSH_6.8': 116, 'SSH-2.0-Mocana SSH 5.8': 117, 'SSH-2.0-OpenSSH_7.9 FreeBSD-20200214': 118, 'SSH-2.0-OpenSSH_7.6': 119, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20221019': 120, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7': 121, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3': 122, 'SSH-2.0-OpenSSH_7.9p1 Debian-10': 123, 'SSH-2.0-OpenSSH_8.7': 124, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2': 125, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3': 126, 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221': 127, 'SSH-2.0-Go': 128, 'SSH-2.0-OpenSSH_4.3': 129, 'SSH-1.99-OpenSSH_8.5': 130, 'SSH-2.0-b95rVonwBt': 131, 'SSH-2.0-OxywS4Oe4sDl': 132, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1': 133, 'SSH-2.0-OpenSSH_8.2p1': 134, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3': 135, 'SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1': 136, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2': 137, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1': 138, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3': 139, 'SSH-2.0-OpenSSH_7.7p1 Debian-2': 140, 'SSH-2.0-OpenSSH_8.4p1 Debian-5': 141, 'SSH-2.0-OpenSSH_9.1': 142, 'SSH-2.0-OpenSSH_9.6p1 Debian-3': 143, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4.ui1': 144, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3': 145, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13': 146, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.7': 147, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2': 148, 'SSH-2.0-OpenSSH_6.3': 149, 'SSH-2.0-dropbear_2019.78': 150, 'SSH-2.0-OpenSSH_Stable': 151, 'SSH-2.0-OpenSSH_7.3p1 Ubuntu-1ubuntu0.1': 152, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8': 153, 'SSH-2.0-OpenSSH_8.4': 154, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2': 155, 'SSH-2.0-OpenSSH_7.2p2': 156, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7': 157, 'SSH-2.0-OpenSSH_8.9': 158, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9': 159, 'SSH-2.0-t1VtSi': 160, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3': 161, 'SSH-2.0-dropbear_2014.63': 162, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8': 163, 'SSH-2.0-dropbear_2022.83': 164, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1': 165, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2': 166, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5': 167, 'SSH-2.0-OpenSSH_8.4p1': 168, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4': 169, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6': 170, 'SSH-2.0-OpenSSH_9.7p1 Debian-5': 171, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3': 172, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1': 173, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4': 174, 'SSH-2.0-OpenSSH_7.9p1 Vyatta-10+deb10u2+danos1': 175, 'SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420': 176, 'SSH-2.0-OpenSSH_8.6p1': 177, 'SSH-2.0-OpenSSH_9.6p1 Debian-2': 178, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10+esm5': 179, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3': 180, 'SSH-2.0-OpenSSH-FIPS(capable)': 181, 'SSH-2.0-OpenSSH_9.0p1 Debian-1+b1': 182, 'SSH-2.0-OpenSSH_8.1': 183, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4': 184, 'SSH-2.0-OpenSSH_9.5p1 Debian-2': 185, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3': 186, 'SSH-2.0-B4I_haIvxy': 187, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4': 188, 'SSH-2.0-OpenSSH_7.6p1': 189, 'SSH-2.0-OpenSSH_7.5 FreeBSD-20170903': 190, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4': 191, 'SSH-2.0-OpenSSH_5.9 NetBSD_Secure_Shell-20110907-hpn13v11-lpk': 192, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4': 193, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20230719': 194, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5': 195, 'SSH-2.0-OpenSSH_5.3': 196, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4': 197, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2': 198, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8': 199, 'SSH-2.0-OpenSSH_7.7': 200, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u3': 201, 'SSH-2.0-OpenSSH_9.4': 202, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u1': 203, 'SSH-2.0-dropbear_2017.75': 204, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5': 205, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.8': 206, 'SSH-2.0-dropbear_2011.54': 207, 'SSH-2.0-dropbear_2015.67': 208, 'SSH-2.0-OpenSSH_8.0p1': 209, 'SSH-2.0-OpenSSH_7.9': 210, 'SSH-1.99-OpenSSH_4.3': 211, 'SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901': 212, 'SSH-2.0-OpenSSH_9.2': 213, 'SSH-2.0-OpenSSH_9.6p1 Debian-5': 214, 'SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20231220-hpn13v14-lpk': 215, 'SSH-2.0-OpenSSH_9.7 FreeBSD-openssh-portable-9.7.p1,1': 216, 'SSH-2.0-Li_mO3m-e_bXh-': 217, 'SSH-2.0-ConfD-6.7.6': 218, 'SSH-2.0-OpenSSH_9.7p1 Debian-4': 219, 'SSH-2.0-OpenSSH_6.7p1': 220, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8': 221, 'SSH-2.0-rPKx-': 222, 'SSH-2.0-OpenSSH_7.5p1 Ubuntu-10ubuntu0.1': 223, 'SSH-2.0-OpenSSH_9.3 FreeBSD-openssh-portable-9.3.p2_2,1': 224, 'SSH-2.0-OpenSSH_9.3 FreeBSD': 225, 'SSH-2.0-billsSSH_3.6.3q3': 226, 'SSH-2.0-Parks': 227, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10': 228, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3': 229, 'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9': 230, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u4': 231, 'SSH-2.0-tiger xxxxxxxxxxxxxxxxxxxxxxxx': 232, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11': 233, 'SSH-2.0-OpenSSH_9.8': 234, 'SSH-2.0-OpenSSH_6.6p2-hpn14v4': 235, 'SSH-2.0-OpenSSH_8.2': 236, 'SSH-2.0-dropbear_2012.55': 237, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6': 238, 'SSH-2.0-OpenSSH_9.7-hpn14v15': 239, 'SSH-2.0-OpenSSH_8.3': 240, 'SSH-2.0-OpenSSH_7.1p2-hpn14v10': 241, 'SSH-2.0-dropbear_2018.76': 242, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4': 243, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6': 244, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240701': 245, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13': 246, 'SSH-2.0-dropbear_2014.66': 247, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7': 248, 'SSH-1.99-OpenSSH_5.3': 249, 'SSH-2.0-OpenSSH_9.7p1 Debian-7': 250, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10': 251, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1': 252, 'SSH-2.0-dropbear_2016.74': 253, 'SSH-2.0-OpenSSH_6.7p1 Debian-5': 254, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6': 255, 'SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3': 256, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1': 257, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3': 258, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5_lol_notrly_JustGoAwayDammit1.0': 259, 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3': 260, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5-lol_notrly_JustGoAwayDammit1.0': 261, 'SSH-2.0-OpenSSH_9.7p1 Debian-6': 262, 'SSH-2.0-OpenSSH_7.4p1 Debian-10': 263, 'SSH-2.0-OpenSSH_8.1 Celeonet': 264, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u9': 265, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20240701': 266, 'SSH-2.0-OpenSSH_7.4p1': 267, 'SSH-2.0-OpenSSH_9.6p1 Raspbian-3': 268, 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310': 269, 'SSH-2.0-OpenSSH_for_Windows_8.9': 270, 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.2': 271, 'SSH-2.0-OpenSSH_6.6p1-hpn14v4': 272, 'SSH-2.0-mod_sftp': 273, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4': 274, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2': 275, 'SSH-2.0-OpenSSH_9.0p1 Debian-1': 276}
    #vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 4, 'Casa Systems, Inc.': 8, 'Ruijie Networks Co., Ltd.': 9, 'Extreme Networks':7, 'Teracom Telematica Ltda.': 10}

    #vendor_dict={ "HUAWEI Technology Co.,Ltd" : 1, 'Sagemcom Broadband SAS': 2, 'zte corporation': 3, 'Intelbras': 4, 'Fiberhome Telecommunication Technologies Co.,LTD': 5, 'Shenzhen Skyworth Digital  Technology  CO., Ltd': 6, 'Space Monkey, Inc.': 7, 'China Mobile Group Device Co.,Ltd.': 8, 'TP-Link Corporation Limited.': 9, 'ciscoSystems': 10}
    
    vendor_dict={'ciscoSystems': 1,  'Juniper Networks, Inc.': 2,  'HUAWEI Technology Co.,Ltd': 3,  'MikroTik': 4,  'H3C': 5,  'Intelbras': 6,  'Sagemcom Broadband SAS': 7,  'zte corporation': 8,  'Brocade Communication Systems, Inc.': 9,  'TP-Link Corporation Limited.': 10}

    for i in jsoncontent:
        flag=True
        line=jsoncontent[i]
        if 'ssh' in line:
            feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
            #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),get_ttl(line['icmpv6']['size'])]
            #feature=[ssh_raw[line['ssh']['type']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
        tt+=1
        try:
            
            linelabel=vendor_dict[line['snmp']['vendor']]

            data_label.append([feature,linelabel])
            cc+=1
        except:
            pass


    f.close()

    random.shuffle(data_label)
    for i in data_label:
        data.append(i[0])
        label.append(i[1])
    return data,label


def load_single_data(line):

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    #vendor_dict={'ciscoSystems': 1, 'Juniper': 2, 'HUAWEI': 3, 'Casa': 4, 'net-snmp': 5, 'Teracom': 6, 'Adtran': 7, 'Brocade': 8, 'Ruijie': 9, 'FS.COM': 10, 'Dell': 11, 'H3C': 12, 'Extreme': 13, 'Stale': 14, 'nVent,': 15, 'OneAccess': 16, 'Alcatel-Lucent': 17, 'Hewlett-Packard': 18,'Hewlett':19,'Unknown': 20,'Alteon':21,'ZyXEL':22,'NAG':23}
    #ssh_raw={'SSH-1.99-OpenSSH_6.1': 1, 'SSH-2.0-OpenSSH_7.2 FIPS': 2, 'SSH-2.0-OpenSSH_8.8': 3, 'SSH-1.99-OpenSSH_7.3': 4, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 5, 'SSH-2.0-OpenSSH_7.4': 6, 'SSH-2.0-OpenSSH_6.4': 7, 'SSH-2.0-OpenSSH_6.9': 8, 'SSH-2.0-OpenSSH_8.0': 9, 'SSH-2.0-OpenSSH_9.0': 10, 'SSH-2.0-Adtran_4.31': 11, 'SSH-2.0-OpenSSH_5.9 FIPS': 12, 'SSH-2.0-OpenSSH_5.5 FIPS': 13, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 14, 'SSH-2.0-OpenSSH_7.1': 15, 'SSH-1.99-RGOS_SSH': 16, 'SSH-2.0-RomSShell_4.61': 17, 'SSH-2.0-OpenSSH_4.4': 18, 'SSH-1.99-SSH': 19, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 20, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 21, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 22, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 23, 'SSH-1.99-OpenSSH_6.9': 24, 'SSH-2.0-OpenSSH_5.8': 25, 'SSH-2.0-RGOS_SSH': 26, 'SSH-2.0-OpenSSH_7.5': 27, 'SSH-1.99-Cisco-1.25': 28, 'SSH-2.0-OpenSSH_6.6': 29, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 30, 'SSH-2.0-OpenSSH_6.2': 31, 'SSH-1.99-OpenSSH_6.4': 32, 'SSH-2.0-OpenSSH_6.1': 33, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 34, 'SSH-2.0-OpenSSH_7.3': 35, 'SSH-2.0-OpenSSH_6.2 FIPS': 36, 'SSH-1.99--': 37, 'SSH-2.0-RomSShell_5.40': 38, 'SSH-2.0-SSH': 39, 'SSH-2.0-Cisco-1.25': 40, 'SSH-2.0-OpenSSH_6.6.1': 41, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 42, 'SSH-2.0-OpenSSH_6.0': 43, 'SSH-2.0-OpenSSH_5.9': 44, 'SSH-2.0-OpenSSH_7.2': 45, 'SSH-2.0-ZTE_SSH.2.0': 46, 'SSH-2.0--': 47,'SSH-1.99-OpenSSH_6.0':48,'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]':49,'SSH-1.99-OpenSSH_4.4':50,'SSH-2.0-Alteon':51,'SSH-2.0-RGOS_PK3223':52,'SSH-1.99-OpenSSH_5.8':53,'SSH-1.99-OpenSSH_6.2':54,'SSH-2.0-SERVER_1.01':55}
    ssh_raw={'SSH-2.0-Cisco-1.25': 1, 'SSH-2.0-OpenSSH_7.5': 2, 'null': 3, 'SSH-2.0--': 4, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 5, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 6, 'SSH-2.0-OpenSSH_7.4': 7, 'SSH-2.0-ROSSSH': 8, 'SSH-2.0-OpenSSH_6.9': 9, 'SSH-2.0-OpenSSH_7.3': 10, 'SSH-2.0-OpenSSH_7.2': 11, 'SSH-2.0-Comware-7.1.075': 12, 'SSH-1.99-Cisco-1.25': 13, 'SSH-2.0-OpenSSH_7.2 FIPS': 14, 'SSH-2.0-OpenSSH_6.6.1': 15, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 16, 'SSH-2.0-OpenSSH_5.9': 17, 'SSH-2.0-HUAWEI-1.5': 18, 'SSH-2.0-OpenSSH_6.4': 19, 'SSH-2.0-OpenSSH_5.9 FIPS': 20, 'SSH-2.0-OpenSSH_6.0': 21, 'SSH-2.0-OpenSSH_6.2': 22, 'SSH-2.0-OpenSSH_4.4': 23, 'SSH-1.99-Comware-7.1.045': 24, 'SSH-2.0-RomSShell_5.40': 25, 'SSH-2.0-OpenSSH_6.2 FIPS': 26, 'SSH-2.0-OpenSSH_5.5 FIPS': 27, 'SSH-2.0-Comware-7.1.070': 28, 'SSH-2.0-Cisco-2.0': 29, 'SSH-2.0-Comware-7.1.059': 30, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 31, 'SSH-2.0-OpenSSH_8.0': 32, 'SSH-2.0-RGOS_SSH': 33, 'SSH-2.0-OpenSSH_5.8': 34, 'SSH-2.0-RomSShell_4.61': 35, 'SSH-2.0-OpenSSH_7.1': 36, 'SSH-2.0-OpenSSH_8.8': 37, 'SSH-2.0-SSH': 38, 'SSH-2.0-OpenSSH_6.1': 39, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 40, 'SSH-2.0-Comware-9.0.001': 41, 'SSH-2.0-OpenSSH_9.5 FreeBSD-20231004': 42, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 43, 'SSH-2.0-Adtran_4.31': 44, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 45, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719': 46, 'SSH-2.0-Dh-v39EVDB8f6LZ': 47, 'SSH-2.0-OpenSSH_9.7 FreeBSD-20240318': 48, 'SSH-1.99-OpenSSH_6.9': 49, 'SSH-1.99-RGOS_SSH': 50, 'SSH-1.99--': 51, 'SSH-2.0-SERVER_1.01': 52, 'SSH-1.99-OpenSSH_6.0': 53, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240104': 54, 'SSH-2.0-Mocana SSH 6.3': 55, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 56, 'SSH-2.0-RGOS_PK3223': 57, 'SSH-1.99-SSH': 58, 'SSH-2.0-OpenSSH_7.8 FreeBSD-20180909': 59, 'SSH-1.99-OpenSSH_7.3': 60, 'SSH-1.99-OpenSSH_6.1': 61, 'SSH-1.99-OpenSSH_6.8': 62, 'SSH-2.0-Comware-7.1.064': 63, 'SSH-1.99-OpenSSH_6.4': 64, 'SSH-1.99-Comware-7.1.075': 65, 'SSH-2.0-OpenSSH_7.7p1': 66, 'SSH-2.0-OpenSSH_6.6': 67, 'SSH-2.0-Comware-9.1.058': 68, 'SSH-2.0-WLH_rbHQLlDeyy': 69, 'SSH-1.99-OpenSSH_6.2': 70, 'SSH-2.0-OpenSSH_9.0': 71, 'SSH-1.99-OpenSSH_7.2p2': 72, 'SSH-2.0-Comware-7.1.045': 73, 'SSH-2.0-Alteon': 74, 'SSH-2.0-RGOS_SSH_1.0': 75, 'SSH-1.99-OpenSSH_5.8': 76, 'SSH-2.0-OpenSSH_3.5p1': 77, 'SSH-1.99-OpenSSH_6.6.1': 78, 'SSH-1.99-OpenSSH_4.4': 79, 'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]': 80, 'SSH-1.99-HUAWEI-1.5': 81, 'SSH-2.0-lancom': 82, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3': 83, 'SSH-2.0-dropbear': 84, 'SSH-2.0-OpenSSH_7.8': 85, 'SSH-2.0-OpenSSH_9.2p1': 86, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7': 87, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6': 88, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11': 89, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10': 90, 'SSH-2.0-OpenSSH_9.7': 91, 'SSH-2.0-ZTE_SSH.2.0': 92, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u1': 93, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2': 94, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1': 95, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1': 96, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 97, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5': 98, 'SSH-2.0-OpenSSH_9.5': 99, 'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7': 100, 'SSH-2.0-FHSSH_8.0': 101, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4': 102, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2': 103, 'SSH-2.0-OpenSSH_9.6': 104, 'SSH-2.0-OpenSSH_8.9p1': 105, 'SSH-2.0-OpenSSH_5.5': 106, 'SSH-2.0-OpenSSH_8.4p1 Debian-2~bpo10+1': 107, 'SSH-2.0-OpenSSH_9.2p1 Debian-2': 108, 'SSH-2.0-OpenSSH_8.6': 109, 'SSH-2.0-OpenSSH_9.3': 110, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u3': 111, 'SSH-2.0-OpenSSH_9.6p1 Debian-4': 112, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7': 113, 'SSH-2.0-dropbear_2020.81': 114, 'SSH-2.0-OpenSSH_7.9p1': 115, 'SSH-2.0-OpenSSH_6.8': 116, 'SSH-2.0-Mocana SSH 5.8': 117, 'SSH-2.0-OpenSSH_7.9 FreeBSD-20200214': 118, 'SSH-2.0-OpenSSH_7.6': 119, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20221019': 120, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7': 121, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3': 122, 'SSH-2.0-OpenSSH_7.9p1 Debian-10': 123, 'SSH-2.0-OpenSSH_8.7': 124, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2': 125, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3': 126, 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221': 127, 'SSH-2.0-Go': 128, 'SSH-2.0-OpenSSH_4.3': 129, 'SSH-1.99-OpenSSH_8.5': 130, 'SSH-2.0-b95rVonwBt': 131, 'SSH-2.0-OxywS4Oe4sDl': 132, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1': 133, 'SSH-2.0-OpenSSH_8.2p1': 134, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3': 135, 'SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1': 136, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2': 137, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1': 138, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3': 139, 'SSH-2.0-OpenSSH_7.7p1 Debian-2': 140, 'SSH-2.0-OpenSSH_8.4p1 Debian-5': 141, 'SSH-2.0-OpenSSH_9.1': 142, 'SSH-2.0-OpenSSH_9.6p1 Debian-3': 143, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4.ui1': 144, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3': 145, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13': 146, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.7': 147, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2': 148, 'SSH-2.0-OpenSSH_6.3': 149, 'SSH-2.0-dropbear_2019.78': 150, 'SSH-2.0-OpenSSH_Stable': 151, 'SSH-2.0-OpenSSH_7.3p1 Ubuntu-1ubuntu0.1': 152, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8': 153, 'SSH-2.0-OpenSSH_8.4': 154, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2': 155, 'SSH-2.0-OpenSSH_7.2p2': 156, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7': 157, 'SSH-2.0-OpenSSH_8.9': 158, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9': 159, 'SSH-2.0-t1VtSi': 160, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3': 161, 'SSH-2.0-dropbear_2014.63': 162, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8': 163, 'SSH-2.0-dropbear_2022.83': 164, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1': 165, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2': 166, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5': 167, 'SSH-2.0-OpenSSH_8.4p1': 168, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4': 169, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6': 170, 'SSH-2.0-OpenSSH_9.7p1 Debian-5': 171, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3': 172, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1': 173, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4': 174, 'SSH-2.0-OpenSSH_7.9p1 Vyatta-10+deb10u2+danos1': 175, 'SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420': 176, 'SSH-2.0-OpenSSH_8.6p1': 177, 'SSH-2.0-OpenSSH_9.6p1 Debian-2': 178, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10+esm5': 179, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3': 180, 'SSH-2.0-OpenSSH-FIPS(capable)': 181, 'SSH-2.0-OpenSSH_9.0p1 Debian-1+b1': 182, 'SSH-2.0-OpenSSH_8.1': 183, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4': 184, 'SSH-2.0-OpenSSH_9.5p1 Debian-2': 185, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3': 186, 'SSH-2.0-B4I_haIvxy': 187, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4': 188, 'SSH-2.0-OpenSSH_7.6p1': 189, 'SSH-2.0-OpenSSH_7.5 FreeBSD-20170903': 190, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4': 191, 'SSH-2.0-OpenSSH_5.9 NetBSD_Secure_Shell-20110907-hpn13v11-lpk': 192, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4': 193, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20230719': 194, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5': 195, 'SSH-2.0-OpenSSH_5.3': 196, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4': 197, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2': 198, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8': 199, 'SSH-2.0-OpenSSH_7.7': 200, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u3': 201, 'SSH-2.0-OpenSSH_9.4': 202, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u1': 203, 'SSH-2.0-dropbear_2017.75': 204, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5': 205, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.8': 206, 'SSH-2.0-dropbear_2011.54': 207, 'SSH-2.0-dropbear_2015.67': 208, 'SSH-2.0-OpenSSH_8.0p1': 209, 'SSH-2.0-OpenSSH_7.9': 210, 'SSH-1.99-OpenSSH_4.3': 211, 'SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901': 212, 'SSH-2.0-OpenSSH_9.2': 213, 'SSH-2.0-OpenSSH_9.6p1 Debian-5': 214, 'SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20231220-hpn13v14-lpk': 215, 'SSH-2.0-OpenSSH_9.7 FreeBSD-openssh-portable-9.7.p1,1': 216, 'SSH-2.0-Li_mO3m-e_bXh-': 217, 'SSH-2.0-ConfD-6.7.6': 218, 'SSH-2.0-OpenSSH_9.7p1 Debian-4': 219, 'SSH-2.0-OpenSSH_6.7p1': 220, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8': 221, 'SSH-2.0-rPKx-': 222, 'SSH-2.0-OpenSSH_7.5p1 Ubuntu-10ubuntu0.1': 223, 'SSH-2.0-OpenSSH_9.3 FreeBSD-openssh-portable-9.3.p2_2,1': 224, 'SSH-2.0-OpenSSH_9.3 FreeBSD': 225, 'SSH-2.0-billsSSH_3.6.3q3': 226, 'SSH-2.0-Parks': 227, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10': 228, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3': 229, 'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9': 230, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u4': 231, 'SSH-2.0-tiger xxxxxxxxxxxxxxxxxxxxxxxx': 232, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11': 233, 'SSH-2.0-OpenSSH_9.8': 234, 'SSH-2.0-OpenSSH_6.6p2-hpn14v4': 235, 'SSH-2.0-OpenSSH_8.2': 236, 'SSH-2.0-dropbear_2012.55': 237, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6': 238, 'SSH-2.0-OpenSSH_9.7-hpn14v15': 239, 'SSH-2.0-OpenSSH_8.3': 240, 'SSH-2.0-OpenSSH_7.1p2-hpn14v10': 241, 'SSH-2.0-dropbear_2018.76': 242, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4': 243, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6': 244, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240701': 245, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13': 246, 'SSH-2.0-dropbear_2014.66': 247, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7': 248, 'SSH-1.99-OpenSSH_5.3': 249, 'SSH-2.0-OpenSSH_9.7p1 Debian-7': 250, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10': 251, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1': 252, 'SSH-2.0-dropbear_2016.74': 253, 'SSH-2.0-OpenSSH_6.7p1 Debian-5': 254, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6': 255, 'SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3': 256, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1': 257, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3': 258, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5_lol_notrly_JustGoAwayDammit1.0': 259, 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3': 260, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5-lol_notrly_JustGoAwayDammit1.0': 261, 'SSH-2.0-OpenSSH_9.7p1 Debian-6': 262, 'SSH-2.0-OpenSSH_7.4p1 Debian-10': 263, 'SSH-2.0-OpenSSH_8.1 Celeonet': 264, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u9': 265, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20240701': 266, 'SSH-2.0-OpenSSH_7.4p1': 267, 'SSH-2.0-OpenSSH_9.6p1 Raspbian-3': 268, 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310': 269, 'SSH-2.0-OpenSSH_for_Windows_8.9': 270, 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.2': 271, 'SSH-2.0-OpenSSH_6.6p1-hpn14v4': 272, 'SSH-2.0-mod_sftp': 273, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4': 274, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2': 275, 'SSH-2.0-OpenSSH_9.0p1 Debian-1': 276}
    #vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 4, 'Casa Systems, Inc.': 8, 'Ruijie Networks Co., Ltd.': 9, 'Extreme Networks':7, 'Teracom Telematica Ltda.': 10}

    #vendor_dict={ "HUAWEI Technology Co.,Ltd" : 1, 'Sagemcom Broadband SAS': 2, 'zte corporation': 3, 'Intelbras': 4, 'Fiberhome Telecommunication Technologies Co.,LTD': 5, 'Shenzhen Skyworth Digital  Technology  CO., Ltd': 6, 'Space Monkey, Inc.': 7, 'China Mobile Group Device Co.,Ltd.': 8, 'TP-Link Corporation Limited.': 9, 'ciscoSystems': 10}
    
    vendor_dict={'ciscoSystems': 1,  'Juniper Networks, Inc.': 2,  'HUAWEI Technology Co.,Ltd': 3,  'MikroTik': 4,  'H3C': 5,  'Intelbras': 6,  'Sagemcom Broadband SAS': 7,  'zte corporation': 8,  'Brocade Communication Systems, Inc.': 9,  'TP-Link Corporation Limited.': 10}


    feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
    #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),get_ttl(line['icmpv6']['size'])]
    #feature=[ssh_raw[line['ssh']['type']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
        
    linelabel=vendor_dict[line['snmp']['vendor']]

    return feature,linelabel
    
def load_m_data(file,target_dict):
    f=open(file, 'r', encoding='utf-8')
    data=[]
    label=[]
    my_data=[]
    my_label=[]
    jsoncontent=json.load(f)

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    #vendor_dict={'ciscoSystems': 1, 'Juniper': 2, 'HUAWEI': 3, 'Casa': 4, 'net-snmp': 5, 'Teracom': 6, 'Adtran': 7, 'Brocade': 8, 'Ruijie': 9, 'FS.COM': 10, 'Dell': 11, 'H3C': 12, 'Extreme': 13, 'Stale': 14, 'nVent,': 15, 'OneAccess': 16, 'Alcatel-Lucent': 17, 'Hewlett-Packard': 18,'Hewlett':19,'Unknown': 20,'Alteon':21,'ZyXEL':22,'NAG':23}
    #ssh_raw={'SSH-1.99-OpenSSH_6.1': 1, 'SSH-2.0-OpenSSH_7.2 FIPS': 2, 'SSH-2.0-OpenSSH_8.8': 3, 'SSH-1.99-OpenSSH_7.3': 4, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 5, 'SSH-2.0-OpenSSH_7.4': 6, 'SSH-2.0-OpenSSH_6.4': 7, 'SSH-2.0-OpenSSH_6.9': 8, 'SSH-2.0-OpenSSH_8.0': 9, 'SSH-2.0-OpenSSH_9.0': 10, 'SSH-2.0-Adtran_4.31': 11, 'SSH-2.0-OpenSSH_5.9 FIPS': 12, 'SSH-2.0-OpenSSH_5.5 FIPS': 13, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 14, 'SSH-2.0-OpenSSH_7.1': 15, 'SSH-1.99-RGOS_SSH': 16, 'SSH-2.0-RomSShell_4.61': 17, 'SSH-2.0-OpenSSH_4.4': 18, 'SSH-1.99-SSH': 19, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 20, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 21, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 22, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 23, 'SSH-1.99-OpenSSH_6.9': 24, 'SSH-2.0-OpenSSH_5.8': 25, 'SSH-2.0-RGOS_SSH': 26, 'SSH-2.0-OpenSSH_7.5': 27, 'SSH-1.99-Cisco-1.25': 28, 'SSH-2.0-OpenSSH_6.6': 29, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 30, 'SSH-2.0-OpenSSH_6.2': 31, 'SSH-1.99-OpenSSH_6.4': 32, 'SSH-2.0-OpenSSH_6.1': 33, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 34, 'SSH-2.0-OpenSSH_7.3': 35, 'SSH-2.0-OpenSSH_6.2 FIPS': 36, 'SSH-1.99--': 37, 'SSH-2.0-RomSShell_5.40': 38, 'SSH-2.0-SSH': 39, 'SSH-2.0-Cisco-1.25': 40, 'SSH-2.0-OpenSSH_6.6.1': 41, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 42, 'SSH-2.0-OpenSSH_6.0': 43, 'SSH-2.0-OpenSSH_5.9': 44, 'SSH-2.0-OpenSSH_7.2': 45, 'SSH-2.0-ZTE_SSH.2.0': 46, 'SSH-2.0--': 47,'SSH-1.99-OpenSSH_6.0':48,'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]':49,'SSH-1.99-OpenSSH_4.4':50,'SSH-2.0-Alteon':51,'SSH-2.0-RGOS_PK3223':52,'SSH-1.99-OpenSSH_5.8':53,'SSH-1.99-OpenSSH_6.2':54,'SSH-2.0-SERVER_1.01':55}
    ssh_raw={'SSH-2.0-Cisco-1.25': 1, 'SSH-2.0-OpenSSH_7.5': 2, 'null': 3, 'SSH-2.0--': 4, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 5, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 6, 'SSH-2.0-OpenSSH_7.4': 7, 'SSH-2.0-ROSSSH': 8, 'SSH-2.0-OpenSSH_6.9': 9, 'SSH-2.0-OpenSSH_7.3': 10, 'SSH-2.0-OpenSSH_7.2': 11, 'SSH-2.0-Comware-7.1.075': 12, 'SSH-1.99-Cisco-1.25': 13, 'SSH-2.0-OpenSSH_7.2 FIPS': 14, 'SSH-2.0-OpenSSH_6.6.1': 15, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 16, 'SSH-2.0-OpenSSH_5.9': 17, 'SSH-2.0-HUAWEI-1.5': 18, 'SSH-2.0-OpenSSH_6.4': 19, 'SSH-2.0-OpenSSH_5.9 FIPS': 20, 'SSH-2.0-OpenSSH_6.0': 21, 'SSH-2.0-OpenSSH_6.2': 22, 'SSH-2.0-OpenSSH_4.4': 23, 'SSH-1.99-Comware-7.1.045': 24, 'SSH-2.0-RomSShell_5.40': 25, 'SSH-2.0-OpenSSH_6.2 FIPS': 26, 'SSH-2.0-OpenSSH_5.5 FIPS': 27, 'SSH-2.0-Comware-7.1.070': 28, 'SSH-2.0-Cisco-2.0': 29, 'SSH-2.0-Comware-7.1.059': 30, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 31, 'SSH-2.0-OpenSSH_8.0': 32, 'SSH-2.0-RGOS_SSH': 33, 'SSH-2.0-OpenSSH_5.8': 34, 'SSH-2.0-RomSShell_4.61': 35, 'SSH-2.0-OpenSSH_7.1': 36, 'SSH-2.0-OpenSSH_8.8': 37, 'SSH-2.0-SSH': 38, 'SSH-2.0-OpenSSH_6.1': 39, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 40, 'SSH-2.0-Comware-9.0.001': 41, 'SSH-2.0-OpenSSH_9.5 FreeBSD-20231004': 42, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 43, 'SSH-2.0-Adtran_4.31': 44, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 45, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719': 46, 'SSH-2.0-Dh-v39EVDB8f6LZ': 47, 'SSH-2.0-OpenSSH_9.7 FreeBSD-20240318': 48, 'SSH-1.99-OpenSSH_6.9': 49, 'SSH-1.99-RGOS_SSH': 50, 'SSH-1.99--': 51, 'SSH-2.0-SERVER_1.01': 52, 'SSH-1.99-OpenSSH_6.0': 53, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240104': 54, 'SSH-2.0-Mocana SSH 6.3': 55, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 56, 'SSH-2.0-RGOS_PK3223': 57, 'SSH-1.99-SSH': 58, 'SSH-2.0-OpenSSH_7.8 FreeBSD-20180909': 59, 'SSH-1.99-OpenSSH_7.3': 60, 'SSH-1.99-OpenSSH_6.1': 61, 'SSH-1.99-OpenSSH_6.8': 62, 'SSH-2.0-Comware-7.1.064': 63, 'SSH-1.99-OpenSSH_6.4': 64, 'SSH-1.99-Comware-7.1.075': 65, 'SSH-2.0-OpenSSH_7.7p1': 66, 'SSH-2.0-OpenSSH_6.6': 67, 'SSH-2.0-Comware-9.1.058': 68, 'SSH-2.0-WLH_rbHQLlDeyy': 69, 'SSH-1.99-OpenSSH_6.2': 70, 'SSH-2.0-OpenSSH_9.0': 71, 'SSH-1.99-OpenSSH_7.2p2': 72, 'SSH-2.0-Comware-7.1.045': 73, 'SSH-2.0-Alteon': 74, 'SSH-2.0-RGOS_SSH_1.0': 75, 'SSH-1.99-OpenSSH_5.8': 76, 'SSH-2.0-OpenSSH_3.5p1': 77, 'SSH-1.99-OpenSSH_6.6.1': 78, 'SSH-1.99-OpenSSH_4.4': 79, 'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]': 80, 'SSH-1.99-HUAWEI-1.5': 81, 'SSH-2.0-lancom': 82, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3': 83, 'SSH-2.0-dropbear': 84, 'SSH-2.0-OpenSSH_7.8': 85, 'SSH-2.0-OpenSSH_9.2p1': 86, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7': 87, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6': 88, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11': 89, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10': 90, 'SSH-2.0-OpenSSH_9.7': 91, 'SSH-2.0-ZTE_SSH.2.0': 92, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u1': 93, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2': 94, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1': 95, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1': 96, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 97, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5': 98, 'SSH-2.0-OpenSSH_9.5': 99, 'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7': 100, 'SSH-2.0-FHSSH_8.0': 101, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4': 102, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2': 103, 'SSH-2.0-OpenSSH_9.6': 104, 'SSH-2.0-OpenSSH_8.9p1': 105, 'SSH-2.0-OpenSSH_5.5': 106, 'SSH-2.0-OpenSSH_8.4p1 Debian-2~bpo10+1': 107, 'SSH-2.0-OpenSSH_9.2p1 Debian-2': 108, 'SSH-2.0-OpenSSH_8.6': 109, 'SSH-2.0-OpenSSH_9.3': 110, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u3': 111, 'SSH-2.0-OpenSSH_9.6p1 Debian-4': 112, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7': 113, 'SSH-2.0-dropbear_2020.81': 114, 'SSH-2.0-OpenSSH_7.9p1': 115, 'SSH-2.0-OpenSSH_6.8': 116, 'SSH-2.0-Mocana SSH 5.8': 117, 'SSH-2.0-OpenSSH_7.9 FreeBSD-20200214': 118, 'SSH-2.0-OpenSSH_7.6': 119, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20221019': 120, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7': 121, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3': 122, 'SSH-2.0-OpenSSH_7.9p1 Debian-10': 123, 'SSH-2.0-OpenSSH_8.7': 124, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2': 125, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3': 126, 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221': 127, 'SSH-2.0-Go': 128, 'SSH-2.0-OpenSSH_4.3': 129, 'SSH-1.99-OpenSSH_8.5': 130, 'SSH-2.0-b95rVonwBt': 131, 'SSH-2.0-OxywS4Oe4sDl': 132, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1': 133, 'SSH-2.0-OpenSSH_8.2p1': 134, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3': 135, 'SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1': 136, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2': 137, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1': 138, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3': 139, 'SSH-2.0-OpenSSH_7.7p1 Debian-2': 140, 'SSH-2.0-OpenSSH_8.4p1 Debian-5': 141, 'SSH-2.0-OpenSSH_9.1': 142, 'SSH-2.0-OpenSSH_9.6p1 Debian-3': 143, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4.ui1': 144, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3': 145, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13': 146, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.7': 147, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2': 148, 'SSH-2.0-OpenSSH_6.3': 149, 'SSH-2.0-dropbear_2019.78': 150, 'SSH-2.0-OpenSSH_Stable': 151, 'SSH-2.0-OpenSSH_7.3p1 Ubuntu-1ubuntu0.1': 152, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8': 153, 'SSH-2.0-OpenSSH_8.4': 154, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2': 155, 'SSH-2.0-OpenSSH_7.2p2': 156, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7': 157, 'SSH-2.0-OpenSSH_8.9': 158, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9': 159, 'SSH-2.0-t1VtSi': 160, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3': 161, 'SSH-2.0-dropbear_2014.63': 162, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8': 163, 'SSH-2.0-dropbear_2022.83': 164, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1': 165, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2': 166, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5': 167, 'SSH-2.0-OpenSSH_8.4p1': 168, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4': 169, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6': 170, 'SSH-2.0-OpenSSH_9.7p1 Debian-5': 171, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3': 172, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1': 173, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4': 174, 'SSH-2.0-OpenSSH_7.9p1 Vyatta-10+deb10u2+danos1': 175, 'SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420': 176, 'SSH-2.0-OpenSSH_8.6p1': 177, 'SSH-2.0-OpenSSH_9.6p1 Debian-2': 178, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10+esm5': 179, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3': 180, 'SSH-2.0-OpenSSH-FIPS(capable)': 181, 'SSH-2.0-OpenSSH_9.0p1 Debian-1+b1': 182, 'SSH-2.0-OpenSSH_8.1': 183, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4': 184, 'SSH-2.0-OpenSSH_9.5p1 Debian-2': 185, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3': 186, 'SSH-2.0-B4I_haIvxy': 187, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4': 188, 'SSH-2.0-OpenSSH_7.6p1': 189, 'SSH-2.0-OpenSSH_7.5 FreeBSD-20170903': 190, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4': 191, 'SSH-2.0-OpenSSH_5.9 NetBSD_Secure_Shell-20110907-hpn13v11-lpk': 192, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4': 193, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20230719': 194, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5': 195, 'SSH-2.0-OpenSSH_5.3': 196, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4': 197, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2': 198, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8': 199, 'SSH-2.0-OpenSSH_7.7': 200, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u3': 201, 'SSH-2.0-OpenSSH_9.4': 202, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u1': 203, 'SSH-2.0-dropbear_2017.75': 204, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5': 205, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.8': 206, 'SSH-2.0-dropbear_2011.54': 207, 'SSH-2.0-dropbear_2015.67': 208, 'SSH-2.0-OpenSSH_8.0p1': 209, 'SSH-2.0-OpenSSH_7.9': 210, 'SSH-1.99-OpenSSH_4.3': 211, 'SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901': 212, 'SSH-2.0-OpenSSH_9.2': 213, 'SSH-2.0-OpenSSH_9.6p1 Debian-5': 214, 'SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20231220-hpn13v14-lpk': 215, 'SSH-2.0-OpenSSH_9.7 FreeBSD-openssh-portable-9.7.p1,1': 216, 'SSH-2.0-Li_mO3m-e_bXh-': 217, 'SSH-2.0-ConfD-6.7.6': 218, 'SSH-2.0-OpenSSH_9.7p1 Debian-4': 219, 'SSH-2.0-OpenSSH_6.7p1': 220, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8': 221, 'SSH-2.0-rPKx-': 222, 'SSH-2.0-OpenSSH_7.5p1 Ubuntu-10ubuntu0.1': 223, 'SSH-2.0-OpenSSH_9.3 FreeBSD-openssh-portable-9.3.p2_2,1': 224, 'SSH-2.0-OpenSSH_9.3 FreeBSD': 225, 'SSH-2.0-billsSSH_3.6.3q3': 226, 'SSH-2.0-Parks': 227, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10': 228, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3': 229, 'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9': 230, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u4': 231, 'SSH-2.0-tiger xxxxxxxxxxxxxxxxxxxxxxxx': 232, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11': 233, 'SSH-2.0-OpenSSH_9.8': 234, 'SSH-2.0-OpenSSH_6.6p2-hpn14v4': 235, 'SSH-2.0-OpenSSH_8.2': 236, 'SSH-2.0-dropbear_2012.55': 237, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6': 238, 'SSH-2.0-OpenSSH_9.7-hpn14v15': 239, 'SSH-2.0-OpenSSH_8.3': 240, 'SSH-2.0-OpenSSH_7.1p2-hpn14v10': 241, 'SSH-2.0-dropbear_2018.76': 242, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4': 243, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6': 244, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240701': 245, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13': 246, 'SSH-2.0-dropbear_2014.66': 247, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7': 248, 'SSH-1.99-OpenSSH_5.3': 249, 'SSH-2.0-OpenSSH_9.7p1 Debian-7': 250, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10': 251, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1': 252, 'SSH-2.0-dropbear_2016.74': 253, 'SSH-2.0-OpenSSH_6.7p1 Debian-5': 254, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6': 255, 'SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3': 256, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1': 257, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3': 258, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5_lol_notrly_JustGoAwayDammit1.0': 259, 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3': 260, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5-lol_notrly_JustGoAwayDammit1.0': 261, 'SSH-2.0-OpenSSH_9.7p1 Debian-6': 262, 'SSH-2.0-OpenSSH_7.4p1 Debian-10': 263, 'SSH-2.0-OpenSSH_8.1 Celeonet': 264, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u9': 265, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20240701': 266, 'SSH-2.0-OpenSSH_7.4p1': 267, 'SSH-2.0-OpenSSH_9.6p1 Raspbian-3': 268, 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310': 269, 'SSH-2.0-OpenSSH_for_Windows_8.9': 270, 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.2': 271, 'SSH-2.0-OpenSSH_6.6p1-hpn14v4': 272, 'SSH-2.0-mod_sftp': 273, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4': 274, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2': 275, 'SSH-2.0-OpenSSH_9.0p1 Debian-1': 276}
    vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 7, 'nVent, Schroff GmbH': 8, 'Ruijie Networks Co., Ltd.': 9, 'Teracom Telematica Ltda.': 10, 'Extreme Networks': 11, 'Casa Systems, Inc.': 12, 'Reserved': 13, 'FS.COM INC': 14, 'Alteon Networks, Inc.': 15, 'The FreeBSD Project': 16, 'EON': 17, 'Alcatel-Lucent Enterprise': 18, 'Adtran': 19, 'Hewlett-Packard': 20, 'Online.net': 21, 'Dell Inc.': 22, 'Fortinet, Inc.': 23, 'Force10 Networks, Inc.': 24, 'NAG LLC': 25, 'Shanghai Baud Data Communication Development Corp.': 26, 'Stale Odegaard AS': 27, 'OneAccess': 28, 'HITRON Technology, Inc.': 29, '3Com': 30, 'Neoteris, Inc.': 31, 'D-Link Systems, Inc.': 32, 'ZyXEL Communications Corp.': 33, 'Meinberg': 34, 'InfoBlox Inc.': 35, 'ALAXALA Networks Corporation': 36, 'Broadcom Limited': 37, 'Lenovo Enterprise Business Group': 38, 'APRESIA Systems, Ltd.': 39, 'Digital China': 40, 'Compaq': 41, 'Aruba, a Hewlett Packard Enterprise company': 42, 'SITA ADS': 43, '': 44, 'Furukawa Electoric Co. Ltd.': 45, 'Hewlett Packard Enterprise': 46, 'Maipu Electric Industrial Co., Ltd': 47, 'Enterasys Networks': 48, 'U.C. Davis, ECE Dept. Tom': 49, 'IBM': 50, 'TP-Link Corporation Limited.': 51, 'Microsoft': 52, 'FJA': 53, 'SNMP Research': 54, 'CacheFlow Inc.': 55, 'Texas Instruments': 56, 'NetScreen Technologies, Inc.': 57, 'Raritan Computer, Inc.': 58, 'Rad Data Communications Ltd.': 59, 'Network Appliance Corporation': 60, 'RND': 61, 'Beijing Topsec Network Security Technology Co., Ltd.': 62, 'Tsinghua Unisplendour Co., ltd': 63, 'RiverDelta Networks': 64, 'LANCOM Systems': 65, 'ACCTON Technology': 66, 'Blade Network Technologies, Inc.': 67, 'MIPS Computer Systems': 68, 'OpenBSD Project': 69}
    for i in jsoncontent:
        flag=True
        line=jsoncontent[i]
        if 'ssh' in line:
            feature=[ssh_raw[line['ssh']['type']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
            #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),get_ttl(line['icmpv6']['size'])]
            #feature=[ssh_raw[line['ssh']['result']['server_id']['raw']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
            linelabel=vendor_dict[line['snmp']['vendor']]


            for j in feature:
                if j == 0:
                    flag=False
            if flag == False:
                pass
            else:
                
                if i in target_dict:
                    my_data.append(feature)
                    my_label.append(linelabel)
                else:
                    data.append(feature)
                    label.append(linelabel)


    f.close()

    return data,label,my_data,my_label  
    
def load_nolabel_ssh_data(file):
    f=open(file, 'r', encoding='utf-8')
    data=[]
    label=[]
    jsoncontent=json.load(f)

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    #vendor_dict={'ciscoSystems': 1, 'Juniper': 2, 'HUAWEI': 3, 'Casa': 4, 'net-snmp': 5, 'Teracom': 6, 'Adtran': 7, 'Brocade': 8, 'Ruijie': 9, 'FS.COM': 10, 'Dell': 11, 'H3C': 12, 'Extreme': 13, 'Stale': 14, 'nVent,': 15, 'OneAccess': 16, 'Alcatel-Lucent': 17, 'Hewlett-Packard': 18,'Hewlett':19,'Unknown': 20,'Alteon':21,'ZyXEL':22,'NAG':23}
    #ssh_raw={'SSH-1.99-OpenSSH_6.1': 1, 'SSH-2.0-OpenSSH_7.2 FIPS': 2, 'SSH-2.0-OpenSSH_8.8': 3, 'SSH-1.99-OpenSSH_7.3': 4, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 5, 'SSH-2.0-OpenSSH_7.4': 6, 'SSH-2.0-OpenSSH_6.4': 7, 'SSH-2.0-OpenSSH_6.9': 8, 'SSH-2.0-OpenSSH_8.0': 9, 'SSH-2.0-OpenSSH_9.0': 10, 'SSH-2.0-Adtran_4.31': 11, 'SSH-2.0-OpenSSH_5.9 FIPS': 12, 'SSH-2.0-OpenSSH_5.5 FIPS': 13, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 14, 'SSH-2.0-OpenSSH_7.1': 15, 'SSH-1.99-RGOS_SSH': 16, 'SSH-2.0-RomSShell_4.61': 17, 'SSH-2.0-OpenSSH_4.4': 18, 'SSH-1.99-SSH': 19, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 20, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 21, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 22, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 23, 'SSH-1.99-OpenSSH_6.9': 24, 'SSH-2.0-OpenSSH_5.8': 25, 'SSH-2.0-RGOS_SSH': 26, 'SSH-2.0-OpenSSH_7.5': 27, 'SSH-1.99-Cisco-1.25': 28, 'SSH-2.0-OpenSSH_6.6': 29, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 30, 'SSH-2.0-OpenSSH_6.2': 31, 'SSH-1.99-OpenSSH_6.4': 32, 'SSH-2.0-OpenSSH_6.1': 33, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 34, 'SSH-2.0-OpenSSH_7.3': 35, 'SSH-2.0-OpenSSH_6.2 FIPS': 36, 'SSH-1.99--': 37, 'SSH-2.0-RomSShell_5.40': 38, 'SSH-2.0-SSH': 39, 'SSH-2.0-Cisco-1.25': 40, 'SSH-2.0-OpenSSH_6.6.1': 41, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 42, 'SSH-2.0-OpenSSH_6.0': 43, 'SSH-2.0-OpenSSH_5.9': 44, 'SSH-2.0-OpenSSH_7.2': 45, 'SSH-2.0-ZTE_SSH.2.0': 46, 'SSH-2.0--': 47,'SSH-1.99-OpenSSH_6.0':48,'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]':49,'SSH-1.99-OpenSSH_4.4':50,'SSH-2.0-Alteon':51,'SSH-2.0-RGOS_PK3223':52,'SSH-1.99-OpenSSH_5.8':53,'SSH-1.99-OpenSSH_6.2':54,'SSH-2.0-SERVER_1.01':55}
    ssh_raw={'SSH-2.0-Cisco-1.25': 1, 'SSH-2.0-OpenSSH_7.5': 2, 'null': 3, 'SSH-2.0--': 4, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 5, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 6, 'SSH-2.0-OpenSSH_7.4': 7, 'SSH-2.0-ROSSSH': 8, 'SSH-2.0-OpenSSH_6.9': 9, 'SSH-2.0-OpenSSH_7.3': 10, 'SSH-2.0-OpenSSH_7.2': 11, 'SSH-2.0-Comware-7.1.075': 12, 'SSH-1.99-Cisco-1.25': 13, 'SSH-2.0-OpenSSH_7.2 FIPS': 14, 'SSH-2.0-OpenSSH_6.6.1': 15, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 16, 'SSH-2.0-OpenSSH_5.9': 17, 'SSH-2.0-HUAWEI-1.5': 18, 'SSH-2.0-OpenSSH_6.4': 19, 'SSH-2.0-OpenSSH_5.9 FIPS': 20, 'SSH-2.0-OpenSSH_6.0': 21, 'SSH-2.0-OpenSSH_6.2': 22, 'SSH-2.0-OpenSSH_4.4': 23, 'SSH-1.99-Comware-7.1.045': 24, 'SSH-2.0-RomSShell_5.40': 25, 'SSH-2.0-OpenSSH_6.2 FIPS': 26, 'SSH-2.0-OpenSSH_5.5 FIPS': 27, 'SSH-2.0-Comware-7.1.070': 28, 'SSH-2.0-Cisco-2.0': 29, 'SSH-2.0-Comware-7.1.059': 30, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 31, 'SSH-2.0-OpenSSH_8.0': 32, 'SSH-2.0-RGOS_SSH': 33, 'SSH-2.0-OpenSSH_5.8': 34, 'SSH-2.0-RomSShell_4.61': 35, 'SSH-2.0-OpenSSH_7.1': 36, 'SSH-2.0-OpenSSH_8.8': 37, 'SSH-2.0-SSH': 38, 'SSH-2.0-OpenSSH_6.1': 39, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 40, 'SSH-2.0-Comware-9.0.001': 41, 'SSH-2.0-OpenSSH_9.5 FreeBSD-20231004': 42, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 43, 'SSH-2.0-Adtran_4.31': 44, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 45, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719': 46, 'SSH-2.0-Dh-v39EVDB8f6LZ': 47, 'SSH-2.0-OpenSSH_9.7 FreeBSD-20240318': 48, 'SSH-1.99-OpenSSH_6.9': 49, 'SSH-1.99-RGOS_SSH': 50, 'SSH-1.99--': 51, 'SSH-2.0-SERVER_1.01': 52, 'SSH-1.99-OpenSSH_6.0': 53, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240104': 54, 'SSH-2.0-Mocana SSH 6.3': 55, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 56, 'SSH-2.0-RGOS_PK3223': 57, 'SSH-1.99-SSH': 58, 'SSH-2.0-OpenSSH_7.8 FreeBSD-20180909': 59, 'SSH-1.99-OpenSSH_7.3': 60, 'SSH-1.99-OpenSSH_6.1': 61, 'SSH-1.99-OpenSSH_6.8': 62, 'SSH-2.0-Comware-7.1.064': 63, 'SSH-1.99-OpenSSH_6.4': 64, 'SSH-1.99-Comware-7.1.075': 65, 'SSH-2.0-OpenSSH_7.7p1': 66, 'SSH-2.0-OpenSSH_6.6': 67, 'SSH-2.0-Comware-9.1.058': 68, 'SSH-2.0-WLH_rbHQLlDeyy': 69, 'SSH-1.99-OpenSSH_6.2': 70, 'SSH-2.0-OpenSSH_9.0': 71, 'SSH-1.99-OpenSSH_7.2p2': 72, 'SSH-2.0-Comware-7.1.045': 73, 'SSH-2.0-Alteon': 74, 'SSH-2.0-RGOS_SSH_1.0': 75, 'SSH-1.99-OpenSSH_5.8': 76, 'SSH-2.0-OpenSSH_3.5p1': 77, 'SSH-1.99-OpenSSH_6.6.1': 78, 'SSH-1.99-OpenSSH_4.4': 79, 'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]': 80, 'SSH-1.99-HUAWEI-1.5': 81, 'SSH-2.0-lancom': 82, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3': 83, 'SSH-2.0-dropbear': 84, 'SSH-2.0-OpenSSH_7.8': 85, 'SSH-2.0-OpenSSH_9.2p1': 86, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7': 87, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6': 88, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11': 89, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10': 90, 'SSH-2.0-OpenSSH_9.7': 91, 'SSH-2.0-ZTE_SSH.2.0': 92, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u1': 93, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2': 94, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1': 95, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1': 96, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 97, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5': 98, 'SSH-2.0-OpenSSH_9.5': 99, 'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7': 100, 'SSH-2.0-FHSSH_8.0': 101, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4': 102, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2': 103, 'SSH-2.0-OpenSSH_9.6': 104, 'SSH-2.0-OpenSSH_8.9p1': 105, 'SSH-2.0-OpenSSH_5.5': 106, 'SSH-2.0-OpenSSH_8.4p1 Debian-2~bpo10+1': 107, 'SSH-2.0-OpenSSH_9.2p1 Debian-2': 108, 'SSH-2.0-OpenSSH_8.6': 109, 'SSH-2.0-OpenSSH_9.3': 110, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u3': 111, 'SSH-2.0-OpenSSH_9.6p1 Debian-4': 112, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7': 113, 'SSH-2.0-dropbear_2020.81': 114, 'SSH-2.0-OpenSSH_7.9p1': 115, 'SSH-2.0-OpenSSH_6.8': 116, 'SSH-2.0-Mocana SSH 5.8': 117, 'SSH-2.0-OpenSSH_7.9 FreeBSD-20200214': 118, 'SSH-2.0-OpenSSH_7.6': 119, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20221019': 120, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7': 121, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3': 122, 'SSH-2.0-OpenSSH_7.9p1 Debian-10': 123, 'SSH-2.0-OpenSSH_8.7': 124, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2': 125, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3': 126, 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221': 127, 'SSH-2.0-Go': 128, 'SSH-2.0-OpenSSH_4.3': 129, 'SSH-1.99-OpenSSH_8.5': 130, 'SSH-2.0-b95rVonwBt': 131, 'SSH-2.0-OxywS4Oe4sDl': 132, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1': 133, 'SSH-2.0-OpenSSH_8.2p1': 134, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3': 135, 'SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1': 136, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2': 137, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1': 138, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3': 139, 'SSH-2.0-OpenSSH_7.7p1 Debian-2': 140, 'SSH-2.0-OpenSSH_8.4p1 Debian-5': 141, 'SSH-2.0-OpenSSH_9.1': 142, 'SSH-2.0-OpenSSH_9.6p1 Debian-3': 143, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4.ui1': 144, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3': 145, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13': 146, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.7': 147, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2': 148, 'SSH-2.0-OpenSSH_6.3': 149, 'SSH-2.0-dropbear_2019.78': 150, 'SSH-2.0-OpenSSH_Stable': 151, 'SSH-2.0-OpenSSH_7.3p1 Ubuntu-1ubuntu0.1': 152, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8': 153, 'SSH-2.0-OpenSSH_8.4': 154, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2': 155, 'SSH-2.0-OpenSSH_7.2p2': 156, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7': 157, 'SSH-2.0-OpenSSH_8.9': 158, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9': 159, 'SSH-2.0-t1VtSi': 160, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3': 161, 'SSH-2.0-dropbear_2014.63': 162, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8': 163, 'SSH-2.0-dropbear_2022.83': 164, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1': 165, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2': 166, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5': 167, 'SSH-2.0-OpenSSH_8.4p1': 168, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4': 169, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6': 170, 'SSH-2.0-OpenSSH_9.7p1 Debian-5': 171, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3': 172, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1': 173, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4': 174, 'SSH-2.0-OpenSSH_7.9p1 Vyatta-10+deb10u2+danos1': 175, 'SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420': 176, 'SSH-2.0-OpenSSH_8.6p1': 177, 'SSH-2.0-OpenSSH_9.6p1 Debian-2': 178, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10+esm5': 179, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3': 180, 'SSH-2.0-OpenSSH-FIPS(capable)': 181, 'SSH-2.0-OpenSSH_9.0p1 Debian-1+b1': 182, 'SSH-2.0-OpenSSH_8.1': 183, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4': 184, 'SSH-2.0-OpenSSH_9.5p1 Debian-2': 185, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3': 186, 'SSH-2.0-B4I_haIvxy': 187, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4': 188, 'SSH-2.0-OpenSSH_7.6p1': 189, 'SSH-2.0-OpenSSH_7.5 FreeBSD-20170903': 190, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4': 191, 'SSH-2.0-OpenSSH_5.9 NetBSD_Secure_Shell-20110907-hpn13v11-lpk': 192, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4': 193, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20230719': 194, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5': 195, 'SSH-2.0-OpenSSH_5.3': 196, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4': 197, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2': 198, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8': 199, 'SSH-2.0-OpenSSH_7.7': 200, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u3': 201, 'SSH-2.0-OpenSSH_9.4': 202, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u1': 203, 'SSH-2.0-dropbear_2017.75': 204, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5': 205, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.8': 206, 'SSH-2.0-dropbear_2011.54': 207, 'SSH-2.0-dropbear_2015.67': 208, 'SSH-2.0-OpenSSH_8.0p1': 209, 'SSH-2.0-OpenSSH_7.9': 210, 'SSH-1.99-OpenSSH_4.3': 211, 'SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901': 212, 'SSH-2.0-OpenSSH_9.2': 213, 'SSH-2.0-OpenSSH_9.6p1 Debian-5': 214, 'SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20231220-hpn13v14-lpk': 215, 'SSH-2.0-OpenSSH_9.7 FreeBSD-openssh-portable-9.7.p1,1': 216, 'SSH-2.0-Li_mO3m-e_bXh-': 217, 'SSH-2.0-ConfD-6.7.6': 218, 'SSH-2.0-OpenSSH_9.7p1 Debian-4': 219, 'SSH-2.0-OpenSSH_6.7p1': 220, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8': 221, 'SSH-2.0-rPKx-': 222, 'SSH-2.0-OpenSSH_7.5p1 Ubuntu-10ubuntu0.1': 223, 'SSH-2.0-OpenSSH_9.3 FreeBSD-openssh-portable-9.3.p2_2,1': 224, 'SSH-2.0-OpenSSH_9.3 FreeBSD': 225, 'SSH-2.0-billsSSH_3.6.3q3': 226, 'SSH-2.0-Parks': 227, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10': 228, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3': 229, 'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9': 230, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u4': 231, 'SSH-2.0-tiger xxxxxxxxxxxxxxxxxxxxxxxx': 232, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11': 233, 'SSH-2.0-OpenSSH_9.8': 234, 'SSH-2.0-OpenSSH_6.6p2-hpn14v4': 235, 'SSH-2.0-OpenSSH_8.2': 236, 'SSH-2.0-dropbear_2012.55': 237, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6': 238, 'SSH-2.0-OpenSSH_9.7-hpn14v15': 239, 'SSH-2.0-OpenSSH_8.3': 240, 'SSH-2.0-OpenSSH_7.1p2-hpn14v10': 241, 'SSH-2.0-dropbear_2018.76': 242, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4': 243, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6': 244, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240701': 245, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13': 246, 'SSH-2.0-dropbear_2014.66': 247, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7': 248, 'SSH-1.99-OpenSSH_5.3': 249, 'SSH-2.0-OpenSSH_9.7p1 Debian-7': 250, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10': 251, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1': 252, 'SSH-2.0-dropbear_2016.74': 253, 'SSH-2.0-OpenSSH_6.7p1 Debian-5': 254, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6': 255, 'SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3': 256, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1': 257, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3': 258, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5_lol_notrly_JustGoAwayDammit1.0': 259, 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3': 260, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5-lol_notrly_JustGoAwayDammit1.0': 261, 'SSH-2.0-OpenSSH_9.7p1 Debian-6': 262, 'SSH-2.0-OpenSSH_7.4p1 Debian-10': 263, 'SSH-2.0-OpenSSH_8.1 Celeonet': 264, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u9': 265, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20240701': 266, 'SSH-2.0-OpenSSH_7.4p1': 267, 'SSH-2.0-OpenSSH_9.6p1 Raspbian-3': 268, 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310': 269, 'SSH-2.0-OpenSSH_for_Windows_8.9': 270, 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.2': 271, 'SSH-2.0-OpenSSH_6.6p1-hpn14v4': 272, 'SSH-2.0-mod_sftp': 273, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4': 274, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2': 275, 'SSH-2.0-OpenSSH_9.0p1 Debian-1': 276}
    #vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 4, 'nVent, Schroff GmbH': 8, 'Ruijie Networks Co., Ltd.': 9, 'Teracom Telematica Ltda.': 10, 'Extreme Networks': 11, 'Casa Systems, Inc.': 12, 'Reserved': 13, 'FS.COM INC': 14, 'Alteon Networks, Inc.': 15, 'The FreeBSD Project': 16, 'EON': 17, 'Alcatel-Lucent Enterprise': 18, 'Adtran': 19, 'Hewlett-Packard': 20, 'Online.net': 21, 'Dell Inc.': 22, 'Fortinet, Inc.': 23, 'Force10 Networks, Inc.': 24, 'NAG LLC': 25, 'Shanghai Baud Data Communication Development Corp.': 26, 'Stale Odegaard AS': 27, 'OneAccess': 28, 'HITRON Technology, Inc.': 29, '3Com': 30, 'Neoteris, Inc.': 31, 'D-Link Systems, Inc.': 32, 'ZyXEL Communications Corp.': 33, 'Meinberg': 34, 'InfoBlox Inc.': 35, 'ALAXALA Networks Corporation': 36, 'Broadcom Limited': 37, 'Lenovo Enterprise Business Group': 38, 'APRESIA Systems, Ltd.': 39, 'Digital China': 40, 'Compaq': 41, 'Aruba, a Hewlett Packard Enterprise company': 42, 'SITA ADS': 43, '': 44, 'Furukawa Electoric Co. Ltd.': 45, 'Hewlett Packard Enterprise': 46, 'Maipu Electric Industrial Co., Ltd': 47, 'Enterasys Networks': 48, 'U.C. Davis, ECE Dept. Tom': 49, 'IBM': 50, 'TP-Link Corporation Limited.': 51, 'Microsoft': 52, 'FJA': 53, 'SNMP Research': 54, 'CacheFlow Inc.': 55, 'Texas Instruments': 56, 'NetScreen Technologies, Inc.': 57, 'Raritan Computer, Inc.': 58, 'Rad Data Communications Ltd.': 59, 'Network Appliance Corporation': 60, 'RND': 61, 'Beijing Topsec Network Security Technology Co., Ltd.': 62, 'Tsinghua Unisplendour Co., ltd': 63, 'RiverDelta Networks': 64, 'LANCOM Systems': 65, 'ACCTON Technology': 66, 'Blade Network Technologies, Inc.': 67, 'MIPS Computer Systems': 68, 'OpenBSD Project': 69}
    vendor_dict={'ciscoSystems': 1,  'Juniper Networks, Inc.': 2,  'HUAWEI Technology Co.,Ltd': 3,  'MikroTik': 4,  'H3C': 5,  'Intelbras': 6,  'Sagemcom Broadband SAS': 7,  'zte corporation': 8,  'Brocade Communication Systems, Inc.': 9,  'TP-Link Corporation Limited.': 10}
    for i in jsoncontent:
        line=jsoncontent[i]
        if 'ssh' in line:
            feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
            #feature=[ssh_raw[line['ssh']['result']['server_id']['raw']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]

            data.append(feature)


    f.close()

    return data


# def draw_confusion_matrix(label_true, label_pred, label_name, title="Confusion Matrix", pdf_save_path=None, dpi=100):
#     """
#
#     @return:
#     @param label_true: True labels, for example, [0, 1, 2, 7, 4, 5, ...]
#     @param label_pred: Predicted labels, for example, [0, 5, 4, 2, 1, 4, ...]
#     @param label_name: Label names, for example, ['cat', 'dog', 'flower', ...]
#     @param title: Title of the plot
#     @param pdf_save_path: Save path if saving is desired, e.g., pdf_save_path=xxx.png | xxx.pdf | ... any other format supported by plt.savefig
#     @param dpi: Resolution for saving to file, usually at least 300 dpi for papers
#     @return:
#
#     example：
#             draw_confusion_matrix(label_true=y_gt,
#                           label_pred=y_pred,
#                           label_name=["Angry", "Disgust", "Fear", "Happy", "Sad", "Surprise", "Neutral"],
#                           title="Confusion Matrix on Fer2013",
#                           pdf_save_path="Confusion_Matrix_on_Fer2013.png",
#                           dpi=300)
#
#     """
#     cm = confusion_matrix(y_true=label_true, y_pred=label_pred, normalize='true')
#
#     plt.imshow(cm, cmap='Blues')
#     plt.title(title)
#     plt.xlabel("Predict label")
#     plt.ylabel("Truth label")
#     plt.yticks(range(label_name.__len__()), label_name)
#     plt.xticks(range(label_name.__len__()), label_name, rotation=45)
#
#     plt.tight_layout()
#
#     plt.colorbar()
#
#     for i in range(label_name.__len__()):
#         for j in range(label_name.__len__()):
#             color = (1, 1, 1) if i == j else (0, 0, 0)  
#             value = float(format('%.2f' % cm[j, i]))
#             plt.text(i, j, value, verticalalignment='center', horizontalalignment='center', color=color)
#
#     # plt.show()
#     if not pdf_save_path is None:
#         plt.savefig(pdf_save_path, bbox_inches='tight', dpi=dpi)
#
#
#      # the lines in file are 'ipv6_address [ipid] lable'
# #X_test,y_test = load_data('validation.txt')
#
# #Pre= load_work_data('R_0_1.txt')  #no label
#
#
#
# # def Mytest_criterion(s,my_criterion='entropy'):
# #
# #     X,Y = load_ssh_data('./eui64/%s/feature_%s_snmp_more.json'%(s,s))
# #     len_X=len(X)
# #     print(len_X)
# #     XX_T=[]
# #     YY_T=[]
# #     X_t=[]
# #     Y_t=[]
# #     for j in range(len_X*7//10):
# #         XX_T.append(X[j])
# #         YY_T.append(Y[j])
# #     for j in range(len_X*7//10,len_X):
# #         X_t.append(X[j])
# #         Y_t.append(Y[j])
# #
# #
# #     tree_model=DecisionTreeClassifier(criterion=my_criterion,max_depth=None,random_state=0,splitter="best")
# #
# #     
# #     vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'MikroTik': 4, 'H3C': 5,}
# #     vendor_dict={'HUAWEI Technology Co.,Ltd': 1, 'Sagemcom Broadband SAS': 2, 'zte corporation': 3, 'Intelbras': 4, 'Fiberhome Telecommunication Technologies Co.,LTD': 5}
# #     tree_model.fit(XX_T,YY_T)
# #
# #     feature_names=['tcp_ttl','tcp_size','udp_ttl','udp_size','icmp_ttl','ipid_type','ipid_increnum','ipid_num']
# #     #target_names=['ciscoSystems', 'Juniper Networks, Inc.', 'HUAWEI Technology Co.,Ltd', 'Brocade Communications Systems, Inc.', 'MikroTik', 'H3C','Extreme Networks','Casa Systems, Inc.', 'Ruijie Networks Co., Ltd.', 'Teracom Telematica Ltda.']
# #
# #     target_names=['ciscoSystems',  'Juniper Networks, Inc.',  'HUAWEI Technology Co.,Ltd',  'MikroTik',  'H3C',  'Intelbras',  'Sagemcom Broadband SAS',  'zte corporation',  'Brocade Communication Systems, Inc.','TP-Link Corporation Limited.']
# #
# #
# #     files=['./0618/nmap_data/0.txt','./0618/nmap_data/1.txt','./0618/nmap_data/2.txt','./0618/nmap_data/3.txt','./0618/nmap_data/4.txt']
# #     lines=[]
# #     for i in files:
# #         f=open(i,'r')
# #         lines+=f.readlines()
# #         f.close()
# #     print(len(lines))
# #
# #     result=[]
# #     c=0
# #     with open('./0618/feature_0618_snmp_more.json','r') as f:
# #         tmp=json.load(f)
# #         for i in lines:
# #             if i.strip() in tmp:
# #                 c+=1
# #                 f_t,l_t=load_single_data(tmp[i.strip()])
# #                 predict_result=tree_model.predict([f_t])
# #                 result.append(predict_result[0])
# #             else:
# #                 print(i.strip())
# #
# #     print(c,len(result))
#
#
#     # Prediction_X=load_nolabel_ssh_data('./eui64/%s/feature_%s_nosnmp_more.json'%(s,s))
#     # vendor_dict={'ciscoSystems': 1,  'Juniper Networks, Inc.': 2,  'HUAWEI Technology Co.,Ltd': 3,  'MikroTik': 4,  'H3C': 5,  'Intelbras': 6,  'Sagemcom Broadband SAS': 7,  'zte corporation': 8,  'Brocade Communication Systems, Inc.': 9,  'TP-Link Corporation Limited.': 10}
#     # predict_result=tree_model.predict(Prediction_X)
#     # v=dict()
#     # for i in predict_result:
#     #     for j in vendor_dict:
#     #         if vendor_dict[j]==i:
#     #             if j in v:
#     #                 v[j]+=1
#     #             else:
#     #                 v[j]=1
#     # print(v)
#     # s=0
#     # for i in v:
#     #     s+=v[i]
#     # for i in v:
#     #     print(v[i]/s)
#     # predict_result=tree_model.predict(X_t)
#     # length=len(predict_result)
#     # accu=[]
#     # tmp1=0
#     # tmp2=0
#     # c3=[]
#     # for i in vendor_dict:
#     #     print(i)
#     #     c1=0
#     #     c2=0
#     #     t3=0
#     #     for j in range(length):
#     #         if Y_t[j]==vendor_dict[i]:
#     #             c1+=1
#     #             if Y_t[j]==predict_result[j]:
#     #                 c2+=1
#     #         if predict_result[j]==vendor_dict[i]:
#     #             t3+=1
#     #     accu.append([c1,c2])
#     #     c3.append(t3)
#     #     tmp1+=c1
#     #     tmp2+=c2
#
#     # print('the accuracy of %s is %.2f'%(s,tmp2*100/tmp1))
#     # s=0
#     # for i in accu:
#     #     s+=i[0]
#     # for i in range(10):
#     #     print(accu[i][1]*100/accu[i][0],c3[i]*100/s)
#
#
# #     dot_data = export_graphviz(tree_model, out_file=None,
# #                            feature_names=feature_names,
# #                            class_names=target_names,
# #                            filled=True, rounded=True,
# #                            special_characters=True)
#
# # 
# #     graph = graphviz.Source(dot_data)
# #     graph.render("vendor_gini", view=True)
#
# #     r=tree.export_text(tree_model, feature_names=feature_names,
# #                            class_names=target_names)
#
# #     with open('decision_tree.log','w') as f:
# #         f.write(r)
#
#     # Prediction_X=load_nolabel_ssh_data('./eui64/%s/feature_%s_nosnmp_more.json'%(s,s))
#     # predict_result=tree_model.predict(Prediction_X)
#     # newlines=dict()
#     # vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 4, 'Casa Systems, Inc.': 8, 'Ruijie Networks Co., Ltd.': 9, 'Extreme Networks':7, 'Teracom Telematica Ltda.': 10}
#
#     # with open('./eui64/%s/feature_%s_nosnmp_more.json'%(s,s),'r') as f:
#     #     lines=json.load(f)
#     #     print(len(lines),len(predict_result))
#     #     c=0
#     #     for i in lines:
#     #         newlines[i]=lines[i]
#     #         newlines[i]['snmp']=dict()
#     #         tmp=predict_result[c]
#     #         for j in vendor_dict:
#     #             if vendor_dict[j]==tmp:
#     #                 v=j
#     #         newlines[i]['snmp']['vendor']=v
#     #         c+=1
#
#     # with open('./total_snmp.json', 'w', encoding='utf-8') as f:
#     #     json.dump(newlines, f, ensure_ascii=False, indent=4)
#
#
#
#
#     '''length=len(X_t)
#     for i in vendor_dict:
#         X_now=[]
#         Y_now=[]
#         for j in range(length):
#             if Y_t[j]==vendor_dict[i]:
#                 X_now.append(X_t[j])
#                 Y_now.append(Y_t[j])
#         if X_now == []:
#             print(i,'pass')
#         else:
#             print(len(X_now),i,tree_model.score(X_now,Y_now))
#
#     target_dict=[]
#     for i in range(5):
#         with open('./0618/nmap_data/%d.txt'%i,'r',encoding='utf-8') as f:
#             tmp=f.readlines()
#             for j in tmp:
#                 target_dict.append(j[:-1])
#
#     X_train=[]
#     Y_train=[]
#     X_test=[]
#     y_test=[]
#     Prediction_X=[]
#     for i in ['0609','0618','0701','itdk']:
#         X,Y = load_ssh_data('./%s/feature_%s_snmp_more.json'%(i,i))
#         len_X=len(X)
#         ranl=list(range(len_X))
#         random.shuffle(ranl)
#         XX_T=[]
#         YY_T=[]
#         X_t=[]
#         Y_t=[]
#         for j in ranl[:len_X*7//10]:
#             XX_T.append(X[j])
#             YY_T.append(Y[j])
#         for j in ranl[len_X*7//10:]:
#             X_t.append(X[j])
#             Y_t.append(Y[j])
#         X_train+=XX_T
#         Y_train+=YY_T
#         #X_test.append(X_t)
#         #y_test.append(Y_t)
#         length=len(X_t)
#         for j in range(length):
#             if X_t[j][0] !=3 and X_t[j][1] !=0 and X_t[j][2] !=0 and X_t[j][3] !=0 and X_t[j][4] !=0 and X_t[j][5] !=0:
#                 X_test.append(X_t[j])
#                 y_test.append(Y_t[j])
#
#         #Prediction_X.append(load_nolabel_ssh_data('./feature_%s_nosnmp_more.json'%i))
#
#     # Create the decision tree classifier
#     tree_model = DecisionTreeClassifier(criterion=my_criterion, max_depth=None, random_state=0, splitter="best")
#
#     # Feed the data
#
#     vendor_dict = {'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'MikroTik': 5, 'H3C': 6}
#     print(len(X_train))
#     tree_model.fit(X_train, Y_train)
#
#
#     print(tree_model.score(X_test,y_test))
#
#     length=len(X_test)
#     for i in vendor_dict:
#         X_now=[]
#         Y_now=[]
#         for j in range(length):
#             if y_test[j]==vendor_dict[i]:
#                 X_now.append(X_test[j])
#                 Y_now.append(y_test[j])
#         if X_now == []:
#             print(i,'pass')
#         else:
#             print(len(X_now),i,tree_model.score(X_now,Y_now))'''
#
#     '''for i in range(4):
#         predict_result=tree_model.predict(Prediction_X[i])
#         pl=len(predict_result)
#         for j in vendor_dict:
#             cur=0
#             for m in range(pl):
#                 if predict_result[m] == vendor_dict[j]:
#                     cur+=1
#             print(j,cur/pl)
#
#
#     feature_importances = tree_model.feature_importances_
#
# # Integrate feature names and importance scores into a DataFrame
# feature_names = 'ssh_raw,tcp_ttl,tcp_size,udp_ttl,udp_size,icmp_ttl,ipid_type,ipid_incre,ipid_num'
# importance_df = pd.DataFrame({'Feature': feature_names.split(','), 'Importance': feature_importances})
# # Sort by importance scores in descending order
# importance_df = importance_df.sort_values(by='Importance', ascending=False)
# print(importance_df)
# #print(tree_model.score(X_test, y_test))'''

'''vendor_dict = {'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Unknown': 4, 'Brocade Communications Systems, Inc.': 5, 'MikroTik': 6, 'H3C': 7, 'Brocade Communication Systems, Inc.': 8, 'net-snmp': 9, 'nVent, Schroff GmbH': 10, 'Ruijie Networks Co., Ltd.': 11, 'Teracom Telematica Ltda.': 12, 'Extreme Networks': 13, 'Casa Systems, Inc.': 14, 'Reserved': 15, 'FS.COM INC': 16, 'Alteon Networks, Inc.': 17, 'The FreeBSD Project': 18, 'EON': 19, 'Alcatel-Lucent Enterprise': 20, 'Adtran': 21, 'Hewlett-Packard': 22, 'Online.net': 23, 'Dell Inc.': 24, 'Fortinet, Inc.': 25, 'Force10 Networks, Inc.': 26, 'NAG LLC': 27, 'Shanghai Baud Data Communication Development Corp.': 28, 'Stale Odegaard AS': 29, 'OneAccess': 30}
target_names = [i for i in vendor_dict]

dot_data = export_graphviz(tree_model, out_file=None,
                           feature_names=feature_names.split(','),
                           class_names=target_names,
                           filled=True, rounded=True,
                           special_characters=True)

# Render the DOT data as a graphic using Graphviz's Python interface

    graph = graphviz.Source(dot_data)  
    graph.render("vendor_gini", view=True) '''



'''draw_confusion_matrix(label_true=y_test,			# y_gt=[0,5,1,6,3,...]
                      label_pred=predict_result,	    # y_pred=[0,5,1,6,3,...]
                      label_name=["Global", "Local", "Random", "Odd"],
                      title="Confusion Matrix of IPID Validation",
                      pdf_save_path="Confusion_Matrix_on_Fer2013.jpg",
                      dpi=300)'''



    
def draw_confusion_matrix(label_true, label_pred, label_name, title="Confusion Matrix", pdf_save_path=None, dpi=100):
    """
    Draw a confusion matrix to visualize classification performance.

    Parameters:
    - label_true (list): True labels.
    - label_pred (list): Predicted labels.
    - label_name (list): Names of the labels.
    - title (str): Title of the plot.
    - pdf_save_path (str): Path to save the plot (optional).
    - dpi (int): Resolution for saving the plot (default is 100).

    Returns:
    - None
    """
    cm = confusion_matrix(label_true, label_pred, normalize='true')
    plt.figure(figsize=(10, 7))
    plt.imshow(cm, cmap='Blues')
    plt.title(title)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.xticks(range(len(label_name)), label_name, rotation=45)
    plt.yticks(range(len(label_name)), label_name)

    plt.colorbar()

    for i in range(len(label_name)):
        for j in range(len(label_name)):
            color = (1, 1, 1) if i == j else (0, 0, 0)  # White text for diagonal, black otherwise
            value = float(format('%.2f' % cm[j, i]))
            plt.text(i, j, value, verticalalignment='center', horizontalalignment='center', color=color)

    plt.tight_layout()

    if pdf_save_path:
        plt.savefig(pdf_save_path, bbox_inches='tight', dpi=dpi)
    else:
        plt.show()

def Mytest_criterion(s, my_criterion='entropy'):
    """
    Train and evaluate a Decision Tree classifier using 10-fold cross-validation.

    Parameters:
    - s (str): Dataset identifier, e.g., '0609'.
    - my_criterion (str): Criterion for splitting ('entropy' or 'gini'). Default is 'entropy'.

    Returns:
    - None
    """
    # Load data
    X, Y = load_ssh_data(f'./eui64/{s}/feature_{s}_snmp_more.json')
    len_X = len(X)
    print(f"Dataset {s} sample size: {len_X}")

    if len_X == 0:
        print(f"Dataset {s} has no valid data.")
        return

    # Define the Decision Tree model
    tree_model = DecisionTreeClassifier(criterion=my_criterion, max_depth=None, random_state=0, splitter="best")

    # Define 10-fold cross-validation with stratification to maintain label distribution
    skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)

    # Compute cross-validation scores
    scores = cross_val_score(tree_model, X, Y, cv=skf)
    print(f"10-fold cross-validation scores: {scores}")
    print(f"Average accuracy: {scores.mean()*100:.2f}%, Standard deviation: {scores.std()*100:.2f}%")

    # Generate cross-validated predictions
    Y_pred = cross_val_predict(tree_model, X, Y, cv=skf)

    # Print classification report
    print("Classification Report:")
    print(classification_report(Y, Y_pred, target_names=[
        'ciscoSystems',
        'Juniper Networks, Inc.',
        'HUAWEI Technology Co.,Ltd',
        'MikroTik',
        'H3C',
        'Intelbras',
        'Sagemcom Broadband SAS',
        'zte corporation',
        'Brocade Communication Systems, Inc.',
        'TP-Link Corporation Limited.'
    ]))

    # Draw confusion matrix
    draw_confusion_matrix(
        label_true=Y,
        label_pred=Y_pred,
        label_name=[
            'ciscoSystems',
            'Juniper Networks, Inc.',
            'HUAWEI Technology Co.,Ltd',
            'MikroTik',
            'H3C',
            'Intelbras',
            'Sagemcom Broadband SAS',
            'zte corporation',
            'Brocade Communication Systems, Inc.',
            'TP-Link Corporation Limited.'
        ],
        title=f"Confusion Matrix - Dataset {s}",
        pdf_save_path=f"Confusion_Matrix_{s}.png",
        dpi=300
    )

    # Train the model on the entire dataset
    tree_model.fit(X, Y)
    feature_names = ['tcp_ttl', 'tcp_size', 'udp_ttl', 'udp_size', 'icmp_ttl', 'ipid_type', 'ipid_increnum', 'ipid_num']
    target_names = [
        'ciscoSystems',
        'Juniper Networks, Inc.',
        'HUAWEI Technology Co.,Ltd',
        'MikroTik',
        'H3C',
        'Intelbras',
        'Sagemcom Broadband SAS',
        'zte corporation',
        'Brocade Communication Systems, Inc.',
        'TP-Link Corporation Limited.'
    ]

    # Export the decision tree to Graphviz format and render it
    dot_data = export_graphviz(
        tree_model, out_file=None,
        feature_names=feature_names,
        class_names=target_names,
        filled=True, rounded=True,
        special_characters=True
    )

    graph = graphviz.Source(dot_data)
    graph.render(f"vendor_tree_{s}", view=False)  # view=True will automatically open the PDF file

    print(f"Decision tree graph saved as vendor_tree_{s}.pdf")
   
for i in ['0609','0618','0701','total']:
    #Mytest_criterion(i,"entropy")#Information Entropy
    X,Y = load_ssh_data('./eui64/%s/feature_%s_snmp_more.json'%(i,i))
    print(len(X))


