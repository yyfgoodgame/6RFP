import re
import matplotlib
import sklearn.tree
from sklearn.datasets import load_iris

from sklearn.tree import DecisionTreeClassifier, plot_tree ,DecisionTreeRegressor ,export_graphviz  
from sklearn.metrics import confusion_matrix

from sklearn.model_selection import train_test_split

import numpy as np

import matplotlib.pyplot as plt
from itertools import groupby
import pandas as pd
import json 
import graphviz 
import random


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


def load_ssh_data(file):
    f=open(file, 'r', encoding='utf-8')
    data=[]
    label=[]
    jsoncontent=json.load(f)

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    ssh_raw={'SSH-2.0-Cisco-1.25': 1, 'SSH-2.0-OpenSSH_7.5': 2, 'null': 3, 'SSH-2.0--': 4, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 5, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 6, 'SSH-2.0-OpenSSH_7.4': 7, 'SSH-2.0-ROSSSH': 8, 'SSH-2.0-OpenSSH_6.9': 9, 'SSH-2.0-OpenSSH_7.3': 10, 'SSH-2.0-OpenSSH_7.2': 11, 'SSH-2.0-Comware-7.1.075': 12, 'SSH-1.99-Cisco-1.25': 13, 'SSH-2.0-OpenSSH_7.2 FIPS': 14, 'SSH-2.0-OpenSSH_6.6.1': 15, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 16, 'SSH-2.0-OpenSSH_5.9': 17, 'SSH-2.0-HUAWEI-1.5': 18, 'SSH-2.0-OpenSSH_6.4': 19, 'SSH-2.0-OpenSSH_5.9 FIPS': 20, 'SSH-2.0-OpenSSH_6.0': 21, 'SSH-2.0-OpenSSH_6.2': 22, 'SSH-2.0-OpenSSH_4.4': 23, 'SSH-1.99-Comware-7.1.045': 24, 'SSH-2.0-RomSShell_5.40': 25, 'SSH-2.0-OpenSSH_6.2 FIPS': 26, 'SSH-2.0-OpenSSH_5.5 FIPS': 27, 'SSH-2.0-Comware-7.1.070': 28, 'SSH-2.0-Cisco-2.0': 29, 'SSH-2.0-Comware-7.1.059': 30, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 31, 'SSH-2.0-OpenSSH_8.0': 32, 'SSH-2.0-RGOS_SSH': 33, 'SSH-2.0-OpenSSH_5.8': 34, 'SSH-2.0-RomSShell_4.61': 35, 'SSH-2.0-OpenSSH_7.1': 36, 'SSH-2.0-OpenSSH_8.8': 37, 'SSH-2.0-SSH': 38, 'SSH-2.0-OpenSSH_6.1': 39, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 40, 'SSH-2.0-Comware-9.0.001': 41, 'SSH-2.0-OpenSSH_9.5 FreeBSD-20231004': 42, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 43, 'SSH-2.0-Adtran_4.31': 44, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 45, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719': 46, 'SSH-2.0-Dh-v39EVDB8f6LZ': 47, 'SSH-2.0-OpenSSH_9.7 FreeBSD-20240318': 48, 'SSH-1.99-OpenSSH_6.9': 49, 'SSH-1.99-RGOS_SSH': 50, 'SSH-1.99--': 51, 'SSH-2.0-SERVER_1.01': 52, 'SSH-1.99-OpenSSH_6.0': 53, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240104': 54, 'SSH-2.0-Mocana SSH 6.3': 55, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 56, 'SSH-2.0-RGOS_PK3223': 57, 'SSH-1.99-SSH': 58, 'SSH-2.0-OpenSSH_7.8 FreeBSD-20180909': 59, 'SSH-1.99-OpenSSH_7.3': 60, 'SSH-1.99-OpenSSH_6.1': 61, 'SSH-1.99-OpenSSH_6.8': 62, 'SSH-2.0-Comware-7.1.064': 63, 'SSH-1.99-OpenSSH_6.4': 64, 'SSH-1.99-Comware-7.1.075': 65, 'SSH-2.0-OpenSSH_7.7p1': 66, 'SSH-2.0-OpenSSH_6.6': 67, 'SSH-2.0-Comware-9.1.058': 68, 'SSH-2.0-WLH_rbHQLlDeyy': 69, 'SSH-1.99-OpenSSH_6.2': 70, 'SSH-2.0-OpenSSH_9.0': 71, 'SSH-1.99-OpenSSH_7.2p2': 72, 'SSH-2.0-Comware-7.1.045': 73, 'SSH-2.0-Alteon': 74, 'SSH-2.0-RGOS_SSH_1.0': 75, 'SSH-1.99-OpenSSH_5.8': 76, 'SSH-2.0-OpenSSH_3.5p1': 77, 'SSH-1.99-OpenSSH_6.6.1': 78, 'SSH-1.99-OpenSSH_4.4': 79, 'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]': 80, 'SSH-1.99-HUAWEI-1.5': 81, 'SSH-2.0-lancom': 82, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3': 83, 'SSH-2.0-dropbear': 84, 'SSH-2.0-OpenSSH_7.8': 85, 'SSH-2.0-OpenSSH_9.2p1': 86, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7': 87, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6': 88, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11': 89, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10': 90, 'SSH-2.0-OpenSSH_9.7': 91, 'SSH-2.0-ZTE_SSH.2.0': 92, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u1': 93, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2': 94, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1': 95, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1': 96, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 97, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5': 98, 'SSH-2.0-OpenSSH_9.5': 99, 'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7': 100, 'SSH-2.0-FHSSH_8.0': 101, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4': 102, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2': 103, 'SSH-2.0-OpenSSH_9.6': 104, 'SSH-2.0-OpenSSH_8.9p1': 105, 'SSH-2.0-OpenSSH_5.5': 106, 'SSH-2.0-OpenSSH_8.4p1 Debian-2~bpo10+1': 107, 'SSH-2.0-OpenSSH_9.2p1 Debian-2': 108, 'SSH-2.0-OpenSSH_8.6': 109, 'SSH-2.0-OpenSSH_9.3': 110, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u3': 111, 'SSH-2.0-OpenSSH_9.6p1 Debian-4': 112, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7': 113, 'SSH-2.0-dropbear_2020.81': 114, 'SSH-2.0-OpenSSH_7.9p1': 115, 'SSH-2.0-OpenSSH_6.8': 116, 'SSH-2.0-Mocana SSH 5.8': 117, 'SSH-2.0-OpenSSH_7.9 FreeBSD-20200214': 118, 'SSH-2.0-OpenSSH_7.6': 119, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20221019': 120, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7': 121, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3': 122, 'SSH-2.0-OpenSSH_7.9p1 Debian-10': 123, 'SSH-2.0-OpenSSH_8.7': 124, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2': 125, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3': 126, 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221': 127, 'SSH-2.0-Go': 128, 'SSH-2.0-OpenSSH_4.3': 129, 'SSH-1.99-OpenSSH_8.5': 130, 'SSH-2.0-b95rVonwBt': 131, 'SSH-2.0-OxywS4Oe4sDl': 132, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1': 133, 'SSH-2.0-OpenSSH_8.2p1': 134, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3': 135, 'SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1': 136, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2': 137, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1': 138, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3': 139, 'SSH-2.0-OpenSSH_7.7p1 Debian-2': 140, 'SSH-2.0-OpenSSH_8.4p1 Debian-5': 141, 'SSH-2.0-OpenSSH_9.1': 142, 'SSH-2.0-OpenSSH_9.6p1 Debian-3': 143, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4.ui1': 144, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3': 145, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13': 146, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.7': 147, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2': 148, 'SSH-2.0-OpenSSH_6.3': 149, 'SSH-2.0-dropbear_2019.78': 150, 'SSH-2.0-OpenSSH_Stable': 151, 'SSH-2.0-OpenSSH_7.3p1 Ubuntu-1ubuntu0.1': 152, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8': 153, 'SSH-2.0-OpenSSH_8.4': 154, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2': 155, 'SSH-2.0-OpenSSH_7.2p2': 156, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7': 157, 'SSH-2.0-OpenSSH_8.9': 158, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9': 159, 'SSH-2.0-t1VtSi': 160, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3': 161, 'SSH-2.0-dropbear_2014.63': 162, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8': 163, 'SSH-2.0-dropbear_2022.83': 164, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1': 165, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2': 166, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5': 167, 'SSH-2.0-OpenSSH_8.4p1': 168, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4': 169, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6': 170, 'SSH-2.0-OpenSSH_9.7p1 Debian-5': 171, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3': 172, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1': 173, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4': 174, 'SSH-2.0-OpenSSH_7.9p1 Vyatta-10+deb10u2+danos1': 175, 'SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420': 176, 'SSH-2.0-OpenSSH_8.6p1': 177, 'SSH-2.0-OpenSSH_9.6p1 Debian-2': 178, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10+esm5': 179, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3': 180, 'SSH-2.0-OpenSSH-FIPS(capable)': 181, 'SSH-2.0-OpenSSH_9.0p1 Debian-1+b1': 182, 'SSH-2.0-OpenSSH_8.1': 183, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4': 184, 'SSH-2.0-OpenSSH_9.5p1 Debian-2': 185, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3': 186, 'SSH-2.0-B4I_haIvxy': 187, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4': 188, 'SSH-2.0-OpenSSH_7.6p1': 189, 'SSH-2.0-OpenSSH_7.5 FreeBSD-20170903': 190, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4': 191, 'SSH-2.0-OpenSSH_5.9 NetBSD_Secure_Shell-20110907-hpn13v11-lpk': 192, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4': 193, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20230719': 194, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5': 195, 'SSH-2.0-OpenSSH_5.3': 196, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4': 197, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2': 198, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8': 199, 'SSH-2.0-OpenSSH_7.7': 200, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u3': 201, 'SSH-2.0-OpenSSH_9.4': 202, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u1': 203, 'SSH-2.0-dropbear_2017.75': 204, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5': 205, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.8': 206, 'SSH-2.0-dropbear_2011.54': 207, 'SSH-2.0-dropbear_2015.67': 208, 'SSH-2.0-OpenSSH_8.0p1': 209, 'SSH-2.0-OpenSSH_7.9': 210, 'SSH-1.99-OpenSSH_4.3': 211, 'SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901': 212, 'SSH-2.0-OpenSSH_9.2': 213, 'SSH-2.0-OpenSSH_9.6p1 Debian-5': 214, 'SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20231220-hpn13v14-lpk': 215, 'SSH-2.0-OpenSSH_9.7 FreeBSD-openssh-portable-9.7.p1,1': 216, 'SSH-2.0-Li_mO3m-e_bXh-': 217, 'SSH-2.0-ConfD-6.7.6': 218, 'SSH-2.0-OpenSSH_9.7p1 Debian-4': 219, 'SSH-2.0-OpenSSH_6.7p1': 220, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8': 221, 'SSH-2.0-rPKx-': 222, 'SSH-2.0-OpenSSH_7.5p1 Ubuntu-10ubuntu0.1': 223, 'SSH-2.0-OpenSSH_9.3 FreeBSD-openssh-portable-9.3.p2_2,1': 224, 'SSH-2.0-OpenSSH_9.3 FreeBSD': 225, 'SSH-2.0-billsSSH_3.6.3q3': 226, 'SSH-2.0-Parks': 227, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10': 228, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3': 229, 'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9': 230, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u4': 231, 'SSH-2.0-tiger xxxxxxxxxxxxxxxxxxxxxxxx': 232, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11': 233, 'SSH-2.0-OpenSSH_9.8': 234, 'SSH-2.0-OpenSSH_6.6p2-hpn14v4': 235, 'SSH-2.0-OpenSSH_8.2': 236, 'SSH-2.0-dropbear_2012.55': 237, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6': 238, 'SSH-2.0-OpenSSH_9.7-hpn14v15': 239, 'SSH-2.0-OpenSSH_8.3': 240, 'SSH-2.0-OpenSSH_7.1p2-hpn14v10': 241, 'SSH-2.0-dropbear_2018.76': 242, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4': 243, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6': 244, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240701': 245, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13': 246, 'SSH-2.0-dropbear_2014.66': 247, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7': 248, 'SSH-1.99-OpenSSH_5.3': 249, 'SSH-2.0-OpenSSH_9.7p1 Debian-7': 250, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10': 251, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1': 252, 'SSH-2.0-dropbear_2016.74': 253, 'SSH-2.0-OpenSSH_6.7p1 Debian-5': 254, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6': 255, 'SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3': 256, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1': 257, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3': 258, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5_lol_notrly_JustGoAwayDammit1.0': 259, 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3': 260, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5-lol_notrly_JustGoAwayDammit1.0': 261, 'SSH-2.0-OpenSSH_9.7p1 Debian-6': 262, 'SSH-2.0-OpenSSH_7.4p1 Debian-10': 263, 'SSH-2.0-OpenSSH_8.1 Celeonet': 264, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u9': 265, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20240701': 266, 'SSH-2.0-OpenSSH_7.4p1': 267, 'SSH-2.0-OpenSSH_9.6p1 Raspbian-3': 268, 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310': 269, 'SSH-2.0-OpenSSH_for_Windows_8.9': 270, 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.2': 271, 'SSH-2.0-OpenSSH_6.6p1-hpn14v4': 272, 'SSH-2.0-mod_sftp': 273, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4': 274, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2': 275, 'SSH-2.0-OpenSSH_9.0p1 Debian-1': 276}
    vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 7, 'nVent, Schroff GmbH': 8, 'Ruijie Networks Co., Ltd.': 9, 'Teracom Telematica Ltda.': 10, 'Extreme Networks': 11, 'Casa Systems, Inc.': 12, 'Reserved': 13, 'FS.COM INC': 14, 'Alteon Networks, Inc.': 15, 'The FreeBSD Project': 16, 'EON': 17, 'Alcatel-Lucent Enterprise': 18, 'Adtran': 19, 'Hewlett-Packard': 20, 'Online.net': 21, 'Dell Inc.': 22, 'Fortinet, Inc.': 23, 'Force10 Networks, Inc.': 24, 'NAG LLC': 25, 'Shanghai Baud Data Communication Development Corp.': 26, 'Stale Odegaard AS': 27, 'OneAccess': 28, 'HITRON Technology, Inc.': 29, '3Com': 30, 'Neoteris, Inc.': 31, 'D-Link Systems, Inc.': 32, 'ZyXEL Communications Corp.': 33, 'Meinberg': 34, 'InfoBlox Inc.': 35, 'ALAXALA Networks Corporation': 36, 'Broadcom Limited': 37, 'Lenovo Enterprise Business Group': 38, 'APRESIA Systems, Ltd.': 39, 'Digital China': 40, 'Compaq': 41, 'Aruba, a Hewlett Packard Enterprise company': 42, 'SITA ADS': 43, '': 44, 'Furukawa Electoric Co. Ltd.': 45, 'Hewlett Packard Enterprise': 46, 'Maipu Electric Industrial Co., Ltd': 47, 'Enterasys Networks': 48, 'U.C. Davis, ECE Dept. Tom': 49, 'IBM': 50, 'TP-Link Corporation Limited.': 51, 'Microsoft': 52, 'FJA': 53, 'SNMP Research': 54, 'CacheFlow Inc.': 55, 'Texas Instruments': 56, 'NetScreen Technologies, Inc.': 57, 'Raritan Computer, Inc.': 58, 'Rad Data Communications Ltd.': 59, 'Network Appliance Corporation': 60, 'RND': 61, 'Beijing Topsec Network Security Technology Co., Ltd.': 62, 'Tsinghua Unisplendour Co., ltd': 63, 'RiverDelta Networks': 64, 'LANCOM Systems': 65, 'ACCTON Technology': 66, 'Blade Network Technologies, Inc.': 67, 'MIPS Computer Systems': 68, 'OpenBSD Project': 69}
    
    for i in jsoncontent:
        flag=True
        line=jsoncontent[i]
        if 'ssh' in line:
            feature=[ssh_raw[line['ssh']['type']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
            #feature using LFP
            #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),get_ttl(line['icmpv6']['size'])]
            linelabel=vendor_dict[line['snmp']['vendor']]

            data.append(feature)
            label.append(linelabel)


    f.close()

    return data,label

def load_nolabel_data(file):
    f=open(file, 'r', encoding='utf-8')
    data=[]
    jsoncontent=json.load(f)

    ipidtype_dict={'global':1,'local':2,'random':3,'other':4}
    ipidincrenum_dict={'one':1,'not one':2,'null':3}
    ipidnumber_dict={'big':1,'small':2}
    ssh_raw={'SSH-2.0-Cisco-1.25': 1, 'SSH-2.0-OpenSSH_7.5': 2, 'null': 3, 'SSH-2.0--': 4, 'SSH-2.0-OpenSSH_6.2 PKIX FIPS': 5, 'SSH-2.0-OpenSSH_8.3 PKIX[12.5.1]': 6, 'SSH-2.0-OpenSSH_7.4': 7, 'SSH-2.0-ROSSSH': 8, 'SSH-2.0-OpenSSH_6.9': 9, 'SSH-2.0-OpenSSH_7.3': 10, 'SSH-2.0-OpenSSH_7.2': 11, 'SSH-2.0-Comware-7.1.075': 12, 'SSH-1.99-Cisco-1.25': 13, 'SSH-2.0-OpenSSH_7.2 FIPS': 14, 'SSH-2.0-OpenSSH_6.6.1': 15, 'SSH-2.0-OpenSSH_8.0 PKIX[12.1]': 16, 'SSH-2.0-OpenSSH_5.9': 17, 'SSH-2.0-HUAWEI-1.5': 18, 'SSH-2.0-OpenSSH_6.4': 19, 'SSH-2.0-OpenSSH_5.9 FIPS': 20, 'SSH-2.0-OpenSSH_6.0': 21, 'SSH-2.0-OpenSSH_6.2': 22, 'SSH-2.0-OpenSSH_4.4': 23, 'SSH-1.99-Comware-7.1.045': 24, 'SSH-2.0-RomSShell_5.40': 25, 'SSH-2.0-OpenSSH_6.2 FIPS': 26, 'SSH-2.0-OpenSSH_5.5 FIPS': 27, 'SSH-2.0-Comware-7.1.070': 28, 'SSH-2.0-Cisco-2.0': 29, 'SSH-2.0-Comware-7.1.059': 30, 'SSH-2.0-OpenSSH_7.5 PKIX[10.1]': 31, 'SSH-2.0-OpenSSH_8.0': 32, 'SSH-2.0-RGOS_SSH': 33, 'SSH-2.0-OpenSSH_5.8': 34, 'SSH-2.0-RomSShell_4.61': 35, 'SSH-2.0-OpenSSH_7.1': 36, 'SSH-2.0-OpenSSH_8.8': 37, 'SSH-2.0-SSH': 38, 'SSH-2.0-OpenSSH_6.1': 39, 'SSH-2.0-OpenSSH_9.1 PKIX[13.5]': 40, 'SSH-2.0-Comware-9.0.001': 41, 'SSH-2.0-OpenSSH_9.5 FreeBSD-20231004': 42, 'SSH-2.0-OpenSSH_8.8-FIPS(capable)': 43, 'SSH-2.0-Adtran_4.31': 44, 'SSH-2.0-OpenSSH_8.2 PKIX[12.4.3]': 45, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719': 46, 'SSH-2.0-Dh-v39EVDB8f6LZ': 47, 'SSH-2.0-OpenSSH_9.7 FreeBSD-20240318': 48, 'SSH-1.99-OpenSSH_6.9': 49, 'SSH-1.99-RGOS_SSH': 50, 'SSH-1.99--': 51, 'SSH-2.0-SERVER_1.01': 52, 'SSH-1.99-OpenSSH_6.0': 53, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240104': 54, 'SSH-2.0-Mocana SSH 6.3': 55, 'SSH-2.0-OpenSSH_9.1 PKIX[12.5.1]': 56, 'SSH-2.0-RGOS_PK3223': 57, 'SSH-1.99-SSH': 58, 'SSH-2.0-OpenSSH_7.8 FreeBSD-20180909': 59, 'SSH-1.99-OpenSSH_7.3': 60, 'SSH-1.99-OpenSSH_6.1': 61, 'SSH-1.99-OpenSSH_6.8': 62, 'SSH-2.0-Comware-7.1.064': 63, 'SSH-1.99-OpenSSH_6.4': 64, 'SSH-1.99-Comware-7.1.075': 65, 'SSH-2.0-OpenSSH_7.7p1': 66, 'SSH-2.0-OpenSSH_6.6': 67, 'SSH-2.0-Comware-9.1.058': 68, 'SSH-2.0-WLH_rbHQLlDeyy': 69, 'SSH-1.99-OpenSSH_6.2': 70, 'SSH-2.0-OpenSSH_9.0': 71, 'SSH-1.99-OpenSSH_7.2p2': 72, 'SSH-2.0-Comware-7.1.045': 73, 'SSH-2.0-Alteon': 74, 'SSH-2.0-RGOS_SSH_1.0': 75, 'SSH-1.99-OpenSSH_5.8': 76, 'SSH-2.0-OpenSSH_3.5p1': 77, 'SSH-1.99-OpenSSH_6.6.1': 78, 'SSH-1.99-OpenSSH_4.4': 79, 'SSH-2.0-OpenSSH_8.8 PKIX[13.2.2 FIPS]': 80, 'SSH-1.99-HUAWEI-1.5': 81, 'SSH-2.0-lancom': 82, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3': 83, 'SSH-2.0-dropbear': 84, 'SSH-2.0-OpenSSH_7.8': 85, 'SSH-2.0-OpenSSH_9.2p1': 86, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7': 87, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6': 88, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11': 89, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10': 90, 'SSH-2.0-OpenSSH_9.7': 91, 'SSH-2.0-ZTE_SSH.2.0': 92, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u1': 93, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2': 94, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1': 95, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1': 96, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2': 97, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5': 98, 'SSH-2.0-OpenSSH_9.5': 99, 'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7': 100, 'SSH-2.0-FHSSH_8.0': 101, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4': 102, 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2': 103, 'SSH-2.0-OpenSSH_9.6': 104, 'SSH-2.0-OpenSSH_8.9p1': 105, 'SSH-2.0-OpenSSH_5.5': 106, 'SSH-2.0-OpenSSH_8.4p1 Debian-2~bpo10+1': 107, 'SSH-2.0-OpenSSH_9.2p1 Debian-2': 108, 'SSH-2.0-OpenSSH_8.6': 109, 'SSH-2.0-OpenSSH_9.3': 110, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u3': 111, 'SSH-2.0-OpenSSH_9.6p1 Debian-4': 112, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7': 113, 'SSH-2.0-dropbear_2020.81': 114, 'SSH-2.0-OpenSSH_7.9p1': 115, 'SSH-2.0-OpenSSH_6.8': 116, 'SSH-2.0-Mocana SSH 5.8': 117, 'SSH-2.0-OpenSSH_7.9 FreeBSD-20200214': 118, 'SSH-2.0-OpenSSH_7.6': 119, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20221019': 120, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7': 121, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3': 122, 'SSH-2.0-OpenSSH_7.9p1 Debian-10': 123, 'SSH-2.0-OpenSSH_8.7': 124, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2': 125, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3': 126, 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221': 127, 'SSH-2.0-Go': 128, 'SSH-2.0-OpenSSH_4.3': 129, 'SSH-1.99-OpenSSH_8.5': 130, 'SSH-2.0-b95rVonwBt': 131, 'SSH-2.0-OxywS4Oe4sDl': 132, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1': 133, 'SSH-2.0-OpenSSH_8.2p1': 134, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3': 135, 'SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1': 136, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2': 137, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1': 138, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3': 139, 'SSH-2.0-OpenSSH_7.7p1 Debian-2': 140, 'SSH-2.0-OpenSSH_8.4p1 Debian-5': 141, 'SSH-2.0-OpenSSH_9.1': 142, 'SSH-2.0-OpenSSH_9.6p1 Debian-3': 143, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4.ui1': 144, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3': 145, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13': 146, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.7': 147, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2': 148, 'SSH-2.0-OpenSSH_6.3': 149, 'SSH-2.0-dropbear_2019.78': 150, 'SSH-2.0-OpenSSH_Stable': 151, 'SSH-2.0-OpenSSH_7.3p1 Ubuntu-1ubuntu0.1': 152, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8': 153, 'SSH-2.0-OpenSSH_8.4': 154, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2': 155, 'SSH-2.0-OpenSSH_7.2p2': 156, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7': 157, 'SSH-2.0-OpenSSH_8.9': 158, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9': 159, 'SSH-2.0-t1VtSi': 160, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3': 161, 'SSH-2.0-dropbear_2014.63': 162, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8': 163, 'SSH-2.0-dropbear_2022.83': 164, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1': 165, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2': 166, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5': 167, 'SSH-2.0-OpenSSH_8.4p1': 168, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4': 169, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6': 170, 'SSH-2.0-OpenSSH_9.7p1 Debian-5': 171, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3': 172, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.1': 173, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4': 174, 'SSH-2.0-OpenSSH_7.9p1 Vyatta-10+deb10u2+danos1': 175, 'SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420': 176, 'SSH-2.0-OpenSSH_8.6p1': 177, 'SSH-2.0-OpenSSH_9.6p1 Debian-2': 178, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10+esm5': 179, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3': 180, 'SSH-2.0-OpenSSH-FIPS(capable)': 181, 'SSH-2.0-OpenSSH_9.0p1 Debian-1+b1': 182, 'SSH-2.0-OpenSSH_8.1': 183, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4': 184, 'SSH-2.0-OpenSSH_9.5p1 Debian-2': 185, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3': 186, 'SSH-2.0-B4I_haIvxy': 187, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4': 188, 'SSH-2.0-OpenSSH_7.6p1': 189, 'SSH-2.0-OpenSSH_7.5 FreeBSD-20170903': 190, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4': 191, 'SSH-2.0-OpenSSH_5.9 NetBSD_Secure_Shell-20110907-hpn13v11-lpk': 192, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4': 193, 'SSH-2.0-OpenSSH_9.1 FreeBSD-20230719': 194, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5': 195, 'SSH-2.0-OpenSSH_5.3': 196, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4': 197, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2': 198, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8': 199, 'SSH-2.0-OpenSSH_7.7': 200, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u3': 201, 'SSH-2.0-OpenSSH_9.4': 202, 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u1': 203, 'SSH-2.0-dropbear_2017.75': 204, 'SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5': 205, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.8': 206, 'SSH-2.0-dropbear_2011.54': 207, 'SSH-2.0-dropbear_2015.67': 208, 'SSH-2.0-OpenSSH_8.0p1': 209, 'SSH-2.0-OpenSSH_7.9': 210, 'SSH-1.99-OpenSSH_4.3': 211, 'SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901': 212, 'SSH-2.0-OpenSSH_9.2': 213, 'SSH-2.0-OpenSSH_9.6p1 Debian-5': 214, 'SSH-2.0-OpenSSH_9.6 NetBSD_Secure_Shell-20231220-hpn13v14-lpk': 215, 'SSH-2.0-OpenSSH_9.7 FreeBSD-openssh-portable-9.7.p1,1': 216, 'SSH-2.0-Li_mO3m-e_bXh-': 217, 'SSH-2.0-ConfD-6.7.6': 218, 'SSH-2.0-OpenSSH_9.7p1 Debian-4': 219, 'SSH-2.0-OpenSSH_6.7p1': 220, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8': 221, 'SSH-2.0-rPKx-': 222, 'SSH-2.0-OpenSSH_7.5p1 Ubuntu-10ubuntu0.1': 223, 'SSH-2.0-OpenSSH_9.3 FreeBSD-openssh-portable-9.3.p2_2,1': 224, 'SSH-2.0-OpenSSH_9.3 FreeBSD': 225, 'SSH-2.0-billsSSH_3.6.3q3': 226, 'SSH-2.0-Parks': 227, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10': 228, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3': 229, 'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9': 230, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u4': 231, 'SSH-2.0-tiger xxxxxxxxxxxxxxxxxxxxxxxx': 232, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11': 233, 'SSH-2.0-OpenSSH_9.8': 234, 'SSH-2.0-OpenSSH_6.6p2-hpn14v4': 235, 'SSH-2.0-OpenSSH_8.2': 236, 'SSH-2.0-dropbear_2012.55': 237, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6': 238, 'SSH-2.0-OpenSSH_9.7-hpn14v15': 239, 'SSH-2.0-OpenSSH_8.3': 240, 'SSH-2.0-OpenSSH_7.1p2-hpn14v10': 241, 'SSH-2.0-dropbear_2018.76': 242, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4': 243, 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6': 244, 'SSH-2.0-OpenSSH_9.6 FreeBSD-20240701': 245, 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13': 246, 'SSH-2.0-dropbear_2014.66': 247, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7': 248, 'SSH-1.99-OpenSSH_5.3': 249, 'SSH-2.0-OpenSSH_9.7p1 Debian-7': 250, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10': 251, 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1': 252, 'SSH-2.0-dropbear_2016.74': 253, 'SSH-2.0-OpenSSH_6.7p1 Debian-5': 254, 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6': 255, 'SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3': 256, 'SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1': 257, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3': 258, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5_lol_notrly_JustGoAwayDammit1.0': 259, 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3': 260, 'SSH-2.0-OpenSSH_7.9p1 SSH-1.5-lol_notrly_JustGoAwayDammit1.0': 261, 'SSH-2.0-OpenSSH_9.7p1 Debian-6': 262, 'SSH-2.0-OpenSSH_7.4p1 Debian-10': 263, 'SSH-2.0-OpenSSH_8.1 Celeonet': 264, 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u9': 265, 'SSH-2.0-OpenSSH_9.3 FreeBSD-20240701': 266, 'SSH-2.0-OpenSSH_7.4p1': 267, 'SSH-2.0-OpenSSH_9.6p1 Raspbian-3': 268, 'SSH-2.0-OpenSSH_7.2 FreeBSD-20160310': 269, 'SSH-2.0-OpenSSH_for_Windows_8.9': 270, 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.2': 271, 'SSH-2.0-OpenSSH_6.6p1-hpn14v4': 272, 'SSH-2.0-mod_sftp': 273, 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4': 274, 'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2': 275, 'SSH-2.0-OpenSSH_9.0p1 Debian-1': 276}
    vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'Brocade Communications Systems, Inc.': 4, 'MikroTik': 5, 'H3C': 6, 'Brocade Communication Systems, Inc.': 7, 'nVent, Schroff GmbH': 8, 'Ruijie Networks Co., Ltd.': 9, 'Teracom Telematica Ltda.': 10, 'Extreme Networks': 11, 'Casa Systems, Inc.': 12, 'Reserved': 13, 'FS.COM INC': 14, 'Alteon Networks, Inc.': 15, 'The FreeBSD Project': 16, 'EON': 17, 'Alcatel-Lucent Enterprise': 18, 'Adtran': 19, 'Hewlett-Packard': 20, 'Online.net': 21, 'Dell Inc.': 22, 'Fortinet, Inc.': 23, 'Force10 Networks, Inc.': 24, 'NAG LLC': 25, 'Shanghai Baud Data Communication Development Corp.': 26, 'Stale Odegaard AS': 27, 'OneAccess': 28, 'HITRON Technology, Inc.': 29, '3Com': 30, 'Neoteris, Inc.': 31, 'D-Link Systems, Inc.': 32, 'ZyXEL Communications Corp.': 33, 'Meinberg': 34, 'InfoBlox Inc.': 35, 'ALAXALA Networks Corporation': 36, 'Broadcom Limited': 37, 'Lenovo Enterprise Business Group': 38, 'APRESIA Systems, Ltd.': 39, 'Digital China': 40, 'Compaq': 41, 'Aruba, a Hewlett Packard Enterprise company': 42, 'SITA ADS': 43, '': 44, 'Furukawa Electoric Co. Ltd.': 45, 'Hewlett Packard Enterprise': 46, 'Maipu Electric Industrial Co., Ltd': 47, 'Enterasys Networks': 48, 'U.C. Davis, ECE Dept. Tom': 49, 'IBM': 50, 'TP-Link Corporation Limited.': 51, 'Microsoft': 52, 'FJA': 53, 'SNMP Research': 54, 'CacheFlow Inc.': 55, 'Texas Instruments': 56, 'NetScreen Technologies, Inc.': 57, 'Raritan Computer, Inc.': 58, 'Rad Data Communications Ltd.': 59, 'Network Appliance Corporation': 60, 'RND': 61, 'Beijing Topsec Network Security Technology Co., Ltd.': 62, 'Tsinghua Unisplendour Co., ltd': 63, 'RiverDelta Networks': 64, 'LANCOM Systems': 65, 'ACCTON Technology': 66, 'Blade Network Technologies, Inc.': 67, 'MIPS Computer Systems': 68, 'OpenBSD Project': 69}
    
    for i in jsoncontent:
        flag=True
        line=jsoncontent[i]
        if 'ssh' in line:
            feature=[ssh_raw[line['ssh']['type']],get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),ipidtype_dict[line['ipid']['type']],ipidincrenum_dict[line['ipid']['incre_num']],ipidnumber_dict[line['ipid']['number']]]
            #feature using LFP
            #feature=[get_ttl(line['tcp']['ttl']),line['tcp']['size'],get_ttl(line['udp']['ttl']),line['udp']['size'],get_ttl(line['icmpv6']['ttl']),get_ttl(line['icmpv6']['size'])]

            data.append(feature)


    f.close()

    return data
    



def draw_confusion_matrix(label_true, label_pred, label_name, title="Confusion Matrix", pdf_save_path=None, dpi=100):
    
    cm = confusion_matrix(y_true=label_true, y_pred=label_pred, normalize='true')

    plt.imshow(cm, cmap='Blues')
    plt.title(title)
    plt.xlabel("Predict label")
    plt.ylabel("Truth label")
    plt.yticks(range(label_name.__len__()), label_name)
    plt.xticks(range(label_name.__len__()), label_name, rotation=45)

    plt.tight_layout()

    plt.colorbar()

    for i in range(label_name.__len__()):
        for j in range(label_name.__len__()):
            color = (1, 1, 1) if i == j else (0, 0, 0)  # 对角线字体白色，其他黑色
            value = float(format('%.2f' % cm[j, i]))
            plt.text(i, j, value, verticalalignment='center', horizontalalignment='center', color=color)

    # plt.show()
    if not pdf_save_path is None:
        plt.savefig(pdf_save_path, bbox_inches='tight', dpi=dpi)
        




def Mytest_criterion(my_criterion):    
    X_train=[]
    Y_train=[]
    X_test=[]
    Y_test=[]
    Prediction_X=[]
    snmp_6RFP_file='./snmp_6RFP.json'
    only_6RFP_file='./only_6RFP.json'
    
    X,Y = load_ssh_data(snmp_6RFP_file)       
    len_X=len(X)
    ranl=list(range(len_X))
    random.shuffle(ranl)
    for j in ranl[:len_X*7//10]:
        X_train.append(X[j])
        Y_train.append(Y[j])
    for j in ranl[len_X*7//10:]:
        X_test.append(X[j])
        Y_test.append(Y[j])
    
    Prediction_X=load_nolabel_data(only_6RFP_file)

    tree_model=DecisionTreeClassifier(criterion=my_criterion,max_depth=None,random_state=0,splitter="best")
    
    vendor_dict={'ciscoSystems': 1, 'Juniper Networks, Inc.': 2, 'HUAWEI Technology Co.,Ltd': 3, 'MikroTik': 5, 'H3C': 6,}

    tree_model.fit(X_train,Y_train)
    
    print('-------Validation--------')
    print("the accuracy in validation datas is",tree_model.score(X_test,Y_test))
   
    length=len(X_test)
    for i in vendor_dict:
        X_now=[]
        Y_now=[]
        for j in range(length):
            if Y_test[j]==vendor_dict[i]:
                X_now.append(X_test[j])
                Y_now.append(Y_test[j])
        if X_now == []:
            print(i,'pass')
        else:
            print("the accuracy in vendor %s is"%i,tree_model.score(X_now,Y_now))
    
    print('-------Prediction--------')
    predict_result=tree_model.predict(Prediction_X)
    pl=len(predict_result)
    for j in vendor_dict:
        cur=0
        for m in range(pl):
            if predict_result[m] == vendor_dict[j]:
                cur+=1
        print("the partition of vendor %s "%j,cur/pl)
                    
    print('-------Feature Importance--------')
    feature_importances = tree_model.feature_importances_

    #print the importance of features
    feature_names = 'ssh_raw,tcp_ttl,tcp_size,udp_ttl,udp_size,icmp_ttl,ipid_type,ipid_incre,ipid_num'
    importance_df = pd.DataFrame({'Feature': feature_names.split(','), 'Importance': feature_importances})

    importance_df = importance_df.sort_values(by='Importance', ascending=False)
    print(importance_df)


    

   
if __name__ == '__main__':
    Mytest_criterion("entropy")


