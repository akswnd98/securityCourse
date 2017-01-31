from winpcapy import *
from dumpy import *
import struct

pMacD = "00:10:f3:4e:58:40"
pMacD = pMacD.split(':')

pMacDlist = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
for i in range(6):
    pMacDlist[i] = int(pMacD[i], 16)
            
packet = (c_ubyte * 42)()

device = get_device()
adhandle = pcap_open_live(device.name, 65526, 1, 1000, errbuf)

condition = 0
while True:        
    recv = pcap_next_ex(adhandle, byref(header), byref(pkt_data))
    data = pkt_data[0: header.contents.len]

    ethHeader = data[0: 14]
    ethHeader = bytes(ethHeader)
    ethHeader = struct.unpack(">6B6BH", ethHeader)

    if ethHeader[12] == 0x0800:
        condition = 1
        ipHeader = data[14: 34]
        ipHeader = bytes(ipHeader)
        ipHeader = struct.unpack(">BBHHBBBBH8B", ipHeader)

        ipDst = str(ipHeader[13]) + "." + str(ipHeader[14]) + "." + str(ipHeader[15]) + "." + str(ipHeader[16])
        ipSrc = str(ipHeader[9]) + "." + str(ipHeader[10]) + "." + str(ipHeader[11]) + "." + str(ipHeader[12])

        if ipSrc != "192.168.3.214" and ipDst != "192.168.3.214" and int(ipHeader[16]) != 255 and int(ipHeader[13]) < 224:
            condition = 1

            if ipHeader[7] == 17:
                condition = 1
                udpHeader = data[34: 42]
                udpHeader = bytes(udpHeader)
                udpHeader = struct.unpack(">HHHH", udpHeader)

                if udpHeader[1] == 53:
                    condition = 1
                    dnsHeaderLen = udpHeader[2] - 8
                    dnsHeader = data[42: 42 + dnsHeaderLen]
                    dnsHeader = bytes(dnsHeader)
                    dnsHeader = struct.unpack(">HHHHHH" + str(dnsHeaderLen - 12) + "s", dnsHeader)
                    print("srcPort: " + str(udpHeader[0]))
                    print("trxId: " + str(dnsHeader[0]))
                    dnsData = dnsHeader[6].decode()
                    print(dnsData)

                    i = 0
                    dnsDomainPart = []
                    dnsDomain = ""
                    while 1:
                        if ord(dnsData[i]) == 0:
                            break
                        
                        dnsDomainPart += [ord(dnsData[i])]
                        dnsDomain += dnsData[i + 1: i + ord(dnsData[i]) + 1] + "."
                        i += (ord(dnsData[i]) + 1)
                    dnsDomain = dnsDomain[0: -1]
                    print(dnsDomainPart)
                    print(dnsDomain)

            else:
                condition = 0
                
        else:
            condition = 0

    else:
        condition = 0

    if condition == 1:
        pass
    
pcap_close(adhandle)
