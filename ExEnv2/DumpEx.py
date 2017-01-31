from winpcapy import *
from dumpy import *
import struct

#패킷을 가져올 인터페이스를 지정
device = get_device()

#해당 장치로부터 패킷을 가져오기 위한 준비
adhandle = pcap_open_live(device.name, 65536, 1, 1000, errbuf)

while 1:
    recv = pcap_next_ex(adhandle, byref(header), byref(pkt_data))

    #실제 읽어들인 패킷 정보
    data = pkt_data[: header.contents.len]

    ethHeader = bytes(data[0: 14])
    ethHeader = struct.unpack(">6B6BH", ethHeader)

    dstMac = str(hex(ethHeader[0]))[2: ] + ":" + str(hex(ethHeader[1]))[2: ] + ":" + str(hex(ethHeader[2]))[2: ] + ":" + str(hex(ethHeader[3]))[2: ] + ":" + str(hex(ethHeader[4]))[2: ] + ":" + str(hex(ethHeader[5]))[2: ]
    srcMac = str(hex(ethHeader[6]))[2: ] + ":" + str(hex(ethHeader[7]))[2: ] + ":" + str(hex(ethHeader[8]))[2: ] + ":" + str(hex(ethHeader[9]))[2: ] + ":" + str(hex(ethHeader[10]))[2: ] + ":" + str(hex(ethHeader[11]))[2: ]
    L3type = ethHeader[12]

    arpSrcMac = ""
    arpSrcIp = ""
    arpDstMac = ""
    arpDstIp = ""
    
    if L3type == 0x800:
        ipHeader = bytes(data[14: 34])
        ipHeader = struct.unpack(">BBHHBBBBH8B", ipHeader)

        ipV = ipHeader[0] >> 4
        ipHeadLen = (ipHeader[0] - ((ipHeader[0] >> 4) << 4)) * 4
        ipTotalLen = ipHeader[2]
        L4protocol = ipHeader[7]
        ipSrcAddress = str(ipHeader[9]) + "."  + str(ipHeader[10]) + "."  + str(ipHeader[11]) + "."  + str(ipHeader[12]) 
        ipDstAddress = str(ipHeader[13]) + "."  + str(ipHeader[14]) + "."  + str(ipHeader[15]) + "."  + str(ipHeader[16])
    
        if L4protocol == 0x6:
            tcpHeader = bytes(data[14 + ipHeadLen: 14 + ipHeadLen + 20])
            tcpHeader = struct.unpack(">HHIIBBHHH", tcpHeader)

            tcpSrcPort = tcpHeader[0]
            tcpDstPort = tcpHeader[1]
            tcpHeadLen = (tcpHeader[4] >> 4) * 4

        elif L4protocol == 0x11:
            udpHeader = bytes(data[14 + ipHeadLen: 14 + ipHeadLen +8])
            udpHeader = struct.unpack(">HHHH", udpHeader)

            udpSrcPort = udpHeader[0]
            udpDstPort = udpHeader[1]
            udpLen = udpHeader[2]

        else:
            pass

    elif L3type == 0x806:
        arp = struct.unpack(">HHBBH6B4B6B4B", bytes(data[14: 42]))
        arpSrcMac = str(hex(arp[5])[2: ]) + ":" + str(hex(arp[6])[2: ]) + ":" + str(hex(arp[7])[2: ]) + ":" + str(hex(arp[8])[2: ]) + ":" + str(hex(arp[9])[2: ]) + ":" + str(hex(arp[10])[2: ])
        arpSrcIp = str(arp[11]) + "." + str(arp[12]) + "." + str(arp[13]) + "." + str(arp[14])
        arpDstMac = str(hex(arp[15])[2: ]) + ":" + str(hex(arp[16])[2: ]) + ":" + str(hex(arp[17])[2: ]) + ":" + str(hex(arp[18])[2: ]) + ":" + str(hex(arp[19])[2: ]) + ":" + str(hex(arp[20])[2: ])
        arpDstIp = str(arp[21]) + "." + str(arp[22]) + "." + str(arp[23]) + "." + str(arp[24])

    else:
        pass
    
    if L3type == 0x800 and (ipSrcAddress == "192.168.3.224" and ipDstAddress == "192.168.3.224") and 0:
        print("\n")
        print("srcMac:", dstMac)
        print("dstMac:", srcMac)
        print("L3type:", str(hex(L3type)))
        print("")
        
        print("ipV:", str(ipV))
        print("ipHeadLen:", str(ipHeadLen))
        print("ipServiceType:", str(ipHeader[1]))
        print("ipTotalLen:", str(ipTotalLen))
        print("ipId:", str(ipHeader[3]))
        ipFlag = (ipHeader[4] >> 5) << 5
        print("ipFlag:", str(ipFlag))
        print("ipFragOffset:", str(ipHeader[4] - ipFlag + ipHeader[5]))
        print("ipTTL:", str(ipHeader[6]))
        print("L4protocol:", str(L4protocol))
        print("ipHeadChSum:", str(ipHeader[8]))
        print("ipSrcAddress:", ipSrcAddress)
        print("ipDstAddress:", ipDstAddress)
        print("")
        
        if L4protocol == 0x6:
            print("tcpSrcPort:", str(tcpSrcPort))
            print("tcpDstPort:", str(tcpDstPort))
            print("tcpSeqNum:", str(tcpHeader[2]))
            print("tcpAckNum:", str(tcpHeader[3]))
            print("tcpHeadLen:", str(tcpHeadLen))
            print("tcpCodeBits:", str(tcpHeader[5]))
            print("tcpWindow:", str(tcpHeader[6]))
            print("tcpChSum:", str(tcpHeader[7]))
            print("tcpUrgent:", str(tcpHeader[8]))
            tcpData = bytes(data[14 + ipHeadLen + tcpHeadLen: ])
            tcpData = struct.unpack(">" + str(ipTotalLen - tcpHeadLen - ipHeadLen) + "s", tcpData)
            print(tcpData)
            print("")
        
        elif L4protocol == 0x11:
            print("udpSrcPort:", str(udpSrcPort))
            print("udpDstPort:", str(udpDstPort))
            print("udpLen:", str(udpHeader[2]))
            print("udpChSum:", str(udpHeader[3]))
            udpData = bytes(data[14 + ipHeadLen + 8: ])
            udpData = struct.unpack(">" + str(ipTotalLen - ipHeadLen - 8) + "s", udpData)
            print(udpData)
            print("")
            
        else:
            pass

    elif L3type == 0x806 and ((arpSrcIp == "192.168.3.98" and arpDstIp == "192.168.3.224") or (arpDstIp == "192.168.3.98" and arpSrcIp == "192.168.3.224")):
        print("")
        print("h/wType:", str(hex(arp[0])))
        print("protocolType:", str(hex(arp[1])))
        print("h/wLen:", str(arp[2]))
        print("protocolLen:", str(arp[3]))
        print("operation:", str(arp[4]))
        print("arpSrcMac:", arpSrcMac)
        print("arpSrcIp:", arpSrcIp)
        print("arpDstMac:", arpDstMac)
        print("arpDstIp:", arpDstIp)
        print("")
        
    else:
        pass
    
pcap_close(adhandle)
