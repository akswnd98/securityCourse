import socket
import struct
from winpcapy import *
from dumpy import *

sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

sendSock.bind(("192.168.3.224", 0))
sendSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

ipVLen = 0x45
ipService =0
ipTotalLen = 40
ipId = 0x1234
ipFlagOffset = 0
ipTTL = 128
ipType = 0x11
ipChkSum = 0
ipSrc = socket.inet_aton("192.168.3.224")
ipDst = socket.inet_aton("192.168.3.236")

ipHeader = struct.pack(">BBHHHBBH4s4s", ipVLen, ipService, ipTotalLen, ipId, ipFlagOffset, ipTTL, ipType, \
                       ipChkSum, ipSrc, ipDst)

udpDstPort = 30303
udpSrcPort = 12333
udpLen = 20
udpChkSum = 0
udpData = b"A" * 12

openPortList = [x for x in range(1, 100)]
closedPortList = []
sendPacket = b""

device = get_device()
adhandle = pcap_open_live(device.name, 65536, 1, 1000, errbuf)

for i in range(1, 100):
    udpDstPort = i
    udpHeader = struct.pack(">HHHH12s", udpSrcPort, udpDstPort, udpLen, udpChkSum, udpData)
    sendPacket = ipHeader + udpHeader
    sendSock.sendto(sendPacket, ("192.168.3.236", i))
    for _ in range(20):
        recv = pcap_next_ex(adhandle, byref(header), byref(pkt_data))
        data = pkt_data[: header.contents.len]
        ethHeader = bytes(data[0: 14])
        ethHeader = struct.unpack(">6B6BH", ethHeader)
        recvIpHeader = bytes(data[14: 34])
        recvIpHeaderUnpacked = struct.unpack(">BBHHBBBBH8B", recvIpHeader)
        ipSrcAddress = str(recvIpHeaderUnpacked[9]) + "."  + str(recvIpHeaderUnpacked[10]) + "."  + str(recvIpHeaderUnpacked[11]) + "."  + str(recvIpHeaderUnpacked[12]) 
        ipDstAddress = str(recvIpHeaderUnpacked[13]) + "."  + str(recvIpHeaderUnpacked[14]) + "."  + str(recvIpHeaderUnpacked[15]) + "."  + str(recvIpHeaderUnpacked[16])
        if ethHeader[12] == 0x800 and ipSrcAddress == "192.168.3.236" and recvIpHeaderUnpacked[7] == 1:
            print(ipSrcAddress)
            openPortList.remove(i)
            break

for port in openPortList:
    print("openPort: " + str(port))
    
sendSock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
sendSock.close()
pcap_close(adhandle)
