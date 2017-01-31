import socket
import struct

sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
recvSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

sendSock.bind(("192.168.3.224", 0))
sendSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

recvSock.bind(("192.168.3.224", 0))
recvSock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

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
for i in range(1, 100):
    udpDstPort = i
    udpHeader = struct.pack(">HHHH12s", udpSrcPort, udpDstPort, udpLen, udpChkSum, udpData)
    sendPacket = ipHeader + udpHeader
    sendSock.sendto(sendPacket, ("192.168.3.236", i))
    for _ in range(5):
        recvPacket, address = recvSock.recvfrom(1500)
        if recvPacket[12: 16] == b"\xc0\xa8\x03\xec" and recvPacket[8: 10] == b"\x00\x01":
            if recvPacket[20] == b"\x03" and recvPacket[21] == b"\x03":
                closedPortList += [i]
                break

for port in openPortList:
    print("openPort: " + str(port))
    
sendSock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
recvSock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
sendSock.close()
recvSock.close()
