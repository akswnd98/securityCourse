import socket
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

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.bind(("192.168.3.224", 0))
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

'''
ipVLen = 0x45
ipService =0
ipTotalLen = 33
ipId = 0x1234
ipFlagOffset = 0
ipTTL = 128
ipType = 1
ipChkSum = 0
ipSrc = socket.inet_aton("192.168.3.224")
ipDst = socket.inet_aton("192.168.3.18")

ipHeader = struct.pack(">BBHHHBBH4s4s", ipVLen, ipService, ipTotalLen, ipId, ipFlagOffset, ipTTL, ipType, \
                       ipChkSum, ipSrc, ipDst)
 '''
icmpType = 8
icmpCode = 0
icmpChkSum = 0x0000
icmpId = 0x1111
icmpSeq = 1
icmpData = 'A' * 32
icmpData = icmpData.encode()

icmpHeader = struct.pack(">BBHHH32s", icmpType, icmpCode, icmpChkSum, icmpId, icmpSeq, icmpData)

icmpChkSum = makeCheckSum(icmpHeader)
icmpHeader = struct.pack(">BBHHH32s", icmpType, icmpCode, icmpChkSum, icmpId, icmpSeq, icmpData)

sock.sendto(icmpHeader, ("192.168.3.18", 0))

n = 0
while n < 2:
    data, info = sock.recvfrom(1500)
    ipAddr, port = info
    print(ipAddr)
    n += 1
    
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
sock.close()
