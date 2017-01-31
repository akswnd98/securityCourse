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

packet=(c_ubyte * 54)()

device = get_device()
adhandle = pcap_open_live( device.name, 65536, 1, 1000, errbuf )

# dst mac address
packet[0], packet[1], packet[2], packet[3], packet[4], packet[5] = \
           0xd0, 0x50, 0x99, 0x8b, 0x4e, 0xec

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
packet[23] = 17

# checksum
packet[24], packet[25] = 0x00, 0x00

# src ip
packet[26], packet[27], packet[28], packet[29] = \
            192, 168, 3, 236

# dst ip
packet[30], packet[31], packet[32], packet[33] = \
            192, 168, 3, 18

packetBytes = bytes(packet[14: 34])
chkSum = makeCheckSum(packetBytes)
chkSum0 = chkSum & 0xff
chkSum1 = (chkSum >> 8) & 0xff

packet[24] = chkSum1
packet[25] = chkSum0

# udp src port
packet[34], packet[35] = 0x12, 0x34

# udp dst port
packet[36], packet[37] = 0x00, 0x01

# udp length
packet[38], packet[39] = 0x00, 0x14

# udp checksum
packet[40], packet[41] = 0x00, 0x00

packet[42] = packet[43] = packet[44] = packet[45] = packet[46] = packet[47] = \
packet[48] = packet[49] = packet[50] = packet[51] = packet[52] = packet[53] = 45

while True:
    pcap_sendpacket(adhandle, packet, 54)









