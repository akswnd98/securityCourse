from winpcapy import *
from dumpy import *
import struct
import socket

backMessageFront = b"GET /challenge/training/programming1/index.php?"
backMessageMiddle = b"action=request"
backMessageBack = b" HTTP/1.1\r\nAccept: text/html, application/xhtml+xml, */*\r\nReferer: http://www.wechall.net/challenge/training/programming1/index.php\r\nAccept-Language: ko-KR\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\nHost: www.wechall.net\r\nConnection: Keep-Alive\r\nCookie: WC=9353258-25526-Ikwcc4cTQsdGlL4m\r\n\r\n"

device = get_device()
adhandle = pcap_open_live(device.name, 65526, 1, 1000, errbuf)

condition = 0
togle = 0
dataBytes = b""

sendMessage = backMessageFront + backMessageMiddle + backMessageBack
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("176.28.31.8", 80))
sock.send(sendMessage)

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

        if ipSrc == "176.28.31.8" and ipDst == "192.168.3.214":
            condition = 1

            if b"HTTP/1.1" in bytes(data[54: ]):
                condition = 1

            else:
                condition = 0
                
        else:
            condition = 0

    else:
        condition = 0

    if condition == 1:
        dataBytes = bytes(data[54: ])
        index = dataBytes.index(b"\r\n\r\n")
        index += 4

        backMessageMiddle = dataBytes[index + 3: -2]
        backMessage = backMessageFront + b"answer=" + backMessageMiddle + backMessageBack
        print(backMessageMiddle)
        print(backMessage)
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("176.28.31.8", 80))
        sock.send(backMessage)
        sock.send(backMessageMiddle)
        recvMesg = b"1"
        while recvMesg != b"":
            recvMesg = sock.recv(1500)
            print(recvMesg)

        break
        
    else:
        pass

sock.close()  
pcap_close(adhandle)
