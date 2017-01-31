import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

host = socket.gethostbyname(socket.gethostname())

sock.bind((host, 0))

sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while 1:
    (data, info) = sock.recvfrom(1500)
    ipHeader = data[: 20]
    ipHeader = struct.unpack(">BBHHBBBBH8B", ipHeader)

    ipV = ipHeader[0] >> 4
    ipHeadLen = (ipHeader[0] - ipV * 0x10) * 4
    totalLen = ipHeader[2]
    ipSrcAddress = str(ipHeader[9]) + "." + str(ipHeader[10]) + "." + str(ipHeader[11]) + "." + str(ipHeader[12])
    ipDstAddress = str(ipHeader[13]) + "." + str(ipHeader[14]) + "." + str(ipHeader[15]) + "." + str(ipHeader[16])

    ipConditionFlag = (ipSrcAddress == "192.168.3.224" and ipDstAddress == "192.168.3.224") or \
                       (ipSrcAddress == "192.168.3.224" and ipDstAddress == "192.168.3.224")
    tcpConditionFlag = 0
    udpConditionFlag = 0
    
    if ipHeader[7] == 6:
        tcpHeader = data[ipHeadLen: ipHeadLen + 20]
        tcpHeader = struct.unpack(">HHIIBBHHH", tcpHeader)

        tcpHeadLen = (tcpHeader[4] >> 4) * 4
        tcpCodeBits = tcpHeader[5]
        flag = {'1': 'FIN', '2': 'SYN', '4': 'RST', '8': 'PSH', '16': 'ACK', '32': 'URG', '18': 'SYN-ACK', '20': 'RST-ACK', '17': 'FIN-ACK', '24': 'PSH-ACK'}

        tcpConditionFlag = (tcpHeader[0] == 30303) or (tcpHeader[1] == 30303)
        
    elif ipHeader[7] == 17:
        udpHeader = data[ipHeadLen: ipHeadLen + 8 ]
        udpHeader = struct.unpack(">HHHH", udpHeader)
        udpSrcPort = udpHeader[0]
        udpDstPort = udpHeader[1]

        udpConditionFlag = (udpHeader[0] == 30303 and udpHeader[1] == 20202) or (udpHeader[0] == 20202 and udpHeader[1] == 30303)
        
    if ipConditionFlag and (tcpConditionFlag or udpConditionFlag):
        print(list(map(hex, data[: 20])))
        print("ipV:", str(ipV))
        print("ipHeadLen:", str(ipHeadLen))
        print("service:", str(ipHeader[1]))
        print("totalLen:", str(totalLen))
        print("identifier:", str(ipHeader[3]))
        print("flag:", str(ipHeader[4]))
        print("flagment offset:", str(ipHeader[5]))
        print("TTL:", str(ipHeader[6]))
        print("L4:", str(ipHeader[7]))
        print("checksum:", str(ipHeader[8]))
        print("src ip:", ipSrcAddress)
        print("dst ip:", ipDstAddress)
        if  ipHeader[7] == 6:
            print("tcpHeadRaw:", list(map(hex, data[ipHeadLen: ipHeadLen + tcpHeadLen])))

            print("Src port:", str(tcpHeader[0]))
            print("Dst port:", str(tcpHeader[1]))
            print("Seq num:", str(tcpHeader[2]))
            print("Ack num:", str(tcpHeader[3]))
            print("tcpHeadLen:", str(tcpHeadLen))
            print("CodeBits:", str(tcpCodeBits))
            print("flag:", str(hex(tcpHeader[5])), flag[str(tcpHeader[5])])
            print("window:", str(tcpHeader[6]))
            print("checksum:", str(hex(tcpHeader[7])))
            print("dummy:", str(hex(tcpHeader[8])))
            
            tcpData = data[ipHeadLen + tcpHeadLen: totalLen]
            tcpData = struct.unpack(">" + str(totalLen - (ipHeadLen + tcpHeadLen)) + "s", tcpData)
            print(tcpData)
            
        elif ipHeader[7] == 17:
            print("udpHeadRaw:", list(map(hex, data[ipHeadLen: ipHeadLen + 8])))
            print("src port:" , udpHeader[0])
            print("dst port:", udpHeader[1])
            print("udpHeadLen:", 8)
            print("udpDataLen", udpHeader[2] - 8)
            print("udp checksum:", udpHeader[3])
            
            udpData = data[ipHeadLen + 8: totalLen]
            udpData = struct.unpack(">" + str(totalLen - (ipHeadLen + 8)) + "s", udpData)
            print(udpData)
            
        else:
            pass
            
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
sock.close()
