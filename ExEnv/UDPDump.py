import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

host = socket.gethostbyname(socket.gethostname())

sock.bind((host, 0))

sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while 1:
    data, info = sock.recvfrom(1500)
    if info[0] == "192.168.3.224":
        ip = data[: 20]
        ip = struct.unpack(">BBHHBBBBH8B", ip)
        udp = data[20: ]
        udp = struct.unpack(">HHHH5s", udp)
        if udp[0] == 32323:
            print(list(map(hex, ip)))
            print("IPv:", ip[0])
            print("Reserved:", ip[1])
            print("ip length:", ip[2])
            print("identifier:", ip[3])
            print("flag:", ip[4])
            print("flagment offset:", ip[5])
            print("TTL:", ip[6])
            print("L4:", ip[7])
            print("checksum:", ip[8])
            print("src ip:", str(ip[9]) + "." + str(ip[10]) + "." + str(ip[11]) + "." + str(ip[12]))
            print("dst ip:", str(ip[13]) + "." + str(ip[14]) + "." + str(ip[15]) + "." + str(ip[16]))
            print("src port" , udp[0])
            print("dst port:", udp[1])
            print("udp length:", udp[2])
            print("udp checksum:", udp[3])
            print("udp data:", udp[4])
            
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
sock.close()
