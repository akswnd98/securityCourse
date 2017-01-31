import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("192.168.3.141", 21))

data = sock.recv(1500)
print(data)

sock.send(b"USER ftpUser\r\n")
data = sock.recv(1500)
print(data)


sock.send(b"PASS abcde1234\r\n")
data = sock.recv(1500)
print(data)

sock.send(b"PASV\r\n")
data = sock.recv(1500)
print(data)

dataStr = data.decode()
start = dataStr.index('(')
end = dataStr.index(')')

print(dataServIp)
print(dataServPort)

while 1:
    sock.send(b"LIST\n\n")
    time.sleep(1)
sock.close()
