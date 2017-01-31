import socket

clntSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clntSock.bind(('192.168.3.214', 22222))

clntSock.connect(('192.168.3.141', 166 * 256 + 247))

data = clntSock.recv(1500)
print(data)

clntSock.close()
