import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ret = sock.connect(("192.168.3.236", 30303))

sock.close()
