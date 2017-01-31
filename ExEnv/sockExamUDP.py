import socket

def serv_proc(argPort):
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serv_sock.bind(('', argPort))
    while 1:
        recv_msg, recv_info = serv_sock.recvfrom(1500)
        if recv_msg.decode() == "q":
            break
        
        print("recvfromMsg:", recv_msg.decode())
        print("recvfromIp:", recv_info[0])
        print("recvfromPort:", recv_info[1])
    serv_sock.close()
    
def clnt_proc(argAddress, argPort):
    recv_msg = ""
    send_msg = ""
    clnt_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clnt_sock.bind(('', 20202))
    while 1:
        send_msg = input("sendto: ")

        clnt_sock.sendto(send_msg.encode(), (argAddress, argPort))
        if  send_msg == "q":
            break
        
    clnt_sock.close()
    
