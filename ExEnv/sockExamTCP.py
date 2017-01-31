import socket

def serv_proc(argPort):
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.bind(('', argPort))
    serv_sock.listen()
    (tmp_clnt_sock, tmp_clnt_info) = serv_sock.accept()
    recv_msg = ""
    print("q to exit")
    while 1:
        recv_msg = tmp_clnt_sock.recv(1500).decode()
        if recv_msg == "q":
            break
        
        print("recv:", recv_msg)
        send_msg = input("send: ")
        
        tmp_clnt_sock.send(send_msg.encode())
        if send_msg == "q":
            break

    serv_sock.close()
    
def clnt_proc(argAddress, argPort):
    recv_msg = ""
    send_msg = ""
    clnt_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clnt_sock.connect((argAddress, argPort))
    print("q to exit")
    while 1:
        send_msg = input("send: ")

        clnt_sock.send(send_msg.encode())
        if  send_msg == "q":
            break
        
        recv_msg = clnt_sock.recv(1500).decode()
        if recv_msg == "q":
            break
        print("recv:", recv_msg)
        
    clnt_sock.close()
    
