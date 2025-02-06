import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

target = "192.168.1.237"
port = 40000
client_socket.connect((target, port))

client_socket.sendall(b'thisisatest')

client_socket.close()
