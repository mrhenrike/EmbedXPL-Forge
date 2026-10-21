#!/usr/bin/python3 
#Remote login example for Huawei Optistar EG8145X6-10
import requests
import base64

r_username = "root"
r_passwd = "password"
r_ip = "192.168.1.1"

r_get_rand_url = "https://" + r_ip + ":80/asp/GetRandCount.asp"
r_login_url = "https://" + r_ip + ":80/login.cgi"
r_lan_devices_url = "https://" + r_ip + ":80/html/bbsp/userdevinfo/getuserdevinfo.asp"

requests.packages.urllib3.disable_warnings()
get_num = requests.get(r_get_rand_url,verify=False)
params = {'UserName':r_username, 'PassWord':base64.b64encode(r_passwd.encode()).decode(), 'x.X_HW_Token':get_num.text[1:]}
post_reply = requests.post(r_login_url, cookies={'Cookie':'body:Language:english:id=-1'}, data=params, verify=False)

#already logged in, get lan device list to prove it (wired + wireless + ipv4 + ipv6 + online + offline)
get_dev_list = requests.get(r_lan_devices_url, cookies={'Cookie':post_reply.cookies.get_dict()['Cookie']}, verify=False)
clean_text = str(get_dev_list.text).replace("\\x20"," ").replace("\\x2c",",").replace("\\x2d","-").replace("\\x2e",".").replace("\\x3a",":").replace("\\x5f","_")
print(clean_text)
