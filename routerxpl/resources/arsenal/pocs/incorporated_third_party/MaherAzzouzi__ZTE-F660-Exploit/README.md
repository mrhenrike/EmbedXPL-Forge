# ZTE F660 Vulnerability Analysis

## Description

This project aims to analyze and document a critical security vulnerability identified in ZTE F660 devices. The vulnerability allows for an authentication bypass leading to remote code execution (RCE), impacting a range of devices produced between 2008 and 2013. This repository contains the PoC.

## Vulnerability Overview

- **CVE Identifier**: Not yet.
- **Affected Devices**: ZTE F660 models produced between 2008 and 2013.
- **Impact**: Authentication bypass leading to remote code execution.
- **Ports Affected**: 80/443 (HTTP/HTTPS).
- **Firmware Version**: Primarily affecting firmware version 5 and below.

## Detection

The repository includes scripts to identify vulnerable devices using specific network signatures. Devices running firmware version 5 and below that are accessible via ports 80/443 are considered at risk.

## Exploitation

Details on how the vulnerability can be exploited are provided for educational and defensive purposes only. It involves unauthorized downloading of the `config.bin` file to leak administrator credentials, followed by Telnet access for full device control.

## Mitigation

Immediate actions to mitigate the risk include:
- Restricting network access to the affected ports.
- Updating firmware to the latest version if available.

## Usage Example
python3 download_config_bin.py 192.168.1.1 2008-2013
cd zte-config-utility
python3 examples/decode.py ../config.bin test.xml

## More Information
This bug was already reported to ZTE.
