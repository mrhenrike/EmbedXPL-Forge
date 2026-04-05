# tapohax

Unauthenticated root shell exploit for the TP-Link Tapo RV20 Max Plus and other LDRobot-based robot vacuums.

The device exposes an unauthenticated ZMQ REP socket on LAN port 30001. The `/Time/SetSystemTime` handler passes user input directly into `system()` with no sanitization, running as root.

## Usage

```bash
# One-shot command injection
python3 poc.py <device-ip>

# Persistent SSH access (survives reboot)
python3 poc.py <device-ip> --persist
```

## Requirements

- Python 3
- pyzmq (`pip install pyzmq`)
- Network access to the target device

## Affected Devices

- TP-Link Tapo RV20 Max Plus (confirmed)
- Likely all LDRobot OEM devices running `apos_server_v1`

**Note:** TP-Link has confirmed that modern firmware versions no longer expose the ZMQ daemon on the network. Do not update if you want to use this.

## Links

- [Blog post](https://x86.cx/blog/tapohax)
- [Valetudo fork for LDRobot](https://github.com/iridium/valetudo)
