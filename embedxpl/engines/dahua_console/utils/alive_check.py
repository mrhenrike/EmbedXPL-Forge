"""Host liveness check utility."""
import os
import platform


def alive_check(ip: str) -> bool:
    """Return True if the host responds to a single ICMP ping."""
    # On Windows -w is milliseconds; on Linux/macOS -W is seconds
    if platform.system().lower() == 'windows':
        cmd = f'ping -n 1 -w 1000 {ip} > nul 2>&1'
    else:
        cmd = f'ping -c 1 -W 1 {ip} > /dev/null 2>&1'
    return os.system(cmd) == 0
