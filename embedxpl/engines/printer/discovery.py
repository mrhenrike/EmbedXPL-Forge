#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

import socket
import subprocess
import ipaddress
import shutil
from utils.helper import output, conv
from core.osdetect import get_os

# SNMP OIDs we’ll query
OID_HRDEV_TYPE            = '1.3.6.1.2.1.25.3.2.1.2.1'
OID_HRDEV_DESCR           = '1.3.6.1.2.1.25.3.2.1.3.1'
OID_SYS_UPTIME            = '1.3.6.1.2.1.1.3.0'
OID_PR_STATUS             = '1.3.6.1.2.1.43.16.5.1.2.1.1'
OID_PR_INTERPRETER        = '1.3.6.1.2.1.43.16.5.1.2.1.2'

# HOST-RESOURCES-MIB Printer Table
OID_HRPRINTER_STATUS      = '1.3.6.1.2.1.25.3.5.1.1.1'
OID_HRPRINTER_ERROR_STATE = '1.3.6.1.2.1.25.3.5.1.2.1'
OID_HRPRINTER_JOB_COUNT   = '1.3.6.1.2.1.25.3.5.1.3.1'

# Printer-MIB Supplies & Alerts
OID_PRT_MARKER_SUPPLY_DESC  = '1.3.6.1.2.1.43.11.1.1.6.1.1'
OID_PRT_MARKER_SUPPLY_TYPE  = '1.3.6.1.2.1.43.11.1.1.2.1.1'
OID_PRT_MARKER_SUPPLY_LEVEL = '1.3.6.1.2.1.43.11.1.1.9.1.1'
OID_PRT_INPUT_MEDIA_TYPE    = '1.3.6.1.2.1.43.11.1.1.2.1.1'
OID_PRT_INPUT_STATUS        = '1.3.6.1.2.1.43.11.1.1.8.1.1'
OID_PRT_ALERTS_VALUE        = '1.3.6.1.2.1.43.18.1.1.8.1.1'

# ENTITY-MIB Physical Entities
OID_ENT_PHYS_DESCR         = '1.3.6.1.2.1.47.1.1.1.1.2'
OID_ENT_PHYS_NAME          = '1.3.6.1.2.1.47.1.1.1.1.7'
OID_ENT_PHYS_FIRMWARE_REV  = '1.3.6.1.2.1.47.1.1.1.1.10'
OID_ENT_PHYS_SERIAL        = '1.3.6.1.2.1.47.1.1.1.1.11'
OID_ENT_PHYS_MODEL_NAME    = '1.3.6.1.2.1.47.1.1.1.1.13'

from utils.ports import GLOBAL_PRINTER_TCP_PORTS

_PRINTER_PROBE_PORTS = sorted(GLOBAL_PRINTER_TCP_PORTS.keys())


def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """Non-blocking TCP probe."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def parse_selection(sel, max_index):
    sel = sel.strip().lower()
    if sel in ('all', 'a', ''):
        return list(range(1, max_index + 1))
    chosen = set()
    for part in sel.split(','):
        if '-' in part:
            start, end = part.split('-', 1)
            chosen.update(range(int(start), int(end) + 1))
        else:
            chosen.add(int(part))
    return sorted(i for i in chosen if 1 <= i <= max_index)


def _get_local_networks(os_type):
    """
    Return a list of IPv4 /24 networks on UP, non-loopback,
    non-link-local interfaces.

    Supports: Linux, WSL, Windows, macOS (darwin), BSD, Android (Termux).
    """
    raw = []

    # ── Linux / WSL / Android (Termux) ───────────────────────────────────
    if os_type in ('linux', 'wsl', 'android'):
        # Try modern iproute2 'ip' command (Linux, Android)
        if shutil.which('ip'):
            try:
                out = subprocess.check_output(
                    ['ip', '-o', '-f', 'inet', 'addr', 'show'],
                    text=True, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    iface = parts[1].rstrip(':')
                    cidr  = next((p for p in parts if '/' in p), None)
                    if not cidr or iface in ('lo', 'lo0'):
                        continue
                    try:
                        raw.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass
            except Exception as e:
                output().warning(f"Could not list interfaces via 'ip': {e}")

        # Fallback: ifconfig (older Linux distros, Android without ip)
        if not raw and shutil.which('ifconfig'):
            try:
                out = subprocess.check_output(
                    ['ifconfig'], text=True, stderr=subprocess.DEVNULL
                )
                for m in __import__('re').finditer(
                    r'inet (?:addr:)?(\d+\.\d+\.\d+\.\d+).*?(?:Mask:|netmask )(\S+)',
                    out, __import__('re').DOTALL
                ):
                    ip_str, mask_str = m.group(1), m.group(2)
                    try:
                        net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                        raw.append(net)
                    except ValueError:
                        pass
            except Exception as e:
                output().warning(f"Could not list interfaces via 'ifconfig': {e}")

    # ── macOS (darwin) ────────────────────────────────────────────────────
    if os_type == 'darwin':
        # networksetup gives cleaner output than ifconfig on macOS
        if shutil.which('networksetup'):
            try:
                # Get list of network services
                svcs = subprocess.check_output(
                    ['networksetup', '-listallnetworkservices'],
                    text=True, stderr=subprocess.DEVNULL
                ).splitlines()[1:]  # skip header line

                for svc in svcs:
                    svc = svc.strip()
                    if not svc or svc.startswith('*'):
                        continue
                    try:
                        info = subprocess.check_output(
                            ['networksetup', '-getinfo', svc],
                            text=True, stderr=subprocess.DEVNULL
                        )
                        ip_m = __import__('re').search(r'IP address: (\d+\.\d+\.\d+\.\d+)', info)
                        mask_m = __import__('re').search(r'Subnet mask: (\d+\.\d+\.\d+\.\d+)', info)
                        if ip_m and mask_m:
                            ip_str, mask_str = ip_m.group(1), mask_m.group(1)
                            net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                            raw.append(net)
                    except Exception:
                        continue
            except Exception as e:
                output().warning(f"Could not list macOS network services: {e}")

        # Fallback: ifconfig (always present on macOS)
        if not raw and shutil.which('ifconfig'):
            try:
                import re as _re
                out = subprocess.check_output(
                    ['ifconfig'], text=True, stderr=subprocess.DEVNULL
                )
                for m in _re.finditer(
                    r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+|\d+\.\d+\.\d+\.\d+)',
                    out
                ):
                    ip_str, mask_str = m.group(1), m.group(2)
                    # macOS ifconfig uses hex netmasks (e.g. 0xffffff00)
                    if mask_str.startswith('0x'):
                        mask_int = int(mask_str, 16)
                        mask_str = str(ipaddress.IPv4Address(mask_int))
                    try:
                        net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                        raw.append(net)
                    except ValueError:
                        pass
            except Exception as e:
                output().warning(f"Could not list macOS interfaces via ifconfig: {e}")

    # ── Windows / WSL ─────────────────────────────────────────────────────
    if os_type in ('windows', 'wsl'):
        pwsh = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
        if pwsh:
            try:
                cmd = [
                    pwsh, '-NoProfile', '-Command',
                    "Get-NetIPAddress -AddressFamily IPv4 "
                    "| Where { $_.IPAddress -ne '127.0.0.1' } "
                    "| Select -ExpandProperty IPAddress"
                ]
                out = subprocess.check_output(
                    cmd, text=True, stderr=subprocess.DEVNULL)
                for ip in out.splitlines():
                    ip = ip.strip()
                    if not ip:
                        continue
                    try:
                        raw.append(ipaddress.ip_network(f"{ip}/24", strict=False))
                    except ValueError:
                        pass
            except Exception as e:
                output().warning(f"Could not list Windows interfaces: {e}")
        else:
            output().warning("PowerShell not found; skipping Windows IPs.")

    # ── BSD ───────────────────────────────────────────────────────────────
    if os_type == 'bsd':
        if shutil.which('ifconfig'):
            try:
                import re as _re
                out = subprocess.check_output(
                    ['ifconfig'], text=True, stderr=subprocess.DEVNULL
                )
                for m in _re.finditer(
                    r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+|\d+\.\d+\.\d+\.\d+)',
                    out
                ):
                    ip_str, mask_str = m.group(1), m.group(2)
                    if mask_str.startswith('0x'):
                        mask_int = int(mask_str, 16)
                        mask_str = str(ipaddress.IPv4Address(mask_int))
                    try:
                        net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                        raw.append(net)
                    except ValueError:
                        pass
            except Exception as e:
                output().warning(f"Could not list BSD interfaces: {e}")

    # ── dedupe and filter loopback/link-local ────────────────────────────
    uniq = []
    for net in raw:
        na = net.network_address
        if na.is_loopback or na.is_link_local:
            continue
        if net not in uniq:
            uniq.append(net)
    return uniq


def _snmp_get(ip, oid):
    """
    Run snmpget and return the value or None.
    """
    cmd = shutil.which('snmpget')
    if not cmd:
        return None
    try:
        from utils.ports import PortConfig as _PC
        _snmp_port = _PC.resolve('snmp')
        return subprocess.check_output(
            [cmd, '-v1', '-c', 'public', '-Oqv', '-t', '1', '-r', '1', f'{ip}:{_snmp_port}', oid],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
    except subprocess.CalledProcessError:
        return None


def _is_public_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version == 4 and not ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return False


def _network_around(ip_str: str, prefix: int) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)


def _scan_target_printer_ports(host: str, verbose: bool = False) -> None:
    """Quick TCP probe for common printer ports on a single host."""
    open_ports = [p for p in _PRINTER_PROBE_PORTS if _tcp_open(host, p)]
    print(f"\n  Target {host} — open printer-related ports: {open_ports or 'none'}")
    descr = _snmp_get(host, OID_HRDEV_DESCR)
    if descr:
        print(f"  SNMP     : {descr}")
    if verbose:
        for port in _PRINTER_PROBE_PORTS:
            state = 'open' if port in open_ports else 'closed'
            print(f"    {port}/tcp  {state}")
    print()


def _print_tcp_scan_results(results: list) -> None:
    if not results:
        output().info("No hosts with open printer ports found.")
        return
    print("\n  Hosts with open printer ports:")
    for entry in sorted(results, key=lambda r: socket.inet_aton(r['host'])):
        ports = ', '.join(str(p) for p in entry['open_ports'])
        print(f"    {entry['host']:<16}  [{ports}]")
    print()


class discovery:
    def __init__(self, usage=False, context_target: str = ''):
        os_type = get_os()
        print(f"Detected OS: {os_type}")
        if os_type == 'unsupported':
            output().warning("This OS is not supported for SNMP-based discovery.")
            return

        ctx = (context_target or '').strip()
        if ctx and _is_public_ipv4(ctx):
            self._discover_public_context(ctx)
            return

        # macOS and Android are supported – just ensure the user knows the requirements
        if os_type == 'darwin':
            output().chitchat("macOS detected. Discovery requires: brew install net-snmp")
        if os_type == 'android':
            output().chitchat("Android/Termux detected. Discovery requires: pkg install net-snmp")

        if usage:
            print("No target given — discovering printers on local network.")
            print("Press CTRL+C at any time to cancel.\n")

        if not shutil.which('snmpget'):
            _install_hints = {
                'linux':   "apt install snmp  OR  yum install net-snmp-utils",
                'wsl':     "apt install snmp",
                'darwin':  "brew install net-snmp",
                'bsd':     "pkg install net-snmp",
                'windows': "choco install net-snmp  OR  use WSL",
                'android': "pkg install net-snmp  (Termux)",
            }
            hint = _install_hints.get(os_type, "install net-snmp for your OS")
            output().warning(f"'snmpget' not found. Install with: {hint}")
            return

        networks = _get_local_networks(os_type)
        if not networks:
            output().warning("No eligible networks found to scan.")
            return

        print(f"Found {len(networks)} network(s) to consider:")
        for idx, net in enumerate(networks, 1):
            hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            print(f"  [{idx}] {net} ({hosts} hosts)")

        sel = input("\nSelect networks to scan [e.g. 1,1-3,all]: ")
        chosen = parse_selection(sel, len(networks))
        if not chosen:
            print("Nothing selected, exiting.")
            return

        verb = input("Verbose probing? [y/N]: ").strip().lower()
        verbose = verb in ('y', 'yes')

        results = {}
        total = 0
        try:
            for i in chosen:
                net = networks[i - 1]
                print(f"\nScanning {net} (Ctrl+C to cancel)...")
                for host in net.hosts():
                    ip = str(host)
                    total += 1

                    typ = _snmp_get(ip, OID_HRDEV_TYPE)
                    if typ != '1.3.6.1.2.1.25.3.1.5':
                        if verbose:
                            print(f"  {ip}: not a printer ({typ})")
                        continue

                    # collect all SNMP fields
                    descr       = _snmp_get(ip, OID_HRDEV_DESCR) or '?'
                    upv         = _snmp_get(ip, OID_SYS_UPTIME)
                    uptime      = conv().elapsed(int(upv), 100, True) if upv and upv.isdigit() else '?'
                    pr_status   = _snmp_get(ip, OID_PR_STATUS) or '?'
                    interp      = _snmp_get(ip, OID_PR_INTERPRETER) or '?'
                    hp_status   = _snmp_get(ip, OID_HRPRINTER_STATUS) or '?'
                    err_state   = _snmp_get(ip, OID_HRPRINTER_ERROR_STATE) or '?'
                    job_count   = _snmp_get(ip, OID_HRPRINTER_JOB_COUNT) or '?'
                    m_desc      = _snmp_get(ip, OID_PRT_MARKER_SUPPLY_DESC) or '?'
                    m_type      = _snmp_get(ip, OID_PRT_MARKER_SUPPLY_TYPE) or '?'
                    m_level     = _snmp_get(ip, OID_PRT_MARKER_SUPPLY_LEVEL) or '?'
                    in_media    = _snmp_get(ip, OID_PRT_INPUT_MEDIA_TYPE) or '?'
                    in_status   = _snmp_get(ip, OID_PRT_INPUT_STATUS) or '?'
                    alerts      = _snmp_get(ip, OID_PRT_ALERTS_VALUE) or '?'
                    phys_descr  = _snmp_get(ip, OID_ENT_PHYS_DESCR) or '?'
                    phys_name   = _snmp_get(ip, OID_ENT_PHYS_NAME) or '?'
                    phys_fw      = _snmp_get(ip, OID_ENT_PHYS_FIRMWARE_REV) or '?'
                    phys_serial = _snmp_get(ip, OID_ENT_PHYS_SERIAL) or '?'
                    phys_model  = _snmp_get(ip, OID_ENT_PHYS_MODEL_NAME) or '?'

                    results[ip] = [
                        descr, uptime, pr_status, interp,
                        hp_status, err_state, job_count,
                        m_desc, m_type, m_level,
                        in_media, in_status, alerts,
                        phys_name, phys_model, phys_serial, phys_fw
                    ]

                    if verbose:
                        print(f"  {ip}:")
                        print(f"    Description: {descr}")
                        print(f"    Uptime:      {uptime}")
                        print(f"    PJL Status:  {pr_status}")
                        print(f"    Interpreter: {interp}")
                        print(f"    hrStatus:    {hp_status}")
                        print(f"    Errors:      {err_state}")
                        print(f"    Jobs:        {job_count}")
                        print(f"    Supplies:    {m_desc} / {m_type} @ {m_level}")
                        print(f"    Input:       {in_media} / {in_status}")
                        print(f"    Alerts:      {alerts}")
                        print(f"    Entity:      {phys_name} ({phys_model})")
                        print(f"    Serial:      {phys_serial}")
                        print(f"    FW Rev:      {phys_fw}")
                    else:
                        print(f"  {ip}: Printer → {descr}, uptime={uptime}, status={pr_status}")

        except KeyboardInterrupt:
            print()
            output().warning("[!] Discovery interrupted by user. Exiting...\n")

        print(f"\nProbed {total} hosts in total.\n")
        if results:
            print("Discovered printers:")
            hdr = (
                'address',
                ('descr','uptime','pjl_status','interp','hr_status','errors',
                 'jobs','sup_desc','sup_type','sup_lvl',
                 'in_media','in_status','alerts',
                 'ent_name','ent_model','ent_serial','ent_fw')
            )
            output().discover(hdr)
            output().hline(79)
            for entry in sorted(results.items(), key=lambda i: socket.inet_aton(i[0])):
                output().discover(entry)
            print()
        else:
            output().info("No printers found via SNMP scan")
            print()

    def _discover_public_context(self, ip: str) -> None:
        """Discovery scoped to a public/WAN target instead of local LAN."""
        print()
        output().chitchat(
            f"Target {ip} is a public address — local LAN scan skipped."
        )
        print(f"  Default printer ports: {', '.join(map(str, _PRINTER_PROBE_PORTS))}")
        print()
        print("  [1]  Probe this host only (TCP + SNMP if available)")
        print("  [2]  TCP scan /24 around target (~254 hosts)")
        print("  [3]  TCP scan /16 around target (large — confirmation required)")
        print("  [4]  Custom CIDR (e.g. 191.37.240.0/24 or ASN allocation)")
        print("  [0]  Cancel")
        print()
        try:
            sel = input("  Select scope [1]: ").strip() or '1'
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if sel in ('0', 'q', 'Q'):
            return
        if sel == '1':
            _scan_target_printer_ports(ip, verbose=True)
            return
        if sel == '2':
            cidr = str(_network_around(ip, 24))
            results = mirai_tcp_scan(cidr)
            _print_tcp_scan_results(results)
            return
        if sel == '3':
            cidr = str(_network_around(ip, 16))
            hosts = _network_around(ip, 16).num_addresses
            print(f"\n  [!] /16 scan covers ~{hosts} addresses — may take a long time.")
            confirm = input("  Continue? [y/N]: ").strip().lower()
            if confirm not in ('y', 'yes'):
                print("  Cancelled.")
                return
            results = mirai_tcp_scan(cidr, threads=512)
            _print_tcp_scan_results(results)
            return
        if sel == '4':
            try:
                cidr = input("  Enter CIDR (e.g. 203.0.113.0/24): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not cidr:
                return
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                output().warning(f"Invalid CIDR: {exc}")
                return
            results = mirai_tcp_scan(cidr)
            _print_tcp_scan_results(results)
            return
        output().warning("Invalid selection.")


# ── Mirai-style concurrent TCP port scanner (batch-32 enhancement) ────────────
# Inspired by jgamblin/Mirai-Source-Code (scanner.c) concurrent scan approach
# and groinc (thau0x01) passive packet inspection patterns.

import concurrent.futures as _futures
import threading as _threading


def mirai_tcp_scan(cidr: str, ports: list = None, threads: int = 256,
                   timeout: float = 1.5) -> list:
    """
    Concurrent Mirai-style TCP scanner.
    Probes all hosts in `cidr` for printer-relevant ports in parallel.
    Returns list of dicts: {host, open_ports}.
    """
    if ports is None:
        ports = _PRINTER_PROBE_PORTS

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        targets = [str(ip) for ip in net.hosts()]
    except ValueError as exc:
        print(f"[!] Invalid CIDR {cidr}: {exc}")
        return []

    print(f"[*] Mirai-TCP scan: {len(targets)} hosts × {len(ports)} ports ({threads} threads)")
    results = []
    lock = _threading.Lock()

    def _probe(host):
        open_ports = [p for p in ports if _tcp_open(host, p, timeout)]
        if open_ports:
            with lock:
                results.append({"host": host, "open_ports": open_ports})

    with _futures.ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(_probe, targets))

    print(f"[*] {len(results)} host(s) with open printer ports.")
    return results


def groinc_passive_sniff(interface: str = None, timeout: int = 30,
                         printer_ports: list = None) -> list:
    """
    Groinc-inspired passive packet capture to detect printer traffic.
    Requires scapy (pip install scapy). Falls back gracefully if unavailable.
    Detects: PJL (port 9100), IPP (port 631), LPD (port 515), SNMP (port 161).
    """
    if printer_ports is None:
        printer_ports = [9100, 631, 515, 161]

    try:
        from scapy.all import sniff, TCP, UDP, IP
    except ImportError:
        print("[!] scapy not installed — passive sniffer unavailable.")
        print("    Install with: pip install scapy")
        return []

    print(f"[*] Passive sniffer on {interface or 'default'} for {timeout}s "
          f"(ports: {printer_ports}) ...")

    seen = {}
    port_filter = " or ".join(f"port {p}" for p in printer_ports)
    bpf = f"tcp or udp and ({port_filter})"

    def _pkt_handler(pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
        elif UDP in pkt:
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
        else:
            return
        for p in printer_ports:
            if dport == p or sport == p:
                key = (src, dst, p)
                if key not in seen:
                    seen[key] = True
                    print(f"  [sniff] {src}:{sport} → {dst}:{dport}")

    try:
        sniff(iface=interface, filter=bpf, prn=_pkt_handler,
              store=False, timeout=timeout)
    except Exception as exc:
        print(f"[!] Sniffer error: {exc}")

    flows = [{"src": k[0], "dst": k[1], "port": k[2]} for k in seen]
    print(f"[*] Captured {len(flows)} unique printer flows.")
    return flows

