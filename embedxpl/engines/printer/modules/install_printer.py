#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — OS Printer Installer
======================================
Installs a network printer on the current host using the OS printer subsystem:
  - Windows : Add-Printer / Add-PrinterPort (PowerShell)
  - Linux   : CUPS lpadmin
  - macOS   : CUPS lpadmin

This allows sending print jobs through the OS spooler (which handles format
conversion, driver rendering and protocol negotiation automatically) instead of
raw socket communication.

Supported driver modes:
  - generic  : Microsoft/HP/CUPS generic RAW/text driver (no rendering)
  - auto     : let OS auto-detect best driver via IPP/WSD discovery
  - epson    : Epson generic inkjet (WF/L/ET series compatible)
  - hp       : HP Universal Print Driver (PCL6)
  - cups-ipp : CUPS IPP Everywhere (AirPrint-compatible, recommended for inkjets)
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike

from __future__ import annotations

import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

_log = logging.getLogger('PrinterXPL-Forge.install_printer')


@dataclass
class InstallResult:
    """Result of a printer installation attempt."""
    success:     bool
    os_type:     str
    printer_name:str
    host:        str
    protocol:    str
    message:     str = ''
    error:       str = ''
    hint:        str = ''
    commands:    List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.commands is None:
            self.commands = []


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace',
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, '', 'Command timed out'
    except FileNotFoundError as exc:
        return 1, '', str(exc)
    except OSError as exc:
        return 1, '', str(exc)


def _probe_ipp_available(host: str, port: int = 631, timeout: float = 4.0) -> bool:
    """Quick check: can we reach the printer on port 631?"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _safe_name(host: str) -> str:
    """Generate a safe printer name from the host IP."""
    return f"PrinterXPL-Forge-{host.replace('.', '-')}"


# ── Windows ────────────────────────────────────────────────────────────────────

_PS_INSTALL_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$PrinterName = '{name}'
$PrinterIP   = '{host}'
$PortName    = 'IP_{host}'
$PortType    = '{port_type}'
$DriverName  = '{driver}'

# Remove existing printer/port with the same name (idempotent)
Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue | Remove-Printer -ErrorAction SilentlyContinue
Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue | Remove-PrinterPort -ErrorAction SilentlyContinue

# Create TCP/IP port
Add-PrinterPort -Name $PortName -PrinterHostAddress $PrinterIP

# Add printer
Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $PortName

Write-Host "Printer '$PrinterName' installed successfully."
Write-Host "To print: Get-Printer -Name '$PrinterName' | Out-Null ; Start-Process notepad /p"
"""

_PS_INSTALL_IPP_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$PrinterName = '{name}'
$PrinterIP   = '{host}'
$PortName    = 'TCP_{host}'

# Remove existing (idempotent)
Get-Printer   -Name $PrinterName -ErrorAction SilentlyContinue | Remove-Printer    -ErrorAction SilentlyContinue
Get-PrinterPort -Name $PortName  -ErrorAction SilentlyContinue | Remove-PrinterPort -ErrorAction SilentlyContinue

# Create Standard TCP/IP port (port 9100 by default; works for RAW and LPD passthrough)
Add-PrinterPort -Name $PortName -PrinterHostAddress $PrinterIP

# Pick best available driver (Generic / Text Only is always present on Windows)
$candidates = @('Microsoft IPP Class Driver','Epson Universal Print Driver','Generic / Text Only')
$driver = 'Generic / Text Only'
foreach ($d in $candidates) {{
    if (Get-PrinterDriver -Name $d -ErrorAction SilentlyContinue) {{
        $driver = $d; break
    }}
}}

Add-Printer -Name $PrinterName -DriverName $driver -PortName $PortName
Write-Host "Printer '$PrinterName' installed — driver: $driver  port: $PortName"
"""

_PS_PRINT_TEST_TEMPLATE = r"""
$PrinterName = '{name}'
$TempFile = [System.IO.Path]::GetTempFileName() + '.txt'
Set-Content -Path $TempFile -Value @"
PrinterXPL-Forge - Test Page
=========================
Target   : {host}
Protocol : {protocol}
Driver   : {driver}
Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
$PrintDoc = New-Object System.Drawing.Printing.PrintDocument
$PrintDoc.PrinterSettings.PrinterName = $PrinterName
$PrintDoc.Print()
Start-Process -FilePath $TempFile -Verb Print -Wait -PassThru | Out-Null
Remove-Item $TempFile -ErrorAction SilentlyContinue
Write-Host "Test page sent to '$PrinterName'."
"""


def _install_windows(host: str, printer_name: str,
                     driver_mode: str = 'generic') -> InstallResult:
    """Install a network printer on Windows using PowerShell cmdlets."""
    ipp_ok = _probe_ipp_available(host)

    if driver_mode in ('cups-ipp', 'auto') and ipp_ok:
        ipp_uri = f'http://{host}:631/ipp/print'
        ps_script = _PS_INSTALL_IPP_TEMPLATE.format(
            name=printer_name, host=host, ipp_uri=ipp_uri,
        )
        protocol = 'IPP'
    else:
        driver_map = {
            'generic': 'Generic / Text Only',
            'hp':      'HP Universal Printing PCL 6',
            'epson':   'Epson Universal Print Driver',
            'auto':    'Generic / Text Only',
        }
        driver = driver_map.get(driver_mode, 'Generic / Text Only')
        ps_script = _PS_INSTALL_TEMPLATE.format(
            name=printer_name, host=host,
            port_type='Standard TCP/IP Port',
            driver=driver,
        )
        protocol = 'RAW TCP/IP'

    ps_path = os.path.join(os.environ.get('TEMP', '.'), '_pr_install.ps1')
    try:
        with open(ps_path, 'w', encoding='utf-8') as f:
            f.write(ps_script)

        rc, out, err = _run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
             '-File', ps_path],
            timeout=60,
        )
        os.unlink(ps_path)

        if rc == 0:
            return InstallResult(
                success=True, os_type='Windows',
                printer_name=printer_name, host=host, protocol=protocol,
                message=out or 'Printer installed.',
                hint=(
                    f"Print via Start menu → print a document and select '{printer_name}', "
                    "or run: Get-PrintJob -PrinterName '{printer_name}'"
                ),
                commands=['Get-Printer | Where-Object Name -like "*PrinterXPL-Forge*"'],
            )
        return InstallResult(
            success=False, os_type='Windows',
            printer_name=printer_name, host=host, protocol=protocol,
            error=err or out,
            hint=(
                'Run PowerShell as Administrator and try again. '
                'Also ensure the print spooler service is running: '
                'Start-Service -Name Spooler'
            ),
        )
    except Exception as exc:
        return InstallResult(
            success=False, os_type='Windows',
            printer_name=printer_name, host=host, protocol='',
            error=str(exc),
        )


# ── Linux / macOS ─────────────────────────────────────────────────────────────

def _install_unix(host: str, printer_name: str,
                  driver_mode: str = 'generic',
                  os_type: str = 'Linux') -> InstallResult:
    """Install a network printer on Linux/macOS using CUPS lpadmin."""
    lpadmin = shutil.which('lpadmin')
    if not lpadmin:
        return InstallResult(
            success=False, os_type=os_type,
            printer_name=printer_name, host=host, protocol='',
            error='lpadmin not found — CUPS is not installed',
            hint='Install CUPS: apt install cups  |  brew install cups',
        )

    ipp_ok = _probe_ipp_available(host)
    if ipp_ok:
        device_uri = f'ipp://{host}/ipp/print'
        ppd_opt    = ['-m', 'everywhere']   # IPP Everywhere / AirPrint
        protocol   = 'IPP Everywhere'
    else:
        device_uri = f'socket://{host}:9100'
        ppd_opt    = ['-m', 'raw']
        protocol   = 'RAW socket'

    cmd = [
        lpadmin, '-p', printer_name,
        '-E',                          # enable + accept jobs
        '-v', device_uri,
        '-D', f'PrinterXPL-Forge {host}',
        '-L', host,
    ] + ppd_opt

    rc, out, err = _run(cmd, timeout=30)
    cmds_run = [' '.join(cmd)]

    if rc == 0:
        # Accept and enable
        for sub in (['cupsenable', printer_name], ['cupsaccept', printer_name]):
            _run([shutil.which(sub[0]) or sub[0]] + sub[1:])
        return InstallResult(
            success=True, os_type=os_type,
            printer_name=printer_name, host=host, protocol=protocol,
            message=f"Printer '{printer_name}' installed via CUPS ({protocol})",
            hint=f"Print test: lp -d {printer_name} /etc/hostname",
            commands=cmds_run,
        )
    return InstallResult(
        success=False, os_type=os_type,
        printer_name=printer_name, host=host, protocol=protocol,
        error=err or out,
        hint='Run as root / with sudo. Check CUPS service: systemctl status cups',
        commands=cmds_run,
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def install_printer(
    host:        str,
    name:        Optional[str] = None,
    driver_mode: str = 'auto',
) -> InstallResult:
    """
    Install a network printer on the current host OS.

    Args:
        host:        Printer IP or hostname.
        name:        Printer name (default: auto-generated from IP).
        driver_mode: 'auto' | 'generic' | 'epson' | 'hp' | 'cups-ipp'.

    Returns:
        InstallResult with .success, .message, .hint.
    """
    printer_name = name or _safe_name(host)
    system       = platform.system()

    _log.info("Installing printer '%s' (%s) on %s", printer_name, host, system)

    if system == 'Windows':
        return _install_windows(host, printer_name, driver_mode)
    if system == 'Darwin':
        return _install_unix(host, printer_name, driver_mode, os_type='macOS')
    if system == 'Linux':
        return _install_unix(host, printer_name, driver_mode, os_type='Linux')

    return InstallResult(
        success=False, os_type=system,
        printer_name=printer_name, host=host, protocol='',
        error=f"Unsupported OS: {system}",
        hint='Supported: Windows, Linux, macOS',
    )
