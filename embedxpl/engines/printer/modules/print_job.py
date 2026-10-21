#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Smart Print Job Sender
=======================================
Sends files or raw data to a printer via:
  - IPP / IPPS (TCP 631)  — AirPrint-compatible, auto-TLS upgrade
  - LPD        (TCP 515)  — legacy, RFC 1179, uses ESC/P for Epson inkjets
  - RAW        (TCP 9100) — JetDirect passthrough (HP/PCL printers)

Format handling (in order of preference):
  .txt          → JPEG via Pillow  → ESC/P  → PostScript
  .jpg/.png/...  → ESC/P bitmap via Pillow  → raw bytes
  .ps/.eps       → sent as-is
  .pcl           → sent as-is
  .pdf           → Ghostscript → PostScript → raw PDF
  .doc/.docx     → LibreOffice → PDF → PostScript
  any            → raw binary stream

Smart protocol probing:
  - IPP:  tests plain TCP first; if 426/connection-reset → auto-retries with TLS
  - LPD:  converts payload to ESC/P (native Epson) to avoid stuck-print issues
  - RAW:  passthrough; works for HP/PCL printers with port 9100 open

Printer readiness:
  - SNMP hrPrinterStatus is checked when pysnmp is installed
  - If printer is busy/printing, a clear warning is shown before sending
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import io
import logging
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

_log = logging.getLogger('PrinterXPL-Forge.print_job')

UEL = b'\x1b%-12345X'

# ── IPP status codes ──────────────────────────────────────────────────────────
_IPP_OK                            = 0x0000
_IPP_STATUS_BUSY                   = 0x0503   # server-error-busy
_IPP_DEVICE_ERROR                  = 0x0507   # server-error-device-error
_IPP_FORMAT_NOT_SUPPORTED          = 0x0408   # client-error-document-format-not-supported
_IPP_NOT_AUTHORIZED                = 0x0403   # client-error-forbidden
_IPP_NOT_FOUND                     = 0x0406   # client-error-not-found
_IPP_OP_NOT_SUPPORTED              = 0x0501   # server-error-operation-not-supported

_IPP_ERRORS = {
    0x0400: "Bad Request",
    0x0401: "Forbidden (authentication required)",
    0x0402: "Not Authenticated",
    0x0403: "Forbidden — printer may be hardened",
    0x0404: "Not Found — printer-uri not recognized",
    0x0405: "Request Too Large",
    0x0406: "Printer URI not found",
    0x0407: "Attributes or values not supported",
    0x0408: "Document format not supported — printer rejects this MIME type",
    0x0409: "URI scheme not supported",
    0x040A: "Charset not supported",
    0x040B: "Conflicting attributes",
    0x040C: "Compression not supported",
    0x040D: "Compressed document too large",
    0x040E: "Document format error (corrupt/invalid data)",
    0x040F: "Document access error",
    0x0500: "Internal server error",
    0x0501: "Operation not supported by printer",
    0x0503: "Printer is busy — try again later",
    0x0505: "Multiple document jobs not supported",
    0x0506: "Printer device error",
    0x0507: "Printer device error",
}


# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class PrintJobResult:
    """Result of a print job submission."""
    success:    bool
    protocol:   str
    host:       str
    port:       int
    file_path:  str
    file_size:  int
    job_id:     Optional[int] = None
    message:    str = ''
    error:      str = ''
    hint:       str = ''   # actionable hint for the operator
    elapsed_ms: float = 0.0

    def __str__(self) -> str:
        status = 'OK' if self.success else 'FAILED'
        out = (
            f"[{status}] {self.protocol.upper()} {self.host}:{self.port}  "
            f"file={self.file_path}  size={self.file_size}B  "
            f"elapsed={self.elapsed_ms:.0f}ms"
        )
        if self.job_id:
            out += f"  job_id={self.job_id}"
        if self.message:
            out += f"  msg={self.message}"
        if self.error:
            out += f"  err={self.error}"
        if self.hint:
            out += f"  hint={self.hint}"
        return out


@dataclass
class PrinterCapabilities:
    """Quick probe result for a printer's print-job capabilities."""
    host:            str
    ipp_available:   bool = False
    ipp_requires_tls:bool = False
    ipp_status:      int  = -1          # last IPP status code
    lpd_available:   bool = False
    raw_available:   bool = False
    snmp_status:     int  = -1          # hrPrinterStatus (-1 = unknown)
    formats:         List[str] = field(default_factory=list)

    @property
    def printer_ready(self) -> bool:
        """True if SNMP says the printer is idle (3) or unknown (-1)."""
        return self.snmp_status in (-1, 3)

    @property
    def printer_busy(self) -> bool:
        return self.snmp_status == 4

    @property
    def best_protocol(self) -> str:
        if self.ipp_available:
            return 'ipp'
        if self.lpd_available:
            return 'lpd'
        if self.raw_available:
            return 'raw'
        return ''


# ── SNMP helper ───────────────────────────────────────────────────────────────

def _snmp_printer_status(host: str, timeout: float = 3.0) -> int:
    """
    Return hrPrinterStatus via SNMP v1 (OID 1.3.6.1.2.1.25.3.5.1.1.1).
    Returns -1 on error or if pysnmp is not installed.
    Status codes: 1=other 2=unknown 3=idle 4=printing 5=warmup
    """
    try:
        from pysnmp.hlapi import (  # type: ignore
            SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity, getCmd,
        )
        for ei, es, eI, vbs in getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((host, 161), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.25.3.5.1.1.1')),
        ):
            if ei or es:
                return -1
            for vb in vbs:
                return int(vb[1])
    except Exception:
        pass
    return -1


_SNMP_STATUS_LABEL = {
    1: 'other',
    2: 'unknown',
    3: 'idle (ready)',
    4: 'printing — BUSY',
    5: 'warming up',
}


# ── Port probe ────────────────────────────────────────────────────────────────

def _tcp_open(host: str, port: int, timeout: float = 4.0) -> bool:
    """Return True if the TCP port is open and accepts connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_ipp(host: str, port: int = 631, timeout: float = 6.0) -> Tuple[bool, bool]:
    """
    Probe IPP endpoint on *port*.
    Returns (available, requires_tls).
    - available=True  if the port accepts IPP connections
    - requires_tls=True if plain TCP returns 426 or connection-reset (Epson behaviour)
    """
    def _minimal_ipp() -> bytes:
        """Build a Get-Printer-Attributes request with no document payload."""
        def _s(name: str, value: str, tag: int = 0x44) -> bytes:
            nb = name.encode(); vb = value.encode()
            return (bytes([tag]) + struct.pack('>H', len(nb)) + nb +
                    struct.pack('>H', len(vb)) + vb)
        uri   = f'ipp://{host}:{port}/ipp/print'
        attrs = b'\x01'
        attrs += _s('attributes-charset', 'utf-8', 0x47)
        attrs += _s('attributes-natural-language', 'en-us', 0x48)
        attrs += _s('printer-uri', uri, 0x45)
        attrs += b'\x03'
        hdr   = struct.pack('>BBHI', 1, 1, 0x000B, 1)
        req   = hdr + attrs
        return (
            f'POST /ipp/print HTTP/1.1\r\nHost: {host}:{port}\r\n'
            f'Content-Type: application/ipp\r\nContent-Length: {len(req)}\r\n'
            f'Connection: close\r\n\r\n'
        ).encode() + req

    ipp_req = _minimal_ipp()

    # 1. Try plain TCP
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(ipp_req)
            resp = b''
            s.settimeout(3)
            try:
                while True:
                    c = s.recv(4096)
                    if not c:
                        break
                    resp += c
            except socket.timeout:
                pass
        if resp.startswith(b'HTTP/1.1 426'):
            return True, True           # port open, needs TLS
        if resp.startswith(b'HTTP/1.1'):
            return True, False          # port open, plain works
    except ConnectionResetError:
        # Epson resets non-TLS connections — treat as "TLS required"
        pass
    except OSError:
        # Port not open
        return False, False

    # 2. Try TLS
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(timeout)
            s.sendall(ipp_req)
            resp = b''
            s.settimeout(3)
            try:
                while True:
                    c = s.recv(4096)
                    if not c:
                        break
                    resp += c
            except socket.timeout:
                pass
        if resp.startswith(b'HTTP/1.1'):
            return True, True           # TLS works
    except OSError:
        pass

    return False, False


def probe_printer(host: str, timeout: float = 5.0) -> PrinterCapabilities:
    """
    Quickly probe a printer's available protocols and readiness.
    Results are used by send_print_job() to choose the best protocol.
    """
    caps = PrinterCapabilities(host=host)

    # SNMP status (non-blocking, best-effort)
    caps.snmp_status = _snmp_printer_status(host, timeout=min(timeout, 3.0))

    # Protocol probes in parallel (sequential to keep deps simple)
    ipp_ok, ipp_tls = _probe_ipp(host, 631, timeout=timeout)
    caps.ipp_available    = ipp_ok
    caps.ipp_requires_tls = ipp_tls

    caps.lpd_available = _tcp_open(host, 515, timeout=timeout)
    caps.raw_available = _tcp_open(host, 9100, timeout=timeout)

    _log.debug(
        "Printer probe %s: IPP=%s(tls=%s) LPD=%s RAW=%s SNMP=%s",
        host, ipp_ok, ipp_tls, caps.lpd_available, caps.raw_available,
        _SNMP_STATUS_LABEL.get(caps.snmp_status, caps.snmp_status),
    )
    return caps


# ── Format detection & conversion ─────────────────────────────────────────────

def _detect_format(path: str) -> str:
    """Return detected format string from file extension and magic bytes."""
    p = Path(path)
    ext_map = {
        '.ps': 'ps', '.eps': 'ps', '.pcl': 'pcl', '.prn': 'raw',
        '.pdf': 'pdf', '.txt': 'text', '.rtf': 'text',
        '.png': 'image', '.jpg': 'image', '.jpeg': 'image',
        '.bmp': 'image', '.gif': 'image', '.tiff': 'image', '.tif': 'image',
        '.doc': 'word', '.docx': 'word', '.odt': 'word',
    }
    fmt = ext_map.get(p.suffix.lower(), 'raw')
    try:
        with open(path, 'rb') as f:
            magic = f.read(8)
        if magic[:4] == b'%PDF':
            return 'pdf'
        if magic[:2] == b'%!':
            return 'ps'
        if magic[:2] == b'\x1b%':
            return 'pcl'
        if magic[:2] == b'\xff\xd8':
            return 'image'
        if magic[:8] == b'\x89PNG\r\n\x1a\n':
            return 'image'
    except OSError:
        pass
    return fmt


def _detect_mime(data: bytes) -> str:
    """Detect MIME type from magic bytes for IPP document-format."""
    if data[:4] == b'%PDF':
        return 'application/pdf'
    if data[:2] == b'%!':
        return 'application/postscript'
    if data[:2] == b'\xff\xd8':
        return 'image/jpeg'
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    if data[:2] == b'BM':
        return 'image/bmp'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    if data[:4] == b'\x1b%G':
        return 'application/vnd.hp-PCL'
    if data[:2] == b'\x1b@':
        return 'application/vnd.epson.escpr'   # ESC/P payload
    return 'application/octet-stream'


def _text_to_ps(text: str, copies: int = 1) -> bytes:
    """Wrap plain text in a minimal PostScript document (laser printers)."""
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    out = []
    for _ in range(copies):
        out += [
            '%!PS-Adobe-3.0', '%%Pages: 1', '%%EndComments',
            '/Courier 10 selectfont', '%%Page: 1 1',
        ]
        y = 750
        for line in lines[:72]:
            safe = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            out.append(f'72 {y} moveto')
            out.append(f'({safe}) show')
            y -= 14
            if y < 50:
                break
        out += ['showpage', '%%Trailer', '%%EOF']
    return '\n'.join(out).encode('latin-1', errors='replace')


def _text_to_escp(text: str, copies: int = 1) -> bytes:
    """
    Render text as ESC/P stream — native Epson language, zero dependencies.
    Works on all Epson inkjets and dot-matrix printers via LPD passthrough.
    """
    ESC = b'\x1b'
    buf = bytearray()
    for _ in range(copies):
        buf += ESC + b'@'          # init / reset
        buf += ESC + b'\x33\x18'  # 24/180-inch line spacing
        lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        for line in lines:
            # Normalize common unicode punctuation to ASCII equivalents
            normalized = (
                line.replace('\u2014', '-')   # em dash → hyphen
                    .replace('\u2013', '-')   # en dash → hyphen
                    .replace('\u2018', "'")   # left single quote
                    .replace('\u2019', "'")   # right single quote
                    .replace('\u201c', '"')   # left double quote
                    .replace('\u201d', '"')   # right double quote
                    .replace('\u2026', '...')  # ellipsis
                    .replace('\u00b7', '.')   # middle dot
            )
            buf += normalized.encode('latin-1', errors='replace') + b'\r\n'
        buf += b'\x0c'             # form-feed — eject page
    return bytes(buf)


def _image_to_pwg_raster(img: object, dpi: int = 150, color: bool = True) -> bytes:
    """
    Convert a PIL Image to PWG Raster (image/pwg-raster, RaS3 sync word).

    PWG Raster is the AirPrint/Mopria native format accepted by Epson
    L-series inkjets via IPP/IPPS.  Field offsets follow cups_page_header2_t
    (CUPS 2.x source: cups/raster.h).

    Args:
        img:   PIL Image object.
        dpi:   Output resolution (150 is sufficient for inkjets).
        color: True → srgb_8 (24-bit), False → sgray_8 (8-bit grayscale).
    """
    try:
        from PIL import Image as _PIL  # type: ignore
    except ImportError:
        return b''

    if color:
        img = img.convert('RGB')  # type: ignore[union-attr]
        cs, bpc, bpp, nc = 19, 8, 24, 3   # sRGB
    else:
        img = img.convert('L')    # type: ignore[union-attr]
        cs, bpc, bpp, nc = 18, 8, 8, 1    # sGray

    pw = int(8.27  * dpi)
    ph = int(11.69 * dpi)
    ratio = pw / img.width       # type: ignore[union-attr]
    new_h = min(int(img.height * ratio), ph)  # type: ignore[union-attr]
    img   = img.resize((pw, new_h), resample=3)  # type: ignore[union-attr]
    W, H  = img.size             # type: ignore[union-attr]
    bpl   = W * (bpp // 8)

    hdr = bytearray(1796)

    def _u32(off: int, v: int) -> None:
        struct.pack_into('>I', hdr, off, v)

    def _f32(off: int, v: float) -> None:
        struct.pack_into('>f', hdr, off, v)

    def _stn(off: int, s: str, ln: int = 64) -> None:
        b = s.encode('ascii')[:ln - 1]
        hdr[off:off + len(b)] = b
        hdr[off + len(b)] = 0

    # String fields (4 × 64 B = offsets 0-255)
    _stn(0,   'PwgRaster')   # MediaClass — REQUIRED for PWG Raster (RaS3)
    _stn(64,  '')
    _stn(128, 'Plain')
    _stn(192, '')             # OutputType — must be empty

    # uint32 / float fields (offsets 256+)
    for off in range(256, 276, 4):
        _u32(off, 0)
    _u32(276, dpi); _u32(280, dpi)                    # HWResolution x, y
    _u32(284, 0); _u32(288, 0); _u32(292, 595); _u32(296, 842)  # ImagingBBox
    for off in range(300, 340, 4):
        _u32(off, 0)
    _u32(340, 1)               # NumCopies
    _u32(344, 0)               # Orientation (portrait)
    _u32(348, 0)               # OutputFaceUp
    _u32(352, 595); _u32(356, 842)   # PageSize A4 in pts (1 pt = 1/72 in)
    for off in range(360, 372, 4):
        _u32(off, 0)
    _u32(372, W);  _u32(376, H)       # cupsWidth, cupsHeight (pixels)
    _u32(380, 0)
    _u32(384, bpc); _u32(388, bpp); _u32(392, bpl)
    _u32(396, 0)               # cupsColorOrder (chunked)
    _u32(400, cs)              # cupsColorSpace (18=sGray, 19=sRGB)
    _u32(404, 0)               # cupsCompression (raw, uncompressed)
    for off in range(408, 420, 4):
        _u32(off, 0)
    _u32(420, nc)              # cupsNumColors
    _f32(424, 0.0)
    _f32(428, 595.28); _f32(432, 841.89)   # cupsPageSize (pts, float)
    _f32(436, 0.0); _f32(440, 0.0)
    _f32(444, 595.28); _f32(448, 841.89)   # cupsImagingBBox
    _stn(1732, 'iso_a4_210x297mm')         # cupsPageSizeName

    raster = img.tobytes()  # type: ignore[union-attr]
    return b'RaS\x03' + bytes(hdr) + raster


def _image_to_escp_bitmap(img: object) -> bytes:  # img: PIL.Image.Image
    """
    Convert a PIL Image to ESC/P 24-pin bitmap stream (ESC * mode 39).
    NOTE: This is a dot-matrix / legacy format — NOT suitable for Epson
    inkjet printers (L-series, EcoTank).  Use _image_to_pwg_raster() for
    inkjets when printing via IPP/IPPS.
    """
    ESC = b'\x1b'

    gray = img.convert('L')  # type: ignore[attr-defined]
    max_w = 480
    if gray.width > max_w:
        ratio = max_w / gray.width
        gray = gray.resize((int(gray.width * ratio), int(gray.height * ratio)), resample=1)
    bw     = gray.convert('1')
    pix    = bw.load()
    width, height = bw.size

    buf = bytearray()
    buf += ESC + b'@'          # init
    buf += ESC + b'\x33\x18'  # tight line spacing for bitmap
    BAND = 24
    for y0 in range(0, height, BAND):
        cols = bytearray(width * 3)
        for x in range(width):
            for pin in range(BAND):
                py = y0 + pin
                if py < height and not pix[x, py]:   # PIL 1-bit: 0 = black
                    bi  = x * 3 + pin // 8
                    bit = 7 - pin % 8
                    cols[bi] |= 1 << bit
        buf += ESC + b'*' + bytes([39])
        buf += struct.pack('<H', width)
        buf += bytes(cols)
        buf += b'\r\n'
    buf += b'\x0c'
    return bytes(buf)


def _text_to_jpeg(text: str, copies: int = 1) -> Optional[bytes]:
    """
    Render text as JPEG via Pillow — best choice for AirPrint/IPP inkjets.
    Returns None if Pillow is unavailable.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
        W, H, MARGIN, LINE_H, FS = 2480, 3508, 150, 55, 40
        try:
            font = ImageFont.truetype('arial.ttf', FS)
        except (IOError, OSError):
            font = ImageFont.load_default()

        lines    = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        max_ln   = (H - 2 * MARGIN) // LINE_H
        pages    = []
        for start in range(0, max(1, len(lines)), max_ln):
            img  = Image.new('RGB', (W, H), (255, 255, 255))
            draw = ImageDraw.Draw(img)
            y    = MARGIN
            for ln in lines[start:start + max_ln]:
                draw.text((MARGIN, y), ln, fill=(0, 0, 0), font=font)
                y += LINE_H
            pages.append(img)

        result = b''
        for img in pages * copies:
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=85, dpi=(300, 300))
            result += buf.getvalue()
        return result
    except ImportError:
        return None


def _convert_to_ps(path: str) -> Optional[bytes]:
    """Convert PDF/image/Word to PostScript via Ghostscript or LibreOffice."""
    fmt = _detect_format(path)
    gs  = shutil.which('gs') or shutil.which('gswin64c') or shutil.which('gswin32c')
    lo  = shutil.which('libreoffice') or shutil.which('soffice')

    for src_fmt, tool, args in [
        ('pdf',   gs, ['-q', '-dNOPAUSE', '-dBATCH', '-sDEVICE=pswrite']),
        ('image', gs, ['-q', '-dNOPAUSE', '-dBATCH', '-sDEVICE=pswrite', '-sPAPERSIZE=a4']),
    ]:
        if fmt == src_fmt and tool:
            try:
                with tempfile.NamedTemporaryFile(suffix='.ps', delete=False) as tmp:
                    tp = tmp.name
                r = subprocess.run([tool] + args + [f'-sOutputFile={tp}', path],
                                   capture_output=True, timeout=30)
                if r.returncode == 0:
                    data = Path(tp).read_bytes()
                    os.unlink(tp)
                    return data
            except (subprocess.TimeoutExpired, OSError):
                pass

    if fmt == 'word' and lo:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                r = subprocess.run([lo, '--headless', '--convert-to', 'pdf',
                                    '--outdir', tmpdir, path],
                                   capture_output=True, timeout=30)
                if r.returncode == 0:
                    pdf = Path(tmpdir) / (Path(path).stem + '.pdf')
                    if pdf.exists():
                        ps = _convert_to_ps(str(pdf))
                        return ps if ps else pdf.read_bytes()
        except (subprocess.TimeoutExpired, OSError):
            pass
    return None


def _prepare_payload(path: str, copies: int = 1,
                     prefer_escp: bool = False,
                     prefer_pwg:  bool = False) -> Tuple[bytes, str]:
    """
    Prepare the print payload and return (data, description).

    Args:
        prefer_escp: When True, prefer ESC/P over JPEG/PS (use for LPD → Epson inkjets).
        prefer_pwg:  When True, generate PWG Raster for images (use for IPP → Epson inkjets).
    """
    fmt      = _detect_format(path)
    raw_data = Path(path).read_bytes()
    _log.debug("Detected format '%s' for %s", fmt, path)

    if fmt == 'ps':
        return (UEL + f'@PJL SET COPIES={copies}\r\n'.encode() + UEL + raw_data
                if copies > 1 else raw_data, 'PostScript (as-is)')

    if fmt == 'pcl':
        return raw_data, 'PCL (as-is)'

    if fmt == 'text':
        text = raw_data.decode('utf-8', errors='replace')
        if prefer_escp:
            data = _text_to_escp(text, copies=copies)
            return data, 'ESC/P (Epson native text mode)'
        jpeg = _text_to_jpeg(text, copies=copies)
        if jpeg:
            return jpeg, 'JPEG via Pillow (300 dpi)'
        data = _text_to_escp(text, copies=copies)
        return data, 'ESC/P (Epson native text mode)'

    if fmt in ('pdf', 'image', 'word'):
        # 1. PWG Raster (AirPrint/Mopria native) for IPP to Epson inkjets
        if prefer_pwg:
            try:
                from PIL import Image as _PIL  # type: ignore
                img  = _PIL.open(path) if fmt == 'image' else None
                if img is None:
                    raise ValueError("Not a direct image — needs conversion")
                pwg = _image_to_pwg_raster(img, dpi=150, color=True)
                if pwg:
                    return pwg, 'PWG Raster srgb_8 @ 150 DPI (AirPrint/Mopria)'
            except Exception as exc:
                _log.debug("PWG Raster conversion failed: %s", exc)

        # 2. Try Ghostscript/LibreOffice → PostScript
        ps = _convert_to_ps(path)
        if ps:
            return ps, 'PostScript (converted)'

        # 3. ESC/P bitmap via Pillow — images only (LPD passthrough, NOT for inkjet IPP)
        if prefer_escp and fmt == 'image':
            try:
                from PIL import Image as _PIL  # type: ignore
                img  = _PIL.open(path)
                data = _image_to_escp_bitmap(img)
                return data, 'ESC/P bitmap via Pillow (LPD passthrough)'
            except (ImportError, Exception):
                pass

        # 4. For PDF/Word: send raw bytes (some printers parse natively)
        if fmt in ('pdf', 'word'):
            return raw_data, f'{fmt.upper()} (raw bytes — use OS driver for reliable printing)'

        # 5. Raw image bytes
        _log.warning("No conversion available for '%s'; sending raw bytes", fmt)
        return raw_data, f'raw {fmt} bytes (no conversion tools found)'

    return raw_data, 'raw binary'


# ── Protocol senders ──────────────────────────────────────────────────────────

def send_raw(host: str, port: int, data: bytes, timeout: float = 15.0) -> PrintJobResult:
    """Send data via RAW/JetDirect (TCP 9100) — HP/PCL printers."""
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            sent = 0
            while sent < len(data):
                n = s.send(data[sent:sent + 4096])
                if n == 0:
                    raise OSError("Connection closed by remote")
                sent += n
        return PrintJobResult(
            success=True, protocol='raw', host=host, port=port,
            file_path='', file_size=len(data),
            elapsed_ms=(time.time() - t0) * 1000,
            message=f"Sent {len(data)} bytes via RAW/JetDirect",
        )
    except OSError as exc:
        hint = ''
        err  = str(exc)
        if 'refused' in err.lower():
            hint = 'Port 9100 closed — printer may not support RAW/JetDirect'
        elif 'timed out' in err.lower():
            hint = 'Connection timed out — printer unreachable or firewalled'
        return PrintJobResult(
            success=False, protocol='raw', host=host, port=port,
            file_path='', file_size=0,
            elapsed_ms=(time.time() - t0) * 1000,
            error=err, hint=hint,
        )


def _make_tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def send_ipp(host: str, port: int, data: bytes,
             job_name: str    = 'PrinterXPL-Forge-Job',
             doc_format: str  = '',
             use_tls: bool    = False,
             timeout: float   = 30.0) -> PrintJobResult:
    """
    Send data via IPP (HTTP) or IPPS (HTTPS).

    Auto-upgrades to TLS when:
    - use_tls=True (explicit)
    - plain TCP returns HTTP 426
    - plain TCP connection is reset (Epson firmware behaviour)
    """
    t0   = time.time()
    mime = doc_format or _detect_mime(data)

    def _s(name: str, value: str, tag: int = 0x44) -> bytes:
        """Encode one IPP attribute per RFC 8011 §3.1.5 (tag + name-len + name + val-len + val)."""
        nb = name.encode(); vb = value.encode()
        return (bytes([tag]) + struct.pack('>H', len(nb)) + nb +
                struct.pack('>H', len(vb)) + vb)

    def _si(name: str, value: int, tag: int = 0x21) -> bytes:
        """Encode one IPP integer attribute."""
        nb = name.encode()
        return (bytes([tag]) + struct.pack('>H', len(nb)) + nb +
                struct.pack('>Hi', 4, value))

    # Epson firmware requires ipp:// URI even over TLS connections
    printer_uri = f'ipp://{host}:{port}/ipp/print'
    ipp_attrs   = b'\x01'
    ipp_attrs  += _s('attributes-charset',          'utf-8', 0x47)
    ipp_attrs  += _s('attributes-natural-language', 'en',    0x48)
    ipp_attrs  += _s('printer-uri',                 printer_uri, 0x45)
    ipp_attrs  += _s('requesting-user-name',        'PrinterXPL-Forge', 0x42)
    ipp_attrs  += _s('job-name',                    job_name, 0x42)
    ipp_attrs  += _s('document-format',             mime, 0x49)
    ipp_attrs  += b'\x02'
    ipp_attrs  += _s('media',                       'iso_a4_210x297mm', 0x44)
    ipp_attrs  += _si('copies',                     1)
    ipp_attrs  += _si('print-quality',              4)
    ipp_attrs  += b'\x03'

    ipp_req = struct.pack('>BBHI', 1, 1, 0x0002, 1) + ipp_attrs + data

    http_req = (
        f'POST /ipp/print HTTP/1.1\r\n'
        f'Host: {host}:{port}\r\n'
        f'Content-Type: application/ipp\r\n'
        f'Content-Length: {len(ipp_req)}\r\n'
        f'Connection: close\r\n\r\n'
    ).encode() + ipp_req

    def _send(sock: socket.socket) -> bytes:
        sock.settimeout(timeout)
        sock.sendall(http_req)
        resp = b''
        sock.settimeout(8)
        try:
            while True:
                c = sock.recv(8192)
                if not c:
                    break
                resp += c
        except socket.timeout:
            pass
        return resp

    resp     = b''
    used_tls = use_tls
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            conn = _make_tls_ctx().wrap_socket(raw, server_hostname=host)
        else:
            conn = raw
        with conn:
            resp = _send(conn)

        # Auto-TLS upgrade: 426 or empty response from reset
        needs_tls = (resp.startswith(b'HTTP/1.1 426') or
                     (not resp and not use_tls))
        if needs_tls and not use_tls:
            _log.info("Plain TCP refused — retrying with TLS (IPPS)")
            raw2 = socket.create_connection((host, port), timeout=timeout)
            with _make_tls_ctx().wrap_socket(raw2, server_hostname=host) as tlsc:
                resp     = _send(tlsc)
                used_tls = True

    except ConnectionResetError:
        # Epson forcibly resets non-TLS connections — upgrade to TLS
        if not use_tls:
            _log.info("Connection reset — retrying with TLS (IPPS)")
            try:
                raw2 = socket.create_connection((host, port), timeout=timeout)
                with _make_tls_ctx().wrap_socket(raw2, server_hostname=host) as tlsc:
                    resp     = _send(tlsc)
                    used_tls = True
            except OSError as exc2:
                return PrintJobResult(
                    success=False, protocol='ipp', host=host, port=port,
                    file_path='', file_size=0,
                    elapsed_ms=(time.time() - t0) * 1000,
                    error=str(exc2), hint='IPPS upgrade also failed',
                )
        else:
            return PrintJobResult(
                success=False, protocol='ipp', host=host, port=port,
                file_path='', file_size=0,
                elapsed_ms=(time.time() - t0) * 1000,
                error='Connection reset by printer',
            )
    except OSError as exc:
        err  = str(exc)
        hint = ''
        if 'refused' in err.lower():
            hint = 'Port 631 closed — printer does not support IPP'
        elif 'timed out' in err.lower():
            hint = 'IPP connection timed out — printer may be firewalled'
        return PrintJobResult(
            success=False, protocol='ipp', host=host, port=port,
            file_path='', file_size=0,
            elapsed_ms=(time.time() - t0) * 1000,
            error=err, hint=hint,
        )

    # Parse IPP response
    ipp_status = 0xFFFF
    job_id     = None
    sep        = resp.find(b'\r\n\r\n')
    ipp_resp   = resp[sep + 4:] if sep != -1 else b''
    if len(ipp_resp) >= 4:
        ipp_status = struct.unpack('>H', ipp_resp[2:4])[0]
        success    = (ipp_status == _IPP_OK)
    else:
        success = b'200' in resp[:100]

    elapsed = (time.time() - t0) * 1000
    proto_label = 'ipps' if used_tls else 'ipp'

    if success:
        return PrintJobResult(
            success=True, protocol=proto_label, host=host, port=port,
            file_path='', file_size=len(data), job_id=job_id,
            elapsed_ms=elapsed,
            message=f"Print-Job accepted ({len(data)} bytes, format={mime})",
        )

    # Map IPP error to actionable hint
    hint = _classify_ipp_error(ipp_status, mime)
    err_desc = _IPP_ERRORS.get(ipp_status, f'IPP error 0x{ipp_status:04X}')
    return PrintJobResult(
        success=False, protocol=proto_label, host=host, port=port,
        file_path='', file_size=len(data),
        elapsed_ms=elapsed,
        error=err_desc,
        hint=hint,
    )


def _classify_ipp_error(status: int, mime: str) -> str:
    """Return an operator-friendly hint for a given IPP error status."""
    install_hint = (
        "Como alternativa, instale a impressora no SO com --install-printer "
        "e tente imprimir normalmente pelo driver do sistema operacional."
    )
    if status == _IPP_FORMAT_NOT_SUPPORTED:
        return (
            f"A impressora não aceita o formato '{mime}' via IPP. "
            f"Tente --send-proto lpd (LPD/ESC-P) ou: {install_hint}"
        )
    if status == 0x0400:   # client-error-bad-request
        return (
            "Requisição IPP rejeitada pela impressora (Bad Request). "
            "A impressora pode estar ocupada ou o formato de dados é incompatível. "
            f"{install_hint}"
        )
    if status == _IPP_STATUS_BUSY:
        return (
            "A impressora está ocupada processando outro job. "
            "Aguarde o LED do painel frontal apagar e tente novamente. "
            f"{install_hint}"
        )
    if status in (_IPP_NOT_AUTHORIZED, 0x0402):
        return (
            "A impressora exige autenticação para impressão via IPP (configuração reforçada). "
            f"{install_hint}"
        )
    if status == _IPP_DEVICE_ERROR:
        return "Erro de hardware na impressora — verifique papel, tinta e tampa."
    if status == _IPP_OP_NOT_SUPPORTED:
        return (
            "A impressora não suporta operação IPP Print-Job via rede. "
            f"{install_hint}"
        )
    return (
        f"Verifique o status da impressora (IPP 0x{status:04X}). "
        f"{install_hint}"
    )


def send_lpd(host: str, port: int, data: bytes,
             queue:    str   = 'lp',
             job_name: str   = 'PrinterXPL-Forge',
             timeout:  float = 20.0) -> PrintJobResult:
    """
    Send data via LPD (RFC 1179) on TCP 515.
    Uses passthrough ('l') control-file command so ESC/P data reaches the print engine.
    """
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)

            s.sendall(b'\x02' + queue.encode() + b'\n')
            ack = s.recv(1)
            if ack != b'\x00':
                raise OSError(f"LPD NAK on receive-job: {ack!r}")

            ctrl      = (
                f'H{host}\nP{job_name}\nJ{job_name}\n'
                f'ldfA001{host}\n'   # 'l' = passthrough, no filter translation
                f'N{job_name}\n'
            ).encode()
            ctrl_name = f'cfA001{host[:15]}'
            s.sendall(f'\x02{len(ctrl)} {ctrl_name}\n'.encode())
            if s.recv(1) != b'\x00':
                raise OSError("LPD NAK on control-file header")
            s.sendall(ctrl + b'\x00')
            s.recv(1)  # ACK for control data

            data_name = f'dfA001{host[:15]}'
            s.sendall(f'\x03{len(data)} {data_name}\n'.encode())
            if s.recv(1) != b'\x00':
                raise OSError("LPD NAK on data-file header")
            s.sendall(data + b'\x00')
            s.settimeout(8)
            try:
                s.recv(1)   # final ACK (may timeout on some printers — OK)
            except socket.timeout:
                pass

        return PrintJobResult(
            success=True, protocol='lpd', host=host, port=port,
            file_path='', file_size=len(data),
            elapsed_ms=(time.time() - t0) * 1000,
            message=f"LPD job submitted on queue '{queue}' ({len(data)} bytes)",
        )
    except OSError as exc:
        err  = str(exc)
        hint = ''
        if 'NAK' in err:
            hint = 'Printer refused the LPD job (hardened or busy). Check queue name.'
        elif 'refused' in err.lower():
            hint = 'Port 515 closed — printer does not support LPD'
        elif 'timed out' in err.lower():
            hint = 'LPD connection timed out — printer may be firewalled or busy'
        return PrintJobResult(
            success=False, protocol='lpd', host=host, port=port,
            file_path='', file_size=0,
            elapsed_ms=(time.time() - t0) * 1000,
            error=err, hint=hint,
        )


def _clear_os_print_queue(printer_name: str = '') -> None:
    """Clear stuck/errored/paused jobs from the OS print queue before sending.

    On Windows: uses PowerShell Get-PrintJob | Remove-PrintJob.
    On Linux/macOS: uses lprm -a or cancel -a.

    Args:
        printer_name: Target printer name. Empty → clears all printers' queues.
    """
    import platform
    os_name = platform.system()
    try:
        if os_name == 'Windows':
            if printer_name:
                pname_esc = printer_name.replace('"', '\\"')
                ps_cmd = (
                    f'Get-PrintJob -PrinterName "{pname_esc}" '
                    f'| Remove-PrintJob'
                )
            else:
                ps_cmd = (
                    'Get-Printer | ForEach-Object { '
                    '  try { Get-PrintJob -PrinterName $_.Name '
                    '    | Remove-PrintJob } catch {} '
                    '}'
                )
            subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive',
                 '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
                capture_output=True, timeout=15,
            )
        else:
            if printer_name:
                subprocess.run(['cancel', '-a', '-U', printer_name],
                               capture_output=True, timeout=10)
            else:
                subprocess.run(['cancel', '-a'],
                               capture_output=True, timeout=10)
    except Exception as exc:
        _log.debug("Queue clear warning (non-fatal): %s", exc)


def send_os_print(path: str, printer_name: str = '',
                  timeout: float = 30.0,
                  clear_queue: bool = True) -> PrintJobResult:
    """
    Print a file via the locally installed OS printer (Windows/Linux/macOS).

    Clears stuck/errored jobs from the queue before sending to avoid
    the printer staying offline or blocked by a previous failed job.

    On Windows: uses PowerShell Start-Process with -Verb PrintTo.
    On Linux/macOS: uses lpr command.

    Args:
        path:         File to print.
        printer_name: OS printer name. Empty → system default.
        timeout:      Wait timeout in seconds.
        clear_queue:  If True, clears stuck jobs before printing (default: True).
    """
    import platform
    t0 = time.time()
    p  = Path(path)
    if not p.exists():
        return PrintJobResult(
            success=False, protocol='os', host='localhost', port=0,
            file_path=path, file_size=0,
            error=f'File not found: {path}',
        )

    os_name = platform.system()

    # Clear the print queue before submitting to avoid blocked/offline state
    if clear_queue:
        _log.info("Clearing OS print queue before sending job...")
        _clear_os_print_queue(printer_name)
        time.sleep(0.5)  # brief pause so the spooler resets

    try:
        if os_name == 'Windows':
            # Choose the best print method based on file type
            suffix = p.suffix.lower()
            img_exts = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif', '.webp'}

            if suffix in img_exts:
                # Images: use mspaint /pt which works for common image formats
                mspaint = shutil.which('mspaint') or 'mspaint'
                args_list = [mspaint, '/pt', str(p.resolve())]
                if printer_name:
                    args_list.append(printer_name)
                r = subprocess.run(args_list, capture_output=True, timeout=timeout)
            elif suffix == '.txt':
                # Plain text: use notepad /pt
                notepad = shutil.which('notepad') or 'notepad'
                args_list = [notepad, '/pt', str(p.resolve())]
                if printer_name:
                    args_list += [printer_name, printer_name, '']
                r = subprocess.run(args_list, capture_output=True, timeout=timeout)
            else:
                # PDF and others: try -Verb PrintTo via PowerShell
                pname_esc = printer_name.replace('"', '\\"')
                ps_cmd = (
                    f'Start-Process -FilePath "{p.resolve()}" -Verb PrintTo '
                    + (f'-ArgumentList "{pname_esc}"' if printer_name else '')
                    + ' -Wait -ErrorAction Stop'
                )
                r = subprocess.run(
                    ['powershell', '-NoProfile', '-NonInteractive',
                     '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
                    capture_output=True, timeout=timeout,
                )

            success = r.returncode == 0
            stderr  = r.stderr.decode('utf-8', errors='replace').strip()
            if not success:
                return PrintJobResult(
                    success=False, protocol='os', host='localhost', port=0,
                    file_path=path, file_size=p.stat().st_size,
                    elapsed_ms=(time.time() - t0) * 1000,
                    error=f'OS print failed (rc={r.returncode}): {stderr}',
                    hint=('Verifique se a impressora está instalada em Configurações → '
                          'Impressoras. Execute --install-printer para adicioná-la.'),
                )
        else:
            lpr = shutil.which('lpr') or shutil.which('lp')
            if not lpr:
                return PrintJobResult(
                    success=False, protocol='os', host='localhost', port=0,
                    file_path=path, file_size=p.stat().st_size,
                    error='lpr/lp not found — CUPS not installed',
                    hint='Install CUPS: sudo apt install cups  (Debian/Ubuntu) '
                         'or brew install cups  (macOS)',
                )
            cmd = [lpr]
            if printer_name:
                cmd += ['-P', printer_name]
            cmd.append(str(p.resolve()))
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            success = r.returncode == 0
            stderr  = r.stderr.decode('utf-8', errors='replace').strip()
            if not success:
                return PrintJobResult(
                    success=False, protocol='os', host='localhost', port=0,
                    file_path=path, file_size=p.stat().st_size,
                    elapsed_ms=(time.time() - t0) * 1000,
                    error=f'lpr failed (rc={r.returncode}): {stderr}',
                    hint=('Check that the printer is configured in CUPS. '
                          'Run --install-printer to add it.'),
                )

        return PrintJobResult(
            success=True, protocol='os', host='localhost', port=0,
            file_path=path, file_size=p.stat().st_size,
            elapsed_ms=(time.time() - t0) * 1000,
            message=(f'File sent to OS printer '
                     f'"{printer_name or "default"}" via {os_name} spooler'),
        )
    except subprocess.TimeoutExpired:
        return PrintJobResult(
            success=False, protocol='os', host='localhost', port=0,
            file_path=path, file_size=p.stat().st_size,
            elapsed_ms=(time.time() - t0) * 1000,
            error='OS print command timed out',
            hint='Printer may be offline or unresponsive.',
        )
    except OSError as exc:
        return PrintJobResult(
            success=False, protocol='os', host='localhost', port=0,
            file_path=path, file_size=p.stat().st_size,
            elapsed_ms=(time.time() - t0) * 1000,
            error=str(exc),
        )


# ── Public API ────────────────────────────────────────────────────────────────

def send_print_job(
    host:      str,
    path:      str,
    protocol:  str   = 'auto',
    port:      int   = 0,
    copies:    int   = 1,
    queue:     str   = 'lp',
    timeout:   float = 25.0,
    caps:      Optional[PrinterCapabilities] = None,
) -> PrintJobResult:
    """
    High-level print-job sender with automatic protocol/format selection.

    Args:
        host:     Target IP or hostname.
        path:     File to print (absolute or relative path).
        protocol: 'auto' (smart probe) | 'ipp' | 'lpd' | 'raw'.
        port:     Override default port (0 = use protocol default).
        copies:   Number of copies to print.
        queue:    LPD queue name (default 'lp').
        timeout:  Socket timeout in seconds.
        caps:     Pre-computed PrinterCapabilities (skips probe if provided).

    Returns:
        PrintJobResult with .success, .message, .error, .hint.
    """
    proto = protocol.lower().strip()
    p     = Path(path)

    if not p.exists():
        return PrintJobResult(
            success=False, protocol=proto or 'unknown',
            host=host, port=port, file_path=path, file_size=0,
            error=f"File not found: {path}",
        )

    # Probe printer if auto-selecting protocol
    if caps is None and (proto == 'auto' or not proto):
        _log.info("Probing printer %s for capabilities...", host)
        caps = probe_printer(host, timeout=min(timeout, 6.0))

    # Resolve protocol
    if proto in ('auto', ''):
        if caps:
            proto = caps.best_protocol or 'ipp'
        else:
            proto = 'ipp'

    # Resolve port
    default_ports  = {'raw': 9100, 'ipp': 631, 'lpd': 515}
    actual_port    = port or default_ports.get(proto, 9100)
    use_tls        = bool(caps and caps.ipp_requires_tls) if proto == 'ipp' else False

    # Prepare payload
    prefer_escp = (proto == 'lpd')
    prefer_pwg  = (proto == 'ipp')   # IPP to Epson inkjets → PWG Raster
    try:
        payload, fmt_desc = _prepare_payload(
            str(p), copies=copies,
            prefer_escp=prefer_escp,
            prefer_pwg=prefer_pwg,
        )
    except Exception as exc:
        return PrintJobResult(
            success=False, protocol=proto, host=host, port=actual_port,
            file_path=path, file_size=0,
            error=f"Payload preparation failed: {exc}",
        )

    _log.info("Sending %s → %s:%d via %s (format: %s, %d bytes)",
              path, host, actual_port, proto.upper(), fmt_desc, len(payload))

    # Dispatch
    result: PrintJobResult
    if proto == 'raw':
        result = send_raw(host, actual_port, payload, timeout=timeout)

    elif proto == 'ipp':
        mime = _detect_mime(payload)
        result = send_ipp(
            host, actual_port, payload,
            job_name   = p.name,
            doc_format = mime,
            use_tls    = use_tls,
            timeout    = timeout,
        )
        # Fallback 1: LPD (ESC/P) if available
        if not result.success and caps and caps.lpd_available:
            _log.info("IPP rejected — falling back to LPD with ESC/P")
            escp_payload, escp_desc = _prepare_payload(
                str(p), copies=copies, prefer_escp=True)
            lpd_result = send_lpd(host, 515, escp_payload, queue=queue,
                                  job_name=p.stem, timeout=timeout)
            if lpd_result.success:
                lpd_result.message = f"[IPP failed → LPD fallback] {lpd_result.message}"
                result = lpd_result

        # Annotate failure with OS install suggestion
        if not result.success:
            _log.info("All network protocols failed for %s — OS printing may work", path)
            if not result.hint:
                result.hint = (
                    "Não foi possível imprimir via protocolos de rede (IPP/LPD). "
                    "Tente instalar a impressora no SO com --install-printer e "
                    "imprimir normalmente pelo spooler do sistema operacional."
                )

    elif proto == 'lpd':
        result = send_lpd(host, actual_port, payload, queue=queue,
                          job_name=p.stem, timeout=timeout)
        if not result.success and not result.hint:
            result.hint = (
                "Falha no envio via LPD. Se a impressora estiver instalada "
                "localmente via driver do SO, tente imprimir normalmente. "
                "Caso contrário, use --install-printer."
            )
    else:
        return PrintJobResult(
            success=False, protocol=proto, host=host, port=actual_port,
            file_path=path, file_size=0, error=f"Unknown protocol: {proto}",
        )

    result.file_path = path
    result.file_size = len(payload)
    return result
