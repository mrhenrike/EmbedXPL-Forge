#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — LPD Simulator (TCP port 515)
==========================================
Implements RFC 1179 Line Printer Daemon.

Intentional vulnerabilities:
  - lpd_unauthenticated: accepts print jobs without auth
  - lpd_bof_probe:       very long queue names or control files → log as BoF probe
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import socketserver

from simulators.base_printer import BaseSimulator, PrinterProfile

# LPD command bytes
CMD_PRINT_WAITING  = 0x01   # Print any waiting jobs
CMD_RECEIVE_JOB    = 0x02   # Receive a printer job
CMD_SEND_QUEUE_STATE_SHORT = 0x03
CMD_SEND_QUEUE_STATE_LONG  = 0x04
CMD_REMOVE_JOBS    = 0x05

# Sub-commands within RECEIVE_JOB
SUB_ABORT_JOB      = 0x01
SUB_RECEIVE_CONTROL= 0x02
SUB_RECEIVE_DATA   = 0x03

ACK = b'\x00'
NAK = b'\x01'


class _LPDHandler(socketserver.BaseRequestHandler):

    def setup(self) -> None:
        self.sim: 'LPDSimulator' = self.server.simulator
        self.profile: PrinterProfile = self.sim.profile
        self.sim.stats['connections'] += 1
        self.sim.log.info("LPD connection from %s:%d", *self.client_address)

    def handle(self) -> None:
        self.request.settimeout(10)
        try:
            data = self.request.recv(1024)
            if not data:
                return
            cmd = data[0]
            rest = data[1:].decode('latin-1', errors='replace').strip()

            self.sim.stats['commands'] += 1

            if cmd == CMD_PRINT_WAITING:
                self._handle_print_waiting(rest)
            elif cmd == CMD_RECEIVE_JOB:
                self._handle_receive_job(rest)
            elif cmd in (CMD_SEND_QUEUE_STATE_SHORT, CMD_SEND_QUEUE_STATE_LONG):
                self._handle_queue_state(rest, long=(cmd == CMD_SEND_QUEUE_STATE_LONG))
            elif cmd == CMD_REMOVE_JOBS:
                self._handle_remove_jobs(rest)
            else:
                self.sim.log.debug("Unknown LPD cmd: 0x%02X", cmd)
                self.request.sendall(NAK)
        except (OSError, TimeoutError):
            pass

    def _handle_print_waiting(self, queue: str) -> None:
        self.sim.log.info("LPD Print-Waiting on queue '%s'", queue)
        self.request.sendall(ACK)

    def _handle_receive_job(self, queue: str) -> None:
        """Receive a print job (RFC 1179 §6.1)."""
        if not self.profile.vuln.get('lpd_unauthenticated'):
            self.request.sendall(NAK)
            return

        self.sim._log_attack(self.client_address, f'LPD Receive-Job on queue "{queue}" (unauthenticated)')
        self.request.sendall(ACK)

        # Read sub-commands
        try:
            for _ in range(20):
                sub_data = self.request.recv(1024)
                if not sub_data:
                    break
                sub_cmd = sub_data[0]
                sub_rest = sub_data[1:].decode('latin-1', errors='replace').strip()

                if sub_cmd == SUB_ABORT_JOB:
                    self.request.sendall(ACK)
                    return
                elif sub_cmd == SUB_RECEIVE_CONTROL:
                    # Control file — check for oversized (BoF probe)
                    parts = sub_rest.split(None, 1)
                    if parts:
                        try:
                            ctrl_size = int(parts[0])
                            ctrl_name = parts[1] if len(parts) > 1 else 'cfA000'
                            if ctrl_size > 4096 and self.profile.vuln.get('lpd_bof_probe'):
                                self.sim._log_attack(
                                    self.client_address,
                                    f'LPD oversized control file ({ctrl_size} bytes) — BoF probe'
                                )
                        except ValueError:
                            pass
                    self.request.sendall(ACK)
                    # Read control file content
                    ctrl_data = self.request.recv(4096)
                    self.request.sendall(ACK)

                elif sub_cmd == SUB_RECEIVE_DATA:
                    parts = sub_rest.split(None, 1)
                    data_size = 0
                    if parts:
                        try:
                            data_size = int(parts[0])
                        except ValueError:
                            pass
                    self.request.sendall(ACK)
                    # Drain print data
                    remaining = data_size
                    while remaining > 0:
                        chunk = self.request.recv(min(4096, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                    self.request.sendall(ACK)
                    self.profile.job_counter += 1
                    self.sim.log.info("LPD job #%d received (%d bytes)", self.profile.job_counter, data_size)
                    return
                else:
                    self.request.sendall(ACK)
        except (OSError, TimeoutError):
            pass

    def _handle_queue_state(self, args: str, long: bool = False) -> None:
        """Return queue status listing."""
        queue = args.split(None, 1)[0] if args else 'lp'
        if long:
            resp = (
                f"{self.profile.make} {self.profile.model} is ready and printing\n"
                f"Rank\tOwner\tJob\tFiles\t\t\t\tTotal Size\n"
                f"active\tjsmith\t001\tConfidential_Q4.pdf\t\t4194304 bytes\n"
                f"1st\tadmin\t002\tEmployee_Salaries.pdf\t\t2097152 bytes\n"
            )
        else:
            resp = (
                f"{self.profile.make} {self.profile.model} is ready and printing\n"
                f"no entries\n"
            )
        self.sim._log_attack(self.client_address, f'LPD queue-state query on "{queue}"')
        self.request.sendall(resp.encode())

    def _handle_remove_jobs(self, args: str) -> None:
        """Remove (cancel) jobs — DoS."""
        parts = args.split()
        queue = parts[0] if parts else 'lp'
        agent = parts[1] if len(parts) > 1 else 'unknown'
        self.sim._log_attack(
            self.client_address,
            f'LPD Remove-Jobs on queue "{queue}" by agent "{agent}" — DoS'
        )
        self.request.sendall(ACK)


class LPDSimulator(BaseSimulator):
    """LPD printer simulator on TCP port 515."""

    PROTOCOL = 'LPD'

    def _make_server(self) -> socketserver.TCPServer:
        server = socketserver.ThreadingTCPServer((self.host, self.port), _LPDHandler)
        server.simulator = self
        return server
