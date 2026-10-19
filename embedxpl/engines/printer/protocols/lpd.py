#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LPD Protocol Support for PrinterXPL-Forge
======================================
Line Printer Daemon protocol (RFC 1179) on port 515

Legacy protocol still widely supported by printers.
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

import socket
import time

class LPDProtocol:
    """
    LPD protocol implementation (Port 515)
    Line Printer Daemon - Legacy but still supported
    """
    
    DEFAULT_PORT = 515
    
    def __init__(self, host, port=None, timeout=30, queue="lp"):
        self.host = host
        self.port = port or self.DEFAULT_PORT
        self.timeout = timeout
        self.queue = queue  # Printer queue name
        self.sock = None
        self.job_number = 1

    def connect(self):
        """Establish LPD connection"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            return False

    def send_control_file(self, hostname, username, filename):
        """Send LPD control file"""
        control = (
            f"H{hostname}\n"
            f"P{username}\n"
            f"fdfA{self.job_number:03d}{hostname}\n"
            f"UdfA{self.job_number:03d}{hostname}\n"
            f"N{filename}\n"
        )
        return control.encode()

    def print_job(self, data, hostname="PrinterXPL-Forge", username="root", filename="job.txt"):
        """
        Send print job via LPD protocol
        
        LPD Protocol Format:
        1. Receive job: \\x02<queue>\\n
        2. Receive control file: \\x02<size> cfA<job><host>\\n
        3. Send control file data
        4. Receive data file: \\x03<size> dfA<job><host>\\n
        5. Send data file
        """
        if not self.sock:
            if not self.connect():
                raise ConnectionError("Failed to connect")
        
        try:
            # Step 1: Receive job command
            cmd = f"\\x02{self.queue}\\n".encode()
            self.sock.send(cmd)
            response = self.sock.recv(1)
            if response != b'\\x00':
                raise Exception("Queue refused job")
            
            # Step 2: Send control file
            control_data = self.send_control_file(hostname, username, filename)
            cmd = f"\\x02{len(control_data)} cfA{self.job_number:03d}{hostname}\\n".encode()
            self.sock.send(cmd)
            response = self.sock.recv(1)
            if response != b'\\x00':
                raise Exception("Control file refused")
            
            self.sock.send(control_data + b'\\x00')
            response = self.sock.recv(1)
            
            # Step 3: Send data file
            if isinstance(data, str):
                data = data.encode()
            
            cmd = f"\\x03{len(data)} dfA{self.job_number:03d}{hostname}\\n".encode()
            self.sock.send(cmd)
            response = self.sock.recv(1)
            if response != b'\\x00':
                raise Exception("Data file refused")
            
            self.sock.send(data + b'\\x00')
            response = self.sock.recv(1)
            
            self.job_number += 1
            return True
            
        except Exception as e:
            raise Exception(f"LPD print failed: {e}")

    def get_queue_status(self):
        """Get printer queue status"""
        if not self.sock:
            if not self.connect():
                raise ConnectionError("Failed to connect")
        
        # Send queue status command
        cmd = f"\\x04{self.queue}\\n".encode()
        self.sock.send(cmd)
        
        # Receive status
        status = b""
        while True:
            chunk = self.sock.recv(1024)
            if not chunk:
                break
            status += chunk
        
        return status.decode('latin-1', errors='ignore')

    def close(self):
        """Close LPD connection"""
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

