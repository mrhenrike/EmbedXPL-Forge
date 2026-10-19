#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPP Protocol Support for PrinterXPL-Forge
======================================
Internet Printing Protocol (RFC 2910/2911) on port 631

Modern HTTP-based printing protocol.
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

import socket
import struct
import time

class IPPProtocol:
    """
    IPP protocol implementation (Port 631)
    Internet Printing Protocol - Modern HTTP-based protocol
    """
    
    DEFAULT_PORT = 631
    
    # IPP versions
    IPP_VERSION_1_0 = (1, 0)
    IPP_VERSION_1_1 = (1, 1)
    IPP_VERSION_2_0 = (2, 0)
    
    # IPP operations
    PRINT_JOB = 0x0002
    GET_PRINTER_ATTRIBUTES = 0x000B
    GET_JOBS = 0x000A
    
    # IPP status codes
    STATUS_OK = 0x0000
    STATUS_CLIENT_ERROR = 0x0400
    STATUS_SERVER_ERROR = 0x0500

    def __init__(self, host, port=None, timeout=30):
        self.host = host
        self.port = port or self.DEFAULT_PORT
        self.timeout = timeout
        self.sock = None
        self.request_id = 1

    def connect(self):
        """Establish IPP connection (HTTP)"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            return False

    def build_ipp_request(self, operation, attributes=None):
        """
        Build IPP request packet
        
        Format:
        - Version (2 bytes)
        - Operation ID (2 bytes)
        - Request ID (4 bytes)
        - Attributes
        - End of attributes tag (0x03)
        """
        version = struct.pack('>BB', 1, 1)  # IPP 1.1
        op_id = struct.pack('>H', operation)
        req_id = struct.pack('>I', self.request_id)
        self.request_id += 1
        
        packet = version + op_id + req_id
        
        # Add attributes if provided
        if attributes:
            packet += attributes
        
        # End of attributes
        packet += b'\\x03'
        
        return packet

    def add_attribute(self, tag, name, value):
        """Add IPP attribute to request"""
        attr = struct.pack('>B', tag)
        attr += struct.pack('>H', len(name))
        attr += name.encode()
        
        if value:
            attr += struct.pack('>H', len(value))
            attr += value.encode() if isinstance(value, str) else value
        
        return attr

    def get_printer_attributes(self):
        """Get printer attributes via IPP"""
        if not self.sock:
            if not self.connect():
                raise ConnectionError("Failed to connect")
        
        # Build GET-PRINTER-ATTRIBUTES request
        attrs = b''
        attrs += self.add_attribute(0x01, "attributes-charset", "utf-8")
        attrs += self.add_attribute(0x48, "attributes-natural-language", "en")
        attrs += self.add_attribute(0x45, "printer-uri", f"ipp://{self.host}/ipp/")
        attrs += self.add_attribute(0x44, "requested-attributes", "all")
        
        request = self.build_ipp_request(self.GET_PRINTER_ATTRIBUTES, attrs)
        
        # Send HTTP POST
        http_request = (
            f"POST /ipp/ HTTP/1.1\\r\\n"
            f"Host: {self.host}:{self.port}\\r\\n"
            f"Content-Type: application/ipp\\r\\n"
            f"Content-Length: {len(request)}\\r\\n"
            f"\\r\\n"
        ).encode() + request
        
        self.sock.send(http_request)
        
        # Receive response
        response = b""
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\\r\\n\\r\\n' in response and len(response) > 100:
                    break
            except socket.timeout:
                break
        
        return response

    def parse_printer_attributes(self, response):
        """Parse IPP response to extract printer attributes"""
        try:
            # Split HTTP headers and body
            if b'\\r\\n\\r\\n' in response:
                headers, body = response.split(b'\\r\\n\\r\\n', 1)
            else:
                body = response
            
            # Parse IPP response
            # This is simplified - full IPP parsing is complex
            attrs = {}
            
            # Look for common patterns
            if b'MDL:' in body:
                model = re.findall(b'MDL:([^;]+);', body)
                if model:
                    attrs['model'] = model[0].decode('latin-1')
            
            if b'CMD:' in body:
                commands = re.findall(b'CMD:([^;]+);', body)
                if commands:
                    attrs['commands'] = commands[0].decode('latin-1')
            
            return attrs
            
        except Exception as e:
            return {}

    def print_job(self, data, job_name="PrinterXPL-Forge_job"):
        """Print job via IPP"""
        if not self.sock:
            if not self.connect():
                raise ConnectionError("Failed to connect")
        
        # Build PRINT-JOB request
        attrs = b''
        attrs += self.add_attribute(0x01, "attributes-charset", "utf-8")
        attrs += self.add_attribute(0x48, "attributes-natural-language", "en")
        attrs += self.add_attribute(0x45, "printer-uri", f"ipp://{self.host}/ipp/")
        attrs += self.add_attribute(0x42, "job-name", job_name)
        
        request = self.build_ipp_request(self.PRINT_JOB, attrs)
        
        # Add document data
        if isinstance(data, str):
            data = data.encode()
        request += data
        
        # Send HTTP POST
        http_request = (
            f"POST /ipp/ HTTP/1.1\\r\\n"
            f"Host: {self.host}:{self.port}\\r\\n"
            f"Content-Type: application/ipp\\r\\n"
            f"Content-Length: {len(request)}\\r\\n"
            f"\\r\\n"
        ).encode() + request
        
        self.sock.send(http_request)
        
        # Receive response
        response = self.sock.recv(4096)
        return response

    def close(self):
        """Close IPP connection"""
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

