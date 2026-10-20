#!/usr/bin/env python3
"""
Payloads Package for PrinterXPL-Forge
=========================================
Pre-built attack payloads for PostScript and PJL

Payloads include:
- banner.ps - Print custom banner
- loop.ps - Infinite loop (DoS)
- erase.ps - Erase page
- storm.ps - Print storm attack
- exfil.ps - Data exfiltration template
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

__all__ = ['execute_payload', 'list_payloads', 'load_payload']

import os
import re

# Payload directory
PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

def list_payloads():
    """List all available payloads"""
    payloads = []
    for file in os.listdir(PAYLOAD_DIR):
        if file.endswith('.ps') or file.endswith('.pjl') or file.endswith('.pcl'):
            payloads.append(file)
    return sorted(payloads)

def load_payload(payload_name, substitutions=None):
    """
    Load payload from file and substitute variables
    
    Args:
        payload_name: Name of payload file (e.g., 'banner.ps')
        substitutions: Dict of {variable: value} to substitute
    
    Returns:
        Payload content with substitutions applied
    
    Example:
        payload = load_payload('banner.ps', {'msg': 'HACKED!'})
    """
    payload_path = os.path.join(PAYLOAD_DIR, payload_name)
    
    if not os.path.exists(payload_path):
        raise FileNotFoundError(f"Payload not found: {payload_name}")
    
    with open(payload_path, encoding='utf-8') as f:
        content = f.read()
    
    # Apply substitutions if provided
    if substitutions:
        # Find all {{variable}} patterns
        placeholders = re.findall(r'\\{\\{(.*?)\\}\\}', content)
        
        # Check for missing substitutions
        missing = [p for p in placeholders if p not in substitutions]
        if missing:
            raise ValueError(f"Missing substitutions: {', '.join(missing)}")
        
        # Apply substitutions
        for key, value in substitutions.items():
            content = content.replace(f'{{{{{key}}}}}', str(value))
    
    return content

def execute_payload(printer_conn, payload_name, substitutions=None):
    """
    Execute payload on printer
    
    Args:
        printer_conn: Active printer connection
        payload_name: Name of payload file
        substitutions: Dict of variables to substitute
    
    Returns:
        Response from printer
    """
    payload = load_payload(payload_name, substitutions)
    
    # Send payload
    printer_conn.send(payload.encode())
    
    # Receive response (with timeout)
    try:
        response = printer_conn.recv(4096)
        return response.decode('latin-1', errors='ignore')
    except:
        return ""

