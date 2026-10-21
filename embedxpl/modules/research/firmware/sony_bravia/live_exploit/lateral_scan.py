#!/usr/bin/env python3
"""
Fast parallel LAN sweep for IoT targets on 192.168.18.0/24.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os, sys, tempfile, socket, threading, json, datetime, re
from queue import Queue
import requests

_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "..", "..", "..", ".tmp")
os.makedirs(_tmp, exist_ok=True)
tempfile.tempdir = _tmp

SUBNET   = "192.168.18"
MY_IPS   = {"192.168.18.6", "192.168.18.147"}
PORTS    = [80, 443, 8080, 23, 2869, 2870, 5000, 8008, 8443, 56789]
WORKERS  = 100
TIMEOUT  = 0.4

results_lock = threading.Lock()
found = {}  # ip -> [port]


def check_host_port(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        s.close()
        with results_lock:
            if ip not in found:
                found[ip] = []
                print(f"  [+] {ip} open:{port}", flush=True)
            elif port not in found[ip]:
                print(f"      {ip}:{port}", flush=True)
            found[ip].append(port)
    except Exception:
        pass


def worker(q):
    while True:
        item = q.get()
        if item is None:
            break
        check_host_port(*item)
        q.task_done()


def banner_grab(ip, ports):
    banners = {}
    for port in ports:
        try:
            r = requests.get(f"http://{ip}:{port}/", timeout=2, allow_redirects=False)
            title = ""
            m = re.search(r"<title[^>]*>([^<]{1,80})</title>", r.text, re.I)
            if m:
                title = m.group(1).strip()
            banners[port] = {
                "status": r.status_code,
                "server": r.headers.get("Server", ""),
                "title": title,
                "content_snippet": r.text[:200],
            }
        except Exception as e:
            banners[port] = {"error": str(e)[:80]}
    return banners


def main():
    print(f"[*] Sweeping {SUBNET}.1-254  ports={PORTS}  workers={WORKERS}")
    q = Queue()
    threads = []
    for _ in range(WORKERS):
        t = threading.Thread(target=worker, args=(q,), daemon=True)
        t.start()
        threads.append(t)

    for last in range(1, 255):
        ip = f"{SUBNET}.{last}"
        if ip in MY_IPS:
            continue
        for port in PORTS:
            q.put((ip, port))

    q.join()
    for _ in threads:
        q.put(None)

    print(f"\n[*] Sweep complete. Found {len(found)} live hosts.")

    enriched = {}
    for ip, ports in sorted(found.items()):
        print(f"\n  Enriching {ip} ports={ports}...")
        http_ports = [p for p in ports if p not in (23,)]
        enriched[ip] = {
            "open_ports": ports,
            "banners": banner_grab(ip, http_ports),
        }
        for p, b in enriched[ip]["banners"].items():
            if "error" not in b:
                print(f"    :{p} [{b['status']}] server={b['server']!r} title={b['title']!r}")

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "subnet": f"{SUBNET}.0/24",
        "hosts_found": len(enriched),
        "hosts": enriched,
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lateral_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Lateral evidence -> {out}")


if __name__ == "__main__":
    main()
