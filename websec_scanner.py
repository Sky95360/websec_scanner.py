import socket
import requests
from datetime import datetime

print("="*50)
print(" Simple Website Security Scanner ")
print(" Author: YourName")
print("="*50)

target = input("Enter website (example.com): ").strip()
ip = socket.gethostbyname(target)

print(f"\nTarget IP: {ip}")
print(f"Scan started: {datetime.now()}\n")

# -------- PORT SCAN --------
print("[+] Scanning common ports...")
common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

open_ports = []
for port in common_ports:
    s = socket.socket()
    s.settimeout(0.5)
    result = s.connect_ex((ip, port))
    if result == 0:
        open_ports.append(port)
        print(f"  OPEN: Port {port}")
    s.close()

if not open_ports:
    print("  No common ports open")

# -------- HTTP HEADERS --------
print("\n[+] Checking HTTP security headers...")
try:
    r = requests.get("http://" + target, timeout=5)
    headers = r.headers

    security_headers = [
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]

    for h in security_headers:
        if h in headers:
            print(f"  {h}: PRESENT")
        else:
            print(f"  {h}: MISSING")

except:
    print("  Website not reachable")

# -------- REPORT --------
print("\n[+] Scan complete")
print(f"Finished at: {datetime.now()}")
print("="*50)
