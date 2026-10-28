import time
import requests
import hmac
import hashlib
import json

TARGET_URL = "http://127.0.0.1:5000"
DATA_URL = f"{TARGET_URL}/api/data"

print("==========================================================")
print("  POULTRYVANTAGE CUSTOMIZED FIREWALL PENETRATION TEST")
print("==========================================================")

tests_run = 0
tests_passed = 0

def log_result(name, passed, detail=""):
    global tests_run, tests_passed
    tests_run += 1
    if passed:
        tests_passed += 1
        print(f"[PASS] {name} - {detail}")
    else:
        print(f"[FAIL] {name} - {detail}")

# Test 1: Forged HMAC Signature (Integrity Attack)
payload = {"timestamp": "2026-10-12T10:00:00Z", "data": {"temperature": 99.9}}
headers = {
    "Content-Type": "application/json",
    "X-Device-ID": "CS-ESP32-001",
    "X-Signature": "invalid_forged_signature_hash_000000"
}
t0 = time.perf_counter()
r1 = requests.post(DATA_URL, json=payload, headers=headers)
d1 = (time.perf_counter() - t0) * 1000
log_result("HMAC Forgery Attack", r1.status_code == 401, f"Status: {r1.status_code} in {d1:.2f}ms")

# Test 2: Spoofed / Unregistered Device ID
headers = {
    "Content-Type": "application/json",
    "X-Device-ID": "ATTACKER-NODE-999",
    "X-Signature": "random_signature"
}
t0 = time.perf_counter()
r2 = requests.post(DATA_URL, json=payload, headers=headers)
d2 = (time.perf_counter() - t0) * 1000
log_result("Unauthorized Device ID", r2.status_code == 403, f"Status: {r2.status_code} in {d2:.2f}ms")

# Test 3: Admin Endpoint Brute Force / Unauthorized Access
r3 = requests.get(f"{TARGET_URL}/api/admin/devices", headers={"X-Admin-Key": "wrong_key"})
log_result("Admin Auth Breach Attempt", r3.status_code == 401, f"Status: {r3.status_code}")

# Test 4: DoS Rate-Limiting Flood Test (Flooding > 30 req / 10 sec)
print("\nExecuting DoS Rate-Limiting Flood (40 rapid requests)...")
blocked = 0
start_flood = time.perf_counter()
for i in range(40):
    res = requests.get(f"{TARGET_URL}/approval")
    if res.status_code in [403, 429]:
        blocked += 1
flood_dur = (time.perf_counter() - start_flood) * 1000
log_result("DoS Flooding Mitigation", blocked > 0, f"Dropped/Banned {blocked}/40 requests in {flood_dur:.2f}ms")

# Calculate Failure Rate
failure_rate = ((tests_run - tests_passed) / tests_run) * 100
print("==========================================================")
print(f"Total Tests Run: {tests_run}")
print(f"Firewall Defense Success Rate: {(tests_passed / tests_run) * 100:.2f}%")
print(f"Firewall Failure Rate: {failure_rate:.2f}%")
print("==========================================================")