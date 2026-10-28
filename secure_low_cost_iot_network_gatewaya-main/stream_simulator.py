import hashlib
import hmac
import json
import random
import time
from datetime import datetime, timezone
import requests

GATEWAY_URL = "http://127.0.0.1:5000/api/data"
DEVICE_ID = "CS-ESP32-001"
SHARED_SECRET = "change-this-shared-secret"

# Initial starting baselines for a poultry house
temp = 24.5
humidity = 62.0
ammonia = 12.0

print(f"🚀 Starting continuous IoT telemetry generator for [{DEVICE_ID}]...")
print(f"Targeting: {GATEWAY_URL}")
print("Press Ctrl + C to stop the simulation.\n")

counter = 1

while True:
    try:
        # 1. Simulate realistic fluctuations (gentle drift with slight randomness)
        temp += random.uniform(-0.4, 0.4)
        humidity += random.uniform(-0.8, 0.8)
        ammonia += random.uniform(-0.3, 0.3)

        # Keep values clamped within realistic poultry farm conditions
        temp = max(18.0, min(35.0, temp))
        humidity = max(40.0, min(85.0, humidity))
        ammonia = max(5.0, min(32.0, ammonia))

        # Temperature-Humidity Index (THI) calculation
        thi = (0.8 * temp) + ((humidity / 100.0) * (temp - 14.4)) + 46.4

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "temperature": round(temp, 1),
                "humidity": round(humidity, 1),
                "ammonia": round(ammonia, 1),
                "thi": round(thi, 1)
            }
        }

        # 2. HMAC-SHA256 Signing
        raw_body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = hmac.new(SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Device-ID": DEVICE_ID,
            "X-Signature": signature,
        }

        # 3. Post to Gateway
        start_t = time.perf_counter()
        resp = requests.post(GATEWAY_URL, data=raw_body, headers=headers, timeout=5)
        duration_ms = (time.perf_counter() - start_t) * 1000

        if resp.status_code in [200, 202]:
            res_data = resp.json()
            status_text = res_data.get("status", "accepted")
            print(f"[{counter:03d}] Sent: Temp={temp:.1f}°C | Hum={humidity:.1f}% | NH3={ammonia:.1f}ppm | Status={status_text} ({duration_ms:.1f}ms)")
        else:
            print(f"[{counter:03d}] Server response {resp.status_code}: {resp.text}")

        counter += 1

    except requests.exceptions.ConnectionError:
        print("⚠️ Waiting for gateway server to start on http://127.0.0.1:5000 ...")
    except Exception as exc:
        print(f"Error: {exc}")

    # Delay between telemetry packets (3 seconds)
    time.sleep(3)