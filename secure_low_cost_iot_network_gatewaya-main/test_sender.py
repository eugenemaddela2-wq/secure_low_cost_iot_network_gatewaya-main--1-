import hashlib
import hmac
import json
from datetime import datetime, timezone

import requests

GATEWAY_URL = "http://127.0.0.1:5000/api/data"
DEVICE_ID = "CS-ESP32-001"
SHARED_SECRET = "change-this-shared-secret"

payload = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "data": {
        "temperature": 30.2,
        "humidity": 71.5,
        "ammonia": 12.4,
        "thi": 78.1
    }
}

raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
signature = hmac.new(SHARED_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()

resp = requests.post(
    GATEWAY_URL,
    data=raw,
    headers={
        "Content-Type": "application/json",
        "X-Device-ID": DEVICE_ID,
        "X-Signature": signature,
    },
    timeout=10,
)

print(resp.status_code)
print(resp.json())
