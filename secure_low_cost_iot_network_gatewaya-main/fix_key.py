import sqlite3
from datetime import datetime, timezone

conn = sqlite3.connect("data/gateway.db")
conn.execute("""
    INSERT INTO authorized_devices (device_id, secret_key, status, created_at, approved_at)
    VALUES ('CS-ESP32-001', 'change-this-shared-secret', 'approved', ?, ?)
    ON CONFLICT(device_id) DO UPDATE SET
        secret_key = 'change-this-shared-secret',
        status = 'approved',
        approved_at = excluded.approved_at
""", (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))

conn.commit()
conn.close()
print("Device CS-ESP32-001 successfully set to APPROVED with matching shared secret.")