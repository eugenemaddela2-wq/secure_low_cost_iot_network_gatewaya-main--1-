import json
import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
PORT = int(os.getenv("GATEWAY_PORT", "5000"))
CLOUD_ENDPOINT = os.getenv("CLOUD_ENDPOINT", "").strip()
CLOUD_TIMEOUT_SECONDS = int(os.getenv("CLOUD_TIMEOUT_SECONDS", "5"))
RETRY_INTERVAL_SECONDS = int(os.getenv("RETRY_INTERVAL_SECONDS", "15"))
MAX_RETRY_ATTEMPTS = int(os.getenv("MAX_RETRY_ATTEMPTS", "10"))
DB_PATH = os.getenv("DB_PATH", "data/gateway.db")
LOG_PATH = os.getenv("LOG_PATH", "logs/gateway.log")
BACKUP_DIR = os.getenv("BACKUP_DIR", "backups")
BACKUP_INTERVAL_SECONDS = int(os.getenv("BACKUP_INTERVAL_SECONDS", "86400"))

try:
    DEVICE_SECRETS = json.loads(os.getenv("DEVICE_SECRETS", "{}"))
except json.JSONDecodeError:
    DEVICE_SECRETS = {}

# Add to config.py
FIREWALL_ALLOWED_SUBNETS = [
    s.strip() for s in os.getenv("FIREWALL_ALLOWED_SUBNETS", "127.0.0.1/32,192.168.1.0/24").split(",") if s.strip()
]
FIREWALL_BLOCKED_IPS = [
    s.strip() for s in os.getenv("FIREWALL_BLOCKED_IPS", "").split(",") if s.strip()
]
FIREWALL_RATE_LIMIT = int(os.getenv("FIREWALL_RATE_LIMIT", "30"))
FIREWALL_RATE_WINDOW = int(os.getenv("FIREWALL_RATE_WINDOW", "10"))
FIREWALL_BAN_DURATION = int(os.getenv("FIREWALL_BAN_DURATION", "300"))
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "default-insecure-admin-key")
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "gateway-fallback-session-secret-key")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "choose-a-strong-admin-secret-password")