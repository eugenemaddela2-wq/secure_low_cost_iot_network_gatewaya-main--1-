import time
import ipaddress
from collections import defaultdict
from flask import request, jsonify

class GatewayFirewall:
    def __init__(
        self,
        allowed_cidrs=None,
        blocked_ips=None,
        rate_limit_requests=30,
        rate_limit_window_seconds=10,
        ban_duration_seconds=300
    ):
        # Networks to allow (e.g., local farm subnet, loopback)
        self.allowed_cidrs = [
            ipaddress.ip_network(cidr) for cidr in (allowed_cidrs or ["127.0.0.1/32", "192.168.1.0/24"])
        ]
        # Permanently blocked individual IPs
        self.blocked_ips = set(blocked_ips or [])
        
        # Rate limiting configuration
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window_seconds
        self.ban_duration = ban_duration_seconds
        
        # Memory tracking
        self.request_history = defaultdict(list)
        self.banned_ips = {}  # {ip_str: ban_expiration_timestamp}

    def get_client_ip(self):
        """Extracts the real client IP address."""
        if request.headers.get("X-Forwarded-For"):
            ip_str = request.headers.get("X-Forwarded-For").split(",")[0].strip()
        else:
            ip_str = request.remote_addr or "127.0.0.1"
        return ip_str

    def is_ip_allowed(self, client_ip: str) -> bool:
        """Checks whether the IP belongs to authorized subnets."""
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            return any(ip_obj in network for network in self.allowed_cidrs)
        except ValueError:
            return False

    def inspect_request(self):
        """
        Main inspection routine executed before each request.
        Returns a tuple: (passed: bool, error_message: str, http_status: int)
        """
        client_ip = self.get_client_ip()
        now = time.time()

        # 1. Check permanent blocklist
        if client_ip in self.blocked_ips:
            return False, f"Firewall: IP {client_ip} is permanently blocked.", 403

        # 2. Check dynamic ban status
        if client_ip in self.banned_ips:
            if now < self.banned_ips[client_ip]:
                remaining = int(self.banned_ips[client_ip] - now)
                return False, f"Firewall: IP temporarily banned. Try again in {remaining}s.", 429
            else:
                del self.banned_ips[client_ip]

        # 3. Check IP subnet authorization
        if not self.is_ip_allowed(client_ip):
            return False, f"Firewall: IP {client_ip} unauthorized on this network.", 403

        # 4. Check Rate Limiting / Flooding
        timestamps = self.request_history[client_ip]
        # Keep only timestamps within sliding window
        self.request_history[client_ip] = [ts for ts in timestamps if now - ts < self.rate_limit_window]
        self.request_history[client_ip].append(now)

        if len(self.request_history[client_ip]) > self.rate_limit_requests:
            self.banned_ips[client_ip] = now + self.ban_duration
            return False, f"Firewall: Rate limit exceeded. Banned for {self.ban_duration}s.", 429

        return True, None, 200