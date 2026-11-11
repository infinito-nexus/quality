import hashlib
import hmac
import ipaddress
import threading
import time
from collections import Counter


def client_address(header):
    """
    Args:
        header: Value of X-Real-IP as openresty sets it, or None.

    Returns:
        The address as text, an IPv6 address as its /64, or None when the header is missing or invalid.
    """
    try:
        address = ipaddress.ip_address((header or "").strip())
    except ValueError:
        return None
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(ipaddress.ip_network(f"{address}/64", strict=False))


class Limiter:
    def __init__(self, secret):
        self.secret = secret
        self.lock = threading.Lock()
        self.counts = Counter()

    def key(self, kind, identity, hour):
        day = time.strftime("%Y-%m-%d", time.gmtime(hour * 3600)).encode()
        daily = hmac.new(self.secret, day, hashlib.sha256).digest()
        return kind, hmac.new(daily, identity.encode(), hashlib.sha256).hexdigest(), hour

    def prune(self, hour):
        self.counts = Counter({key: count for key, count in self.counts.items() if key[2] == hour})

    def sweep(self):
        hour = int(time.time() // 3600)
        with self.lock:
            self.prune(hour)

    def allow(self, checks):
        """
        Args:
            checks: (kind, identity, limit) triples that must all stay under their hourly limit.

        Returns:
            True and counts the request in every bucket, or False and counts nothing.
        """
        hour = int(time.time() // 3600)
        with self.lock:
            self.prune(hour)
            keys = [(self.key(kind, identity, hour), limit) for kind, identity, limit in checks]
            if any(self.counts[key] >= limit for key, limit in keys):
                return False
            self.counts.update(key for key, _limit in keys)
            return True
