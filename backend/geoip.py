"""GeoIP enrichment for security events.

Resolution order for an IP address (first match wins):
  1. placeholder  - the simulator's RFC 5737 documentation IPs get an explicit, flagged placeholder city
  2. documentation / multicast / unspecified ranges -> unresolvable (None)
  3. private, loopback, link-local, CGNAT          -> the configured internal "lab network" location
  4. MaxMind GeoLite2 / GeoIP2 City database       -> real approximate location

The result is a small dict stored on event.geo:
  {city, country, country_code, lat, lon, accuracy_km, internal, simulated, source, role}
  source is "geoip" | "internal" | "simulated"; None means "could not be located".

Configuration (environment variables, all optional):
  GEOIP_DB_PATH   path to a .mmdb City database (default: backend/data/GeoLite2-City.mmdb)
  HQ_NAME / HQ_LAT / HQ_LON   where internal (private-IP) activity is drawn on the map
                              (default: Manila, Philippines  14.5995, 120.9842)
"""
import ipaddress
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

try:
    import maxminddb  # MaxMind's official reader (pip install maxminddb)
except ImportError:  # the app keeps working, just without real lookups
    maxminddb = None

DEFAULT_DB = Path(__file__).parent / "data" / "GeoLite2-City.mmdb"
ATTRIBUTION = ("This product includes GeoLite2 data created by MaxMind, "
               "available from https://www.maxmind.com")
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_MISSING = object()
DEFAULT_HQ = {"city": "Lab network (internal)", "lat": 14.5995, "lon": 120.9842}  # Manila, Philippines


def _env_coord(name, default, limit):
    """Read a coordinate from the environment; a typo or out-of-range value falls back instead of crashing startup."""
    try:
        value = float(os.getenv(name, default))
    except ValueError:
        return default
    return value if -limit <= value <= limit else default


class GeoIPService:
    def __init__(self, db_path=None, placeholder=None):
        self.db_path = Path(db_path or os.getenv("GEOIP_DB_PATH") or DEFAULT_DB)
        self.placeholder = placeholder            # callable(ip) -> geo dict | None
        # Where internal (private-IP) activity is drawn. Defaults to Metro Manila, Philippines.
        self.hq = {"city": os.getenv("HQ_NAME", DEFAULT_HQ["city"]),
                   "lat": _env_coord("HQ_LAT", DEFAULT_HQ["lat"], 90), "lon": _env_coord("HQ_LON", DEFAULT_HQ["lon"], 180)}
        self._reader, self._error = None, None
        self._cache, self._lock = {}, threading.Lock()
        self._open()

    # ---- database -----------------------------------------------------------
    def _open(self):
        if maxminddb is None:
            self._error = "The 'maxminddb' package is not installed (pip install maxminddb)."
        elif not self.db_path.is_file():
            self._error = f"Database not found at {self.db_path}."
        else:
            try:
                self._reader = maxminddb.open_database(str(self.db_path))
            except Exception as exc:  # corrupt / wrong file type
                self._error = f"Could not open database: {exc}"

    def close(self):
        if self._reader:
            self._reader.close()
            self._reader = None

    def status(self):
        info = {"enabled": self._reader is not None, "provider": "MaxMind", "path": str(self.db_path), "error": self._error, "hq": dict(self.hq)}
        if self._reader:
            meta = self._reader.metadata()
            info.update(database_type=meta.database_type,
                        build_date=datetime.fromtimestamp(meta.build_epoch, tz=timezone.utc).isoformat(),
                        attribution=ATTRIBUTION)
        return info

    # ---- lookup -------------------------------------------------------------
    def lookup(self, ip):
        """Return a geo dict, or None if the address is invalid or cannot be located. Never raises."""
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        key = str(addr)
        with self._lock:
            geo = self._cache.get(key, _MISSING)
        if geo is _MISSING:
            geo = self._resolve(addr, key)
            with self._lock:
                if len(self._cache) > 10000:
                    self._cache.clear()
                self._cache[key] = geo
        return dict(geo) if geo else None

    def _resolve(self, addr, key):
        if self.placeholder:
            geo = self.placeholder(key)
            if geo:
                return geo
        if any(addr in net for net in _DOC_NETS) or addr.is_multicast or addr.is_unspecified:
            return None
        if not addr.is_global:
            return {"city": self.hq["city"], "country": None, "country_code": None, "lat": self.hq["lat"],
                    "lon": self.hq["lon"], "accuracy_km": None, "internal": True, "simulated": False, "source": "internal"}
        return self._maxmind(key)

    def _maxmind(self, key):
        if not self._reader:
            return None
        try:
            rec = self._reader.get(key)
        except Exception:
            return None
        if not rec:
            return None
        loc = rec.get("location") or {}
        if loc.get("latitude") is None or loc.get("longitude") is None:
            return None
        country = rec.get("country") or rec.get("registered_country") or {}
        city = ((rec.get("city") or {}).get("names") or {}).get("en")
        cname = (country.get("names") or {}).get("en")
        return {"city": city or cname or country.get("iso_code") or "Unknown", "country": cname,
                "country_code": country.get("iso_code"), "lat": loc["latitude"], "lon": loc["longitude"],
                "accuracy_km": loc.get("accuracy_radius"), "internal": False, "simulated": False, "source": "geoip"}

    # ---- enrichment ---------------------------------------------------------
    def enrich(self, event):
        """Attach event.geo for the remote party: the destination for outbound traffic, otherwise the source."""
        outbound = event.event_type == "outbound_connection_suspicious"
        geo = self.lookup(event.destination_ip if outbound else event.source_ip)
        if geo:
            geo["role"] = "destination" if outbound else "source"
        event.geo = geo
        return event