"""
IP enrichment for log-analyzer: threat-intelligence reputation + GeoIP country.

Threat intel is a local list of known-bad CIDRs (offline, no API key needed).
GeoIP uses MaxMind GeoLite2 *if* the geoip2 package and a DB file are available;
otherwise country resolves to "Unknown" and everything degrades gracefully.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path

try:
    import geoip2.database  # type: ignore
    _GEOIP_LIB = True
except ImportError:  # pragma: no cover - optional dependency
    _GEOIP_LIB = False

_DEFAULT_TI_FILE = Path(__file__).parent / "threat_intel.txt"


__all__ = ["load_threat_intel", "is_known_bad", "GeoIP", "enrich_incidents"]


def load_threat_intel(path: str | os.PathLike | None = None) -> list:
    """Load known-bad CIDRs from a file (one CIDR/IP per line, '#' comments)."""
    p = Path(path) if path else _DEFAULT_TI_FILE
    networks = []
    if not p.exists():
        return networks
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return networks


def is_known_bad(ip: str, networks: list) -> bool:
    """True if ip falls inside any known-bad network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


class GeoIP:
    """Thin optional wrapper around MaxMind GeoLite2-Country.

    Set GEOIP_DB_PATH to a .mmdb file to enable. Without it, lookups return
    "Unknown" so the rest of the pipeline keeps working offline.
    """

    def __init__(self, db_path: str | None = None):
        self._reader = None
        db_path = db_path or os.environ.get("GEOIP_DB_PATH")
        if _GEOIP_LIB and db_path and Path(db_path).exists():
            try:
                self._reader = geoip2.database.Reader(db_path)
            except Exception:
                self._reader = None

    @property
    def enabled(self) -> bool:
        return self._reader is not None

    def country(self, ip: str) -> str:
        if self._reader is None:
            return "Unknown"
        try:
            return self._reader.country(ip).country.iso_code or "Unknown"
        except Exception:
            return "Unknown"

    def close(self):
        if self._reader is not None:
            self._reader.close()


def enrich_incidents(incidents: list[dict], networks: list, geo: GeoIP | None = None) -> list[dict]:
    """Attach 'country' and 'known_bad' to each incident in-place."""
    for inc in incidents:
        ip = inc.get("source_ip")
        inc["known_bad"] = bool(ip) and is_known_bad(ip, networks)
        inc["country"] = geo.country(ip) if (geo and ip) else "Unknown"
    return incidents
