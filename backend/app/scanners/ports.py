# backend/app/scanners/ports.py
import asyncio
from typing import Optional

from ._config import COMMON_PORTS

# Ports for which we send a service-specific probe to get a meaningful banner
_BANNER_PROBES: dict[int, bytes] = {
    21:    b"",                                 # FTP sends banner immediately
    22:    b"",                                 # SSH sends banner immediately
    23:    b"",                                 # Telnet sends banner immediately
    25:    b"EHLO recon\r\n",                   # SMTP
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",                                 # POP3 sends banner immediately
    143:   b"",                                 # IMAP sends banner immediately
    443:   b"HEAD / HTTP/1.0\r\n\r\n",
    3306:  b"",                                 # MySQL sends banner immediately
    5432:  b"",                                 # PostgreSQL - first bytes reveal version
    6379:  b"INFO server\r\n",                  # Redis
    8080:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",           # Elasticsearch
    27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
           b"\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00"
           b"\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61"
           b"\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00",  # MongoDB isMaster
}

# Service labels for risk assessment
_SERVICE_RISK: dict[int, tuple[str, str]] = {
    21:    ("FTP",           "medium"),
    22:    ("SSH",           "info"),
    23:    ("Telnet",        "critical"),
    25:    ("SMTP",          "info"),
    80:    ("HTTP",          "info"),
    110:   ("POP3",          "info"),
    143:   ("IMAP",          "info"),
    443:   ("HTTPS",         "info"),
    445:   ("SMB",           "high"),
    465:   ("SMTPS",         "info"),
    587:   ("SMTP/TLS",      "info"),
    993:   ("IMAPS",         "info"),
    995:   ("POP3S",         "info"),
    1433:  ("MSSQL",         "high"),
    1521:  ("Oracle DB",     "high"),
    2375:  ("Docker API",    "critical"),
    2376:  ("Docker TLS",    "medium"),
    3000:  ("Node/Grafana",  "medium"),
    3001:  ("Node.js",       "medium"),
    3306:  ("MySQL",         "high"),
    3389:  ("RDP",           "high"),
    4848:  ("GlassFish",     "high"),
    5000:  ("Flask/Docker",  "medium"),
    5001:  ("Docker reg",    "medium"),
    5432:  ("PostgreSQL",    "high"),
    5900:  ("VNC",           "critical"),
    6379:  ("Redis",         "critical"),
    6380:  ("Redis TLS",     "medium"),
    7001:  ("WebLogic",      "critical"),
    8000:  ("HTTP-alt",      "info"),
    8001:  ("HTTP-alt",      "info"),
    8080:  ("HTTP-Proxy",    "info"),
    8081:  ("HTTP-alt",      "info"),
    8443:  ("HTTPS-Alt",     "info"),
    8500:  ("Consul",        "high"),
    8888:  ("HTTP-Alt",      "info"),
    9000:  ("PHP-FPM",       "high"),
    9200:  ("Elasticsearch", "critical"),
    9300:  ("ES-cluster",    "high"),
    11211: ("Memcached",     "critical"),
    27017: ("MongoDB",       "critical"),
    27018: ("MongoDB",       "high"),
    50000: ("SAP/Jenkins",   "high"),
}


async def _check_port(ip: str, port: int) -> Optional[int]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2
        )
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def scan_ports(ip: str) -> dict:
    tasks = [_check_port(ip, p) for p in COMMON_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    open_ports = [p for p in results if isinstance(p, int)]
    # Annotate each port with service + risk level
    annotated = [
        {
            "port": p,
            "service": _SERVICE_RISK.get(p, ("unknown", "info"))[0],
            "risk": _SERVICE_RISK.get(p, ("unknown", "info"))[1],
        }
        for p in open_ports
    ]
    return {"open_ports": open_ports, "ports_detail": annotated, "count": len(open_ports)}


async def grab_banners(ip: str, open_ports: list) -> dict:
    banners = {}

    async def grab_one(port: int):
        probe = _BANNER_PROBES.get(port)
        if probe is None:
            return port, None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=4
            )
            if probe:
                writer.write(probe)
                await writer.drain()
            await asyncio.sleep(0.5)
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = data.decode(errors="ignore").strip()[:300]
            return port, banner if banner else None
        except Exception:
            return port, None

    tasks = [grab_one(p) for p in open_ports if p in _BANNER_PROBES]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for item in results:
        if isinstance(item, tuple):
            port, banner = item
            if banner:
                banners[str(port)] = banner
    return {"banners": banners}
