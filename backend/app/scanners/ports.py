# backend/app/scanners/ports.py
import asyncio
from typing import Optional

from ._config import COMMON_PORTS

BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 8080}


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
    return {"open_ports": open_ports, "count": len(open_ports)}


async def grab_banners(ip: str, open_ports: list) -> dict:
    banners = {}

    async def grab_one(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3
            )
            if port == 80:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            await asyncio.sleep(0.3)
            data = await asyncio.wait_for(reader.read(512), timeout=2)
            writer.close()
            await writer.wait_closed()
            return port, data.decode(errors="ignore").strip()[:200]
        except Exception:
            return port, None

    tasks = [grab_one(p) for p in open_ports if p in BANNER_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for item in results:
        if isinstance(item, tuple):
            port, banner = item
            if banner:
                banners[str(port)] = banner
    return {"banners": banners}
