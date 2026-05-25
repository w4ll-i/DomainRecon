# backend/app/routers/vpn.py
"""Mullvad VPN control endpoints."""

from fastapi import APIRouter

from ..schemas import VpnLocationRequest
from ..vpn_manager import (
    connect as vpn_connect,
    disconnect as vpn_disconnect,
    get_status as vpn_get_status,
    list_locations as vpn_list_locations,
    set_location as vpn_set_location,
)

router = APIRouter(prefix="/api/vpn", tags=["VPN"])


@router.get("/status")
async def vpn_status_endpoint():
    """Mullvad VPN status (only if Mullvad is installed)."""
    return await vpn_get_status()


@router.post("/connect")
async def vpn_connect_endpoint():
    return await vpn_connect()


@router.post("/disconnect")
async def vpn_disconnect_endpoint():
    return await vpn_disconnect()


@router.get("/locations")
async def vpn_locations_endpoint():
    """List available exit countries/cities."""
    return await vpn_list_locations()


@router.post("/location")
async def vpn_set_location_endpoint(request: VpnLocationRequest):
    """Set the VPN exit country/city."""
    return await vpn_set_location(request.code)
