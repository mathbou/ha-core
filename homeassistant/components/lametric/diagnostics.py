"""Diagnostics support for LaMetric."""

from __future__ import annotations

import json
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .coordinator import LaMetricConfigEntry

TO_REDACT = {
    "device_id",
    "name",
    "serial_number",
    "ssid",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: LaMetricConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data
    # Round-trip via JSON to trigger serialization
    data = json.loads(coordinator.data.to_json())
    return async_redact_data(data, TO_REDACT)
