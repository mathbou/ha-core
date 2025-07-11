"""Reolink additional services."""

from __future__ import annotations

from reolink_aio.api import Chime
from reolink_aio.enums import ChimeToneEnum
import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_DEVICE_ID
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN
from .host import ReolinkHost
from .util import get_device_uid_and_ch, raise_translated_error

ATTR_RINGTONE = "ringtone"


@raise_translated_error
async def _async_play_chime(service_call: ServiceCall) -> None:
    """Play a ringtone."""
    service_data = service_call.data
    device_registry = dr.async_get(service_call.hass)

    for device_id in service_data[ATTR_DEVICE_ID]:
        config_entry = None
        device = device_registry.async_get(device_id)
        if device is not None:
            for entry_id in device.config_entries:
                config_entry = service_call.hass.config_entries.async_get_entry(
                    entry_id
                )
                if config_entry is not None and config_entry.domain == DOMAIN:
                    break
        if (
            config_entry is None
            or device is None
            or config_entry.state != ConfigEntryState.LOADED
        ):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="service_entry_ex",
                translation_placeholders={"service_name": "play_chime"},
            )
        host: ReolinkHost = config_entry.runtime_data.host
        (device_uid, chime_id, is_chime) = get_device_uid_and_ch(device, host)
        chime: Chime | None = host.api.chime(chime_id)
        if not is_chime or chime is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="service_not_chime",
                translation_placeholders={"device_name": str(device.name)},
            )

        ringtone = service_data[ATTR_RINGTONE]
        await chime.play(ChimeToneEnum[ringtone].value)


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Set up Reolink services."""

    hass.services.async_register(
        DOMAIN,
        "play_chime",
        _async_play_chime,
        schema=vol.Schema(
            {
                vol.Required(ATTR_DEVICE_ID): list[str],
                vol.Required(ATTR_RINGTONE): vol.In(
                    [method.name for method in ChimeToneEnum][1:]
                ),
            }
        ),
    )
