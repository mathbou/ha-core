"""The Fjäråskupan data update coordinator."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, contextmanager
from datetime import timedelta
import logging

from fjaraskupan import (
    Device,
    FjaraskupanConnectionError,
    FjaraskupanError,
    FjaraskupanReadError,
    FjaraskupanWriteError,
    State,
)

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_address_present,
    async_ble_device_from_address,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN

type FjaraskupanConfigEntry = ConfigEntry[dict[str, FjaraskupanCoordinator]]

_LOGGER = logging.getLogger(__name__)


@contextmanager
def exception_converter():
    """Convert exception so home assistant translated ones."""

    try:
        yield
    except FjaraskupanWriteError as exception:
        raise HomeAssistantError(
            translation_domain=DOMAIN, translation_key="write_error"
        ) from exception
    except FjaraskupanReadError as exception:
        raise HomeAssistantError(
            translation_domain=DOMAIN, translation_key="read_error"
        ) from exception
    except FjaraskupanConnectionError as exception:
        raise HomeAssistantError(
            translation_domain=DOMAIN, translation_key="connection_error"
        ) from exception
    except FjaraskupanError as exception:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="unexpected_error",
            translation_placeholders={"msg": str(exception)},
        ) from exception


class UnableToConnect(HomeAssistantError):
    """Exception to indicate that we cannot connect to device."""


class FjaraskupanCoordinator(DataUpdateCoordinator[State]):
    """Update coordinator for each device."""

    config_entry: FjaraskupanConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: FjaraskupanConfigEntry,
        device: Device,
        device_info: DeviceInfo,
    ) -> None:
        """Initialize the coordinator."""
        self.device = device
        self.device_info = device_info
        self._refresh_was_scheduled = False

        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name="Fjäråskupan",
            update_interval=timedelta(seconds=120),
        )

    async def _async_refresh(
        self,
        log_failures: bool = True,
        raise_on_auth_failed: bool = False,
        scheduled: bool = False,
        raise_on_entry_error: bool = False,
    ) -> None:
        self._refresh_was_scheduled = scheduled
        await super()._async_refresh(
            log_failures=log_failures,
            raise_on_auth_failed=raise_on_auth_failed,
            scheduled=scheduled,
            raise_on_entry_error=raise_on_entry_error,
        )

    async def _async_update_data(self) -> State:
        """Handle an explicit update request."""
        if self._refresh_was_scheduled:
            if async_address_present(self.hass, self.device.address, False):
                return self.device.state
            raise UpdateFailed(
                "No data received within schedule, and device is no longer present"
            )

        if (
            ble_device := async_ble_device_from_address(
                self.hass, self.device.address, True
            )
        ) is None:
            raise UpdateFailed("No connectable path to device")

        with exception_converter():
            async with self.device.connect(ble_device) as device:
                await device.update()

        return self.device.state

    def detection_callback(self, service_info: BluetoothServiceInfoBleak) -> None:
        """Handle a new announcement of data."""
        self.device.detection_callback(service_info.device, service_info.advertisement)
        self.async_set_updated_data(self.device.state)

    @asynccontextmanager
    async def async_connect_and_update(self) -> AsyncIterator[Device]:
        """Provide an up-to-date device for use during connections."""
        if (
            ble_device := async_ble_device_from_address(
                self.hass, self.device.address, True
            )
        ) is None:
            raise UnableToConnect("No connectable path to device")

        with exception_converter():
            async with self.device.connect(ble_device) as device:
                yield device

        self.async_set_updated_data(self.device.state)
