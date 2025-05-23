"""Coordinator for BMW."""

from __future__ import annotations

from datetime import timedelta
import logging

from bimmer_connected.account import MyBMWAccount
from bimmer_connected.api.regions import get_region_from_name
from bimmer_connected.models import (
    GPSPosition,
    MyBMWAPIError,
    MyBMWAuthError,
    MyBMWCaptchaMissingError,
)
from httpx import RequestError

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_REGION, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util.ssl import get_default_context

from .const import CONF_GCID, CONF_READ_ONLY, CONF_REFRESH_TOKEN, DOMAIN, SCAN_INTERVALS

_LOGGER = logging.getLogger(__name__)


type BMWConfigEntry = ConfigEntry[BMWDataUpdateCoordinator]


class BMWDataUpdateCoordinator(DataUpdateCoordinator[None]):
    """Class to manage fetching BMW data."""

    account: MyBMWAccount
    config_entry: BMWConfigEntry

    def __init__(self, hass: HomeAssistant, *, config_entry: BMWConfigEntry) -> None:
        """Initialize account-wide BMW data updater."""
        self.account = MyBMWAccount(
            config_entry.data[CONF_USERNAME],
            config_entry.data[CONF_PASSWORD],
            get_region_from_name(config_entry.data[CONF_REGION]),
            observer_position=GPSPosition(hass.config.latitude, hass.config.longitude),
            verify=get_default_context(),
        )
        self.read_only: bool = config_entry.options[CONF_READ_ONLY]

        if CONF_REFRESH_TOKEN in config_entry.data:
            self.account.set_refresh_token(
                refresh_token=config_entry.data[CONF_REFRESH_TOKEN],
                gcid=config_entry.data.get(CONF_GCID),
            )

        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=f"{DOMAIN}-{config_entry.data[CONF_USERNAME]}",
            update_interval=timedelta(
                seconds=SCAN_INTERVALS[config_entry.data[CONF_REGION]]
            ),
        )

        # Default to false on init so _async_update_data logic works
        self.last_update_success = False

    async def _async_update_data(self) -> None:
        """Fetch data from BMW."""
        old_refresh_token = self.account.refresh_token

        try:
            await self.account.get_vehicles()
        except MyBMWCaptchaMissingError as err:
            # If a captcha is required (user/password login flow), always trigger the reauth flow
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN,
                translation_key="missing_captcha",
            ) from err
        except MyBMWAuthError as err:
            # Allow one retry interval before raising AuthFailed to avoid flaky API issues
            if self.last_update_success:
                raise UpdateFailed(
                    translation_domain=DOMAIN,
                    translation_key="update_failed",
                    translation_placeholders={"exception": str(err)},
                ) from err
            # Clear refresh token and trigger reauth if previous update failed as well
            self._update_config_entry_refresh_token(None)
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN,
                translation_key="invalid_auth",
            ) from err
        except (MyBMWAPIError, RequestError) as err:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="update_failed",
                translation_placeholders={"exception": str(err)},
            ) from err

        if self.account.refresh_token != old_refresh_token:
            self._update_config_entry_refresh_token(self.account.refresh_token)

    def _update_config_entry_refresh_token(self, refresh_token: str | None) -> None:
        """Update or delete the refresh_token in the Config Entry."""
        data = {
            **self.config_entry.data,
            CONF_REFRESH_TOKEN: refresh_token,
        }
        if not refresh_token:
            data.pop(CONF_REFRESH_TOKEN)
        self.hass.config_entries.async_update_entry(self.config_entry, data=data)
