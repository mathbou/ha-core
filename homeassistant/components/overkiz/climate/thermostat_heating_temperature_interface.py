"""Support for Somfy Smart Thermostat."""

from __future__ import annotations

from typing import Any, cast

from pyoverkiz.enums import OverkizCommand, OverkizCommandParam, OverkizState

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
    HVACAction
)
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature

from ..const import DOMAIN
from ..coordinator import OverkizDataUpdateCoordinator
from ..entity import OverkizEntity

# controllableName is somfythermostat:SomfyThermostatTemperatureSensor
TEMPERATURE_SENSOR_DEVICE_INDEX = 2


class ThermostatHeatingTemperatureInterface(OverkizEntity, ClimateEntity):
    """Representation of Somfy Smart Thermostat."""

    _attr_hvac_mode = HVACMode.HEAT
    _attr_hvac_modes = [HVACMode.HEAT]
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_translation_key = DOMAIN

    # Both min and max temp values have been retrieved from the Somfy Application.
    _attr_min_temp = 5.0
    _attr_max_temp = 26.0

    def __init__(
        self, device_url: str, coordinator: OverkizDataUpdateCoordinator
    ) -> None:
        """Init method."""
        super().__init__(device_url, coordinator)
        self.temperature_device = self.executor.linked_device(
            TEMPERATURE_SENSOR_DEVICE_INDEX
        )

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        if self.temperature_device is not None and (
            temperature := self.temperature_device.states[OverkizState.CORE_TEMPERATURE]
        ):
            return cast(float, temperature.value)
        return None

    @property
    def target_temperature(self) -> float | None:
        """Return the temperature we try to reach."""
        return cast(
            float,
            self.executor.select_state(OverkizState.CORE_TARGET_TEMPERATURE),
        )

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set new target temperature."""
        temperature = kwargs[ATTR_TEMPERATURE]

        await self.executor.async_execute_command(
            OverkizCommand.SET_DEROGATION,
            temperature,
            OverkizCommandParam.FURTHER_NOTICE,
        )

    @property
    def hvac_action(self) -> HVACAction | None:
        """Return the current running hvac operation if supported."""
        return HVACAction.HEATING if self.target_temperature > self.current_temperature else HVACAction.IDLE

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new target hvac mode."""
        return
