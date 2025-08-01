"""The tests for the Template Binary sensor platform."""

from collections.abc import Generator
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import logging
from unittest.mock import Mock, patch

from freezegun.api import FrozenDateTimeFactory
import pytest
from syrupy.assertion import SnapshotAssertion

from homeassistant import setup
from homeassistant.components import binary_sensor, template
from homeassistant.const import (
    ATTR_DEVICE_CLASS,
    EVENT_HOMEASSISTANT_START,
    STATE_OFF,
    STATE_ON,
    STATE_UNAVAILABLE,
    STATE_UNKNOWN,
)
from homeassistant.core import Context, CoreState, HomeAssistant, State
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_component import async_update_entity
from homeassistant.helpers.typing import ConfigType
from homeassistant.setup import async_setup_component

from tests.common import (
    MockConfigEntry,
    assert_setup_component,
    async_fire_time_changed,
    mock_restore_cache,
    mock_restore_cache_with_extra_data,
)

_BEER_TRIGGER_VALUE_TEMPLATE = (
    "{% if trigger.event.data.beer < 0 %}"
    "{{ 1 / 0 == 10 }}"
    "{% elif trigger.event.data.beer == 0 %}"
    "{{ None }}"
    "{% else %}"
    "{{ trigger.event.data.beer == 2 }}"
    "{% endif %}"
)


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id", "name", "attributes"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test": {
                            "value_template": "{{ True }}",
                        }
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test",
            "test",
            {"friendly_name": "test"},
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "state": "{{ True }}",
                    }
                },
            },
            template.DOMAIN,
            "binary_sensor.unnamed_device",
            "unnamed device",
            {},
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_setup_minimal(
    hass: HomeAssistant, entity_id: str, name: str, attributes: dict[str, str]
) -> None:
    """Test the setup."""
    state = hass.states.get(entity_id)
    assert state is not None
    assert state.name == name
    assert state.state == STATE_ON
    assert state.attributes == attributes


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ True }}",
                            "device_class": "motion",
                        }
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "name": "virtual thingy",
                        "state": "{{ True }}",
                        "device_class": "motion",
                    }
                },
            },
            template.DOMAIN,
            "binary_sensor.virtual_thingy",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_setup(hass: HomeAssistant, entity_id: str) -> None:
    """Test the setup."""
    state = hass.states.get(entity_id)
    assert state is not None
    assert state.name == "virtual thingy"
    assert state.state == STATE_ON
    assert state.attributes["device_class"] == "motion"


@pytest.mark.parametrize(
    "config_entry_extra_options",
    [
        {},
        {"device_class": "battery"},
    ],
)
async def test_setup_config_entry(
    hass: HomeAssistant,
    snapshot: SnapshotAssertion,
    config_entry_extra_options: dict[str, str],
) -> None:
    """Test the config flow."""
    state_template = (
        "{{ states('binary_sensor.one') == 'on' or "
        "   states('binary_sensor.two') == 'on' }}"
    )
    input_entities = ["one", "two"]
    input_states = {"one": "on", "two": "off"}
    template_type = binary_sensor.DOMAIN

    for input_entity in input_entities:
        hass.states.async_set(
            f"{template_type}.{input_entity}",
            input_states[input_entity],
            {},
        )

    template_config_entry = MockConfigEntry(
        data={},
        domain=template.DOMAIN,
        options={
            "name": "My template",
            "state": state_template,
            "template_type": template_type,
        }
        | config_entry_extra_options,
        title="My template",
    )
    template_config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(template_config_entry.entry_id)
    await hass.async_block_till_done()

    state = hass.states.get(f"{template_type}.my_template")
    assert state is not None
    assert state == snapshot


@pytest.mark.parametrize("count", [0])
@pytest.mark.parametrize(
    ("config", "domain"),
    [
        # No legacy binary sensors
        (
            {"binary_sensor": {"platform": "template"}},
            binary_sensor.DOMAIN,
        ),
        # Legacy binary sensor missing mandatory config
        (
            {"binary_sensor": {"platform": "template", "sensors": {"foo bar": {}}}},
            binary_sensor.DOMAIN,
        ),
        # Binary sensor missing mandatory config
        (
            {"template": {"binary_sensor": {}}},
            template.DOMAIN,
        ),
        # Legacy binary sensor with invalid device class
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test": {
                            "value_template": "{{ foo }}",
                            "device_class": "foobarnotreal",
                        }
                    },
                }
            },
            binary_sensor.DOMAIN,
        ),
        # Binary sensor with invalid device class
        (
            {
                "template": {
                    "binary_sensor": {
                        "state": "{{ foo }}",
                        "device_class": "foobarnotreal",
                    }
                }
            },
            template.DOMAIN,
        ),
        # Legacy binary sensor missing mandatory config
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {"test": {"device_class": "motion"}},
                }
            },
            binary_sensor.DOMAIN,
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_setup_invalid_sensors(hass: HomeAssistant, count: int) -> None:
    """Test setup with no sensors."""
    assert len(hass.states.async_entity_ids("binary_sensor")) == count


@pytest.mark.parametrize(
    ("state_template", "expected_result"),
    [
        ("{{ None }}", STATE_OFF),
        ("{{ True }}", STATE_ON),
        ("{{ False }}", STATE_OFF),
        ("{{ 1 }}", STATE_ON),
        (
            "{% if states('binary_sensor.three') in ('unknown','unavailable') %}"
            "{{ None }}"
            "{% else %}"
            "{{ states('binary_sensor.three') == 'off' }}"
            "{% endif %}",
            STATE_OFF,
        ),
        ("{{ 1 / 0 == 10 }}", STATE_UNAVAILABLE),
    ],
)
async def test_state(
    hass: HomeAssistant,
    state_template: str,
    expected_result: str,
) -> None:
    """Test the config flow."""
    hass.states.async_set("binary_sensor.one", "on")
    hass.states.async_set("binary_sensor.two", "off")
    hass.states.async_set("binary_sensor.three", "unknown")

    template_config_entry = MockConfigEntry(
        data={},
        domain=template.DOMAIN,
        options={
            "name": "My template",
            "state": state_template,
            "template_type": binary_sensor.DOMAIN,
        },
        title="My template",
    )
    template_config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(template_config_entry.entry_id)
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.my_template")
    assert state is not None
    assert state.state == expected_result


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test_template_sensor": {
                            "value_template": "{{ states.sensor.xyz.state }}",
                            "icon_template": "{% if "
                            "states.binary_sensor.test_state.state == "
                            "'on' %}"
                            "mdi:check"
                            "{% endif %}",
                        },
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test_template_sensor",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "state": "{{ states.sensor.xyz.state }}",
                        "icon": "{% if "
                        "states.binary_sensor.test_state.state == "
                        "'on' %}"
                        "mdi:check"
                        "{% endif %}",
                    },
                },
            },
            template.DOMAIN,
            "binary_sensor.unnamed_device",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_icon_template(hass: HomeAssistant, entity_id: str) -> None:
    """Test icon template."""
    state = hass.states.get(entity_id)
    assert state.attributes.get("icon") == ""

    hass.states.async_set("binary_sensor.test_state", STATE_ON)
    await hass.async_block_till_done()
    state = hass.states.get(entity_id)
    assert state.attributes["icon"] == "mdi:check"


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test_template_sensor": {
                            "value_template": "{{ states.sensor.xyz.state }}",
                            "entity_picture_template": "{% if "
                            "states.binary_sensor.test_state.state == "
                            "'on' %}"
                            "/local/sensor.png"
                            "{% endif %}",
                        },
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test_template_sensor",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "state": "{{ states.sensor.xyz.state }}",
                        "picture": "{% if "
                        "states.binary_sensor.test_state.state == "
                        "'on' %}"
                        "/local/sensor.png"
                        "{% endif %}",
                    },
                },
            },
            template.DOMAIN,
            "binary_sensor.unnamed_device",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_entity_picture_template(hass: HomeAssistant, entity_id: str) -> None:
    """Test entity_picture template."""
    state = hass.states.get(entity_id)
    assert state.attributes.get("entity_picture") == ""

    hass.states.async_set("binary_sensor.test_state", STATE_ON)
    await hass.async_block_till_done()
    state = hass.states.get(entity_id)
    assert state.attributes["entity_picture"] == "/local/sensor.png"


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test_template_sensor": {
                            "value_template": "{{ states.sensor.xyz.state }}",
                            "attribute_templates": {
                                "test_attribute": "It {{ states.sensor.test_state.state }}."
                            },
                        },
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test_template_sensor",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "state": "{{ states.sensor.xyz.state }}",
                        "attributes": {
                            "test_attribute": "It {{ states.sensor.test_state.state }}."
                        },
                    },
                },
            },
            template.DOMAIN,
            "binary_sensor.unnamed_device",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_attribute_templates(hass: HomeAssistant, entity_id: str) -> None:
    """Test attribute_templates template."""
    state = hass.states.get(entity_id)
    assert state.attributes.get("test_attribute") == "It ."
    hass.states.async_set("sensor.test_state", "Works2")
    await hass.async_block_till_done()
    hass.states.async_set("sensor.test_state", "Works")
    await hass.async_block_till_done()
    state = hass.states.get(entity_id)
    assert state.attributes["test_attribute"] == "It Works."


@pytest.fixture
def setup_mock() -> Generator[Mock]:
    """Do setup of sensor mock."""
    with patch(
        "homeassistant.components.template.binary_sensor."
        "BinarySensorTemplate._update_state"
    ) as _update_state:
        yield _update_state


@pytest.mark.parametrize(("count", "domain"), [(1, binary_sensor.DOMAIN)])
@pytest.mark.parametrize(
    "config",
    [
        {
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "match_all_template_sensor": {
                        "value_template": (
                            "{% for state in states %}"
                            "{% if state.entity_id == 'sensor.humidity' %}"
                            "{{ state.entity_id }}={{ state.state }}"
                            "{% endif %}"
                            "{% endfor %}"
                        ),
                    },
                },
            }
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_match_all(hass: HomeAssistant, setup_mock: Mock) -> None:
    """Test template that is rerendered on any state lifecycle."""
    init_calls = len(setup_mock.mock_calls)

    hass.states.async_set("sensor.any_state", "update")
    await hass.async_block_till_done()
    assert len(setup_mock.mock_calls) == init_calls


@pytest.mark.parametrize(("count", "domain"), [(1, binary_sensor.DOMAIN)])
@pytest.mark.parametrize(
    "config",
    [
        {
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "test": {
                        "friendly_name": "virtual thingy",
                        "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                        "device_class": "motion",
                    },
                },
            },
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_event(hass: HomeAssistant) -> None:
    """Test the event."""
    state = hass.states.get("binary_sensor.test")
    assert state.state == STATE_OFF

    hass.states.async_set("sensor.test_state", STATE_ON)
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == STATE_ON


@pytest.mark.parametrize(
    ("config", "count", "domain"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test_on": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_on": 5,
                        },
                        "test_off": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_off": 5,
                        },
                    },
                },
            },
            1,
            binary_sensor.DOMAIN,
        ),
        (
            {
                "template": [
                    {
                        "binary_sensor": {
                            "name": "test on",
                            "state": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_on": 5,
                        },
                    },
                    {
                        "binary_sensor": {
                            "name": "test off",
                            "state": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_off": 5,
                        },
                    },
                ]
            },
            2,
            template.DOMAIN,
        ),
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test_on": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_on": '{{ ({ "seconds": 10 / 2 }) }}',
                        },
                        "test_off": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_off": '{{ ({ "seconds": 10 / 2 }) }}',
                        },
                    },
                },
            },
            1,
            binary_sensor.DOMAIN,
        ),
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test_on": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_on": '{{ ({ "seconds": states("input_number.delay")|int }) }}',
                        },
                        "test_off": {
                            "friendly_name": "virtual thingy",
                            "value_template": "{{ states.sensor.test_state.state == 'on' }}",
                            "device_class": "motion",
                            "delay_off": '{{ ({ "seconds": states("input_number.delay")|int }) }}',
                        },
                    },
                },
            },
            1,
            binary_sensor.DOMAIN,
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_template_delay_on_off(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory
) -> None:
    """Test binary sensor template delay on."""
    # Ensure the initial state is not on
    assert hass.states.get("binary_sensor.test_on").state != STATE_ON
    assert hass.states.get("binary_sensor.test_off").state != STATE_ON

    hass.states.async_set("input_number.delay", 5)
    hass.states.async_set("sensor.test_state", STATE_ON)
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.test_on").state == STATE_OFF
    assert hass.states.get("binary_sensor.test_off").state == STATE_ON

    freezer.tick(timedelta(seconds=5))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.test_on").state == STATE_ON
    assert hass.states.get("binary_sensor.test_off").state == STATE_ON

    # check with time changes
    hass.states.async_set("sensor.test_state", STATE_OFF)
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.test_on").state == STATE_OFF
    assert hass.states.get("binary_sensor.test_off").state == STATE_ON

    hass.states.async_set("sensor.test_state", STATE_ON)
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.test_on").state == STATE_OFF
    assert hass.states.get("binary_sensor.test_off").state == STATE_ON

    hass.states.async_set("sensor.test_state", STATE_OFF)
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.test_on").state == STATE_OFF
    assert hass.states.get("binary_sensor.test_off").state == STATE_ON

    freezer.tick(timedelta(seconds=5))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.test_on").state == STATE_OFF
    assert hass.states.get("binary_sensor.test_off").state == STATE_OFF


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test": {
                            "friendly_name": "virtual thingy",
                            "value_template": "true",
                            "device_class": "motion",
                            "delay_off": 5,
                        },
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "name": "virtual thingy",
                        "state": "true",
                        "device_class": "motion",
                        "delay_off": 5,
                    },
                },
            },
            template.DOMAIN,
            "binary_sensor.virtual_thingy",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_available_without_availability_template(
    hass: HomeAssistant, entity_id: str
) -> None:
    """Ensure availability is true without an availability_template."""
    state = hass.states.get(entity_id)

    assert state.state != STATE_UNAVAILABLE
    assert state.attributes[ATTR_DEVICE_CLASS] == "motion"


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test": {
                            "friendly_name": "virtual thingy",
                            "value_template": "true",
                            "device_class": "motion",
                            "delay_off": 5,
                            "availability_template": "{{ is_state('sensor.test_state','on') }}",
                        },
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "name": "virtual thingy",
                        "state": "true",
                        "device_class": "motion",
                        "delay_off": 5,
                        "availability": "{{ is_state('sensor.test_state','on') }}",
                    },
                },
            },
            template.DOMAIN,
            "binary_sensor.virtual_thingy",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_availability_template(hass: HomeAssistant, entity_id: str) -> None:
    """Test availability template."""
    hass.states.async_set("sensor.test_state", STATE_OFF)
    await hass.async_block_till_done()

    assert hass.states.get(entity_id).state == STATE_UNAVAILABLE

    hass.states.async_set("sensor.test_state", STATE_ON)
    await hass.async_block_till_done()

    state = hass.states.get(entity_id)

    assert state.state != STATE_UNAVAILABLE
    assert state.attributes[ATTR_DEVICE_CLASS] == "motion"


@pytest.mark.parametrize(("count", "domain"), [(1, binary_sensor.DOMAIN)])
@pytest.mark.parametrize(
    "config",
    [
        {
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "invalid_template": {
                        "value_template": "{{ states.binary_sensor.test_sensor }}",
                        "attribute_templates": {
                            "test_attribute": "{{ states.binary_sensor.unknown.attributes.picture }}"
                        },
                    }
                },
            },
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_invalid_attribute_template(
    hass: HomeAssistant, caplog_setup_text: str
) -> None:
    """Test that errors are logged if rendering template fails."""
    hass.states.async_set("binary_sensor.test_sensor", STATE_ON)
    assert len(hass.states.async_all()) == 2
    assert ("test_attribute") in caplog_setup_text
    assert ("TemplateError") in caplog_setup_text


@pytest.mark.parametrize(("count", "domain"), [(1, binary_sensor.DOMAIN)])
@pytest.mark.parametrize(
    "config",
    [
        {
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "my_sensor": {
                        "value_template": "{{ states.binary_sensor.test_sensor }}",
                        "availability_template": "{{ x - 12 }}",
                    },
                },
            },
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_invalid_availability_template_keeps_component_available(
    hass: HomeAssistant, caplog_setup_text: str
) -> None:
    """Test that an invalid availability keeps the device available."""

    assert hass.states.get("binary_sensor.my_sensor").state != STATE_UNAVAILABLE
    assert "UndefinedError: 'x' is undefined" in caplog_setup_text


async def test_no_update_template_match_all(hass: HomeAssistant) -> None:
    """Test that we do not update sensors that match on all."""

    hass.set_state(CoreState.not_running)

    await setup.async_setup_component(
        hass,
        binary_sensor.DOMAIN,
        {
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "all_state": {"value_template": '{{ "true" }}'},
                    "all_icon": {
                        "value_template": "{{ states.binary_sensor.test_sensor.state }}",
                        "icon_template": "{{ 1 + 1 }}",
                    },
                    "all_entity_picture": {
                        "value_template": "{{ states.binary_sensor.test_sensor.state }}",
                        "entity_picture_template": "{{ 1 + 1 }}",
                    },
                    "all_attribute": {
                        "value_template": "{{ states.binary_sensor.test_sensor.state }}",
                        "attribute_templates": {"test_attribute": "{{ 1 + 1 }}"},
                    },
                },
            }
        },
    )
    await hass.async_block_till_done()
    hass.states.async_set("binary_sensor.test_sensor", STATE_ON)
    assert len(hass.states.async_all()) == 5

    assert hass.states.get("binary_sensor.all_state").state == STATE_UNKNOWN
    assert hass.states.get("binary_sensor.all_icon").state == STATE_UNKNOWN
    assert hass.states.get("binary_sensor.all_entity_picture").state == STATE_UNKNOWN
    assert hass.states.get("binary_sensor.all_attribute").state == STATE_UNKNOWN

    hass.bus.async_fire(EVENT_HOMEASSISTANT_START)
    await hass.async_block_till_done()

    assert hass.states.get("binary_sensor.all_state").state == STATE_ON
    assert hass.states.get("binary_sensor.all_icon").state == STATE_ON
    assert hass.states.get("binary_sensor.all_entity_picture").state == STATE_ON
    assert hass.states.get("binary_sensor.all_attribute").state == STATE_ON

    hass.states.async_set("binary_sensor.test_sensor", STATE_OFF)
    await hass.async_block_till_done()

    assert hass.states.get("binary_sensor.all_state").state == STATE_ON
    # Will now process because we have one valid template
    assert hass.states.get("binary_sensor.all_icon").state == STATE_OFF
    assert hass.states.get("binary_sensor.all_entity_picture").state == STATE_OFF
    assert hass.states.get("binary_sensor.all_attribute").state == STATE_OFF

    await async_update_entity(hass, "binary_sensor.all_state")
    await async_update_entity(hass, "binary_sensor.all_icon")
    await async_update_entity(hass, "binary_sensor.all_entity_picture")
    await async_update_entity(hass, "binary_sensor.all_attribute")

    assert hass.states.get("binary_sensor.all_state").state == STATE_ON
    assert hass.states.get("binary_sensor.all_icon").state == STATE_OFF
    assert hass.states.get("binary_sensor.all_entity_picture").state == STATE_OFF
    assert hass.states.get("binary_sensor.all_attribute").state == STATE_OFF


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": {
                "unique_id": "group-id",
                "binary_sensor": {
                    "name": "top-level",
                    "unique_id": "sensor-id",
                    "state": STATE_ON,
                },
            },
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "test_template_cover_01": {
                        "unique_id": "not-so-unique-anymore",
                        "value_template": "{{ true }}",
                    },
                    "test_template_cover_02": {
                        "unique_id": "not-so-unique-anymore",
                        "value_template": "{{ false }}",
                    },
                },
            },
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_unique_id(
    hass: HomeAssistant, entity_registry: er.EntityRegistry
) -> None:
    """Test unique_id option only creates one binary sensor per id."""
    assert len(hass.states.async_all()) == 2

    assert len(entity_registry.entities) == 2
    assert entity_registry.async_get_entity_id(
        "binary_sensor", "template", "group-id-sensor-id"
    )
    assert entity_registry.async_get_entity_id(
        "binary_sensor", "template", "not-so-unique-anymore"
    )


@pytest.mark.parametrize(("count", "domain"), [(1, binary_sensor.DOMAIN)])
@pytest.mark.parametrize(
    "config",
    [
        {
            "binary_sensor": {
                "platform": "template",
                "sensors": {
                    "test": {
                        "friendly_name": "virtual thingy",
                        "value_template": "True",
                        "icon_template": "{{ states.sensor.test_state.state }}",
                        "device_class": "motion",
                        "delay_on": 5,
                    },
                },
            },
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_template_validation_error(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """Test binary sensor template delay on."""
    caplog.set_level(logging.ERROR)
    state = hass.states.get("binary_sensor.test")
    assert state.attributes.get("icon") == ""

    hass.states.async_set("sensor.test_state", "mdi:check")
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.attributes.get("icon") == "mdi:check"

    hass.states.async_set("sensor.test_state", "invalid_icon")
    await hass.async_block_till_done()
    assert len(caplog.records) == 1
    assert caplog.records[0].message.startswith(
        "Error validating template result 'invalid_icon' from template"
    )

    state = hass.states.get("binary_sensor.test")
    assert state.attributes.get("icon") is None


@pytest.mark.parametrize("count", [1])
@pytest.mark.parametrize(
    ("config", "domain", "entity_id"),
    [
        (
            {
                "binary_sensor": {
                    "platform": "template",
                    "sensors": {
                        "test": {
                            "availability_template": "{{ is_state('sensor.bla', 'available') }}",
                            "entity_picture_template": "{{ 'blib' + 'blub' }}",
                            "icon_template": "mdi:{{ 1+2 }}",
                            "friendly_name": "{{ 'My custom ' + 'sensor' }}",
                            "value_template": "{{ true }}",
                        },
                    },
                },
            },
            binary_sensor.DOMAIN,
            "binary_sensor.test",
        ),
        (
            {
                "template": {
                    "binary_sensor": {
                        "availability": "{{ is_state('sensor.bla', 'available') }}",
                        "picture": "{{ 'blib' + 'blub' }}",
                        "icon": "mdi:{{ 1+2 }}",
                        "name": "{{ 'My custom ' + 'sensor' }}",
                        "state": "{{ true }}",
                    },
                },
            },
            template.DOMAIN,
            "binary_sensor.my_custom_sensor",
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_availability_icon_picture(hass: HomeAssistant, entity_id: str) -> None:
    """Test name, icon and picture templates are rendered at setup."""
    state = hass.states.get(entity_id)
    assert state.state == "unavailable"
    assert state.attributes == {
        "entity_picture": "blibblub",
        "friendly_name": "My custom sensor",
        "icon": "mdi:3",
    }

    hass.states.async_set("sensor.bla", "available")
    await hass.async_block_till_done()

    state = hass.states.get(entity_id)
    assert state.state == "on"
    assert state.attributes == {
        "entity_picture": "blibblub",
        "friendly_name": "My custom sensor",
        "icon": "mdi:3",
    }


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": {
                "binary_sensor": {
                    "name": "test",
                    "state": "{{ states.sensor.test_state.state }}",
                },
            },
        },
    ],
)
@pytest.mark.parametrize(
    ("extra_config", "source_state", "restored_state", "initial_state"),
    [
        ({}, STATE_OFF, STATE_ON, STATE_OFF),
        ({}, STATE_OFF, STATE_OFF, STATE_OFF),
        ({}, STATE_OFF, STATE_UNAVAILABLE, STATE_OFF),
        ({}, STATE_OFF, STATE_UNKNOWN, STATE_OFF),
        ({"delay_off": 5}, STATE_OFF, STATE_ON, STATE_ON),
        ({"delay_off": 5}, STATE_OFF, STATE_OFF, STATE_OFF),
        ({"delay_off": 5}, STATE_OFF, STATE_UNAVAILABLE, STATE_UNKNOWN),
        ({"delay_off": 5}, STATE_OFF, STATE_UNKNOWN, STATE_UNKNOWN),
        ({"delay_on": 5}, STATE_OFF, STATE_ON, STATE_OFF),
        ({"delay_on": 5}, STATE_OFF, STATE_OFF, STATE_OFF),
        ({"delay_on": 5}, STATE_OFF, STATE_UNAVAILABLE, STATE_OFF),
        ({"delay_on": 5}, STATE_OFF, STATE_UNKNOWN, STATE_OFF),
        ({}, STATE_ON, STATE_ON, STATE_ON),
        ({}, STATE_ON, STATE_OFF, STATE_ON),
        ({}, STATE_ON, STATE_UNAVAILABLE, STATE_ON),
        ({}, STATE_ON, STATE_UNKNOWN, STATE_ON),
        ({"delay_off": 5}, STATE_ON, STATE_ON, STATE_ON),
        ({"delay_off": 5}, STATE_ON, STATE_OFF, STATE_ON),
        ({"delay_off": 5}, STATE_ON, STATE_UNAVAILABLE, STATE_ON),
        ({"delay_off": 5}, STATE_ON, STATE_UNKNOWN, STATE_ON),
        ({"delay_on": 5}, STATE_ON, STATE_ON, STATE_ON),
        ({"delay_on": 5}, STATE_ON, STATE_OFF, STATE_OFF),
        ({"delay_on": 5}, STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN),
        ({"delay_on": 5}, STATE_ON, STATE_UNKNOWN, STATE_UNKNOWN),
        ({}, None, STATE_ON, STATE_OFF),
        ({}, None, STATE_OFF, STATE_OFF),
        ({}, None, STATE_UNAVAILABLE, STATE_OFF),
        ({}, None, STATE_UNKNOWN, STATE_OFF),
        ({"delay_off": 5}, None, STATE_ON, STATE_ON),
        ({"delay_off": 5}, None, STATE_OFF, STATE_OFF),
        ({"delay_off": 5}, None, STATE_UNAVAILABLE, STATE_UNKNOWN),
        ({"delay_off": 5}, None, STATE_UNKNOWN, STATE_UNKNOWN),
        ({"delay_on": 5}, None, STATE_ON, STATE_OFF),
        ({"delay_on": 5}, None, STATE_OFF, STATE_OFF),
        ({"delay_on": 5}, None, STATE_UNAVAILABLE, STATE_OFF),
        ({"delay_on": 5}, None, STATE_UNKNOWN, STATE_OFF),
    ],
)
async def test_restore_state(
    hass: HomeAssistant,
    count: int,
    domain: str,
    config: ConfigType,
    extra_config: ConfigType,
    source_state: str | None,
    restored_state: str,
    initial_state: str,
) -> None:
    """Test restoring template binary sensor."""

    hass.states.async_set("sensor.test_state", source_state)
    fake_state = State(
        "binary_sensor.test",
        restored_state,
        {},
    )
    mock_restore_cache(hass, (fake_state,))
    config = deepcopy(config)
    config["template"]["binary_sensor"].update(**extra_config)
    with assert_setup_component(count, domain):
        assert await async_setup_component(
            hass,
            domain,
            config,
        )

        await hass.async_block_till_done()

        context = Context()
        hass.bus.async_fire("test_event", {"beer": 2}, context=context)
        await hass.async_block_till_done()

        await hass.async_start()
        await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == initial_state


@pytest.mark.parametrize(("count", "domain"), [(2, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": [
                {"invalid": "config"},
                # Config after invalid should still be set up
                {
                    "unique_id": "listening-test-event",
                    "trigger": {"platform": "event", "event_type": "test_event"},
                    "binary_sensors": {
                        "hello": {
                            "friendly_name": "Hello Name",
                            "unique_id": "hello_name-id",
                            "device_class": "battery",
                            "value_template": _BEER_TRIGGER_VALUE_TEMPLATE,
                            "entity_picture_template": "{{ '/local/dogs.png' }}",
                            "icon_template": "{{ 'mdi:pirate' }}",
                            "attribute_templates": {
                                "plus_one": "{{ trigger.event.data.beer + 1 }}"
                            },
                        },
                    },
                    "binary_sensor": [
                        {
                            "name": "via list",
                            "unique_id": "via_list-id",
                            "device_class": "battery",
                            "state": _BEER_TRIGGER_VALUE_TEMPLATE,
                            "picture": "{{ '/local/dogs.png' }}",
                            "icon": "{{ 'mdi:pirate' }}",
                            "attributes": {
                                "plus_one": "{{ trigger.event.data.beer + 1 }}",
                                "another": "{{ trigger.event.data.uno_mas or 1 }}",
                            },
                        }
                    ],
                },
                {
                    "trigger": [],
                    "binary_sensors": {
                        "bare_minimum": {
                            "value_template": "{{ trigger.event.data.beer == 1 }}"
                        },
                    },
                },
            ],
        },
    ],
)
@pytest.mark.parametrize(
    (
        "beer_count",
        "final_state",
        "icon_attr",
        "entity_picture_attr",
        "plus_one_attr",
        "another_attr",
        "another_attr_update",
    ),
    [
        (2, STATE_ON, "mdi:pirate", "/local/dogs.png", 3, 1, "si"),
        (1, STATE_OFF, "mdi:pirate", "/local/dogs.png", 2, 1, "si"),
        (0, STATE_OFF, "mdi:pirate", "/local/dogs.png", 1, 1, "si"),
        (-1, STATE_UNAVAILABLE, None, None, None, None, None),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_trigger_entity(
    hass: HomeAssistant,
    beer_count: int,
    final_state: str,
    icon_attr: str | None,
    entity_picture_attr: str | None,
    plus_one_attr: int | None,
    another_attr: int | None,
    another_attr_update: str | None,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test trigger entity works."""
    await hass.async_block_till_done()
    state = hass.states.get("binary_sensor.hello_name")
    assert state is not None
    assert state.state == STATE_UNKNOWN

    state = hass.states.get("binary_sensor.bare_minimum")
    assert state is not None
    assert state.state == STATE_UNKNOWN

    context = Context()
    hass.bus.async_fire("test_event", {"beer": beer_count}, context=context)
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.hello_name")
    assert state.state == final_state
    assert state.attributes.get("device_class") == "battery"
    assert state.attributes.get("icon") == icon_attr
    assert state.attributes.get("entity_picture") == entity_picture_attr
    assert state.attributes.get("plus_one") == plus_one_attr
    assert state.context is context

    assert len(entity_registry.entities) == 2
    assert (
        entity_registry.entities["binary_sensor.hello_name"].unique_id
        == "listening-test-event-hello_name-id"
    )
    assert (
        entity_registry.entities["binary_sensor.via_list"].unique_id
        == "listening-test-event-via_list-id"
    )

    state = hass.states.get("binary_sensor.via_list")
    assert state.state == final_state
    assert state.attributes.get("device_class") == "battery"
    assert state.attributes.get("icon") == icon_attr
    assert state.attributes.get("entity_picture") == entity_picture_attr
    assert state.attributes.get("plus_one") == plus_one_attr
    assert state.attributes.get("another") == another_attr
    assert state.context is context

    # Even if state itself didn't change, attributes might have changed
    hass.bus.async_fire("test_event", {"beer": beer_count, "uno_mas": "si"})
    await hass.async_block_till_done()
    state = hass.states.get("binary_sensor.via_list")
    assert state.state == final_state
    assert state.attributes.get("another") == another_attr_update


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": {
                "trigger": {"platform": "event", "event_type": "test_event"},
                "binary_sensor": {
                    "name": "test",
                    "state": _BEER_TRIGGER_VALUE_TEMPLATE,
                    "device_class": "motion",
                    "delay_on": '{{ ({ "seconds": 6 / 2 }) }}',
                    "auto_off": '{{ ({ "seconds": 1 + 1 }) }}',
                },
            },
        },
    ],
)
@pytest.mark.usefixtures("start_ha")
@pytest.mark.parametrize(
    ("beer_count", "first_state", "second_state", "final_state"),
    [
        (2, STATE_UNKNOWN, STATE_ON, STATE_OFF),
        (1, STATE_OFF, STATE_OFF, STATE_OFF),
        (0, STATE_OFF, STATE_OFF, STATE_OFF),
        (-1, STATE_UNAVAILABLE, STATE_UNAVAILABLE, STATE_UNAVAILABLE),
    ],
)
async def test_template_with_trigger_templated_delay_on(
    hass: HomeAssistant,
    beer_count: int,
    first_state: str,
    second_state: str,
    final_state: str,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test binary sensor template with template delay on."""
    state = hass.states.get("binary_sensor.test")
    assert state.state == STATE_UNKNOWN

    context = Context()
    hass.bus.async_fire("test_event", {"beer": beer_count}, context=context)
    await hass.async_block_till_done()

    # State should still be unknown
    state = hass.states.get("binary_sensor.test")
    assert state.state == first_state

    # Now wait for the on delay
    freezer.tick(timedelta(seconds=3))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == second_state

    # Now wait for the auto-off
    freezer.tick(timedelta(seconds=2))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == final_state


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    ("config", "delay_state"),
    [
        (
            {
                "template": {
                    "trigger": {"platform": "event", "event_type": "test_event"},
                    "binary_sensor": {
                        "name": "test",
                        "state": "{{ trigger.event.data.beer == 2 }}",
                        "device_class": "motion",
                        "delay_on": '{{ ({ "seconds": 10 }) }}',
                    },
                },
            },
            STATE_ON,
        ),
        (
            {
                "template": {
                    "trigger": {"platform": "event", "event_type": "test_event"},
                    "binary_sensor": {
                        "name": "test",
                        "state": "{{ trigger.event.data.beer != 2 }}",
                        "device_class": "motion",
                        "delay_off": '{{ ({ "seconds": 10 }) }}',
                    },
                },
            },
            STATE_OFF,
        ),
    ],
)
@pytest.mark.usefixtures("start_ha")
async def test_trigger_template_delay_with_multiple_triggers(
    hass: HomeAssistant, delay_state: str, freezer: FrozenDateTimeFactory
) -> None:
    """Test trigger based binary sensor with multiple triggers occurring during the delay."""
    for _ in range(10):
        # State should still be unknown
        state = hass.states.get("binary_sensor.test")
        assert state.state == STATE_UNKNOWN

        hass.bus.async_fire("test_event", {"beer": 2}, context=Context())
        await hass.async_block_till_done()

        freezer.tick(timedelta(seconds=1))
        async_fire_time_changed(hass)
        await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == delay_state


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": {
                "trigger": {"platform": "event", "event_type": "test_event"},
                "binary_sensor": {
                    "name": "test",
                    "state": _BEER_TRIGGER_VALUE_TEMPLATE,
                    "device_class": "motion",
                    "picture": "{{ '/local/dogs.png' }}",
                    "icon": "{{ 'mdi:pirate' }}",
                    "attributes": {
                        "plus_one": "{{ trigger.event.data.beer + 1 }}",
                        "another": "{{ trigger.event.data.uno_mas or 1 }}",
                    },
                },
            },
        },
    ],
)
@pytest.mark.parametrize(
    ("restored_state", "initial_state", "initial_attributes"),
    [
        (STATE_ON, STATE_ON, ["entity_picture", "icon", "plus_one"]),
        (STATE_OFF, STATE_OFF, ["entity_picture", "icon", "plus_one"]),
        (STATE_UNAVAILABLE, STATE_UNKNOWN, []),
        (STATE_UNKNOWN, STATE_UNKNOWN, []),
    ],
)
async def test_trigger_entity_restore_state(
    hass: HomeAssistant,
    count: int,
    domain: str,
    config: ConfigType,
    restored_state: str,
    initial_state: str,
    initial_attributes: list[str],
) -> None:
    """Test restoring trigger template binary sensor."""

    restored_attributes = {
        "entity_picture": "/local/cats.png",
        "icon": "mdi:ship",
        "plus_one": 55,
    }

    fake_state = State(
        "binary_sensor.test",
        restored_state,
        restored_attributes,
    )
    fake_extra_data = {
        "auto_off_time": None,
    }
    mock_restore_cache_with_extra_data(hass, ((fake_state, fake_extra_data),))
    with assert_setup_component(count, domain):
        assert await async_setup_component(
            hass,
            domain,
            config,
        )

        await hass.async_block_till_done()
        await hass.async_start()
        await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == initial_state
    for attr, value in restored_attributes.items():
        if attr in initial_attributes:
            assert state.attributes[attr] == value
        else:
            assert attr not in state.attributes
    assert "another" not in state.attributes

    hass.bus.async_fire("test_event", {"beer": 2})
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == STATE_ON
    assert state.attributes["icon"] == "mdi:pirate"
    assert state.attributes["entity_picture"] == "/local/dogs.png"
    assert state.attributes["plus_one"] == 3
    assert state.attributes["another"] == 1


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": {
                "trigger": {"platform": "event", "event_type": "test_event"},
                "binary_sensor": {
                    "name": "test",
                    "state": _BEER_TRIGGER_VALUE_TEMPLATE,
                    "device_class": "motion",
                    "auto_off": '{{ ({ "seconds": 1 + 1 }) }}',
                },
            },
        },
    ],
)
@pytest.mark.parametrize("restored_state", [STATE_ON, STATE_OFF])
async def test_trigger_entity_restore_state_auto_off(
    hass: HomeAssistant,
    count: int,
    domain: str,
    config: ConfigType,
    restored_state: str,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test restoring trigger template binary sensor."""

    freezer.move_to("2022-02-02 12:02:00+00:00")
    fake_state = State(
        "binary_sensor.test",
        restored_state,
        {},
    )
    fake_extra_data = {
        "auto_off_time": {
            "__type": "<class 'datetime.datetime'>",
            "isoformat": datetime(2022, 2, 2, 12, 2, 2, tzinfo=UTC).isoformat(),
        },
    }
    mock_restore_cache_with_extra_data(hass, ((fake_state, fake_extra_data),))
    with assert_setup_component(count, domain):
        assert await async_setup_component(
            hass,
            domain,
            config,
        )

        await hass.async_block_till_done()
        await hass.async_start()
        await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == restored_state

    # Now wait for the auto-off
    freezer.move_to("2022-02-02 12:02:03+00:00")
    await hass.async_block_till_done()
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == STATE_OFF


@pytest.mark.parametrize(("count", "domain"), [(1, "template")])
@pytest.mark.parametrize(
    "config",
    [
        {
            "template": {
                "trigger": {"platform": "event", "event_type": "test_event"},
                "binary_sensor": {
                    "name": "test",
                    "state": _BEER_TRIGGER_VALUE_TEMPLATE,
                    "device_class": "motion",
                    "auto_off": '{{ ({ "seconds": 1 + 1 }) }}',
                },
            },
        },
    ],
)
async def test_trigger_entity_restore_state_auto_off_expired(
    hass: HomeAssistant,
    count: int,
    domain: str,
    config: ConfigType,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test restoring trigger template binary sensor."""

    freezer.move_to("2022-02-02 12:02:00+00:00")
    fake_state = State(
        "binary_sensor.test",
        STATE_ON,
        {},
    )
    fake_extra_data = {
        "auto_off_time": {
            "__type": "<class 'datetime.datetime'>",
            "isoformat": datetime(2022, 2, 2, 12, 2, 0, tzinfo=UTC).isoformat(),
        },
    }
    mock_restore_cache_with_extra_data(hass, ((fake_state, fake_extra_data),))
    with assert_setup_component(count, domain):
        assert await async_setup_component(
            hass,
            domain,
            config,
        )

        await hass.async_block_till_done()
        await hass.async_start()
        await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.test")
    assert state.state == STATE_OFF


async def test_device_id(
    hass: HomeAssistant,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test for device for Template."""

    device_config_entry = MockConfigEntry()
    device_config_entry.add_to_hass(hass)
    device_entry = device_registry.async_get_or_create(
        config_entry_id=device_config_entry.entry_id,
        identifiers={("sensor", "identifier_test")},
        connections={("mac", "30:31:32:33:34:35")},
    )
    await hass.async_block_till_done()
    assert device_entry is not None
    assert device_entry.id is not None

    template_config_entry = MockConfigEntry(
        data={},
        domain=template.DOMAIN,
        options={
            "name": "My template",
            "state": "{{10 > 8}}",
            "template_type": "binary_sensor",
            "device_id": device_entry.id,
        },
        title="My template",
    )
    template_config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(template_config_entry.entry_id)
    await hass.async_block_till_done()

    template_entity = entity_registry.async_get("binary_sensor.my_template")
    assert template_entity is not None
    assert template_entity.device_id == device_entry.id
