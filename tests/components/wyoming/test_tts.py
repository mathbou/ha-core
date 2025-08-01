"""Test tts."""

from __future__ import annotations

import io
from unittest.mock import patch
import wave

import pytest
from syrupy.assertion import SnapshotAssertion
from wyoming.audio import AudioChunk, AudioStart, AudioStop
from wyoming.tts import SynthesizeStopped

from homeassistant.components import tts, wyoming
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_component import DATA_INSTANCES

from . import MockAsyncTcpClient


async def test_support(hass: HomeAssistant, init_wyoming_tts) -> None:
    """Test supported properties."""
    state = hass.states.get("tts.test_tts")
    assert state is not None

    entity = hass.data[DATA_INSTANCES]["tts"].get_entity("tts.test_tts")
    assert entity is not None

    assert entity.supported_languages == ["en-US"]
    assert entity.supported_options == [
        tts.ATTR_AUDIO_OUTPUT,
        tts.ATTR_VOICE,
        wyoming.ATTR_SPEAKER,
    ]
    voices = entity.async_get_supported_voices("en-US")
    assert len(voices) == 1
    assert voices[0].name == "Test Voice"
    assert voices[0].voice_id == "Test Voice"
    assert not entity.async_get_supported_voices("de-DE")


async def test_get_tts_audio(
    hass: HomeAssistant, init_wyoming_tts, snapshot: SnapshotAssertion
) -> None:
    """Test get audio."""
    entity = hass.data[DATA_INSTANCES]["tts"].get_entity("tts.test_tts")
    assert entity is not None
    assert not entity.async_supports_streaming_input()

    audio = bytes(100)

    # Verify audio
    audio_events = [
        AudioChunk(audio=audio, rate=16000, width=2, channels=1).event(),
        AudioStop().event(),
    ]

    with patch(
        "homeassistant.components.wyoming.tts.AsyncTcpClient",
        MockAsyncTcpClient(audio_events),
    ) as mock_client:
        extension, data = await tts.async_get_media_source_audio(
            hass,
            tts.generate_media_source_id(
                hass,
                "Hello world",
                "tts.test_tts",
                "en-US",
                options={tts.ATTR_PREFERRED_FORMAT: "wav"},
            ),
        )

    assert extension == "wav"
    assert data is not None
    with io.BytesIO(data) as wav_io, wave.open(wav_io, "rb") as wav_file:
        assert wav_file.getframerate() == 16000
        assert wav_file.getsampwidth() == 2
        assert wav_file.getnchannels() == 1
        assert wav_file.readframes(wav_file.getnframes()) == audio

    assert mock_client.written == snapshot


async def test_get_tts_audio_different_formats(
    hass: HomeAssistant, init_wyoming_tts, snapshot: SnapshotAssertion
) -> None:
    """Test changing preferred audio format."""
    audio = bytes(16000 * 2 * 1)  # one second
    audio_events = [
        AudioChunk(audio=audio, rate=16000, width=2, channels=1).event(),
        AudioStop().event(),
    ]

    # Request a different sample rate, etc.
    with patch(
        "homeassistant.components.wyoming.tts.AsyncTcpClient",
        MockAsyncTcpClient(audio_events),
    ) as mock_client:
        extension, data = await tts.async_get_media_source_audio(
            hass,
            tts.generate_media_source_id(
                hass,
                "Hello world",
                "tts.test_tts",
                "en-US",
                options={
                    tts.ATTR_PREFERRED_FORMAT: "wav",
                    tts.ATTR_PREFERRED_SAMPLE_RATE: 48000,
                    tts.ATTR_PREFERRED_SAMPLE_CHANNELS: 2,
                },
            ),
        )

    assert extension == "wav"
    assert data is not None
    with io.BytesIO(data) as wav_io, wave.open(wav_io, "rb") as wav_file:
        assert wav_file.getframerate() == 48000
        assert wav_file.getsampwidth() == 2
        assert wav_file.getnchannels() == 2

    assert mock_client.written == snapshot

    # MP3 is the default
    audio_events = [
        AudioChunk(audio=audio, rate=16000, width=2, channels=1).event(),
        AudioStop().event(),
    ]

    with patch(
        "homeassistant.components.wyoming.tts.AsyncTcpClient",
        MockAsyncTcpClient(audio_events),
    ) as mock_client:
        extension, data = await tts.async_get_media_source_audio(
            hass,
            tts.generate_media_source_id(
                hass,
                "Hello world",
                "tts.test_tts",
                "en-US",
            ),
        )

    assert extension == "mp3"
    assert b"ID3" in data
    assert mock_client.written == snapshot


async def test_get_tts_audio_connection_lost(
    hass: HomeAssistant, init_wyoming_tts
) -> None:
    """Test streaming audio and losing connection."""
    stream = tts.async_create_stream(hass, "tts.test_tts", "en-US")
    with patch(
        "homeassistant.components.wyoming.tts.AsyncTcpClient",
        MockAsyncTcpClient([None]),
    ):
        stream.async_set_message("Hello world")
        with pytest.raises(HomeAssistantError):
            async for _chunk in stream.async_stream_result():
                pass


async def test_get_tts_audio_audio_oserror(
    hass: HomeAssistant, init_wyoming_tts
) -> None:
    """Test get audio and error raising."""
    audio = bytes(100)
    audio_events = [
        AudioChunk(audio=audio, rate=16000, width=2, channels=1).event(),
        AudioStop().event(),
    ]

    mock_client = MockAsyncTcpClient(audio_events)

    with (
        patch(
            "homeassistant.components.wyoming.tts.AsyncTcpClient",
            mock_client,
        ),
        patch.object(mock_client, "read_event", side_effect=OSError("Boom!")),
        pytest.raises(
            HomeAssistantError,
        ),
    ):
        await tts.async_get_media_source_audio(
            hass,
            tts.generate_media_source_id(
                hass, "Hello world", "tts.test_tts", hass.config.language
            ),
        )


async def test_voice_speaker(
    hass: HomeAssistant, init_wyoming_tts, snapshot: SnapshotAssertion
) -> None:
    """Test using a different voice and speaker."""
    audio = bytes(100)
    audio_events = [
        AudioChunk(audio=audio, rate=16000, width=2, channels=1).event(),
        AudioStop().event(),
    ]

    with patch(
        "homeassistant.components.wyoming.tts.AsyncTcpClient",
        MockAsyncTcpClient(audio_events),
    ) as mock_client:
        await tts.async_get_media_source_audio(
            hass,
            tts.generate_media_source_id(
                hass,
                "Hello world",
                "tts.test_tts",
                "en-US",
                options={tts.ATTR_VOICE: "voice1", wyoming.ATTR_SPEAKER: "speaker1"},
            ),
        )
        assert mock_client.written == snapshot


async def test_get_tts_audio_streaming(
    hass: HomeAssistant, init_wyoming_streaming_tts, snapshot: SnapshotAssertion
) -> None:
    """Test get audio with streaming."""
    entity = hass.data[DATA_INSTANCES]["tts"].get_entity("tts.test_streaming_tts")
    assert entity is not None
    assert entity.async_supports_streaming_input()

    audio = bytes(100)

    # Verify audio
    audio_events = [
        AudioStart(rate=16000, width=2, channels=1).event(),
        AudioChunk(audio=audio, rate=16000, width=2, channels=1).event(),
        AudioStop().event(),
        SynthesizeStopped().event(),
    ]

    async def message_gen():
        yield "Hello "
        yield "Word."

    with patch(
        "homeassistant.components.wyoming.tts.AsyncTcpClient",
        MockAsyncTcpClient(audio_events),
    ) as mock_client:
        stream = tts.async_create_stream(
            hass,
            "tts.test_streaming_tts",
            "en-US",
            options={tts.ATTR_PREFERRED_FORMAT: "wav"},
        )
        stream.async_set_message_stream(message_gen())
        data = b"".join([chunk async for chunk in stream.async_stream_result()])

        # Ensure client was disconnected properly
        assert mock_client.is_connected is False

    assert data is not None
    with io.BytesIO(data) as wav_io, wave.open(wav_io, "rb") as wav_file:
        assert wav_file.getframerate() == 16000
        assert wav_file.getsampwidth() == 2
        assert wav_file.getnchannels() == 1
        assert wav_file.getnframes() == 0  # streaming
        assert data[44:] == audio  # WAV header is 44 bytes

    assert mock_client.written == snapshot
