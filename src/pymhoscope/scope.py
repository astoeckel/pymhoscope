#  pymhoscope -- Communicate with the Rigol MHO series oscilloscopes
#  Copyright (C) 2026 Andreas Stöckel
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Abstract oscilloscope interface."""

import abc
import dataclasses
import enum
import typing

import numpy as np
import numpy.typing as npt


class UnchangedType(enum.Enum):
    """Type of the `Unchanged` sentinel."""

    UNCHANGED = "Unchanged"

    def __repr__(self) -> str:
        return "Unchanged"


Unchanged: typing.Final = UnchangedType.UNCHANGED
"""Indicates that a setting shouldn't change."""


class Impedance(enum.Enum):
    HIGH = "1MΩ"
    LOW = "50Ω"


class Coupling(enum.Enum):
    DC = "DC"
    AC = "AC"
    GND = "GND"


class Bandwidth(enum.Enum):
    MAX = "MAX"
    MHZ_250 = "250 MHz"
    MHZ_20 = "20 MHz"


class Edge(enum.Enum):
    RISING = "RISING"
    FALLING = "FALLING"
    BOTH = "BOTH"


class TriggerStatus(enum.Enum):
    """Trigger status of the oscilloscope."""

    STOP = "STOP"
    """Acquisition stopped; the last record can be read."""

    RUN = "RUN"
    """The oscilloscope is in free-running mode."""

    WAIT = "WAIT"
    """Waiting for the trigger event."""

    TRIGGERED = "TRIGGERED"
    """Triggered. The oscilloscope acquires data after the trigger point."""

    AUTO = "AUTO"
    """Acquiring without a trigger event (auto trigger sweep)."""


class AnalogueChannel(typing.NamedTuple):
    """Zero-indexed analogue channel; `AnalogueChannel(0)` is CH1."""

    idx: int


class DigitalChannel(typing.NamedTuple):
    """Zero-indexed logic analyser channel; `DigitalChannel(0)` is D0."""

    idx: int


@dataclasses.dataclass(frozen=True)
class Identification:
    """
    Device identification as returned by the IEEE 488.2 `*IDN?` query.

    Attributes
    ----------

    manufacturer:
        Name of the manufacturer.

    model:
        Model name.

    serial_number:
        Serial number.

    firmware_version:
        Firmware version or equivalent.
    """

    manufacturer: str
    model: str
    serial_number: str
    firmware_version: str


@dataclasses.dataclass(frozen=True)
class HorizontalSettings:
    """
    Time-base settings applied by the scope after `configure_horizontal()`.

    Note that some of these settings are only computed by the scope while it
    is not stopped; in that case, the code models how the scope normally
    responds to the given `configure_horizontal()` request. If the parameters
    are outside the range that is known to be modelled correctly, this function
    will set the unknown values to `None`.

    Attributes
    ----------

    n_samples:
        Number of samples per channel in the record.

    sample_rate:
        Sample rate in samples per second.

    t_offset:
        Time in seconds recorded before the trigger.

    resolution_bits:
        Vertical resolution in bits. Exceeds the ADC resolution if the scope
        averages neighbouring samples (high-resolution mode).
    """

    n_samples: int | None
    sample_rate: float | None
    t_offset: float | None
    resolution_bits: int


@dataclasses.dataclass(frozen=True)
class EdgeTriggerSettings:
    """
    Edge trigger settings as applied by the scope.

    Attributes
    ----------

    channel:
        Channel the scope triggers on.

    level:
        Trigger level in volt or `None` for digital channels.

    edge:
        Edge the scope triggers on.
    """

    channel: AnalogueChannel | DigitalChannel
    level: float | None
    edge: Edge


@dataclasses.dataclass(frozen=True)
class AnalogueChannelSettings:
    """
    Analogue channel settings as applied by the scope.

    See `Scope.configure_analogue_channel()` for a detailed description.
    """

    channel: AnalogueChannel
    enabled: bool
    scale: float
    offset: float
    probe_scale: float
    impedance: Impedance
    coupling: Coupling
    bandwidth: Bandwidth


@dataclasses.dataclass(frozen=True)
class DigitalChannelSettings:
    """
    Logic analyser channel settings as applied by the scope.

    See `Scope.configure_digital_channel()` for a detailed description.
    """

    channel: DigitalChannel
    enabled: bool
    label: str
    threshold: float


@dataclasses.dataclass
class AnalogueWaveform:
    """
    Structure holding analogue data recorded from one channel.

    Attributes
    ----------

    channel:
        Channel the data was recorded from.

    data:
        Numpy array containing floting point samples that encode the
        meausred analog value in Volt.

    t_base:
        Time of the first sample relative to the trigger in seconds.

    t_inc:
        Sample interval in seconds.

    n_average:
        Number of acquisitions averaged into `data`.
    """

    channel: AnalogueChannel
    data: npt.NDArray[np.float32]
    t_base: float
    t_inc: float
    n_average: int = 1


@dataclasses.dataclass
class DigitalWaveform:
    """
    Structure holding multiple digital channels.

    Each word in `data` contains multiple channels; bit n holds channel Dn.
    For 16 channels, `data` is thus an array of 16-bit words.

    Attributes
    ----------

    data:
        One word per sample.

    t_base:
        Time of the first sample relative to the trigger in seconds.

    t_inc:
        Sample interval in seconds.

    n_channels:
        Number of channels in each word.
    """

    data: npt.NDArray[np.uint16]
    t_base: float
    t_inc: float
    n_channels: int = 16


@dataclasses.dataclass
class Capture:
    """
    Structure holding captured data.

    Attributes
    ----------

    analogue_channels:
        Waveforms of all enabled analogue channels.

    digital_waveform:
        Logic analyser data, or `None` if the logic analyser is disabled.
    """

    analogue_channels: dict[AnalogueChannel, AnalogueWaveform]
    digital_waveform: DigitalWaveform | None


class Scope(abc.ABC):
    """Interface of an oscilloscope with an optional logic analyser."""

    @abc.abstractmethod
    def identify(self) -> Identification:
        """Query the manufacturer, model, serial number and firmware version."""
        ...

    @abc.abstractmethod
    def reset(self) -> None:
        """
        Reset the oscilloscope settings to its factory default settings.

        This ensures that measurement results do not depend on previous user
        settings.
        """
        ...

    @abc.abstractmethod
    def configure_horizontal(
        self,
        *,
        min_n_samples: int | UnchangedType = Unchanged,
        min_sample_rate: float | UnchangedType = Unchanged,
        t_offset: float | UnchangedType = Unchanged,
        resolution_bits: int | UnchangedType = Unchanged,
    ) -> HorizontalSettings:
        """
        Configure the time-base for sample acquisition.

        Parameters set to `Unchanged` indicate that the currently configured
        value should be used.

        Parameters
        ----------

        min_n_samples:
            Minimum number of samples to capture.

        min_sample_rate:
            Minimum sample rate in samples per second to use for the capture.

        t_offset:
            Time in seconds that should be recorded before the trigger.

        resolution_bits:
            Vertical resolution in bits. Values above the ADC resolution
            enable the high-resolution mode, which averages neighbouring
            samples at the cost of bandwidth. Supported values depend on the
            scope.

        Returns
        -------

        Actually applied horizontal configuration. The code needs to derive
        oscilloscope settings from the specified minimum sample count and
        sample rate; those settings are returned by this function.
        """
        ...

    @abc.abstractmethod
    def configure_edge_trigger(
        self,
        channel: AnalogueChannel | DigitalChannel,
        *,
        level: float | UnchangedType | None = Unchanged,
        edge: Edge | UnchangedType = Unchanged,
    ) -> EdgeTriggerSettings:
        """
        Configure the trigger condition.

        Parameters set to `Unchanged` indicate that the currently configured
        value should be used.

        Parameters
        ----------

        channel:
            Analogue or digital channel that the scope should trigger on. The
            referenced channel must have been set up.

        level:
            Trigger level in volt. Must be `None` or `Unchanged` for digital
            channels, which have no trigger level, and must not be `None`
            for analogue channels.

        edge:
            Edge to trigger on.

        Returns
        -------

        The current trigger settings.
        """
        ...

    @abc.abstractmethod
    def configure_analogue_channel(
        self,
        channel: AnalogueChannel,
        *,
        enabled: bool | UnchangedType = Unchanged,
        scale: float | UnchangedType = Unchanged,
        offset: float | UnchangedType = Unchanged,
        probe_scale: float | UnchangedType = Unchanged,
        impedance: Impedance | UnchangedType = Unchanged,
        coupling: Coupling | UnchangedType = Unchanged,
        bandwidth: Bandwidth | UnchangedType = Unchanged,
    ) -> AnalogueChannelSettings:
        """
        Configure an analogue channel.

        Parameters set to `Unchanged` indicate that the currently configured
        value should be used.

        Parameters
        ----------

        channel:
            Analogue channel that should be configured.

        enabled:
            Set to `False` to exclude the channel from the acquisition.

        scale:
            Scale in volt per division.

        offset:
            Offset in volt.

        probe_scale:
            Probe scaling factor.

        impedance:
            Frontend impedance. Note that Impedance.LOW (typically 50 Ω) is only
            safe for a limited voltage range.

        coupling:
            Coupling between the probe and the oscilloscope frontend.

        bandwidth:
            Configures the bandwidth limit in the analogue frontend.

        Returns
        -------

        The current settings for the selected analogue channel.
        """
        ...

    @abc.abstractmethod
    def configure_digital_channel(
        self,
        channel: DigitalChannel,
        *,
        enabled: bool | UnchangedType = Unchanged,
        label: str | UnchangedType = Unchanged,
        threshold: float | UnchangedType = Unchanged,
    ) -> DigitalChannelSettings:
        """
        Configure a logic analyser channel and returns the resulting settings.

        Parameters set to `Unchanged` indicate that the currently configured
        value should be used.

        Parameters
        ----------

        channel:
            Logic analyser channel that should be configured.

        enabled:
            Set to `False` to disable acquisition from this channel.

        label:
            Label to display for this channel.

        threshold:
            Threshold level in volt for this channel. Note that the threshold
            voltage may not be independent.

        Returns
        -------

        The current settings for the selected digital channel.
        """
        ...

    @abc.abstractmethod
    def run(self, *, auto: bool = False) -> None:
        """
        Start continuous acquisition until `stop()` or `arm()` is called.

        Parameters
        ----------

        auto:
            If `True`, the scope also acquires in the absence of trigger events
            (auto sweep). Otherwise, it only acquires upon a trigger event
            (normal sweep).
        """
        ...

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop acquisition."""
        ...

    @abc.abstractmethod
    def arm(self) -> None:
        """
        Start a single-shot acquisition.

        This function returns once the scope waits for the trigger event.
        """
        ...

    @abc.abstractmethod
    def status(self) -> TriggerStatus:
        """
        Query the current trigger status.
        """
        ...

    @abc.abstractmethod
    def force_trigger(self) -> None:
        """
        Generate a trigger event regardless of the trigger condition.
        """
        ...

    @abc.abstractmethod
    def capture(self) -> Capture:
        """
        Wait until acquisition has stopped and download the captured data.
        """
        ...
