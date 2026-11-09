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

"""Implementation of the `Scope` interface for the Rigol MHO900 series."""

import contextlib
import enum
import logging
import queue
import socket
import threading
import time
import types
import typing

import numpy as np

from . import binfmt
from .errors import DiscoveryError, ScopeTimeoutError, ScpiError, SMBServerError
from .mdns import MDnsEndpoint, MDnsFilter
from .scope import (
    AnalogueChannel,
    AnalogueChannelSettings,
    AnalogueWaveform,
    Bandwidth,
    Capture,
    Coupling,
    DigitalChannel,
    DigitalChannelSettings,
    DigitalWaveform,
    Edge,
    EdgeTriggerSettings,
    HorizontalSettings,
    Identification,
    Impedance,
    Scope,
    TriggerStatus,
    Unchanged,
    UnchangedType,
)
from .scpi import Scpi
from .smb import MemoryBackend, VirtualSMBServer

log = logging.getLogger(__name__)

N_ANALOGUE_CHANNELS = 4
N_DIGITAL_CHANNELS = 16

_MEMORY_DEPTHS = (
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    125_000_000,
    200_000_000,
    250_000_000,
    500_000_000,
)

# The sample rate rules below were measured on an MHO984 with firmware
# 00.01.00 with auto roll mode disabled.

# Rate of the ADC; rates above 10 MSa/s are this divided by an integer.
_ADC_SAMPLE_RATE = 4e9

# Sample rates above 10 MSa/s that the scope falls back to.
_HIGH_SAMPLE_RATES = (4e9, 2e9, 1e9, 500e6, 250e6, 125e6, 50e6, 25e6, 10e6)

# Maximum sample rate and memory depth by the number of enabled analogue
# channels; the logic analyser does not count.
_MAX_SAMPLE_RATE = {0: 4e9, 1: 4e9, 2: 2e9, 3: 1e9, 4: 1e9}
_MAX_DEPTH = {0: 500_000_000, 1: 500_000_000, 2: 250_000_000, 3: 125_000_000}
_MAX_DEPTH[4] = _MAX_DEPTH[3]

# From this timebase, the scope ignores attempts to set memory depths below
# 1M, and raises the memory depth to 1M when switching to the timebase.
_SLOW_SWEEP_TIMEBASE = 200e-3
_SLOW_SWEEP_MIN_DEPTH = 1_000_000

# Resolution in normal mode, and the resolutions of the high-resolution mode,
# which averages neighbouring samples.
_ADC_BITS = 12
_RESOLUTION_BITS = (_ADC_BITS, 14, 16)
# 1 ns/div to 500 s/div.
_TIMEBASES = [m * 10.0**e for e in range(-9, 3) for m in (1, 2, 5)]

_SMB_SHARE = "RIGOL"  # Letters only (scope limitation).
_SMB_USER = "rigol"
_SMB_PASSWORD = "rigol"
_SMB_DRIVE = "I:/"  # Drive letter under which the scope mounts the share.
_SMB_FILENAME = "capture.bin"
_SMB_PORT = 445  # Default port, used if mount options are not injected.
_SMB_MOUNT_OPTIONS = ("cache=loose",)  # Speeds up transfers by ~15-25%

# Samples per `:WAVEFORM:DATA?` query in RAW mode. Larger reads are truncated
# to 1M samples and fail with "Command execute failed (-200)".
_WAV_CHUNK = 1_000_000
_WAV_ATTEMPTS = 3

# Transfer time model, fitted to captures of 1M to 500M samples of one channel
# at 10 MSa/s: a fixed overhead plus bytes per second. SCPI transfers two
# bytes per sample, the `.bin` file on the SMB share four (float32). With
# injected mount options, SMB was fitted to 1M-50M samples with the LA enabled.
_SCPI_OVERHEAD, _SCPI_BYTES_PER_S, _SCPI_BYTES_PER_SAMPLE = 0.7, 1.51e6, 2
_SMB_OVERHEAD, _SMB_BYTES_PER_S, _SMB_BYTES_PER_SAMPLE = 6.5, 6.7e6, 4
_SMB_INJECTED_OVERHEAD, _SMB_INJECTED_BYTES_PER_S = 6.7, 7.9e6

# Seconds to wait for the scope to complete "*RST".
_RESET_TIMEOUT = 60.0

_T = typing.TypeVar("_T")

# Command parameters and the corresponding query responses.
_BOOL = {True: ("ON", "1"), False: ("OFF", "0")}
_IMPEDANCE = {Impedance.HIGH: ("OMEG", "OMEG"), Impedance.LOW: ("FIFTY", "FIFT")}
_COUPLING = {c: (c.value, c.value) for c in Coupling}
_BANDWIDTH = {
    Bandwidth.MAX: ("OFF", "OFF"),
    Bandwidth.MHZ_250: ("250M", "250M"),
    Bandwidth.MHZ_20: ("20M", "20M"),
}
_EDGE = {
    Edge.RISING: ("POSITIVE", "POS"),
    Edge.FALLING: ("NEGATIVE", "NEG"),
    Edge.BOTH: ("RFALL", "RFAL"),
}


class TransferMode(enum.Enum):
    """How `MHO900.capture()` reads the record from the scope."""

    AUTO = "AUTO"
    """`SMB` if the logic analyser is enabled; otherwise, whichever of `SMB`
    and `SCPI` is expected to be faster. Falls back to `SCPI` if the SMB
    server cannot be started and the logic analyser is disabled."""

    SMB = "SMB"
    """Save the record as a `.bin` file to a virtual SMB share. Faster for
    long records, and the only way to read the logic analyser data."""

    SCPI = "SCPI"
    """Read the analogue channels via `:WAVEFORM:DATA?`. Faster for short
    records; cannot read the logic analyser data."""


def _transfer_time(
    mode: TransferMode, n_samples: int, *, inject_mount_options: bool
) -> float:
    """
    Expected seconds to read `n_samples` samples (summed over all channels)
    with `mode` (`SMB` or `SCPI`).
    """
    if mode == TransferMode.SMB:
        overhead, rate = _SMB_OVERHEAD, _SMB_BYTES_PER_S
        if inject_mount_options:
            overhead, rate = _SMB_INJECTED_OVERHEAD, _SMB_INJECTED_BYTES_PER_S
        return overhead + n_samples * _SMB_BYTES_PER_SAMPLE / rate
    return _SCPI_OVERHEAD + n_samples * _SCPI_BYTES_PER_SAMPLE / _SCPI_BYTES_PER_S


def _unprivileged_port_hint() -> str:
    """Explain how to allow binding `_SMB_PORT` without root privileges."""
    cmd = f"sudo sysctl -w net.ipv4.ip_unprivileged_port_start={_SMB_PORT}"
    try:
        with open("/proc/sys/net/ipv4/ip_unprivileged_port_start") as f:
            start = int(f.read())
    except (OSError, ValueError):
        return (
            f"Port {_SMB_PORT} is privileged on this system. On Linux, run"
            f" `{cmd}` to allow unprivileged processes to use it."
        )
    return (
        f"Ports below {start} are privileged on this system"
        " (net.ipv4.ip_unprivileged_port_start). Run"
        f" `{cmd}` to allow unprivileged processes to use port {_SMB_PORT}."
    )


def _sample_rate(depth: int, timebase: float, n_channels: int) -> float | None:
    """
    Compute the sample rate the scope selects.

    This function takes the given memory depth, timebase and number of enabled
    analogue channels. Return `None` if values are out-of-range for the model.

    The scope selects the rate at which the memory depth covers the ten screen
    divisions, if it supports it: any rate up to 10 MSa/s, and rates for which
    the ADC rate divided by the rate is a power of two or a multiple of 16.
    Otherwise, it falls back to the next lower rate in `_HIGH_SAMPLE_RATES`;
    then, the record exceeds the screen.
    """
    eps = 1e-9
    if timebase >= _SLOW_SWEEP_TIMEBASE * (1 - eps) and depth < _SLOW_SWEEP_MIN_DEPTH:
        return None
    if timebase > _TIMEBASES[-1] * (1 + eps):
        return None
    limit = min(_MAX_SAMPLE_RATE[n_channels], depth / (10 * timebase))
    if limit <= 10e6 * (1 + eps):
        return limit
    div = _ADC_SAMPLE_RATE / limit
    if abs(div - round(div)) <= eps * div:
        div = round(div)
        if div % 16 == 0 or div & (div - 1) == 0:
            return limit
    return next(r for r in _HIGH_SAMPLE_RATES if r <= limit * (1 + eps))


class MHO900(Scope):
    """
    Rigol MHO900 series oscilloscope connected via raw SCPI (TCP port 5555).

    Captures without the logic analyser are read via `:WAVEFORM:DATA?`. On the
    first capture with the logic analyser enabled, starts a virtual SMB server
    and connects the scope to it, since the logic analyser data is only
    available in `.bin` files. Call `close()` (or use this object as a context
    manager) to disconnect the scope from the share and to stop the server.
    """

    AnalogueChannel = AnalogueChannel
    DigitalChannel = DigitalChannel
    Bandwidth = Bandwidth
    Coupling = Coupling
    Edge = Edge
    TriggerStatus = TriggerStatus
    TransferMode = TransferMode
    Impedance = Impedance

    def __init__(
        self,
        addr: str | None = None,
        port: int = 5555,
        *,
        serial_number: str | None = None,
        host_addr: str | None = None,
        timeout: float = 10.0,
        capture_timeout: float = 10.0,
        save_timeout: float = 600.0,
        inject_mount_options: bool = True,
    ):
        """
        Parameters
        ----------

        addr:
            IP address or hostname of the scope. If `None`, searches for a
            single Rigol scope via mDNS.

        port:
            Raw SCPI port of the scope.

        serial_number:
            Serial number of the scope to search for via mDNS (case
            insensitive). Mutually exclusive with `addr`.

        host_addr:
            IP address of this machine as seen by the scope. Determined
            automatically if `None`.

        timeout:
            Timeout in seconds for SCPI queries, for arming, and for the scope
            to start writing the capture to the SMB share.

        capture_timeout:
            Seconds to wait for the scope to trigger in `capture()`.

        save_timeout:
            Seconds to wait for the scope to write the logic analyser data
            to the SMB share.

        inject_mount_options:
            If `True`, append extra options for the scope's CIFS mount to the
            SMB password: run the SMB server on a free unprivileged port and
            enable client-side write caching. If `False`, use the scope's
            default mount, which requires port 445; disable this if a firmware
            update breaks the injection.
        """
        if addr is not None and serial_number is not None:
            raise ValueError("`addr` and `serial_number` are mutually exclusive")
        if addr is None:
            # The port is not taken from mDNS; the scope advertises port 80
            # for its raw SCPI service (firmware 00.01.00.00.26).
            endpoints = MDnsEndpoint.find(
                MDnsFilter(
                    manufacturer="Rigol Technologies", serial_number=serial_number
                )
            )
            if len(endpoints) != 1:
                what = "Rigol scope"
                if serial_number is not None:
                    what += f" with serial number {serial_number}"
                raise DiscoveryError(
                    f"Expected one {what} via mDNS, found {len(endpoints)}"
                    " (check that mDNS is enabled in the scope's LAN settings)"
                )
            addr = endpoints[0].addr
            log.info(
                "Found %s (%s) at %s",
                endpoints[0].model,
                endpoints[0].serial_number,
                addr,
            )

        self._timeout = timeout
        self._capture_timeout = capture_timeout
        self._save_timeout = save_timeout
        self._inject_mount_options = inject_mount_options
        self._files: queue.Queue[bytearray] = queue.Queue()
        self._created = threading.Event()
        self._smb_connected = False
        self._smb: VirtualSMBServer | None = None

        if host_addr is None:
            # Address of the interface used to reach the scope. UDP connect
            # does not send any packets.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((addr, 9))
                host_addr = s.getsockname()[0]
        self._unc = f"\\\\{host_addr}\\{_SMB_SHARE}"
        self._scpi = Scpi(addr, port, timeout=timeout)

    def close(self) -> None:
        try:
            if self._smb_connected:
                with self._scpi as scpi:
                    scpi(":SAVE:SMB:DISCONNECT")
                    self._wait_smb_state(scpi, False)
                self._smb_connected = False
        finally:
            self._scpi.close()
            if self._smb is not None:
                self._smb.stop()
                self._smb = None

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        self.close()

    ###########################################################################
    # Scope interface                                                         #
    ###########################################################################

    def identify(self) -> Identification:
        with self._scpi as scpi:
            res = scpi("*IDN?").decode()
        fields = [field.strip() for field in res.split(",")]
        if len(fields) != 4:
            raise ScpiError(f"Invalid *IDN? response {res!r}")
        return Identification(*fields)

    def reset(self) -> None:
        with self._scpi as scpi:
            scpi("*RST")
            scpi("*OPC?")
            # The reset completes asynchronously: the scope reports "STOP" for
            # a few seconds (about 8 s after a 500M record) and then starts
            # running. A ":STOP" before that is lost.
            with contextlib.suppress(ScopeTimeoutError):  # Missed the reset phase.
                self._poll(scpi, ":TRIGGER:STATUS?", lambda x: x == b"STOP", b"STOP")
            self._poll(
                scpi,
                ":TRIGGER:STATUS?",
                lambda x: x != b"STOP",
                "not STOP",
                timeout=_RESET_TIMEOUT,
            )
            scpi(":STOP")
            self._poll(scpi, ":TRIGGER:STATUS?", lambda x: x == b"STOP", b"STOP")
            for channel in range(N_ANALOGUE_CHANNELS):
                scpi(f":CHANNEL{channel + 1}:DISPLAY", "OFF")
            scpi(":LA:ENABLE", "OFF")

    def configure_horizontal(
        self,
        *,
        min_n_samples: int | UnchangedType = Unchanged,
        min_sample_rate: float | UnchangedType = Unchanged,
        t_offset: float | UnchangedType = Unchanged,
        resolution_bits: int | UnchangedType = Unchanged,
    ) -> HorizontalSettings:
        if resolution_bits is not Unchanged and resolution_bits not in _RESOLUTION_BITS:
            raise ValueError(
                f"resolution_bits={resolution_bits} must be one of"
                f" {', '.join(map(str, _RESOLUTION_BITS))}"
            )
        with self._scpi as scpi:
            n_channels = sum(
                scpi(f":CHANNEL{c + 1}:DISPLAY?") == b"1"
                for c in range(N_ANALOGUE_CHANNELS)
            )
            self._disable_roll(scpi)
            if resolution_bits == _ADC_BITS:
                self._apply(scpi, ":ACQUIRE:TYPE", ("NORMAL", "NORM"))
            elif resolution_bits is not Unchanged:
                self._apply(scpi, ":ACQUIRE:TYPE", ("HRESOLUTION", "HRES"))
                scpi(":ACQUIRE:BITS", resolution_bits)
                self._expect(scpi, ":ACQUIRE:BITS?", resolution_bits)
            if min_n_samples is not Unchanged:
                depth = next((d for d in _MEMORY_DEPTHS if d >= min_n_samples), None)
                if depth is None or depth > _MAX_DEPTH[n_channels]:
                    raise ValueError(
                        f"min_n_samples={min_n_samples} is too large; the maximum"
                        f" with {n_channels} enabled analogue channel(s) is"
                        f" {_MAX_DEPTH[n_channels]}"
                    )
            else:
                res = scpi(":ACQUIRE:MDEPTH?")
                depth = None if res == b"AUTO" else int(float(res))

            # `:ACQUIRE:SRATE?` only follows setting changes while the scope is
            # running. Compute the rate the scope selects instead. The scope
            # records the full memory depth even if it exceeds the screen.

            def sample_rate(timebase: float) -> float | None:
                if depth is None:
                    return None
                return _sample_rate(depth, timebase, n_channels)

            timebase = float(scpi(":TIMEBASE:MAIN:SCALE?"))
            if min_sample_rate is not Unchanged:
                if depth is None:
                    raise ValueError("Requires a fixed memory depth; set min_n_samples")
                timebase = max(
                    (
                        tb
                        for tb in _TIMEBASES
                        if (sample_rate(tb) or 0.0) >= min_sample_rate * (1 - 1e-6)
                    ),
                    default=None,
                )
                if timebase is None:
                    raise ValueError(f"min_sample_rate={min_sample_rate} is too high")

            slow = timebase >= _SLOW_SWEEP_TIMEBASE * (1 - 1e-9)
            if slow and depth is not None and depth < _SLOW_SWEEP_MIN_DEPTH:
                raise ValueError(
                    f"Timebases from {_SLOW_SWEEP_TIMEBASE} s/div require at least"
                    f" {_SLOW_SWEEP_MIN_DEPTH} samples; set min_n_samples"
                )

            def apply_depth() -> None:
                if min_n_samples is not Unchanged and depth is not None:
                    scpi(":ACQUIRE:MDEPTH", depth)
                    self._expect(scpi, ":ACQUIRE:MDEPTH?", depth)

            def apply_timebase() -> None:
                if min_sample_rate is not Unchanged:
                    scpi(":TIMEBASE:VERNIER", "OFF")
                    scpi(":TIMEBASE:MAIN:SCALE", timebase)
                    self._expect(scpi, ":TIMEBASE:MAIN:SCALE?", timebase)

            rate = sample_rate(timebase)
            record = None if depth is None or rate is None else depth / rate
            if t_offset is not Unchanged and record is None:
                raise ValueError(
                    "Cannot set t_offset; requires a fixed memory depth of at"
                    f" least {_SLOW_SWEEP_MIN_DEPTH} for timebases from"
                    f" {_SLOW_SWEEP_TIMEBASE} s/div"
                )

            # While stopped, the scope only zooms and pans within the last
            # record; e.g., it ignores timebases below two sample intervals of
            # that record. Apply the changes while running instead.
            stopped = scpi(":TRIGGER:STATUS?") == b"STOP"
            restart = stopped and (
                min_sample_rate is not Unchanged or t_offset is not Unchanged
            )
            if restart:
                scpi(":RUN")
            try:
                # Order the changes such that the scope never sees a memory
                # depth below 1M together with a slow timebase.
                if slow:
                    apply_depth()
                    apply_timebase()
                else:
                    apply_timebase()
                    apply_depth()

                if t_offset is not Unchanged and record is not None:
                    # Without an offset, the trigger is in the middle of the
                    # record.
                    offset = record / 2 - t_offset
                    scpi(":TIMEBASE:MAIN:OFFSET", offset)
                    self._expect(scpi, ":TIMEBASE:MAIN:OFFSET?", offset)
            finally:
                if restart:
                    scpi(":STOP")

            return HorizontalSettings(
                n_samples=depth,
                sample_rate=rate,
                t_offset=None
                if record is None
                else record / 2 - float(scpi(":TIMEBASE:MAIN:OFFSET?")),
                resolution_bits=int(scpi(":ACQUIRE:BITS?"))
                if scpi(":ACQUIRE:TYPE?") == b"HRES"
                else _ADC_BITS,
            )

    def configure_edge_trigger(
        self,
        channel: AnalogueChannel | DigitalChannel,
        *,
        level: float | UnchangedType | None = Unchanged,
        edge: Edge | UnchangedType = Unchanged,
    ) -> EdgeTriggerSettings:
        analogue = isinstance(channel, AnalogueChannel)
        if analogue and level is None:
            raise ValueError("Analogue channels require a trigger level")
        if not analogue and level not in (None, Unchanged):
            raise ValueError("Digital channels have no trigger level; use None")
        if analogue:
            source = (f"CHANNEL{channel.idx + 1}", f"CHAN{channel.idx + 1}")
        else:
            source = (f"D{channel.idx}", f"D{channel.idx}")
        with self._scpi as scpi:
            self._apply(scpi, ":TRIGGER:MODE", ("EDGE", "EDGE"))
            self._apply(scpi, ":TRIGGER:EDGE:SOURCE", source)
            if edge is not Unchanged:
                self._apply(scpi, ":TRIGGER:EDGE:SLOPE", _EDGE[edge])
            if level is not None and level is not Unchanged:
                scpi(":TRIGGER:EDGE:LEVEL", level)
                self._expect(scpi, ":TRIGGER:EDGE:LEVEL?", level)

            return EdgeTriggerSettings(
                channel=channel,
                level=float(scpi(":TRIGGER:EDGE:LEVEL?")) if analogue else None,
                edge=self._parse(_EDGE, scpi(":TRIGGER:EDGE:SLOPE?")),
            )

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
        prefix = f":CHANNEL{channel.idx + 1}"
        with self._scpi as scpi:
            if enabled is not Unchanged:
                self._apply(scpi, f"{prefix}:DISPLAY", _BOOL[enabled])
            if impedance is not Unchanged:
                self._apply(scpi, f"{prefix}:IMPEDANCE", _IMPEDANCE[impedance])
            if probe_scale is not Unchanged:
                scpi(f"{prefix}:PROBE", probe_scale)
                self._expect(scpi, f"{prefix}:PROBE?", probe_scale)
            if coupling is not Unchanged:
                self._apply(scpi, f"{prefix}:COUPLING", _COUPLING[coupling])
            if bandwidth is not Unchanged:
                self._apply(scpi, f"{prefix}:BWLIMIT", _BANDWIDTH[bandwidth])
            if scale is not Unchanged:
                scpi(f"{prefix}:VERNIER", "ON")
                scpi(f"{prefix}:SCALE", scale)
                self._expect(scpi, f"{prefix}:SCALE?", scale)
            if offset is not Unchanged:
                scpi(f"{prefix}:OFFSET", offset)
                self._expect(scpi, f"{prefix}:OFFSET?", offset)

            return AnalogueChannelSettings(
                channel=channel,
                enabled=self._parse(_BOOL, scpi(f"{prefix}:DISPLAY?")),
                scale=float(scpi(f"{prefix}:SCALE?")),
                offset=float(scpi(f"{prefix}:OFFSET?")),
                probe_scale=float(scpi(f"{prefix}:PROBE?")),
                impedance=self._parse(_IMPEDANCE, scpi(f"{prefix}:IMPEDANCE?")),
                coupling=self._parse(_COUPLING, scpi(f"{prefix}:COUPLING?")),
                bandwidth=self._parse(_BANDWIDTH, scpi(f"{prefix}:BWLIMIT?")),
            )

    def configure_digital_channel(
        self,
        channel: DigitalChannel,
        *,
        enabled: bool | UnchangedType = Unchanged,
        label: str | UnchangedType = Unchanged,
        threshold: float | UnchangedType = Unchanged,
    ) -> DigitalChannelSettings:
        name = f"D{channel.idx}"
        # One threshold per pod of eight channels.
        pod = f":LA:POD{channel.idx // 8 + 1}"
        with self._scpi as scpi:
            if enabled is not Unchanged:
                if enabled and not self._parse(_BOOL, scpi(":LA:ENABLE?")):
                    self._apply(scpi, ":LA:ENABLE", _BOOL[True])
                    for other_idx in range(N_DIGITAL_CHANNELS):
                        if other_idx != channel.idx:
                            other = f"D{other_idx}"
                            self._apply(scpi, ":LA:DIGITAL:ENABLE", _BOOL[False], other)
                self._apply(scpi, ":LA:DIGITAL:ENABLE", _BOOL[enabled], name)
            if label is not Unchanged:
                self._apply(scpi, ":LA:DIGITAL:LABEL", (label, label), name)
            if threshold is not Unchanged:
                scpi(f"{pod}:THRESHOLD", threshold)
                self._expect(scpi, f"{pod}:THRESHOLD?", threshold)

            return DigitalChannelSettings(
                channel=channel,
                enabled=self._parse(_BOOL, scpi(":LA:ENABLE?"))
                and self._parse(_BOOL, scpi(":LA:DIGITAL:ENABLE?", name)),
                label=scpi(":LA:DIGITAL:LABEL?", name).decode(),
                threshold=float(scpi(f"{pod}:THRESHOLD?")),
            )

    def run(self, *, auto: bool = False) -> None:
        with self._scpi as scpi:
            scpi(":TRIGGER:SWEEP", "AUTO" if auto else "NORMAL")
            scpi(":RUN")

    def stop(self) -> None:
        with self._scpi as scpi:
            scpi(":STOP")

    def arm(self) -> None:
        with self._scpi as scpi:
            self._disable_roll(scpi)
            # The scope records the data before the trigger point before it
            # waits for the trigger; triggers in that time are ignored.
            record = self._record_time(scpi)
            offset = float(scpi(":TIMEBASE:MAIN:OFFSET?"))
            t_pre = min(record, max(0.0, record / 2 - offset))
            scpi(":SINGLE")
            t_start = time.monotonic()
            deadline = t_start + self._timeout + t_pre
            # Right after ":SINGLE", the trigger status may still report the
            # previous "STOP", or report "WAIT" before recording the data
            # before the trigger point. A "STOP" after any other status means
            # that the scope already triggered.
            started = False
            last = None
            while True:
                status = self._status(scpi)
                elapsed = time.monotonic() - t_start
                if status != last:
                    log.debug("Trigger status %s after %.2f s", status.name, elapsed)
                    last = status
                if status == TriggerStatus.WAIT and elapsed >= 0.95 * t_pre:
                    break
                if status != TriggerStatus.STOP:
                    started = True
                elif started:
                    break
                if time.monotonic() > deadline:
                    raise ScopeTimeoutError(f"Scope did not arm (status {status.name})")
                time.sleep(0.05)

    def status(self) -> TriggerStatus:
        with self._scpi as scpi:
            return self._status(scpi)

    def force_trigger(self) -> None:
        with self._scpi as scpi:
            scpi(":TFORCE")

    def capture(self, *, transfer_mode: TransferMode = TransferMode.AUTO) -> Capture:
        """
        See `Scope.capture()`.

        Parameters
        ----------

        transfer_mode:
            How to read the record from the scope; see `TransferMode`.
            `TransferMode.SCPI` raises `ValueError` if the logic analyser is
            enabled.
        """
        with self._scpi as scpi:
            la_enabled = self._parse(_BOOL, scpi(":LA:ENABLE?"))
            if transfer_mode == TransferMode.SCPI and la_enabled:
                raise ValueError(
                    "TransferMode.SCPI cannot read the logic analyser data;"
                    " disable the logic analyser or use TransferMode.SMB"
                )
            # After the trigger, the scope records the data after the trigger
            # point.
            self._poll(
                scpi,
                ":TRIGGER:STATUS?",
                lambda x: x == b"STOP",
                b"STOP",
                self._capture_timeout + self._record_time(scpi),
            )
            log.info("Acquisition complete")

            depth = scpi(":ACQUIRE:MDEPTH?")
            if depth == b"AUTO":
                raise ValueError("Requires a fixed memory depth; set min_n_samples")
            n_samples = int(float(depth))

            # The logic analyser data is only available in `.bin` files, which
            # the scope can only save to a (network) drive.
            if transfer_mode == TransferMode.AUTO:
                n_channels = sum(
                    scpi(f":CHANNEL{c + 1}:DISPLAY?") == b"1"
                    for c in range(N_ANALOGUE_CHANNELS)
                )
                n_total = n_channels * n_samples
                inject = self._inject_mount_options
                smb_faster = _transfer_time(
                    TransferMode.SMB, n_total, inject_mount_options=inject
                ) < _transfer_time(
                    TransferMode.SCPI, n_total, inject_mount_options=inject
                )
                if la_enabled:
                    return self._capture_smb(scpi, n_samples)
                if smb_faster:
                    try:
                        return self._capture_smb(scpi, n_samples)
                    except SMBServerError as e:
                        log.warning("%s Falling back to SCPI.", e)
                return self._capture_scpi(scpi, n_samples)
            if transfer_mode == TransferMode.SMB:
                return self._capture_smb(scpi, n_samples)
            return self._capture_scpi(scpi, n_samples)

    def _capture_scpi(self, scpi: Scpi, n_samples: int) -> Capture:
        """Reads all enabled analogue channels via `:WAVEFORM:DATA?`."""
        is_average = scpi(":ACQUIRE:TYPE?") == b"AVER"
        analogue = {}
        for idx in range(N_ANALOGUE_CHANNELS):
            if scpi(f":CHANNEL{idx + 1}:DISPLAY?") != b"1":
                continue
            ch = AnalogueChannel(idx)
            scpi(":WAVEFORM:SOURCE", f"CHANNEL{idx + 1}")
            scpi(":WAVEFORM:MODE", "RAW")
            scpi(":WAVEFORM:FORMAT", "WORD")
            raw = np.empty(n_samples, dtype=np.uint16)
            pre = None
            for start in range(0, n_samples, _WAV_CHUNK):
                stop = min(start + _WAV_CHUNK, n_samples)
                scpi(":WAVEFORM:START", start + 1)
                scpi(":WAVEFORM:STOP", stop)
                if pre is None:
                    # Preamble of the first chunk, whose x origin is the time
                    # of the first sample.
                    pre = scpi(":WAVEFORM:PREAMBLE?").split(b",")
                    if len(pre) != 10:
                        raise ScpiError(f"Invalid preamble {bytes(b','.join(pre))!r}")
                # The scope rarely returns an empty block (once while reading
                # 500M samples); repeat the query in that case.
                for attempt in range(_WAV_ATTEMPTS):
                    chunk = scpi(":WAVEFORM:DATA?", binary_response=True)
                    if len(chunk) == 2 * (stop - start):
                        break
                    log.warning(
                        "Expected %d samples from %s at %d, got %d (attempt %d)",
                        stop - start,
                        ch,
                        start,
                        len(chunk) // 2,
                        attempt + 1,
                    )
                else:
                    raise ScpiError(
                        f"Expected {stop - start} samples from {ch} at {start}, got"
                        f" {len(chunk) // 2}"
                    )
                raw[start:stop] = np.frombuffer(chunk, dtype="<u2")
                if (
                    n_samples >= 10 * _WAV_CHUNK
                    and (stop * 10) // n_samples > (start * 10) // n_samples
                ):
                    log.info("Read %d of %d samples from %s", stop, n_samples, ch)
            assert pre is not None
            count = int(pre[3])
            x_inc, x_origin, x_ref, y_inc, y_origin, y_ref = map(float, pre[4:])
            log.info("Read %d samples from %s", n_samples, ch)
            # Convert in place to avoid float64 temporaries for long records.
            data = raw.astype(np.float32)
            del raw
            data -= y_origin + y_ref
            data *= y_inc
            analogue[ch] = AnalogueWaveform(
                channel=ch,
                data=data,
                t_base=x_origin - x_ref * x_inc,
                t_inc=x_inc,
                n_average=count if is_average else 1,
            )
        return Capture(analogue_channels=analogue, digital_waveform=None)

    def _capture_smb(self, scpi: Scpi, n_samples: int) -> Capture:
        """Saves the memory waveform as a `.bin` file to the SMB share."""
        # Before the first capture, the scope may still be connected to
        # another share.
        if not self._smb_connected or scpi(":SAVE:SMB:CONSTATE?") != b"1":
            self._connect_smb(scpi)

        # A save issued while a previous one is still finishing is silently
        # dropped by the scope.
        self._wait_save_idle(scpi)
        self._created.clear()
        scpi(":SAVE:MEMORY:WAVEFORM", _SMB_DRIVE + _SMB_FILENAME)
        try:
            # The scope ignores saves it cannot do without reporting an error,
            # so do not wait for the full timeout unless it starts writing.
            if not self._created.wait(self._timeout):
                raise ScopeTimeoutError("Scope did not start writing the waveform file")
            try:
                buf = self._files.get(timeout=self._save_timeout)
            except queue.Empty:
                raise ScopeTimeoutError(
                    "Scope did not finish writing the waveform file"
                ) from None

            # The scope keeps the save "in progress" for a few seconds after
            # the file is closed; disconnecting or saving in that time aborts
            # it.
            self._wait_save_idle(scpi)
        finally:
            while not self._files.empty():
                self._files.get_nowait()
        waveforms = binfmt.parse(buf)

        # The LA x increment in the file is wrong. The LA covers the same time
        # span as the analogue record.
        record = n_samples / float(scpi(":ACQUIRE:SRATE?"))

        analogue = {}
        digital = None
        for wfm in waveforms:
            if wfm.buf_type == binfmt.BUFFER_TYPE_LOGIC:
                digital = DigitalWaveform(
                    data=wfm.data.astype(np.uint16),
                    t_base=wfm.x_origin,
                    t_inc=record / len(wfm.data),
                    n_channels=N_DIGITAL_CHANNELS,
                )
            elif m := binfmt.ANALOGUE_CHANNEL_NAME.fullmatch(wfm.name):
                ch = AnalogueChannel(int(m[1]) - 1)
                is_average = wfm.wfm_type == binfmt.WFM_TYPE_AVERAGE
                analogue[ch] = AnalogueWaveform(
                    channel=ch,
                    data=wfm.data.astype(np.float32),
                    t_base=wfm.x_origin,
                    t_inc=wfm.x_inc,
                    n_average=wfm.count if is_average else 1,
                )
            else:
                log.warning("Ignoring waveform %r in .bin file", wfm.name)
        return Capture(analogue_channels=analogue, digital_waveform=digital)

    ###########################################################################
    # SMB helpers                                                             #
    ###########################################################################

    def _on_create(self, name: str) -> None:
        log.info("Scope is writing %s", name)
        self._created.set()

    def _on_file(self, name: str, data: bytearray) -> None:
        log.info("Received %s (%d bytes)", name, len(data))
        self._files.put(data)

    def _connect_smb(self, scpi: Scpi) -> None:
        if self._smb is None:
            try:
                self._smb = VirtualSMBServer(
                    MemoryBackend(self._on_file, self._on_create),
                    share=_SMB_SHARE,
                    user=_SMB_USER,
                    password=_SMB_PASSWORD,
                    port=0 if self._inject_mount_options else _SMB_PORT,
                    max_mpx_count=50 if self._inject_mount_options else 1,
                    large_read_write=self._inject_mount_options,
                )
            except PermissionError as e:
                raise SMBServerError(
                    e.errno,
                    f"Cannot listen on TCP port {_SMB_PORT}, which is required to"
                    " receive data from the scope via SMB (always needed for logic"
                    " analyser data)."
                    f" {_unprivileged_port_hint()}",
                ) from e
            self._smb.start()
        if scpi(":SAVE:SMB:CONSTATE?") == b"1":
            log.info("Scope already connected to an SMB share, disconnecting")
            scpi(":SAVE:SMB:DISCONNECT")
            self._wait_smb_state(scpi, False)
        scpi(":SAVE:SMB:SERVERPATH", self._unc)
        scpi(":SAVE:SMB:USERNAME", _SMB_USER)
        password = _SMB_PASSWORD
        if self._inject_mount_options:
            options = (f"port={self._smb.port}", *_SMB_MOUNT_OPTIONS)
            password += "".join(f" -o {o}" for o in options)
        scpi(":SAVE:SMB:PASSWORD", password)
        scpi(":SAVE:SMB:CONNECT")
        self._wait_smb_state(scpi, True, timeout=20.0)
        self._smb_connected = True
        log.info("Scope connected to %s (port %d)", self._unc, self._smb.port)

    @staticmethod
    def _wait_smb_state(scpi: Scpi, connected: bool, timeout: float = 10.0) -> None:
        state = b"1" if connected else b"0"
        MHO900._poll(scpi, ":SAVE:SMB:CONSTATE?", lambda x: x == state, state, timeout)

    def _wait_save_idle(self, scpi: Scpi) -> None:
        self._poll(scpi, ":SAVE:STATUS?", lambda x: x == b"1", b"1", self._save_timeout)

    ###########################################################################
    # SCPI helpers                                                            #
    ###########################################################################

    @staticmethod
    def _status(scpi: Scpi) -> TriggerStatus:
        res = scpi(":TRIGGER:STATUS?")
        if res == b"TD":
            return TriggerStatus.TRIGGERED
        try:
            return TriggerStatus(res.decode())
        except ValueError:
            raise ScpiError(f"Unexpected trigger status {res!r}") from None

    @staticmethod
    def _disable_roll(scpi: Scpi) -> None:
        """
        Disables the auto roll mode, in which the scope does not trigger.
        Setting the roll mode resets the trigger offset, so only do it if
        necessary.
        """
        if scpi(":TIMEBASE:ROLL?") != b"0":
            MHO900._apply(scpi, ":TIMEBASE:ROLL", ("0", "0"))

    @staticmethod
    def _record_time(scpi: Scpi) -> float:
        """
        Duration of the record in seconds for the current settings. Falls back
        to the duration of the screen if the sample rate is unknown.
        """
        timebase = float(scpi(":TIMEBASE:MAIN:SCALE?"))
        res = scpi(":ACQUIRE:MDEPTH?")
        n_channels = sum(
            scpi(f":CHANNEL{c + 1}:DISPLAY?") == b"1"
            for c in range(N_ANALOGUE_CHANNELS)
        )
        if res != b"AUTO":
            depth = int(float(res))
            rate = _sample_rate(depth, timebase, n_channels)
            if rate is not None:
                return depth / rate
        return 10 * timebase

    @staticmethod
    def _poll(
        scpi: Scpi,
        query: str,
        pred: typing.Callable[[bytes], bool],
        expected: object,
        timeout: float = 2.0,
        args: tuple[str, ...] = (),
    ) -> None:
        """Repeats `query` until `pred` holds for its response."""
        deadline = time.monotonic() + timeout
        while not pred(res := scpi(query, *args)):
            if time.monotonic() > deadline:
                raise ScopeTimeoutError(
                    f"{query} returned {res!r}, expected {expected}"
                )
            time.sleep(0.05)

    @staticmethod
    def _expect(scpi: Scpi, query: str, value: float | str, *args: str) -> None:
        """
        Raises if the scope did not apply `value`. Derived settings update with
        a delay, so the query is repeated for up to two seconds. `args` are the
        query arguments.
        """
        if isinstance(value, str):
            pred = lambda x: x == value.encode()
        else:
            pred = lambda x: abs(float(x) - value) <= 1e-6 * abs(value)
        MHO900._poll(scpi, query, pred, value, args=args)

    @staticmethod
    def _apply(scpi: Scpi, cmd: str, value: tuple[str, str], *args: str) -> None:
        """
        Sends `cmd` with `args` and the parameter `value[0]`, then checks that
        the query returns `value[1]`.
        """
        scpi(cmd, *args, value[0])
        MHO900._expect(scpi, cmd + "?", value[1], *args)

    @staticmethod
    def _parse(table: dict[_T, tuple[str, str]], res: bytes) -> _T:
        """Returns the key in `table` whose query response is `res`."""
        for key, (_, response) in table.items():
            if response.encode() == res:
                return key
        raise ScpiError(f"Unexpected response {res!r}")
