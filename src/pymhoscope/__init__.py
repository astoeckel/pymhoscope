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

"""
Capture analogue and logic analyser data from Rigol MHO900 series
oscilloscopes.
"""

from importlib.metadata import version

from .errors import (
    BinFormatError,
    DiscoveryError,
    MHOScopeError,
    ScopeTimeoutError,
    ScpiError,
    SMBServerError,
)
from .mdns import MDnsEndpoint, MDnsFilter
from .mho900 import MHO900, TransferMode
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

__version__ = version(__name__)

__all__ = [
    "MHO900",
    "AnalogueChannel",
    "AnalogueChannelSettings",
    "AnalogueWaveform",
    "Bandwidth",
    "BinFormatError",
    "Capture",
    "Coupling",
    "DigitalChannel",
    "DigitalChannelSettings",
    "DigitalWaveform",
    "DiscoveryError",
    "Edge",
    "EdgeTriggerSettings",
    "HorizontalSettings",
    "Identification",
    "Impedance",
    "MDnsEndpoint",
    "MDnsFilter",
    "MHOScopeError",
    "SMBServerError",
    "Scope",
    "ScopeTimeoutError",
    "Scpi",
    "ScpiError",
    "TransferMode",
    "TriggerStatus",
    "Unchanged",
    "UnchangedType",
]
