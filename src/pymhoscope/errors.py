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

"""Exceptions raised by pymhoscope."""


class MHOScopeError(Exception):
    """Base class of all pymhoscope errors."""


class ScpiError(MHOScopeError):
    """The scope reported an error or sent a malformed SCPI response."""


class ScopeTimeoutError(MHOScopeError, TimeoutError):
    """The scope did not respond or reach the expected state in time."""


class DiscoveryError(MHOScopeError, LookupError):
    """No unique scope was found via mDNS."""


class BinFormatError(MHOScopeError, ValueError):
    """A Rigol `.bin` waveform file is malformed."""


class SMBServerError(MHOScopeError, OSError):
    """The virtual SMB server used to receive logic analyser data failed to start."""
