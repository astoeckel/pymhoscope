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
Parser for Rigol ".bin" waveform files (`:SAVE:MEM:WAV x.bin`).

Layout (little endian):

```txt
file header (16 bytes)
    char[2]  cookie "RG"
    char[2]  version, e.g. "03"
    u64      file size
    u32      number of waveforms
per waveform:
    waveform header (header_size bytes, 140 on the MHO900)
        u32  header_size
        u32  waveform type (1 normal, 2 peak, 3 average, 6 logic)
        u32  number of buffers
        u32  n_pts
        u32  count
        f32  x display range
        f64  x display origin
        f64  x increment [s]
        f64  x origin [s]
        u32  x units, u32 y units
        char[16] date, char[16] time, char[24] model, char[16] channel name
        (padding up to header_size)
    data header (header_size bytes, 16)
        u32  header_size
        u16  buffer type (1-3: float32 volts, 5: logic)
        u16  bytes per point
        u64  buffer size
    n_pts * bytes_per_point bytes of samples
```
"""

import dataclasses
import re
import struct

import numpy as np
import numpy.typing as npt

from .errors import BinFormatError

_FILE_HEADER = struct.Struct("<2s2sQI")
_WFM_HEADER = struct.Struct("<IIIIIfdddII16s16s24s16s")
_DATA_HEADER = struct.Struct("<IHHQ")

WFM_TYPE_AVERAGE = 3
BUFFER_TYPE_LOGIC = 5

ANALOGUE_CHANNEL_NAME = re.compile(r"CH(\d+)")


@dataclasses.dataclass
class Waveform:
    """
    Single waveform stored in a `.bin` file.

    Attributes
    ----------

    name:
        Channel name, e.g. `CH1` for analogue channels.

    wfm_type:
        Waveform type; `WFM_TYPE_AVERAGE` for averaged waveforms.

    count:
        Number of averaged acquisitions for averaged waveforms.

    buf_type:
        Buffer type; `BUFFER_TYPE_LOGIC` for the logic analyser.

    x_origin:
        Time of the first sample in seconds.

    x_inc:
        Sample interval in seconds.

    data:
        float32 volts for analogue waveforms, one unsigned word per sample for
        the logic analyser. A view into the parsed buffer.
    """

    name: str
    wfm_type: int
    count: int
    buf_type: int
    x_origin: float
    x_inc: float
    data: npt.NDArray[np.float32] | npt.NDArray[np.unsignedinteger]


def parse(buf: bytes | bytearray | memoryview) -> list[Waveform]:
    """
    Parse a Rigol `.bin` file.

    Analogue waveforms are an array of float32 values in volt. The logic
    analyser waveform holds one word per sample (bit `n` holds channel `Dn`).

    Note that the MHO900 (firmware 00.01.00) writes an incorrect buffer size
    for the logic analyser waveform. The actual size is
    `n_pts * bytes_per_point`.
    """
    mv = memoryview(buf)
    try:
        cookie, _, _, n_waveforms = _FILE_HEADER.unpack_from(mv, 0)
    except struct.error:
        raise BinFormatError("Truncated `.bin` file header") from None
    if cookie != b"RG":
        raise BinFormatError(f"Not a Rigol `.bin` file (cookie {cookie!r})")
    offset = _FILE_HEADER.size
    res = []
    for _ in range(n_waveforms):
        try:
            hdr = _WFM_HEADER.unpack_from(mv, offset)
            hdr_size, wfm_type, n_pts, count = hdr[0], hdr[1], hdr[3], hdr[4]
            x_inc, x_origin, name = hdr[7], hdr[8], hdr[14]
            offset += hdr_size
            dh_size, buf_type, bpp, _ = _DATA_HEADER.unpack_from(mv, offset)
            offset += dh_size
        except struct.error:
            raise BinFormatError("Truncated `.bin` waveform header") from None
        size = n_pts * bpp
        if offset + size > len(mv):
            raise BinFormatError("Waveform data exceeds `.bin` file size")
        dtype = f"<u{bpp}" if buf_type == BUFFER_TYPE_LOGIC else "<f4"
        res.append(
            Waveform(
                name=name.split(b"\0", 1)[0].decode("ascii"),
                wfm_type=wfm_type,
                count=count,
                buf_type=buf_type,
                x_origin=x_origin,
                x_inc=x_inc,
                data=np.frombuffer(mv[offset : offset + size], dtype=dtype),
            )
        )
        offset += size
    return res
