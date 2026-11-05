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

"""Tiny SCPI protocol wrapper."""

import logging
import re
import socket
import types
import typing

from .errors import ScopeTimeoutError, ScpiError

logger = logging.getLogger(__name__)

_SCPI_CMD = re.compile("^[:*][A-Z0-9]+(:[A-Z0-9]+)*[?]?$")


class Scpi:
    """
    Simple SCPI client with error management.

    This class acts as a context manager. Commands can only be issued while
    the context manager is active. Upon entering the context, `Scpi` clears
    the error queue. When leaving the context this class reads out any errors
    that might have occured. Commands execute in order, but overlapped commands
    (e.g. `:SINGLE`) may still be running; callers must poll for those.
    """

    def __init__(self, addr: str, port: int, *, timeout: float = 1.0):
        """
        Connect to the raw SCPI TCP/IP device at `<addr>:<port>`.

        Parameters
        ----------

        addr:
            IP address or hostname to connect to.

        port:
            Target host port.

        timeout:
            Timeout in seconds for queries.
        """
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        self._socket.connect((addr, port))
        self._buf = bytearray()

        self._in_xact = False

    def close(self) -> None:
        self._socket.close()

    def __enter__(self) -> typing.Self:
        """
        Marks the `Scpi` instance as active.

        Entering the context clears all pending errors on the device.
        """
        if self._in_xact:
            raise ScpiError("SCPI interface already in a transaction.")
        self._in_xact = True
        self("*CLS")  # Clear errors
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        """
        Marks the `Scpi` instance as inactive.

        Retrieves all errors that are currently on the error queue and raises
        `ScpiError` if there was an error.
        """
        try:
            if self._in_xact:
                errors = []
                while True:
                    status = int(self("*STB?"))
                    if (status & 4) == 0:
                        break  # No error in the queue.
                    err_code, err_msg = self(":SYST:ERR?").split(b",", 1)
                    errors.append(f"{str(err_msg[1:-1], 'utf-8')} ({int(err_code)})")
                if errors:
                    raise ScpiError(
                        "Transaction failed:\n\t" + "\n\t".join(errors)
                    ) from exc
        finally:
            self._in_xact = False

    def __call__(
        self, cmd: str, *args: typing.Any, binary_response: bool = False
    ) -> bytes:
        """
        Executes a command `cmd` with the given arguments `args`.

        Parameters
        ----------

        cmd:
            SCPI command to execute. Must match the regular expression
            `^[:*][A-Z0-9]+(:[A-Z0-9]+)*[?]?$`. Commands that end in `?` are
            interpreted as queries.

        args:
            Arguments to be appended to the command, separated by commas.
            Note that these will be converted to a string via `str`. No
            additional escaping takes place.

        binary_response:
            If `True`, expect a binary response to the query.
        """
        if not self._in_xact:
            raise ScpiError("SCPI instance is not active")

        # Ensure that the command is valid.
        if _SCPI_CMD.match(cmd) is None:
            raise ValueError(f"Invalid SCPI command {cmd!r}")

        # Join command and comma-separated arguments, and append the ending
        # linebreak.
        full_cmd = cmd
        if args:
            full_cmd += " " + ",".join(
                f"{arg:.12g}" if isinstance(arg, float) else str(arg) for arg in args
            )
        full_cmd += "\n"
        if len(full_cmd) < 100:
            logger.debug("Sending SCPI command %r", full_cmd)
        else:
            logger.debug("Sending SCPI command %r...", full_cmd[:100])
        self._socket.sendall(full_cmd.encode("utf-8"))

        # Parse the response, if this command is a query.
        is_query = cmd.endswith("?")
        if binary_response and not is_query:
            raise ValueError("`binary_response = True` is only valid for queries.")
        if not is_query:
            return b""
        if not binary_response:
            return self._recv_until(b"\n")[:-1]

        # IEEE 488.2 block: "#<n><len, n digits><data>\n"; "#0" is indefinite
        # length, i.e., data is terminated by the newline.
        hdr = self._recv_exact(2)
        if hdr[0:1] != b"#" or not hdr[1:2].isdigit():
            raise ScpiError(f"Invalid binary block header {bytes(hdr)!r}")
        n_digits = int(hdr[1:2])
        if n_digits == 0:
            return self._recv_until(b"\n")[:-1]
        n_bytes = int(self._recv_exact(n_digits))
        data = self._recv_exact(n_bytes)
        if self._recv_exact(1) != b"\n":
            raise ScpiError("Binary block not terminated by newline")
        return data

    def _recv_more(self) -> None:
        try:
            block = self._socket.recv(65536)
        except TimeoutError:
            raise ScopeTimeoutError("Timeout waiting for SCPI response") from None
        if not block:
            raise ScpiError("Connection closed")
        self._buf.extend(block)

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._recv_more()
        res = bytes(self._buf[:n])
        del self._buf[:n]
        return res

    def _recv_until(self, delim: bytes) -> bytes:
        start = 0
        while (idx := self._buf.find(delim, start)) < 0:
            start = max(0, len(self._buf) - len(delim) + 1)
            self._recv_more()
        return self._recv_exact(idx + len(delim))
