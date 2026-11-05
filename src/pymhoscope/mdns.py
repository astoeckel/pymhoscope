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

"""Utilities to discover LXI instruments via mDNS."""

import dataclasses
import queue
import re
import time

import zeroconf


@dataclasses.dataclass(frozen=True)
class MDnsFilter:
    """Filter settings for mDNS discovery."""

    model: re.Pattern | str | None = None
    serial_number: re.Pattern | str | None = None
    manufacturer: re.Pattern | str | None = None
    protocol: str = "_scpi-raw._tcp"

    def matches(self, endpoint: "MDnsEndpoint") -> bool:
        for crit, value in (
            (self.model, endpoint.model),
            (self.serial_number, endpoint.serial_number),
            (self.manufacturer, endpoint.manufacturer),
        ):
            if crit is None:
                continue
            if isinstance(crit, str):
                if crit.casefold() != value.casefold():
                    return False
            elif crit.fullmatch(value) is None:
                return False
        return True


@dataclasses.dataclass(frozen=True)
class MDnsEndpoint:
    """An instrument service found via mDNS."""

    model: str
    serial_number: str
    manufacturer: str
    addr: str
    port: int
    protocol: str

    @staticmethod
    def find(
        filter: MDnsFilter | None = None, timeout: float = 2.0
    ) -> list["MDnsEndpoint"]:
        """
        Return all endpoints with an IPv4 address that match `filter`.

        `None` matches all SCPI raw endpoints. Collects answers in 200 ms
        intervals and returns after the first interval in which at least one
        matching endpoint answered, or after `timeout` seconds.
        """
        filter = filter or MDnsFilter()
        service_type = f"{filter.protocol}.local."
        names: queue.SimpleQueue[str] = queue.SimpleQueue()  # Browser thread

        def on_change(zeroconf, service_type, name, state_change):
            names.put(name)

        zc = zeroconf.Zeroconf()
        try:
            zeroconf.ServiceBrowser(zc, service_type, handlers=[on_change])
            deadline = time.monotonic() + timeout
            seen: set[str] = set()
            res: dict[tuple[str, int], MDnsEndpoint] = {}
            while not res and (remaining := deadline - time.monotonic()) > 0:
                time.sleep(min(0.2, remaining))
                while not names.empty():
                    name = names.get()
                    if name in seen:
                        continue
                    seen.add(name)
                    info = zc.get_service_info(service_type, name, timeout=1000)
                    if info is None or info.port is None:
                        continue
                    addrs = info.parsed_addresses(zeroconf.IPVersion.V4Only)
                    if not addrs:
                        continue
                    txt = {
                        k.decode(errors="replace"): (v or b"").decode(errors="replace")
                        for k, v in info.properties.items()
                    }
                    endpoint = MDnsEndpoint(
                        model=txt.get("Model", ""),
                        serial_number=txt.get("SerialNumber", ""),
                        manufacturer=txt.get("Manufacturer", ""),
                        addr=addrs[0],
                        port=info.port,
                        protocol=filter.protocol,
                    )
                    if filter.matches(endpoint):
                        res[(endpoint.addr, endpoint.port)] = endpoint
        finally:
            zc.close()
        return list(res.values())
