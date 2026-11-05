#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["frida==16.7.19", "zeroconf"]
# ///

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
Live firmware fix for the MHO900 logic-analyser save corruption (fw 00.01.00).

With fewer than three analogue channels enabled, the scope saves corrupted
logic analyser data. In `CWaveFile::saveMemAsBin`, the per-chunk start of the
logic-analyser transfer is computed as `(chunk * 1000000 >> 2) * chanMode`,
where `chanMode` is 1 (zero or one analogue channels), 2 (two channels), or 4
(three or four channels). The FPGA, however, expects the start in memory
points, i.e., `chunk * 1000000`, independently of `chanMode`. Hence, with
`chanMode` 1 and 2, consecutive chunks overlap by 75 % and 50 %, the back of
the record is lost, and the front is duplicated. The analogue channels and the
on-screen data are correct; only saved logic analyser data is affected.

This script replaces the `mul w0, w8, w9` (`* chanMode`) after the
`lsr w8, w8, #2` with `lsl w0, w8, #2` in the running scope application's
memory via Frida, so the start becomes `chunk * 1000000` for every channel
count. This makes `.bin` memory saves (and pymhoscope's SMB capture) record the
full, correct logic analyser record.

By default the patch lives only in the running process: it is undone by
restarting the scope application or power-cycling the scope, and it writes
nothing to the instrument's storage. Re-run it after each boot.

With `--permanent` the instruction is additionally patched in the library on
the scope's filesystem, so the fix survives reboots. The library is not
extracted on the scope; the app maps it directly out of its (uncompressed)
APK entry, so the script patches those 4 bytes inside the installed APK in
place, updates the entry's zip CRC, and restores the APK's modification time.
The latter is essential: Android re-verifies the APK signature at boot when the
mtime changes, which would fail and uninstall the scope application. A copy of
the unmodified APK is kept in `~/.cache/pymhoscope` before the first write. A
firmware update replaces the APK and thus removes the patch.

Only `adb` and `uv` are required on the host. The script finds the scope via
mDNS (or use `--addr`), connects to its adb interface (TCP 55555, open by
default), downloads a matching `frida-server` on first use (cached in
`~/.cache/pymhoscope`), pushes it to `/data/local/tmp`, starts it as root
listening on the scope's loopback only, applies the patch through an adb port
forward, and finally stops `frida-server` and removes the forward again.

    ./patch_mho_la_save.py               # apply the fix
    ./patch_mho_la_save.py --revert      # restore the original instruction
    ./patch_mho_la_save.py --check       # report the current state only
    ./patch_mho_la_save.py --permanent   # also patch the APK on the scope
"""

import argparse
import hashlib
import logging
import lzma
import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.request
import zipfile
import zlib

import frida
import zeroconf

logger = logging.getLogger(__name__)

# The scope application. Frida reports its process name as "RIGOL.SCOPE"; the
# Android package is "com.rigol.scope". We resolve it by matching either.
PROCESS_HINTS = ("RIGOL.SCOPE", "com.rigol.scope", "rigol.scope")
MODULE = "libscope-auklet.so"
ADB_PORT = 55555  # The scope's adb-over-TCP port (open by default).
FRIDA_PORT = 27042  # frida-server port on the scope (bound to its loopback only).
FRIDA_REMOTE = "/data/local/tmp/frida-server"
FRIDA_URL = (
    "https://github.com/frida/frida/releases/download/"
    "{v}/frida-server-{v}-android-arm64.xz"
)
MDNS_SERVICE = "_scpi-raw._tcp.local."
LSR2 = 0x53027D08  # lsr w8, w8, #2
MUL = 0x1B097D00  # mul w0, w8, w9  (original; w9 = chanMode)
LSL2 = 0x531E7500  # lsl w0, w8, #2  (fix)
AND_W3_W8_1 = 0x12000103  # and w3, w8, #1
PATCH_TMP = "/data/local/tmp/mho_la_patch"

# The fix site is the `lsr` feeding the logic-analyser DrvWaveform_ExportData
# call in saveMemAsBin. We locate it by its instruction signature rather than a
# fixed address (the offset differs between firmware builds):
#   lsr  w8, w8, #2         (chunk * 1000000 >> 2)   +0x00
#   ldr  w9, [sp, ...]      (chanMode)               +0x04
#   mul  w0, w8, w9         <- patch target          +0x08
#   ...
#   and  w3, w8, #1         (isLogicAnalyser)        +0x18
#   bl   DrvWaveform_ExportData                      +0x1c
PATCH_OFFSET = 0x08
STATES = {MUL: "original (bug present)", LSL2: "fixed"}
TARGETS = {"apply": LSL2, "revert": MUL}

_SCRIPT = r"""
const PROCESS_MODULE = %r;
const MUL = %#x, LSL2 = %#x;
const AND_W3_W8_1 = %#x;
const PATCH_OFFSET = %#x;
const action = %r;

function findSites() {
  const m = Process.findModuleByName(PROCESS_MODULE);
  if (!m) throw new Error('module not found: ' + PROCESS_MODULE);
  const sites = [];
  // Scan for the `lsr w8,w8,#2` instruction followed by the `and w3,w8,#1` +
  // `bl` of the logic-analyser ExportData call.
  // (Scan the whole module; enumerateRanges('r-x') is unreliable on this build.)
  for (const mm of Memory.scanSync(m.base, m.size, '08 7d 02 53')) {
    const a = mm.address;
    try {
      if (a.add(0x18).readU32() === AND_W3_W8_1 &&
          ((a.add(0x1c).readU32() & 0xfc000000) >>> 0) === 0x94000000)
        sites.push(a.add(PATCH_OFFSET));
    } catch (e) { /* out of range */ }
  }
  return sites;
}

const sites = findSites();
const out = { module_base: Process.findModuleByName(PROCESS_MODULE).base.toString(),
              sites: sites.map(a => a.toString()), action: action, results: [] };
for (const a of sites) {
  const cur = a.readU32();
  let note;
  if (action === 'check') {
    note = (cur === MUL) ? 'original (bug present)'
         : (cur === LSL2) ? 'already fixed' : 'UNEXPECTED 0x' + cur.toString(16);
  } else if (action === 'apply') {
    if (cur === LSL2) note = 'already fixed';
    else if (cur !== MUL) note = 'REFUSED unexpected 0x' + cur.toString(16);
    else {
      Memory.patchCode(a, 4, c => c.writeU32(LSL2));
      note = 'fixed (mul -> lsl)';
    }
  } else {  // revert
    if (cur === MUL) note = 'already original';
    else if (cur !== LSL2) note = 'REFUSED unexpected 0x' + cur.toString(16);
    else {
      Memory.patchCode(a, 4, c => c.writeU32(MUL));
      note = 'reverted (lsl -> mul)';
    }
  }
  out.results.push({
    addr: a.toString(), before: '0x' + cur.toString(16), note: note,
  });
}
send(out);
"""


class Error(Exception):
    pass


def find_scopes(timeout: float = 3.0) -> list[tuple[str, str, str]]:
    """Return `(addr, model, serial)` of all Rigol instruments found via mDNS."""
    names: list[str] = []
    zc = zeroconf.Zeroconf()
    try:
        zeroconf.ServiceBrowser(
            zc, MDNS_SERVICE, handlers=[lambda name, **_: names.append(name)]
        )
        res: dict[str, tuple[str, str, str]] = {}
        deadline = time.monotonic() + timeout
        seen: set[str] = set()
        while not res and time.monotonic() < deadline:
            time.sleep(0.2)
            for name in [n for n in names if n not in seen]:
                seen.add(name)
                info = zc.get_service_info(MDNS_SERVICE, name, timeout=1000)
                if info is None:
                    continue
                addrs = info.parsed_addresses(zeroconf.IPVersion.V4Only)
                if not addrs:
                    continue
                txt = {
                    k.decode(errors="replace"): (v or b"").decode(errors="replace")
                    for k, v in info.properties.items()
                }
                if not txt.get("Model", "").startswith("MHO9"):
                    continue
                if "RIGOL" not in txt.get("Manufacturer", ""):
                    continue
                res[addrs[0]] = (
                    addrs[0],
                    txt.get("Model", "?"),
                    txt.get("SerialNumber", "?"),
                )
    finally:
        zc.close()
    return sorted(res.values())


class Adb:
    def __init__(self, addr: str):
        if shutil.which("adb") is None:
            raise Error("`adb` not found; please install the Android platform tools")
        self.serial = addr if ":" in addr else f"{addr}:{ADB_PORT}"

    def run(
        self, *args: str, check: bool = True, device: bool = True, timeout: float = 30
    ) -> str:
        cmd = ["adb", *(("-s", self.serial) if device else ()), *args]
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise Error(f"`{' '.join(cmd)}` timed out") from None
        if check and p.returncode != 0:
            raise Error(f"`{' '.join(cmd)}` failed: {(p.stderr or p.stdout).strip()}")
        return p.stdout.strip()

    def shell(self, cmd: str, check: bool = True) -> str:
        return self.run("shell", cmd, check=check)

    def connect(self) -> None:
        for _ in range(3):
            out = self.run("connect", self.serial, device=False, check=False)
            if self.run("get-state", check=False) == "device":
                return
            time.sleep(1)
        raise Error(f"Cannot connect to adb at {self.serial}: {out}")


def cache_dir() -> pathlib.Path:
    cache = pathlib.Path(
        os.environ.get("XDG_CACHE_HOME", pathlib.Path.home() / ".cache")
    )
    return cache / "pymhoscope"


def find_lib_container(adb: Adb) -> str:
    """Return the on-device file the scope app maps `MODULE` from."""
    pid = ""
    for name in PROCESS_HINTS:
        pid = adb.shell(f"pidof {name}", check=False).split(" ")[0]
        if pid:
            break
    if not pid:
        raise Error("Scope application not running; cannot locate its library")
    maps = adb.shell(f"su -c 'cat /proc/{pid}/maps'")
    paths = {
        line.split()[-1]
        for line in maps.splitlines()
        if len(line.split()) >= 6 and " r-xp " in line
    }
    cands = sorted(p for p in paths if p.endswith(("/" + MODULE, ".apk")))
    if len(cands) != 1:
        raise Error(f"Cannot determine the file {MODULE} is loaded from: {cands}")
    return cands[0]


def find_file_sites(data: bytes) -> list[tuple[int, int]]:
    """Return `(offset, current_insn)` of the patch site(s) in an ELF image."""
    sites = []
    pat = struct.pack("<I", LSR2)
    i = data.find(pat)
    while i >= 0:
        if i % 4 == 0 and i + 0x20 <= len(data):
            and_, bl = struct.unpack_from("<II", data, i + 0x18)
            if and_ == AND_W3_W8_1 and (bl & 0xFC000000) == 0x94000000:
                (insn,) = struct.unpack_from("<I", data, i + PATCH_OFFSET)
                sites.append((i + PATCH_OFFSET, insn))
        i = data.find(pat, i + 1)
    return sites


def _central_dir_entry_offset(
    path: pathlib.Path, zf: zipfile.ZipFile, name: str
) -> int:
    """Return the file offset of `name`'s central directory record."""
    with path.open("rb") as f:
        f.seek(zf.start_dir)
        cd = f.read()
    pos = 0
    while cd[pos : pos + 4] == b"PK\x01\x02":
        n, m, k = struct.unpack_from("<HHH", cd, pos + 28)
        if cd[pos + 46 : pos + 46 + n].decode("utf-8", "replace") == name:
            return zf.start_dir + pos
        pos += 46 + n + m + k
    raise Error(f"Central directory record of {name} not found")


def _dd_read(adb: Adb, path: str, offset: int, n: int) -> bytes:
    out = adb.shell(
        f"toybox dd if={path} bs=1 skip={offset} count={n} 2>/dev/null"
        " | toybox od -An -tx1"
    )
    return bytes.fromhex(out.replace(" ", "").replace("\n", ""))


def _dd_write(adb: Adb, path: str, writes: list[tuple[int, bytes]]) -> None:
    """Overwrite bytes of a device file in place, keeping its timestamps."""
    ref = f"{PATCH_TMP}.ref"
    adb.shell(f"su -c 'touch -r {path} {ref}'")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for i, (offset, data) in enumerate(writes):
                local = pathlib.Path(tmp) / f"w{i}"
                local.write_bytes(data)
                adb.run("push", str(local), f"{PATCH_TMP}.{i}")
                adb.shell(
                    f"su -c 'toybox dd if={PATCH_TMP}.{i} of={path} bs=1"
                    f" seek={offset} conv=notrunc 2>/dev/null'"
                )
    finally:
        # Always restore the mtime, even after a partial write.
        adb.shell(f"su -c 'touch -r {ref} {path}; sync'", check=False)
        adb.shell(f"su -c 'rm -f {PATCH_TMP}.*'", check=False)
    for offset, data in writes:
        if _dd_read(adb, path, offset, len(data)) != data:
            raise Error(f"Read-back mismatch at {path}+{offset:#x}")


def patch_file(adb: Adb, action: str) -> bool:
    """Apply `action` to the library on the scope's filesystem."""
    remote = find_lib_container(adb)
    mtime = adb.shell(f"stat -c %y {remote}")
    with tempfile.TemporaryDirectory() as tmp:
        local = pathlib.Path(tmp) / pathlib.Path(remote).name
        logger.info(f"Pulling {remote}")
        adb.run("pull", remote, str(local), timeout=600)
        raw = local.read_bytes()

        writes: list[tuple[int, bytes]] = []
        if remote.endswith(".apk"):
            zf = zipfile.ZipFile(local)
            infos = [i for i in zf.infolist() if i.filename.endswith("/" + MODULE)]
            infos = [i for i in infos if "arm64" in i.filename] or infos
            if len(infos) != 1:
                raise Error(f"Expected one {MODULE} in {remote}, found {len(infos)}")
            info = infos[0]
            if info.compress_type != zipfile.ZIP_STORED:
                raise Error(f"{info.filename} is compressed; cannot patch in place")
            n, m = struct.unpack_from("<HH", raw, info.header_offset + 26)
            base = info.header_offset + 30 + n + m
            elf = raw[base : base + info.file_size]
            if zlib.crc32(elf) != info.CRC:
                raise Error(f"CRC mismatch in pulled {info.filename}; aborting")
        else:
            info, base, elf = None, 0, raw

        sites = find_file_sites(elf)
        if len(sites) != 1:
            raise Error(f"Expected one patch site in {MODULE}, found {len(sites)}")
        off, cur = sites[0]
        state = STATES.get(cur)
        print(f"{remote}+{base + off:#x}  {cur:#x}  {state or 'UNEXPECTED'}")
        if state is None:
            raise Error(f"Unexpected instruction {cur:#x} at the patch site")
        want = TARGETS.get(action, cur)
        if want == cur:
            return True

        # Back up the unmodified container before the first write.
        if cur == TARGETS["revert"]:
            digest = hashlib.sha256(raw).hexdigest()[:16]
            backup = cache_dir() / f"{local.name}.{digest}.orig"
            if not backup.exists():
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(local, backup)
                logger.info(f"Saved unmodified copy to {backup}")

        new = bytearray(elf)
        struct.pack_into("<I", new, off, want)
        writes.append((base + off, struct.pack("<I", want)))
        if info is not None:
            crc = struct.pack("<I", zlib.crc32(new))
            cd = _central_dir_entry_offset(local, zf, info.filename)
            writes.append((info.header_offset + 14, crc))
            writes.append((cd + 16, crc))
            if info.flag_bits & 0x08:
                raise Error("Entry uses a data descriptor; refusing to patch")

    _dd_write(adb, remote, writes)
    if adb.shell(f"stat -c %y {remote}") != mtime:
        raise Error(f"Failed to preserve the modification time of {remote}!")
    verb = "fixed" if action == "apply" else "reverted"
    print(f"{remote}+{base + off:#x}  {want:#x}  {verb} on disk")
    return True


def frida_server_binary() -> pathlib.Path:
    """Return a local `frida-server` matching the frida Python package."""
    path = cache_dir() / f"frida-server-{frida.__version__}-android-arm64"
    if not path.exists():
        url = FRIDA_URL.format(v=frida.__version__)
        logger.info(f"Downloading {url}")
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url) as r:
            data = lzma.decompress(r.read())
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
    return path


def start_frida_server(adb: Adb) -> None:
    stop_frida_server(adb)
    remote_version = adb.shell(f"{FRIDA_REMOTE} --version 2>/dev/null", check=False)
    if remote_version != frida.__version__:
        local = frida_server_binary()
        logger.info(f"Pushing frida-server {frida.__version__} to {FRIDA_REMOTE}")
        adb.run("push", str(local), FRIDA_REMOTE, timeout=300)
        adb.shell(f"chmod 755 {FRIDA_REMOTE}")
    # Detach stdio: otherwise the daemon holds adb's stdout open and adb hangs.
    adb.shell(
        f"su -c '{FRIDA_REMOTE} -l 127.0.0.1:{FRIDA_PORT} -D'"
        " </dev/null >/dev/null 2>&1"
    )


def stop_frida_server(adb: Adb) -> None:
    """Stop frida-server and wait for it to exit (it shuts down asynchronously)."""
    adb.shell("su -c 'killall frida-server' 2>/dev/null", check=False)
    for _ in range(25):
        if not adb.shell("pidof frida-server", check=False):
            return
        time.sleep(0.2)
    adb.shell("su -c 'killall -9 frida-server' 2>/dev/null", check=False)


def attach(host: str) -> frida.core.Session:
    """Attach to the scope application, retrying while frida-server starts."""
    device = frida.get_device_manager().add_remote_device(host)
    for attempt in range(20):
        try:
            procs = device.enumerate_processes()
            break
        except (frida.ServerNotRunningError, frida.TransportError):
            if attempt == 19:
                raise Error(f"Cannot reach frida-server at {host}") from None
            time.sleep(0.5)
    for proc in procs:
        if any(h.lower() in proc.name.lower() for h in PROCESS_HINTS):
            return device.attach(proc.pid)
    raise Error("Scope application not found (is the scope running?)")


def patch(session: frida.core.Session, action: str) -> int:
    result = {}

    def on_message(message, data):
        if message["type"] == "send":
            result.update(message["payload"])
        else:
            logger.info(str(message))

    script = session.create_script(
        _SCRIPT % (MODULE, MUL, LSL2, AND_W3_W8_1, PATCH_OFFSET, action)
    )
    script.on("message", on_message)
    script.load()
    session.detach()

    if not result.get("sites"):
        raise Error("No patch site found — firmware may differ; aborting")
    for r in result["results"]:
        print(f"{r['addr']}  {r['before']}  {r['note']}")
    bad = [
        r
        for r in result["results"]
        if "REFUSED" in r["note"] or "UNEXPECTED" in r["note"]
    ]
    return not bool(bad)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("--addr", help="Scope IP address (default: find via mDNS)")
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--revert", action="store_true", help="Restore the original instruction"
    )
    g.add_argument(
        "--check", action="store_true", help="Report state without changing it"
    )
    p.add_argument(
        "--permanent",
        action="store_true",
        help="Also apply the action to the library on the scope's filesystem"
        " (survives reboots)",
    )
    args = p.parse_args()
    action = "revert" if args.revert else "check" if args.check else "apply"

    logging.basicConfig(level=logging.INFO)

    try:
        # If no address is given, search for a scope via mDNS.
        addr = args.addr
        if addr is None:
            scopes = find_scopes()
            if len(scopes) != 1:
                found = "".join(f"\n  {a}  {m}  {s}" for a, m, s in scopes)
                raise Error(
                    f"Expected one Rigol scope via mDNS, found {len(scopes)}{found}\n"
                    "Pass --addr, or check that mDNS is enabled in the scope's"
                    " LAN settings"
                )
            addr, model, serial = scopes[0]
            logger.info(f"Found {model} ({serial}) at {addr}")

        # Connect to the scope via the Android debug bridge.
        adb = Adb(addr)
        logger.info("Connecting via adb...")
        adb.connect()

        # For the permanent fix, override the file on the filesystem.
        if args.permanent:
            logger.info("Patching the library on the scope's filesystem...")
            patch_file(adb, action)

        # For the live fix, start the frida debug server on the scope.
        logger.info("Starting frida server...")
        start_frida_server(adb)
        logger.info("Forwarding frida debug port through adb...")
        try:
            local_port = adb.run("forward", "tcp:0", f"tcp:{FRIDA_PORT}")
            try:
                # Once the debug serer is running, apply the live patch.
                logger.info("Patching...")
                if patch(attach(f"127.0.0.1:{local_port}"), action):
                    logger.info("Done!")
                    return 0
                else:
                    logger.info("Error while patching. See message above.")
                    return 1
            finally:
                adb.run("forward", "--remove", f"tcp:{local_port}", check=False)
        finally:
            logger.info("Stopping frida server...")
            stop_frida_server(adb)
    except Error as e:
        logger.error(f"Error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
