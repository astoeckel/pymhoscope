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
Minimal SMB1 server with a virtual file system.

Implements enough of SMB1 ("NT LM 0.12") for a Linux kernel CIFS client used
by the Rigol MHO900 oscilloscopes. In particular, the following calls are
supported:

    NEGOTIATE, SESSION_SETUP_ANDX (raw or SPNEGO NTLMSSP, NTLMv2), TREE_CONNECT_ANDX,
    TREE_DISCONNECT, LOGOFF_ANDX, ECHO,
    NT_CREATE_ANDX, WRITE_ANDX, FLUSH, CLOSE, FIND_CLOSE2,
    READ_ANDX (always refused; see `_read_andx`),
    TRANS2: QUERY_FS_INFORMATION, QUERY_PATH_INFORMATION,
            QUERY_FILE_INFORMATION, SET_FILE_INFORMATION,
            SET_PATH_INFORMATION, FIND_FIRST2, FIND_NEXT2

The created share is flat, is write-only, and has no subdirectories. All writes
are handed to `Backend`. Unsupported operations are logged at WARNING
level.

Note that this server was developed with Impacket's `impacket/smbserver.py`
(https://github.com/fortra/impacket, version 0.13.1, author Alberto Solino) as a
reference. It shares no code with Impacket beyond protocol constants and a few
negotiation parameters.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import hmac
import logging
import os
import socket
import socketserver
import struct
import threading
import time
import typing
import zlib

log = logging.getLogger(__name__)

###############################################################################
# Public backend API                                                          #
###############################################################################


@dataclasses.dataclass
class FileInfo:
    """File entry in a directory."""

    name: str
    size: int = 0
    mtime: float = dataclasses.field(default_factory=time.time)


class FileWriter(typing.Protocol):
    """Interface to be implemented by the client."""

    def write(self, offset: int, data: bytes) -> None: ...

    def truncate(self, size: int) -> None: ...

    def close(self) -> None:
        """The client closed the file: its contents are complete."""

    def abort(self) -> None:
        """The client deleted the file or the connection was lost."""


class Backend:
    """Override to provide the virtual file system."""

    def list_files(self) -> typing.Iterable[FileInfo]:
        """Files shown in directory listings (besides files being written)."""
        return []

    def create(self, name: str) -> FileWriter:
        """Called when the client creates (or overwrites) file `name`."""
        raise PermissionError(name)


class MemoryWriter:
    def __init__(self, name: str, on_complete: typing.Callable[[str, bytearray], None]):
        self.name = name
        self.buf = bytearray()
        self._on_complete = on_complete

    def write(self, offset: int, data: bytes) -> None:
        end = offset + len(data)
        if end > len(self.buf):
            self.buf.extend(b"\0" * (end - len(self.buf)))
        self.buf[offset:end] = data

    def truncate(self, size: int) -> None:
        if size < len(self.buf):
            del self.buf[size:]
        else:
            self.buf.extend(b"\0" * (size - len(self.buf)))

    def close(self) -> None:
        # Hand over the buffer itself (no copy): files may be several GB.
        buf, self.buf = self.buf, bytearray()
        self._on_complete(self.name, buf)

    def abort(self) -> None:
        log.info("Discarding %s (%d bytes)", self.name, len(self.buf))


class MemoryBackend(Backend):
    """Collect each written file in memory and pass it to `on_complete`.

    The directory always appears empty, so clients that pick "the next free
    filename" always pick the same one.  `on_create` (optional) is called as
    soon as the client starts writing a file.
    """

    def __init__(
        self,
        on_complete: typing.Callable[[str, bytearray], None],
        on_create: typing.Callable[[str], None] | None = None,
    ):
        self.on_complete = on_complete
        self.on_create = on_create

    def create(self, name: str) -> FileWriter:
        if self.on_create:
            self.on_create(name)
        return MemoryWriter(name, self.on_complete)


###############################################################################
# Protocol constants                                                          #
###############################################################################

# Commands
SMB_COM_CLOSE = 0x04
SMB_COM_FLUSH = 0x05
SMB_COM_ECHO = 0x2B
SMB_COM_READ_ANDX = 0x2E
SMB_COM_WRITE_ANDX = 0x2F
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_FIND_CLOSE2 = 0x34
SMB_COM_TREE_DISCONNECT = 0x71
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_LOGOFF_ANDX = 0x74
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_NT_CREATE_ANDX = 0xA2
SMB_COM_NT_CANCEL = 0xA4

# TRANS2 subcommands
TRANS2_FIND_FIRST2 = 0x01
TRANS2_FIND_NEXT2 = 0x02
TRANS2_QUERY_FS_INFORMATION = 0x03
TRANS2_QUERY_PATH_INFORMATION = 0x05
TRANS2_SET_PATH_INFORMATION = 0x06
TRANS2_QUERY_FILE_INFORMATION = 0x07
TRANS2_SET_FILE_INFORMATION = 0x08

# NT status codes
STATUS_SUCCESS = 0x00000000
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_DISK_FULL = 0xC000007F
STATUS_TOO_MANY_OPENED_FILES = 0xC000011F
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
STATUS_BAD_NETWORK_NAME = 0xC00000CC
STATUS_INVALID_LEVEL = 0xC0000148
STATUS_SMB_BAD_UID = 0x005B0002
STATUS_SMB_BAD_TID = 0x00050002

# Header flags
FLAGS_REPLY = 0x80
FLAGS2_RESPONSE = 0xC801  # unicode, NT status, extended security, long names
FLAGS2_UNICODE = 0x8000

# Negotiate response values (as used by impacket, known to work with the scope)
SECURITY_MODE = 0x03  # user level security, challenge/response
MAX_BUFFER_SIZE = 64000
# Unicode, large files, RPC APIs, NT SMBs, NT status, extended security. Without
# large files (0x8), the scope's client truncates files at 2 GiB - 1 byte.
CAPABILITIES = 0x8000007C
CAP_LARGE_READX = 0x4000
CAP_LARGE_WRITEX = 0x8000
# SPNEGO negTokenInit advertising NTLMSSP (1.3.6.1.4.1.311.2.2.10)
NEGOTIATE_BLOB = bytes.fromhex(
    "601c06062b0601050502a0123010a00e300c060a2b06010401823702020a"
)
# SPNEGO negTokenResp, negResult accept-completed
ACCEPT_COMPLETED_BLOB = bytes.fromhex("a1073005a0030a0100")
# DER-encoded NTLMSSP mechanism OID (1.3.6.1.4.1.311.2.2.10)
NTLMSSP_OID = bytes.fromhex("060a2b06010401823702020a")

# NT_CREATE_ANDX dispositions / options / actions
FILE_SUPERSEDE, FILE_OPEN, FILE_CREATE = 0, 1, 2
FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF = 3, 4, 5
FILE_DIRECTORY_FILE = 0x01
FILE_NON_DIRECTORY_FILE = 0x40
FILE_DELETE_ON_CLOSE = 0x1000
FILE_OPENED, FILE_CREATED, FILE_OVERWRITTEN = 1, 2, 3
_DISPOSITIONS = {
    0: "supersede",
    1: "open",
    2: "create",
    3: "open_if",
    4: "overwrite",
    5: "overwrite_if",
}

ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

# Information levels: native SMB levels and pass-through (native + 1000) ones
QUERY_FS_VOLUME_INFO = 0x102
QUERY_FS_SIZE_INFO = 0x103
QUERY_FS_DEVICE_INFO = 0x104
QUERY_FS_ATTRIBUTE_INFO = 0x105
FS_SIZE_INFORMATION = 1003
FS_FULL_SIZE_INFORMATION = 1007

QUERY_FILE_BASIC_INFO = 0x101
QUERY_FILE_STANDARD_INFO = 0x102
QUERY_FILE_EA_INFO = 0x103
QUERY_FILE_ALL_INFO = 0x107
FILE_BASIC_INFORMATION = 1004
FILE_STANDARD_INFORMATION = 1005
FILE_INTERNAL_INFORMATION = 1006
FILE_EA_INFORMATION = 1007
FILE_NETWORK_OPEN_INFORMATION = 1034

SET_FILE_BASIC_INFO = 0x101
SET_FILE_DISPOSITION_INFO = 0x102
SET_FILE_ALLOCATION_INFO = 0x103
SET_FILE_END_OF_FILE_INFO = 0x104
FILE_DISPOSITION_INFORMATION = 1013
FILE_ALLOCATION_INFORMATION = 1019
FILE_END_OF_FILE_INFORMATION = 1020

FIND_FILE_DIRECTORY_INFO = 0x101
FIND_FILE_FULL_DIRECTORY_INFO = 0x102
FIND_FILE_NAMES_INFO = 0x103
FIND_FILE_BOTH_DIRECTORY_INFO = 0x104
FIND_FILE_ID_FULL_DIRECTORY_INFO = 0x105
FIND_FILE_ID_BOTH_DIRECTORY_INFO = 0x106
FIND_CLOSE_AFTER_REQUEST = 0x01
FIND_CLOSE_AT_EOS = 0x02

_HEADER = struct.Struct("<4sBIBH12sHHHH")  # 32 bytes
_ANDX_NONE = b"\xff\x00\x00\x00"  # AndXCommand none, reserved, offset 0

###############################################################################
# Helpers                                                                     #
###############################################################################


def _filetime(t: float) -> int:
    return int((t + 11644473600) * 10_000_000)


def _from_filetime(ft: int) -> float:
    return ft / 10_000_000 - 11644473600


def _inode(name: str) -> int:
    return 1 if name == "" else zlib.crc32(name.encode()) + 2


def _norm(name: str) -> str:
    """Normalise a client path to a name relative to the (flat) share root."""
    return name.replace("/", "\\").strip("\x00").strip("\\")


def _utf16z(s: str) -> bytes:
    return s.encode("utf-16le") + b"\0\0"


def _read_utf16z(buf: bytes, offset: int = 0) -> str:
    end = offset
    while end + 1 < len(buf) and buf[end : end + 2] != b"\0\0":
        end += 2
    return buf[offset:end].decode("utf-16le", errors="replace")


def _md4(data: bytes) -> bytes:
    """MD4 (RFC 1320); hashlib's md4 is unavailable with OpenSSL 3."""

    def rol(v: int, s: int) -> int:
        v &= 0xFFFFFFFF
        return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF

    msg = bytearray(data) + b"\x80"
    msg += b"\0" * ((56 - len(msg)) % 64) + struct.pack("<Q", len(data) * 8)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    rounds = (
        (lambda x, y, z: (x & y) | (~x & z), range(16), (3, 7, 11, 19), 0),
        (
            lambda x, y, z: (x & y) | (x & z) | (y & z),
            (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15),
            (3, 5, 9, 13),
            0x5A827999,
        ),
        (
            lambda x, y, z: x ^ y ^ z,
            (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15),
            (3, 9, 11, 15),
            0x6ED9EBA1,
        ),
    )
    for chunk in range(0, len(msg), 64):
        x = struct.unpack_from("<16I", msg, chunk)
        state = list(h)
        for f, order, shifts, add in rounds:
            for i, k in enumerate(order):
                p = (-i) % 4  # a, d, c, b, a, ...
                v, b, c, d = (
                    state[p],
                    state[(p + 1) % 4],
                    state[(p + 2) % 4],
                    state[(p + 3) % 4],
                )
                state[p] = rol(v + f(b, c, d) + x[k] + add, shifts[i % 4])
        h = [(a + b) & 0xFFFFFFFF for a, b in zip(h, state, strict=True)]
    return struct.pack("<4I", *h)


def nt_hash(password: str) -> bytes:
    return _md4(password.encode("utf-16le"))


def _ntlm_av_pairs(computer: str, domain: str) -> bytes:
    out = b""
    for av_id, value in ((2, domain), (1, computer), (4, domain), (3, computer)):
        raw = value.encode("utf-16le")
        out += struct.pack("<HH", av_id, len(raw)) + raw
    out += struct.pack("<HH", 7, 8) + struct.pack("<Q", _filetime(time.time()))
    return out + struct.pack("<HH", 0, 0)


def _ntlm_challenge(
    client_flags: int, challenge: bytes, computer: str, domain: str
) -> bytes:
    # NEGOTIATE_UNICODE | REQUEST_TARGET | NTLM | TARGET_TYPE_SERVER |
    # TARGET_INFO; plus the client's EXTENDED_SESSIONSECURITY/128/56/KEY_EXCH
    flags = 0x00820205 | (client_flags & 0xE0088000)
    target = domain.encode("utf-16le")
    info = _ntlm_av_pairs(computer, domain)
    payload_off = 48
    return (
        b"NTLMSSP\0"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target), len(target), payload_off)
        + struct.pack("<I", flags)
        + challenge
        + b"\0" * 8
        + struct.pack("<HHI", len(info), len(info), payload_off + len(target))
        + target
        + info
    )


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = b"\x81" + bytes([n])
    else:
        length = b"\x82" + n.to_bytes(2, "big")
    return bytes([tag]) + length + body


def _spnego_challenge(token: bytes) -> bytes:
    """Wrap an NTLMSSP CHALLENGE in a SPNEGO negTokenResp.

    negState accept-incomplete, supportedMech NTLMSSP, responseToken `token`.
    """
    return _der(
        0xA1,
        _der(
            0x30,
            _der(0xA0, b"\x0a\x01\x01")
            + _der(0xA1, NTLMSSP_OID)
            + _der(0xA2, _der(0x04, token)),
        ),
    )


def _ntlm_field(msg: bytes, offset: int) -> bytes:
    length, _, off = struct.unpack_from("<HHI", msg, offset)
    return msg[off : off + length]


def _ntlm_verify(
    auth: bytes, challenge: bytes, user: str, hashed_password: bytes
) -> tuple[bool, str]:
    """Verify an NTLMv2 AUTHENTICATE message.  Returns (ok, user name)."""
    if not auth.startswith(b"NTLMSSP\0") or struct.unpack_from("<I", auth, 8)[0] != 3:
        return False, ""
    nt_resp = _ntlm_field(auth, 20)
    domain = _ntlm_field(auth, 28).decode("utf-16le", errors="replace")
    name = _ntlm_field(auth, 36).decode("utf-16le", errors="replace")
    if name.lower() != user.lower():
        return False, name
    if len(nt_resp) <= 24:
        log.warning("Client %r uses NTLMv1, which is not supported", name)
        return False, name
    key = hmac.new(
        hashed_password, (name.upper() + domain).encode("utf-16le"), "md5"
    ).digest()
    proof = hmac.new(key, challenge + nt_resp[16:], "md5").digest()
    return hmac.compare_digest(proof, nt_resp[:16]), name


@dataclasses.dataclass
class _Request:
    raw: bytes  # the complete SMB message, header included
    cmd: int
    flags2: int
    tid: int
    pid_high: bytes
    pid: int
    uid: int
    mid: int
    words: bytes
    data: bytes
    data_offset: int  # offset of `data` from the start of the SMB header

    @property
    def unicode(self) -> bool:
        return bool(self.flags2 & FLAGS2_UNICODE)

    def string(self, buf_offset: int) -> tuple[str, int]:
        """Read a NUL-terminated string at `buf_offset` (relative to `raw`).

        Unicode strings are aligned to an even offset.  Returns (string, end).
        """
        if self.unicode:
            buf_offset += buf_offset & 1
            s = _read_utf16z(self.raw, buf_offset)
            return s, buf_offset + 2 * len(s) + 2
        end = self.raw.index(b"\0", buf_offset)
        return self.raw[buf_offset:end].decode("latin-1"), end + 1


class SMBError(Exception):
    def __init__(self, status: int, message: str = ""):
        super().__init__(message or hex(status))
        self.status = status


###############################################################################
# Virtual file system state                                                   #
###############################################################################


@dataclasses.dataclass
class _OpenFile:
    name: str
    writer: FileWriter
    size: int = 0
    ctime: float = dataclasses.field(default_factory=time.time)
    mtime: float = dataclasses.field(default_factory=time.time)
    handles: int = 0
    delete_on_close: bool = False
    failed: bool = False  # a write was refused: discard instead of completing


@dataclasses.dataclass
class _Handle:
    conn_id: int
    file: _OpenFile | None  # None: the share's root directory


@dataclasses.dataclass
class _Search:
    conn_id: int
    rest: list  # entries not yet returned
    level: int


###############################################################################
# Server                                                                      #
###############################################################################


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class VirtualSMBServer:
    def __init__(
        self,
        backend: Backend,
        share: str = "SHARE",
        user: str = "user",
        password: str = "password",
        listen_address: str = "0.0.0.0",
        port: int = 445,
        free_bytes: int = 1 << 40,
        max_file_size: int = 16 << 30,
        challenge: bytes | None = None,  # fixed NTLM challenge (testing only)
        max_mpx_count: int = 1,
        large_read_write: bool = False,
    ):
        self.backend = backend
        self.share = share
        self.user = user
        self.free_bytes = free_bytes
        self.max_file_size = max_file_size
        self.max_mpx_count = max_mpx_count
        self.capabilities = CAPABILITIES
        if large_read_write:
            self.capabilities |= CAP_LARGE_READX | CAP_LARGE_WRITEX
        self._password_hash = nt_hash(password)
        self._fixed_challenge = challenge
        self._lock = threading.RLock()
        self._files: dict[str, _OpenFile] = {}
        self._handles: dict[int, _Handle] = {}
        self._searches: dict[int, _Search] = {}
        self._next_fid = 1
        self._next_sid = 1
        self._next_conn = 1
        self._server_guid = os.urandom(16)

        server = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                server._serve_connection(self.request, self.client_address)

        self._tcp = _TCPServer((listen_address, port), Handler)
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """TCP port the server listens on; chosen by the OS if `port=0`."""
        return self._tcp.server_address[1]

    ###########################################################################
    # Lifecycle                                                               #
    ###########################################################################

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._tcp.serve_forever, name="virtual-smb", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._tcp.shutdown()
        self._tcp.server_close()
        with self._lock:
            for f in list(self._files.values()):
                f.writer.abort()
            self._files.clear()
            self._handles.clear()

    def __enter__(self) -> typing.Self:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    ###########################################################################
    # Connection handling                                                     #
    ###########################################################################

    def _serve_connection(self, sock: socket.socket, addr) -> None:
        with self._lock:
            conn_id = self._next_conn
            self._next_conn += 1
        log.info("Connection %d from %s:%d", conn_id, *addr[:2])
        session = {
            "id": conn_id,
            "uid": None,
            "authenticated": False,
            "challenge": None,
            "tids": {},
            "next_tid": 1,
        }
        min_len = 35  # header, word count, byte count
        try:
            while True:
                msg_type, msg = self._recv_nbss(sock)
                if msg_type is None:
                    break
                if msg_type == 0x85:  # keep-alive
                    continue
                if msg_type == 0x81:  # NetBIOS session request (port 139)
                    sock.sendall(b"\x82\0\0\0")
                    continue
                if msg_type != 0x00 or not msg.startswith(b"\xffSMB"):
                    log.warning(
                        "Connection %d: unsupported message (type 0x%02x, %r)",
                        conn_id,
                        msg_type,
                        msg[:4],
                    )
                    break
                if len(msg) < min_len:
                    log.warning(
                        "Connection %d: truncated SMB message (%d bytes)",
                        conn_id,
                        len(msg),
                    )
                    break
                resp = self._dispatch(session, msg)
                if resp is not None:
                    sock.sendall(struct.pack(">I", len(resp)) + resp)
        except (ConnectionError, OSError) as e:
            log.info("Connection %d: %s", conn_id, e)
        finally:
            log.info("Connection %d closed", conn_id)
            self._connection_lost(conn_id)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def _recv_nbss(self, sock: socket.socket) -> tuple[int | None, bytes]:
        hdr = self._recv_exact(sock, 4)
        if hdr is None:
            return None, b""
        length = int.from_bytes(hdr[1:], "big")
        msg = self._recv_exact(sock, length) if length else b""
        if msg is None:
            return None, b""
        return hdr[0], msg

    def _connection_lost(self, conn_id: int) -> None:
        with self._lock:
            for fid, h in list(self._handles.items()):
                if h.conn_id == conn_id:
                    log.info("Connection %d lost with fid %d open", conn_id, fid)
                    self._release(fid, abort=True)
            for sid, s in list(self._searches.items()):
                if s.conn_id == conn_id:
                    del self._searches[sid]

    ###########################################################################
    # Message framing                                                         #
    ###########################################################################

    def _dispatch(self, session: dict, msg: bytes) -> bytes | None:
        # The caller guarantees len(msg) >= 35, i.e. header, WordCount and a
        # ByteCount for WordCount == 0.
        (_, cmd, _, _, flags2, pid_high, tid, pid, uid, mid) = _HEADER.unpack_from(msg)
        wc = msg[32]
        data_offset = 35 + 2 * wc
        malformed = data_offset > len(msg)
        if malformed:
            words, data, data_offset = b"", b"", len(msg)
        else:
            words = msg[33 : 33 + 2 * wc]
            (bc,) = struct.unpack_from("<H", msg, data_offset - 2)
            data = msg[data_offset : data_offset + bc]
        req = _Request(
            msg, cmd, flags2, tid, pid_high[:2], pid, uid, mid, words, data, data_offset
        )

        handler = self._COMMANDS.get(cmd)
        if cmd == SMB_COM_NT_CANCEL:
            return None  # no response
        try:
            if malformed:
                raise SMBError(STATUS_INVALID_PARAMETER, "WordCount exceeds message")
            if handler is None:
                log.warning("Unsupported SMB command 0x%02x", cmd)
                raise SMBError(STATUS_NOT_IMPLEMENTED)
            if cmd not in (SMB_COM_NEGOTIATE, SMB_COM_SESSION_SETUP_ANDX, SMB_COM_ECHO):
                if not session["authenticated"] or uid != session["uid"]:
                    raise SMBError(STATUS_SMB_BAD_UID)
                if (
                    cmd not in (SMB_COM_TREE_CONNECT_ANDX, SMB_COM_LOGOFF_ANDX)
                    and tid not in session["tids"]
                ):
                    raise SMBError(STATUS_SMB_BAD_TID)
            result = handler(self, session, req)
        except SMBError as e:
            log.debug("cmd 0x%02x -> status 0x%08x %s", cmd, e.status, e)
            return self._response(req, e.status, b"", b"")
        except Exception:
            log.exception("Error handling SMB command 0x%02x", cmd)
            return self._response(req, STATUS_NOT_SUPPORTED, b"", b"")
        if isinstance(result, bytes) or result is None:
            return result
        status, words_out, data_out, *overrides = result
        return self._response(req, status, words_out, data_out, *overrides)

    @staticmethod
    def _response(
        req: _Request,
        status: int,
        words: bytes,
        data: bytes,
        uid: int | None = None,
        tid: int | None = None,
        flags2: int = FLAGS2_RESPONSE,
    ) -> bytes:
        header = _HEADER.pack(
            b"\xffSMB",
            req.cmd,
            status,
            FLAGS_REPLY,
            flags2,
            req.pid_high + b"\0" * 10,
            req.tid if tid is None else tid,
            req.pid,
            req.uid if uid is None else uid,
            req.mid,
        )
        return (
            header
            + bytes([len(words) // 2])
            + words
            + struct.pack("<H", len(data))
            + data
        )

    @staticmethod
    def _data_start(n_words: int) -> int:
        """Offset of the data block in a response with `n_words` words."""
        return 32 + 1 + 2 * n_words + 2

    ###########################################################################
    # Session commands                                                        #
    ###########################################################################

    def _negotiate(self, session, req):
        dialects = [d.decode("latin-1") for d in req.data.split(b"\x02")[1:]]
        dialects = [d.rstrip("\0") for d in dialects]
        log.debug("NEGOTIATE dialects %s", dialects)
        if "NT LM 0.12" not in dialects:
            log.warning("Client does not offer NT LM 0.12: %s", dialects)
            return STATUS_SUCCESS, struct.pack("<H", 0xFFFF), b""
        words = struct.pack(
            "<HBHHIIIIQhB",
            dialects.index("NT LM 0.12"),
            SECURITY_MODE,
            self.max_mpx_count,
            1,
            MAX_BUFFER_SIZE,
            65536,
            0,
            self.capabilities,
            _filetime(time.time()),
            0,
            0,
        )
        return (
            STATUS_SUCCESS,
            words,
            self._server_guid + NEGOTIATE_BLOB,
            None,
            None,
            0xC800,
        )

    def _session_setup(self, session, req):
        if len(req.words) != 24:
            log.warning("SESSION_SETUP without extended security is not supported")
            raise SMBError(STATUS_NOT_SUPPORTED)
        (blob_len,) = struct.unpack_from("<H", req.words, 14)
        blob = req.data[:blob_len]
        spnego = blob.startswith((b"\x60", b"\xa1"))
        if spnego:
            # SPNEGO-wrapped token: the NTLMSSP message is embedded verbatim and
            # parsed by its own offsets, so trailing DER is harmless.
            idx = blob.find(b"NTLMSSP\0")
            if idx < 0:
                raise SMBError(STATUS_NOT_SUPPORTED, "SPNEGO without NTLMSSP")
            blob = blob[idx:]
        if not blob.startswith(b"NTLMSSP\0"):
            raise SMBError(STATUS_NOT_SUPPORTED, "unknown security blob")
        (msg_type,) = struct.unpack_from("<I", blob, 8)

        if msg_type == 1:  # NEGOTIATE -> CHALLENGE
            (client_flags,) = struct.unpack_from("<I", blob, 12)
            session["challenge"] = self._fixed_challenge or os.urandom(8)
            with self._lock:
                session["uid"] = 100 + session["id"]
            token = _ntlm_challenge(
                client_flags, session["challenge"], "VIRTUALSMB", "WORKGROUP"
            )
            if spnego:  # answer in kind; raw NTLMSSP clients get a raw token
                token = _spnego_challenge(token)
            return (
                STATUS_MORE_PROCESSING_REQUIRED,
                *self._setup_response(token),
                session["uid"],
            )

        if msg_type == 3:  # AUTHENTICATE
            if session["challenge"] is None or req.uid != session["uid"]:
                raise SMBError(STATUS_LOGON_FAILURE, "unexpected AUTHENTICATE")
            ok, name = _ntlm_verify(
                blob, session["challenge"], self.user, self._password_hash
            )
            session["challenge"] = None
            if not ok:
                log.warning("Authentication failed for user %r", name)
                raise SMBError(STATUS_LOGON_FAILURE)
            session["authenticated"] = True
            log.info("User %r authenticated", name)
            return (
                STATUS_SUCCESS,
                *self._setup_response(ACCEPT_COMPLETED_BLOB),
                session["uid"],
            )

        raise SMBError(STATUS_NOT_SUPPORTED, f"NTLMSSP message type {msg_type}")

    def _setup_response(self, blob: bytes) -> tuple[bytes, bytes]:
        words = _ANDX_NONE + struct.pack("<HH", 0, len(blob))
        data = blob
        if (self._data_start(4) + len(data)) & 1:
            data += b"\0"
        data += _utf16z("Unix") + _utf16z("virtual_smb")
        return words, data

    def _tree_connect(self, session, req):
        (_, _, _, _, password_len) = struct.unpack_from("<BBHHH", req.words)
        path, end = req.string(req.data_offset + password_len)
        service = req.raw[end:].split(b"\0", 1)[0].decode("latin-1")
        share = path.rsplit("\\", 1)[-1]
        log.debug("TREE_CONNECT %r service %r", path, service)
        if share.upper() == "IPC$":
            kind, svc = "ipc", b"IPC\0"
        elif share.lower() == self.share.lower():
            kind, svc = "disk", b"A:\0"
        else:
            log.warning("Client asked for unknown share %r", share)
            raise SMBError(STATUS_BAD_NETWORK_NAME)
        tid = session["next_tid"]
        session["next_tid"] += 1
        session["tids"][tid] = kind
        # Extended response (7 words): optional support "search bits",
        # maximal and guest maximal share access rights.
        words = _ANDX_NONE + struct.pack("<HII", 0x0001, 0x001F01FF, 0x001F01FF)
        data = svc
        if (self._data_start(7) + len(data)) & 1:
            data += b"\0"
        data += _utf16z("NTFS")
        return STATUS_SUCCESS, words, data, None, tid

    def _tree_disconnect(self, session, req):
        session["tids"].pop(req.tid, None)
        return STATUS_SUCCESS, b"", b""

    def _logoff(self, session, req):
        session["authenticated"] = False
        session["tids"].clear()
        return STATUS_SUCCESS, _ANDX_NONE, b""

    def _echo(self, session, req):
        return STATUS_SUCCESS, struct.pack("<H", 1), req.data

    ###########################################################################
    # State helpers                                                           #
    ###########################################################################

    def _lookup(self, name: str) -> tuple[bool, int, float, float] | None:
        """Return (is_dir, size, ctime, mtime) for `name`, or None."""
        if name == "":
            now = time.time()
            return True, 0, now, now
        if name in self._files:
            f = self._files[name]
            return False, f.size, f.ctime, f.mtime
        for fi in self.backend.list_files():
            if fi.name.lower() == name.lower():
                return False, fi.size, fi.mtime, fi.mtime
        return None

    def _listing(self) -> list[tuple[str, bool, int, float, float]]:
        now = time.time()
        entries = {".": (True, 0, now, now), "..": (True, 0, now, now)}
        for fi in self.backend.list_files():
            entries[fi.name] = (False, fi.size, fi.mtime, fi.mtime)
        for f in self._files.values():
            entries[f.name] = (False, f.size, f.ctime, f.mtime)
        return [(n, *v) for n, v in entries.items()]

    def _alloc_id(self, counter: str, in_use: dict) -> int:
        """Next free 16-bit id (1..0xFFFE) from the counter attribute `counter`."""
        for _ in range(0xFFFE):
            new_id = getattr(self, counter)
            setattr(self, counter, new_id % 0xFFFE + 1)
            if new_id not in in_use:
                return new_id
        raise SMBError(STATUS_TOO_MANY_OPENED_FILES)

    def _new_handle(self, conn_id: int, f: _OpenFile | None) -> int:
        fid = self._alloc_id("_next_fid", self._handles)
        self._handles[fid] = _Handle(conn_id, f)
        if f is not None:
            f.handles += 1
        return fid

    def _handle(self, session, fid: int) -> _Handle:
        h = self._handles.get(fid)
        if h is None or h.conn_id != session["id"]:
            raise SMBError(STATUS_INVALID_HANDLE)
        return h

    def _search(self, session, sid: int) -> _Search:
        s = self._searches.get(sid)
        if s is None or s.conn_id != session["id"]:
            raise SMBError(STATUS_INVALID_HANDLE)
        return s

    def _check_size(self, f: _OpenFile, size: int) -> None:
        if size > self.max_file_size:
            log.warning(
                "Refusing to grow %s to %d bytes (limit %d)",
                f.name,
                size,
                self.max_file_size,
            )
            f.failed = True
            raise SMBError(STATUS_DISK_FULL)

    def _release(self, fid: int, abort: bool = False) -> None:
        h = self._handles.pop(fid)
        f = h.file
        if f is None:
            return
        f.handles -= 1
        if f.handles > 0:
            return
        del self._files[f.name]
        if abort or f.delete_on_close or f.failed:
            f.writer.abort()
        else:
            log.debug("File %s complete (%d bytes)", f.name, f.size)
            f.writer.close()

    def _require_disk(self, session, req) -> None:
        if session["tids"].get(req.tid) != "disk":
            raise SMBError(STATUS_ACCESS_DENIED, "not a disk share")

    ###########################################################################
    # File commands                                                           #
    ###########################################################################

    def _nt_create(self, session, req):
        self._require_disk(session, req)
        (
            _,
            _,
            _,
            _,
            _name_len,
            _flags,
            root_fid,
            access,
            _alloc,
            _attrs,
            _share,
            disp,
            opts,
            _imp,
            _sec,
        ) = struct.unpack_from("<BBHBHIIIQIIIIIB", req.words)
        name, _ = req.string(req.data_offset)
        name = _norm(name)
        log.debug(
            "NT_CREATE_ANDX %r %s options=0x%x access=0x%x",
            name,
            _DISPOSITIONS.get(disp, disp),
            opts,
            access,
        )

        with self._lock:
            if root_fid:
                root = self._handle(session, root_fid)
                if root.file is not None:
                    raise SMBError(STATUS_INVALID_HANDLE)
            if "\\" in name:
                raise SMBError(STATUS_OBJECT_PATH_NOT_FOUND)

            info = self._lookup(name)
            action = FILE_OPENED
            if name == "":  # the share root
                if disp not in (FILE_OPEN, FILE_OPEN_IF):
                    raise SMBError(STATUS_ACCESS_DENIED)
                if opts & FILE_NON_DIRECTORY_FILE:
                    raise SMBError(STATUS_FILE_IS_A_DIRECTORY)
                f = None
            elif opts & FILE_DIRECTORY_FILE:
                raise SMBError(
                    STATUS_ACCESS_DENIED
                    if disp != FILE_OPEN
                    else STATUS_OBJECT_NAME_NOT_FOUND
                )
            elif name in self._files:  # already being written: share it
                if disp == FILE_CREATE:
                    raise SMBError(STATUS_OBJECT_NAME_COLLISION)
                f = self._files[name]
                if disp in (FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF):
                    f.writer.truncate(0)
                    f.size = 0
                    action = FILE_OVERWRITTEN
            else:
                if disp in (FILE_OPEN, FILE_OVERWRITE):
                    # Opening existing files (for reading) is not supported.
                    raise SMBError(
                        STATUS_OBJECT_NAME_NOT_FOUND
                        if info is None
                        else STATUS_ACCESS_DENIED
                    )
                if disp == FILE_CREATE and info is not None:
                    raise SMBError(STATUS_OBJECT_NAME_COLLISION)
                try:
                    writer = self.backend.create(name)
                except PermissionError:
                    raise SMBError(STATUS_ACCESS_DENIED) from None
                f = _OpenFile(name, writer)
                self._files[name] = f
                action = FILE_CREATED if info is None else FILE_OVERWRITTEN
                log.info("Client creates %s", name)

            if f is not None and opts & FILE_DELETE_ON_CLOSE:
                f.delete_on_close = True
            fid = self._new_handle(session["id"], f)
            now = time.time()
            is_dir, size, ctime, mtime = (
                (True, 0, now, now) if f is None else (False, f.size, f.ctime, f.mtime)
            )

        words = _ANDX_NONE + struct.pack(
            "<BHIQQQQIQQHHB",
            0,  # oplock level: none
            fid,
            action,
            _filetime(ctime),
            _filetime(mtime),
            _filetime(mtime),
            _filetime(mtime),
            ATTR_DIRECTORY if is_dir else ATTR_ARCHIVE,
            size,
            size,
            0,  # resource type: disk file or directory
            0,  # named pipe status
            int(is_dir),
        )
        return STATUS_SUCCESS, words, b""

    def _write_andx(self, session, req):
        if len(req.words) == 28:
            (
                _,
                _,
                _,
                fid,
                offset,
                _timeout,
                _mode,
                _remaining,
                len_hi,
                length,
                data_off,
                offset_hi,
            ) = struct.unpack_from("<BBHHIIHHHHHI", req.words)
        else:
            (
                _,
                _,
                _,
                fid,
                offset,
                _timeout,
                _mode,
                _remaining,
                len_hi,
                length,
                data_off,
            ) = struct.unpack_from("<BBHHIIHHHHH", req.words)
            offset_hi = 0
        length |= len_hi << 16
        offset |= offset_hi << 32
        data = req.raw[data_off : data_off + length]
        if len(data) != length:
            raise SMBError(STATUS_ACCESS_DENIED, "truncated WRITE_ANDX")

        with self._lock:
            h = self._handle(session, fid)
            if h.file is None:
                raise SMBError(STATUS_ACCESS_DENIED, "write to directory")
            f = h.file
            log.debug("WRITE_ANDX %s: %d bytes at %d", f.name, length, offset)
            self._check_size(f, offset + length)
            f.writer.write(offset, data)
            f.size = max(f.size, offset + length)
            f.mtime = time.time()

        words = _ANDX_NONE + struct.pack(
            "<HHHH", length & 0xFFFF, 0xFFFF, length >> 16, 0
        )
        return STATUS_SUCCESS, words, b""

    def _read_andx(self, session, req):
        # With `cache=loose`, the Linux client reads pages it only partially
        # overwrites. When the read fails, it writes the data directly instead.
        log.debug("READ_ANDX refused (share is write-only)")
        raise SMBError(STATUS_ACCESS_DENIED, "share is write-only")

    def _flush(self, session, req):
        (fid,) = struct.unpack_from("<H", req.words)
        if fid != 0xFFFF:
            with self._lock:
                self._handle(session, fid)
        return STATUS_SUCCESS, b"", b""

    def _close(self, session, req):
        (fid,) = struct.unpack_from("<H", req.words)
        with self._lock:
            self._handle(session, fid)
            log.debug("CLOSE fid %d", fid)
            self._release(fid)
        return STATUS_SUCCESS, b"", b""

    def _find_close2(self, session, req):
        (sid,) = struct.unpack_from("<H", req.words)
        with self._lock:
            self._search(session, sid)
            del self._searches[sid]
        return STATUS_SUCCESS, b"", b""

    ###########################################################################
    # Trans2 Call                                                             #
    ###########################################################################

    def _trans2(self, session, req):
        (
            total_params,
            total_data,
            _max_params,
            max_data,
            _max_setup,
            _,
            _flags,
            _timeout,
            _,
            param_count,
            param_off,
            data_count,
            data_off,
            _setup_count,
            _,
        ) = struct.unpack_from("<HHHHBBHIHHHHHBB", req.words)
        if param_count != total_params or data_count != total_data:
            log.warning("Multi-part TRANS2 requests are not supported")
            raise SMBError(STATUS_NOT_SUPPORTED)
        (sub,) = struct.unpack_from("<H", req.words, 28)
        params = req.raw[param_off : param_off + param_count]
        data = req.raw[data_off : data_off + data_count]
        handler = self._TRANS2.get(sub)
        if handler is None:
            log.warning("Unsupported TRANS2 subcommand 0x%02x", sub)
            raise SMBError(STATUS_NOT_SUPPORTED)
        if sub != TRANS2_QUERY_FS_INFORMATION:
            self._require_disk(session, req)
        resp_params, resp_data = handler(self, session, req, params, data, max_data)

        # Response: 10 words, then params and data, each 4-byte aligned.
        start = self._data_start(10)
        pad1 = (-start) % 4
        p_off = start + pad1
        pad2 = (-(p_off + len(resp_params))) % 4
        d_off = p_off + len(resp_params) + pad2
        words = struct.pack(
            "<HHHHHHHHHBB",
            len(resp_params),
            len(resp_data),
            0,
            len(resp_params),
            p_off,
            0,
            len(resp_data),
            d_off,
            0,
            0,
            0,
        )
        out = b"\0" * pad1 + resp_params + b"\0" * pad2 + resp_data
        return STATUS_SUCCESS, words, out

    def _trans2_string(self, req, params: bytes, offset: int) -> str:
        if req.unicode:
            return _norm(_read_utf16z(params, offset))
        return _norm(params[offset:].split(b"\0", 1)[0].decode("latin-1"))

    def _query_fs_info(self, session, req, params, data, max_data):
        (level,) = struct.unpack_from("<H", params)
        log.debug("QUERY_FS_INFORMATION level 0x%x", level)
        unit = 4096
        total, free = 2 * self.free_bytes // unit, self.free_bytes // unit
        if level in (QUERY_FS_SIZE_INFO, FS_SIZE_INFORMATION):
            out = struct.pack("<QQII", total, free, 8, 512)
        elif level == FS_FULL_SIZE_INFORMATION:
            out = struct.pack("<QQQII", total, free, free, 8, 512)
        elif level == QUERY_FS_DEVICE_INFO:
            out = struct.pack("<II", 0x07, 0)  # FILE_DEVICE_DISK
        elif level == QUERY_FS_ATTRIBUTE_INFO:
            fs_name = "NTFS".encode("utf-16le")
            # FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES
            out = struct.pack("<III", 0x03, 255, len(fs_name)) + fs_name
        elif level == QUERY_FS_VOLUME_INFO:
            out = struct.pack("<QIIH", _filetime(time.time()), 0x52494730, 0, 0)
        else:
            log.warning("Unsupported QUERY_FS_INFORMATION level 0x%x", level)
            raise SMBError(STATUS_INVALID_LEVEL)
        return b"", out

    def _info_record(self, name: str, level: int) -> bytes:
        with self._lock:
            info = self._lookup(name)
            f = self._files.get(name)
        if info is None:
            raise SMBError(STATUS_OBJECT_NAME_NOT_FOUND)
        is_dir, size, ctime, mtime = info
        attrs = ATTR_DIRECTORY if is_dir else ATTR_ARCHIVE
        delete_pending = int(bool(f and f.delete_on_close))
        times = struct.pack(
            "<QQQQ",
            _filetime(ctime),
            _filetime(mtime),
            _filetime(mtime),
            _filetime(mtime),
        )
        if level in (QUERY_FILE_BASIC_INFO, FILE_BASIC_INFORMATION):
            return times + struct.pack("<II", attrs, 0)
        if level == QUERY_FILE_STANDARD_INFO:
            return struct.pack("<QQIBB", size, size, 1, delete_pending, int(is_dir))
        if level == FILE_STANDARD_INFORMATION:
            return struct.pack("<QQIBBH", size, size, 1, delete_pending, int(is_dir), 0)
        if level in (QUERY_FILE_EA_INFO, FILE_EA_INFORMATION):
            return struct.pack("<I", 0)
        if level == QUERY_FILE_ALL_INFO:
            fname = name.encode("utf-16le")
            return (
                times
                + struct.pack(
                    "<IIQQIBBHII",
                    attrs,
                    0,
                    size,
                    size,
                    1,
                    delete_pending,
                    int(is_dir),
                    0,
                    0,
                    len(fname),
                )
                + fname
            )
        if level == FILE_INTERNAL_INFORMATION:
            return struct.pack("<Q", _inode(name))
        if level == FILE_NETWORK_OPEN_INFORMATION:
            return times + struct.pack("<QQII", size, size, attrs, 0)
        log.warning("Unsupported query info level 0x%x for %r", level, name)
        raise SMBError(STATUS_INVALID_LEVEL)

    def _query_path_info(self, session, req, params, data, max_data):
        (level,) = struct.unpack_from("<H", params)
        name = self._trans2_string(req, params, 6)
        log.debug("QUERY_PATH_INFORMATION %r level 0x%x", name, level)
        return struct.pack("<H", 0), self._info_record(name, level)

    def _query_file_info(self, session, req, params, data, max_data):
        fid, level = struct.unpack_from("<HH", params)
        with self._lock:
            h = self._handle(session, fid)
        name = "" if h.file is None else h.file.name
        log.debug("QUERY_FILE_INFORMATION %r level 0x%x", name, level)
        return struct.pack("<H", 0), self._info_record(name, level)

    def _apply_set_info(self, f: _OpenFile, level: int, data: bytes) -> None:
        if level in (SET_FILE_END_OF_FILE_INFO, FILE_END_OF_FILE_INFORMATION):
            (size,) = struct.unpack_from("<Q", data)
            log.debug("SET_FILE_INFO %s: end of file %d", f.name, size)
            self._check_size(f, size)
            f.writer.truncate(size)
            f.size = size
        elif level in (SET_FILE_BASIC_INFO, FILE_BASIC_INFORMATION):
            (_, _, mtime, _) = struct.unpack_from("<qqqq", data)
            if mtime not in (0, -1):
                f.mtime = _from_filetime(mtime)
        elif level in (SET_FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFORMATION):
            f.delete_on_close = bool(data[:1] and data[0])
            log.debug("SET_FILE_INFO %s: delete pending %s", f.name, f.delete_on_close)
        elif level in (SET_FILE_ALLOCATION_INFO, FILE_ALLOCATION_INFORMATION):
            pass  # pre-allocation hint
        else:
            log.warning("Unsupported set info level 0x%x for %r", level, f.name)
            raise SMBError(STATUS_INVALID_LEVEL)

    def _set_file_info(self, session, req, params, data, max_data):
        fid, level = struct.unpack_from("<HH", params)
        with self._lock:
            h = self._handle(session, fid)
            if h.file is not None:  # setting times etc. on the root: ignore
                self._apply_set_info(h.file, level, data)
        return struct.pack("<H", 0), b""

    def _set_path_info(self, session, req, params, data, max_data):
        (level,) = struct.unpack_from("<H", params)
        name = self._trans2_string(req, params, 6)
        log.debug("SET_PATH_INFORMATION %r level 0x%x", name, level)
        with self._lock:
            f = self._files.get(name)
            if f is not None:
                self._apply_set_info(f, level, data)
            elif name != "":  # root: ignore
                raise SMBError(
                    STATUS_ACCESS_DENIED
                    if self._lookup(name)
                    else STATUS_OBJECT_NAME_NOT_FOUND
                )
        return struct.pack("<H", 0), b""

    ###########################################################################
    # Directory Listing                                                       #
    ###########################################################################

    _FIND_LEVELS = (
        FIND_FILE_DIRECTORY_INFO,
        FIND_FILE_FULL_DIRECTORY_INFO,
        FIND_FILE_NAMES_INFO,
        FIND_FILE_BOTH_DIRECTORY_INFO,
        FIND_FILE_ID_FULL_DIRECTORY_INFO,
        FIND_FILE_ID_BOTH_DIRECTORY_INFO,
    )

    @staticmethod
    def _find_entry(level: int, unicode: bool, entry) -> bytes:
        """One directory entry without NextEntryOffset (first 4 bytes)."""
        name, is_dir, size, ctime, mtime = entry
        fname = name.encode("utf-16le" if unicode else "latin-1")
        if level == FIND_FILE_NAMES_INFO:
            return struct.pack("<II", 0, len(fname)) + fname
        fixed = struct.pack(
            "<IQQQQQQII",
            0,
            _filetime(ctime),
            _filetime(mtime),
            _filetime(mtime),
            _filetime(mtime),
            size,
            size,
            ATTR_DIRECTORY if is_dir else ATTR_ARCHIVE,
            len(fname),
        )
        file_id = _inode("" if name in (".", "..") else name)
        if level == FIND_FILE_DIRECTORY_INFO:
            return fixed + fname
        if level == FIND_FILE_FULL_DIRECTORY_INFO:
            return fixed + struct.pack("<I", 0) + fname
        if level == FIND_FILE_ID_FULL_DIRECTORY_INFO:
            return fixed + struct.pack("<IIQ", 0, 0, file_id) + fname
        short = struct.pack("<IBB", 0, 0, 0) + b"\0" * 24  # EaSize, no short name
        if level == FIND_FILE_BOTH_DIRECTORY_INFO:
            return fixed + short + fname
        return fixed + short + struct.pack("<HQ", 0, file_id) + fname  # ID_BOTH

    def _find_page(
        self, entries: list, level: int, unicode: bool, max_count: int, max_data: int
    ) -> tuple[bytes, int, int, list]:
        """Pack entries (8-byte aligned, chained by NextEntryOffset).

        Returns (data, count, offset of the last entry, remaining entries).
        """
        raws: list[bytes] = []
        total = 0
        for e in entries[:max_count]:
            raw = self._find_entry(level, unicode, e)
            size = 4 + len(raw)
            if raws and total + size > max_data:
                break
            raws.append(raw)
            total += size + (-size) % 8
        out = b""
        last_offset = 0
        for i, raw in enumerate(raws):
            size = 4 + len(raw)
            pad = 0 if i == len(raws) - 1 else (-size) % 8
            next_off = 0 if i == len(raws) - 1 else size + pad
            last_offset = len(out)
            out += struct.pack("<I", next_off) + raw + b"\0" * pad
        return out, len(raws), last_offset, entries[len(raws) :]

    def _find_first2(self, session, req, params, data, max_data):
        (_attrs, search_count, flags, level, _storage) = struct.unpack_from(
            "<HHHHI", params
        )
        pattern = self._trans2_string(req, params, 12)
        log.debug("FIND_FIRST2 %r level 0x%x", pattern, level)
        if level not in self._FIND_LEVELS:
            log.warning("Unsupported FIND_FIRST2 level 0x%x", level)
            raise SMBError(STATUS_INVALID_LEVEL)
        if "\\" in pattern:
            raise SMBError(STATUS_OBJECT_PATH_NOT_FOUND)

        with self._lock:
            listing = self._listing()
        if pattern == "*":
            entries = listing
        else:
            entries = [
                e
                for e in listing
                if e[0] not in (".", "..")
                and fnmatch.fnmatch(e[0].lower(), pattern.lower())
            ]
        if not entries:
            raise SMBError(STATUS_NO_SUCH_FILE)

        out, count, last_offset, rest = self._find_page(
            entries, level, req.unicode, search_count or 0xFFFF, max_data
        )
        close = bool(
            flags & FIND_CLOSE_AFTER_REQUEST or (not rest and flags & FIND_CLOSE_AT_EOS)
        )
        with self._lock:
            sid = self._alloc_id("_next_sid", self._searches)
            if not close:
                self._searches[sid] = _Search(session["id"], rest, level)
        resp = struct.pack("<HHHHH", sid, count, int(not rest), 0, last_offset)
        return resp, out

    def _find_next2(self, session, req, params, data, max_data):
        sid, search_count, level, _resume, flags = struct.unpack_from("<HHHIH", params)
        with self._lock:
            search = self._search(session, sid)
        out, count, last_offset, rest = self._find_page(
            search.rest,
            level or search.level,
            req.unicode,
            search_count or 0xFFFF,
            max_data,
        )
        with self._lock:
            if flags & FIND_CLOSE_AFTER_REQUEST or (
                not rest and flags & FIND_CLOSE_AT_EOS
            ):
                self._searches.pop(sid, None)
            else:
                search.rest = rest
        return struct.pack("<HHHH", count, int(not rest), 0, last_offset), out

    ###########################################################################
    # Dispatch tables                                                         #
    ###########################################################################

    _COMMANDS: typing.ClassVar = {
        SMB_COM_NEGOTIATE: _negotiate,
        SMB_COM_SESSION_SETUP_ANDX: _session_setup,
        SMB_COM_TREE_CONNECT_ANDX: _tree_connect,
        SMB_COM_TREE_DISCONNECT: _tree_disconnect,
        SMB_COM_LOGOFF_ANDX: _logoff,
        SMB_COM_ECHO: _echo,
        SMB_COM_NT_CREATE_ANDX: _nt_create,
        SMB_COM_WRITE_ANDX: _write_andx,
        SMB_COM_READ_ANDX: _read_andx,
        SMB_COM_FLUSH: _flush,
        SMB_COM_CLOSE: _close,
        SMB_COM_FIND_CLOSE2: _find_close2,
        SMB_COM_TRANSACTION2: _trans2,
    }
    _TRANS2: typing.ClassVar = {
        TRANS2_QUERY_FS_INFORMATION: _query_fs_info,
        TRANS2_QUERY_PATH_INFORMATION: _query_path_info,
        TRANS2_QUERY_FILE_INFORMATION: _query_file_info,
        TRANS2_SET_FILE_INFORMATION: _set_file_info,
        TRANS2_SET_PATH_INFORMATION: _set_path_info,
        TRANS2_FIND_FIRST2: _find_first2,
        TRANS2_FIND_NEXT2: _find_next2,
    }
