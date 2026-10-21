import socket
import struct
import unittest
from contextlib import redirect_stdout
from io import StringIO

from name_poisoner import NamePoisoner, _dns_answer, _nbns_answer


def dns_query(name, txid=0x1234):
    encoded = b"".join(bytes([len(part)]) + part.encode("ascii")
                       for part in name.split(".")) + b"\x00"
    return (struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + encoded +
            struct.pack("!HH", 1, 1))


def nbns_query(name, txid=0x4321):
    raw = name.upper().ljust(15).encode("ascii") + b"\x20"
    encoded = bytearray()
    for value in raw:
        encoded.extend((0x41 + (value >> 4), 0x41 + (value & 0x0F)))
    return (struct.pack("!HHHHHH", txid, 0x0110, 1, 0, 0, 0) + b"\x20" +
            bytes(encoded) + b"\x00" + struct.pack("!HH", 0x20, 1))


class PacketTests(unittest.TestCase):
    def test_llmnr_answer_contains_listener_address(self):
        name, qclass, response = _dns_answer(
            dns_query("missing.lab"), "192.168.56.10", "llmnr")
        self.assertEqual(name, "missing.lab")
        self.assertEqual(qclass, 1)
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(response[-4:], socket.inet_aton("192.168.56.10"))

    def test_nbns_answer_decodes_name_and_address(self):
        name, response = _nbns_answer(
            nbns_query("FILESERVER"), "192.168.56.10")
        self.assertEqual(name, "FILESERVER<20>")
        self.assertEqual(response[:2], b"\x43\x21")
        self.assertEqual(response[-4:], socket.inet_aton("192.168.56.10"))

    def test_scope_and_allowlist_are_enforced(self):
        poisoner = NamePoisoner(
            "192.168.56.10", "192.168.56.0/24", {"llmnr"},
            allow_names=["lab.local"])
        self.assertTrue(poisoner._allowed("192.168.56.20", "dc.lab.local"))
        self.assertTrue(poisoner._allowed("192.168.56.20", "LAB.LOCAL<20>"))
        self.assertFalse(poisoner._allowed("192.168.57.20", "dc.lab.local"))
        self.assertFalse(poisoner._allowed("192.168.56.20", "public.example"))
        self.assertFalse(poisoner._allowed("192.168.56.10", "dc.lab.local"))

    def test_rejects_ipv6_and_overbroad_scope(self):
        with self.assertRaisesRegex(ValueError, "IPv4"):
            NamePoisoner("::1", "::1/128", {"llmnr"})
        with self.assertRaisesRegex(ValueError, "at least"):
            NamePoisoner("10.0.0.1", "0.0.0.0/0", {"llmnr"})

    def test_toggles_only_configured_protocols(self):
        poisoner = NamePoisoner(
            "192.168.56.10", "192.168.56.0/24", {"llmnr"})
        with redirect_stdout(StringIO()):
            poisoner.toggle("llmnr")
        self.assertFalse(poisoner.enabled["llmnr"])
        with redirect_stdout(StringIO()):
            poisoner.toggle("mdns")
        self.assertFalse(poisoner.enabled["mdns"])


if __name__ == "__main__":
    unittest.main()
