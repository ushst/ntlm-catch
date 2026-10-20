import io
import os
import pathlib
import struct
import tempfile
import threading
import unittest

import ntlm_catch
import serve_external_xlsx


class FormattingTests(unittest.TestCase):
    def test_ansi_fit_uses_terminal_cells(self):
        value = ntlm_catch.ansi_fit("A界B", 4)
        self.assertEqual(ntlm_catch.visible_len(value), 4)
        self.assertEqual(ntlm_catch.strip_ansi(value), "A界B")

    def test_ansi_wrap_preserves_cell_width(self):
        lines = ntlm_catch.ansi_wrap("ab界cd", 4)
        self.assertEqual([ntlm_catch.strip_ansi(v) for v in lines],
                         ["ab界", "cd"])
        self.assertTrue(all(ntlm_catch.visible_len(v) <= 4 for v in lines))

    def test_fragmented_escape_sequence_is_retained(self):
        view = ntlm_catch._SplitView.__new__(ntlm_catch._SplitView)
        actions, rest = view._parse_input("\x1b")
        self.assertEqual(actions, [])
        self.assertEqual(rest, "\x1b")
        actions, rest = view._parse_input(rest + "[A")
        self.assertEqual(actions, ["up"])
        self.assertEqual(rest, "")


class ProtocolTests(unittest.TestCase):
    def test_type2_challenge_and_downgrade_flag(self):
        challenge = bytes.fromhex("1122334455667788")
        normal = ntlm_catch.build_type2(challenge, "CORP", "HOST", False)
        downgraded = ntlm_catch.build_type2(challenge, "CORP", "HOST", True)
        self.assertEqual(normal[:8], ntlm_catch.NTLMSSP_SIG)
        self.assertEqual(normal[24:32], challenge)
        self.assertTrue(struct.unpack("<I", normal[20:24])[0] & 0x00080000)
        self.assertFalse(struct.unpack("<I", downgraded[20:24])[0] & 0x00080000)

    def test_type3_rejects_out_of_bounds_fields(self):
        message = bytearray(64)
        message[:8] = ntlm_catch.NTLMSSP_SIG
        struct.pack_into("<I", message, 8, 3)
        struct.pack_into("<H", message, 20, 24)
        struct.pack_into("<I", message, 24, 1000)
        with self.assertRaisesRegex(ValueError, "outside"):
            ntlm_catch.parse_type3(bytes(message))

    def test_smb_frame_size_limit(self):
        payload = struct.pack(">I", ntlm_catch.MAX_MESSAGE_SIZE + 1)

        class FakeSocket:
            def __init__(self, data):
                self.data = io.BytesIO(data)

            def recv(self, size):
                return self.data.read(size)

        with self.assertRaisesRegex(ValueError, "too large"):
            ntlm_catch._read_smb(FakeSocket(payload))


class FileWriteTests(unittest.TestCase):
    def test_concurrent_atomic_writes_do_not_share_temp_file(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = []

            def write(value):
                try:
                    serve_external_xlsx.write_to_disk(
                        directory, "result.bin", value)
                except Exception as exc:  # pragma: no cover - assertion below
                    errors.append(exc)

            values = [bytes([n]) * 100 for n in range(16)]
            threads = [threading.Thread(target=write, args=(v,))
                       for v in values]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(errors, [])
            result = pathlib.Path(directory, "result.bin").read_bytes()
            self.assertIn(result, values)
            leftovers = [p for p in os.listdir(directory)
                         if p.endswith(".tmp")]
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
