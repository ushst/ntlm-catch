#!/usr/bin/env python3
"""Serve a tiny XLSX that Excel can pull via UNC/WebDAV/HTTP.

Formula example (in another workbook):
  ='\\\\HOST\\PUBLIC\\[extenal.xlsx]Лист1'!$A$1

Each GET rebuilds the workbook with a fresh random digit (0-9) in Лист1!A1.

Usage:
  # HTTP/WebDAV (Excel often uses WebDAV redirector for http hosts)
  python3 serve_external_xlsx.py --port 80

  # also keep a file on disk for Samba share PUBLIC/
  python3 serve_external_xlsx.py --write-dir ./PUBLIC --port 8080

Pure stdlib. Authorized testing only.
"""
from __future__ import annotations

import argparse
import io
import os
import random
import sys
import tempfile
import time
from typing import Optional
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse
from xml.sax.saxutils import escape


SHEET_NAME = "Лист1"
DEFAULT_FILENAME = "extenal.xlsx"


def build_xlsx(value) -> bytes:
    """Minimal XLSX: one sheet, A1 = value (number or string)."""
    # Inline number in the cell (no sharedStrings needed).
    if isinstance(value, (int, float)):
        cell_xml = f'<c r="A1"><v>{value}</v></c>'
    else:
        cell_xml = (
            f'<c r="A1" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>'
        )

    sheet = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">{cell_xml}</row>
  </sheetData>
</worksheet>
"""

    workbook = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="{escape(SHEET_NAME)}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
"""

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>
"""

    rels_root = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"/>
</Relationships>
"""

    rels_wb = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"/>
</Relationships>
"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels_root)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", rels_wb)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()


def random_digit() -> int:
    return random.randint(0, 9)


def write_to_disk(outdir: str, filename: str, data: bytes) -> str:
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, filename)
    fd, tmp = tempfile.mkstemp(prefix=filename + ".", suffix=".tmp",
                               dir=outdir)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def make_handler(filename: str, write_dir: Optional[str], lo: int, hi: int):
    targets = {
        f"/{filename}".lower(),
        f"/public/{filename}".lower(),
        f"/PUBLIC/{filename}".lower(),
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "Microsoft-IIS/10.0"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            sys.stderr.write("[%s] %s - %s\n"
                             % (self.log_date_time_string(),
                                self.address_string(), fmt % args))

        def _path(self) -> str:
            return unquote(urlparse(self.path).path)

        def _is_file(self) -> bool:
            p = self._path().rstrip("/").lower()
            return p in targets or p.endswith("/" + filename.lower())

        def _is_dir(self) -> bool:
            p = self._path().rstrip("/").lower()
            return p in ("", "/", "/public", "/PUBLIC".lower())

        def _xlsx(self) -> bytes:
            value = random.randint(lo, hi)
            data = build_xlsx(value)
            print(f"[+] serving {filename}: Лист1!A1 = {value} "
                  f"({len(data)} bytes) -> {self.client_address[0]}")
            if write_dir:
                path = write_to_disk(write_dir, filename, data)
                print(f"    wrote {path}")
            return data

        def _send(self, code, body=b"", content_type="text/plain",
                  extra=None):
            self.send_response(code)
            self.send_header("Server", "Microsoft-IIS/10.0")
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("DAV", "1,2")
            self.send_header("MS-Author-Via", "DAV")
            self.send_header("Allow",
                             "OPTIONS, GET, HEAD, PROPFIND")
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def do_OPTIONS(self):
            self._send(200, b"", extra=[
                ("Public", "OPTIONS, GET, HEAD, PROPFIND"),
            ])

        def do_HEAD(self):
            if self._is_file():
                data = self._xlsx()
                ctype = ("application/vnd.openxmlformats-officedocument."
                         "spreadsheetml.sheet")
                self.send_response(200)
                self.send_header("Server", "Microsoft-IIS/10.0")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("DAV", "1,2")
                self.end_headers()
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            if self._is_file():
                data = self._xlsx()
                ctype = ("application/vnd.openxmlformats-officedocument."
                         "spreadsheetml.sheet")
                self._send(200, data, content_type=ctype)
                return
            if self._is_dir():
                body = (f"PUBLIC share — GET /PUBLIC/{filename}\n").encode()
                self._send(200, body, content_type="text/plain; charset=utf-8")
                return
            self._send(404, b"not found\n")

        def do_PROPFIND(self):
            """Minimal WebDAV so Excel's redirector can list/stat the file."""
            depth = self.headers.get("Depth", "1")
            path = self._path().rstrip("/") or "/"
            href_base = path if path.startswith("/") else "/" + path

            items = []
            if self._is_file() or href_base.lower().endswith(
                    "/" + filename.lower()):
                items.append((f"{href_base}", False, 1024))
            else:
                # collection
                items.append((href_base if href_base.endswith("/")
                              else href_base + "/", True, 0))
                if depth != "0":
                    items.append((f"{href_base.rstrip('/')}/{filename}",
                                  False, 1024))

            chunks = [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<D:multistatus xmlns:D="DAV:">',
            ]
            now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            for href, is_dir, size in items:
                chunks.append("<D:response>")
                chunks.append(f"<D:href>{escape(href)}</D:href>")
                chunks.append("<D:propstat><D:prop>")
                if is_dir:
                    chunks.append("<D:resourcetype><D:collection/></D:resourcetype>")
                else:
                    chunks.append("<D:resourcetype/>")
                    chunks.append(
                        "<D:getcontenttype>application/vnd.openxmlformats-"
                        "officedocument.spreadsheetml.sheet</D:getcontenttype>")
                    chunks.append(f"<D:getcontentlength>{size}</D:getcontentlength>")
                chunks.append(f"<D:getlastmodified>{now}</D:getlastmodified>")
                chunks.append("<D:displayname>%s</D:displayname>"
                              % escape(os.path.basename(href.rstrip("/"))
                                       or "PUBLIC"))
                chunks.append("</D:prop><D:status>HTTP/1.1 200 OK</D:status>")
                chunks.append("</D:propstat></D:response>")
            chunks.append("</D:multistatus>")
            body = "\n".join(chunks).encode("utf-8")
            self._send(207, body, content_type='text/xml; charset="utf-8"')

        def do_PUT(self):
            self._send(403, b"read-only\n")

        def do_POST(self):
            self.do_GET()

    return Handler


def main():
    p = argparse.ArgumentParser(
        description="Serve extenal.xlsx with a random digit in Лист1!A1")
    p.add_argument("-i", "--bind", default="0.0.0.0")
    p.add_argument("-p", "--port", type=int, default=8080)
    p.add_argument("--filename", default=DEFAULT_FILENAME,
                   help="workbook name (default: extenal.xlsx)")
    p.add_argument("--write-dir", default=None,
                   help="also write the xlsx here (e.g. Samba PUBLIC/)")
    p.add_argument("--min", type=int, default=0, help="min random value")
    p.add_argument("--max", type=int, default=9, help="max random value")
    p.add_argument("--once", action="store_true",
                   help="only write one file to --write-dir and exit")
    args = p.parse_args()

    if args.min > args.max:
        p.error("--min must be <= --max")

    if args.once:
        if not args.write_dir:
            p.error("--once requires --write-dir")
        value = random.randint(args.min, args.max)
        path = write_to_disk(args.write_dir, args.filename, build_xlsx(value))
        print(f"[+] {path}  Лист1!A1 = {value}")
        return

    if args.write_dir:
        value = random.randint(args.min, args.max)
        path = write_to_disk(args.write_dir, args.filename, build_xlsx(value))
        print(f"[+] seed file {path}  Лист1!A1 = {value}")

    handler = make_handler(args.filename, args.write_dir, args.min, args.max)
    httpd = ThreadingHTTPServer((args.bind, args.port), handler)
    print(f"listening on http://{args.bind}:{args.port}/PUBLIC/{args.filename}")
    print(f"Excel formula (SMB/UNC via Samba):")
    print(f"  ='\\\\HOST\\PUBLIC\\[{args.filename}]{SHEET_NAME}'!$A$1")
    print(f"Excel / WebDAV HTTP:")
    print(f"  ='http://HOST:{args.port}/PUBLIC/[{args.filename}]"
          f"{SHEET_NAME}'!$A$1")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
