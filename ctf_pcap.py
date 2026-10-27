#!/usr/bin/env python3
"""ctf_pcap.py -- one-shot triage for CTF packet-capture challenges.

Single streaming pass over a pcap/pcapng, then a ranked report:

  * file / link-layer metadata, protocol mix, conversations
  * DNS: names, TXT rdata, tunneling + exfil candidates (base32/hex decode)
  * HTTP: requests, auth, cookies, uploads, form/JSON creds, served files,
    gzip/deflate/chunked response decoding
  * TLS SNI, SSH banners, 802.11 SSIDs, EAPOL (WPA handshake) detection
  * cleartext creds: FTP, SMTP, POP3, IMAP, telnet, HTTP, SNMP community
  * covert channels: ICMP payload, DNS labels, IP-ID, TTL, TCP seq low byte
  * file carving from raw + reassembled TCP/UDP streams (magic + base64)
  * USB HID keyboard decode (and mouse delta trace)
  * ranked "weird strings" with auto-decode (base64 / hex / rot13 / xor)
  * flag hunt across payloads, streams, carved files and decoded blobs

Usage:
  python ctf_pcap.py challenge.pcap
  python ctf_pcap.py challenge.pcap -o out --json
  python ctf_pcap.py challenge.pcap --dump-streams --all-strings
  python ctf_pcap.py challenge.pcap --quiet

Requires scapy (pip install scapy). tshark optional (USB HID decoding,
protocol-hierarchy/expert summary) -- auto-detected, script works without it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import lzma
    import bz2
except ImportError:  # pragma: no cover
    lzma = bz2 = None

try:
    from scapy.all import (  # type: ignore
        ARP, DNS, DNSQR, DNSRR, Dot11, Dot11Beacon, Dot11Elt, EAPOL, ICMP,
        IP, IPv6, PcapNgReader, PcapReader, Raw, SNMP, TCP, UDP, rdpcap,
    )
except Exception as exc:  # pragma: no cover
    sys.exit("scapy is required: pip install scapy  (%s)" % exc)

VERSION = "1.0"

# --------------------------------------------------------------------------
# tunables
# --------------------------------------------------------------------------
MAX_STREAM_BYTES = 32 * 1024 * 1024      # per reassembled stream
MAX_TOTAL_STREAM_BYTES = 512 * 1024 * 1024
MAX_CARVE_BYTES = 64 * 1024 * 1024       # per carved blob
MAX_STRINGS = 200000                     # unique strings kept
MAX_OCCURRENCES = 500000                 # raw string occurrences kept
MIN_STRING_LEN = 4
MAX_HTTP_MSGS = 2000
TSHARK_PATHS = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
]

# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------
KNOWN_CTF_PREFIXES = (
    b"flag|ctf|picoctf|htb|thm|uiuctf|ictf|ductf|corctf|grey|wctf|kctf|actf|"
    b"pctf|asis|hitcon|n1ctf|zer0pts|idek|sekai|maple|vsctf|buckeye|utflag|"
    b"udctf|lactf|byuctf|tjctf|damctf|sctf|justctf|midnight|sunshine|kalmar|"
    b"wolvctf|swampctf|angstrom|bronco|irisctf|squ1rrel|pingctf|hkcert|hxp|"
    b"rwctf|bi0s|nite|crew|bsides|tamilctf|csrf|csaw|naham|defcon|0ctf|"
    b"seccon|line|aero|utctf|umd|bcactf|dice|rarctf"
)

FLAG_RE = re.compile(
    rb"(?i)(?:" + KNOWN_CTF_PREFIXES + rb")[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
FLAG_RE_LOOSE = re.compile(rb"\b[A-Za-z][A-Za-z0-9_]{1,24}\{[ -~]{1,200}\}")

HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
    b"PATCH ", b"CONNECT ", b"TRACE ",
)
HTTP_PORTS = {80, 81, 88, 3128, 8000, 8008, 8080, 8081, 8888, 9000, 9418}
TLS_PORTS = {443, 4443, 8443, 993, 995, 465, 636, 853, 9443}
SSH_HINT = b"SSH-2.0-"
SUSPICIOUS_PORTS = {1337, 1234, 31337, 4444, 4445, 5555, 6666, 7777, 12345, 65535}

# (magic, ext, friendly, end-marker)
MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image", b"IEND"),
    (b"\xff\xd8\xff", "jpg", "JPEG image", b"\xff\xd9"),
    (b"GIF87a", "gif", "GIF image", None),
    (b"GIF89a", "gif", "GIF image", None),
    (b"%PDF", "pdf", "PDF document", b"%%EOF"),
    (b"PK\x03\x04", "zip", "ZIP archive", None),
    (b"PK\x05\x06", "zip", "ZIP archive (empty)", None),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-zip archive", None),
    (b"Rar!\x1a\x07", "rar", "RAR archive", None),
    (b"\x1f\x8b\x08", "gz", "gzip data", None),
    (b"BZh9", "bz2", "bzip2 data", None),
    (b"\xfd7zXZ\x00", "xz", "xz data", None),
    (b"\x7fELF", "elf", "ELF binary", None),
    (b"MZ\x90\x00", "exe", "PE executable", None),
    (b"SQLite format 3\x00", "sqlite", "SQLite database", None),
    (b"RIFF", "riff", "RIFF container (wav/avi/webp)", None),
    (b"OggS", "ogg", "Ogg stream", None),
    (b"fLaC", "flac", "FLAC audio", None),
    (b"ID3", "mp3", "MP3 audio", None),
    (b"\xca\xfe\xba\xbe", "class", "Java class / Mach-O fat", None),
    (b"\x1aE\xdf\xa3", "mkv", "Matroska/WebM", None),
    (b"\x00asm", "wasm", "WebAssembly module", None),
    (b"\xd0\xcf\x11\xe0", "ole", "OLE/legacy Office document", None),
    (b"regf", "regf", "Windows registry hive", None),
    (b"wOFF", "woff", "WOFF font", None),
    (b"\x04\x22\x4d\x18", "lz4", "LZ4 frame", None),
    (b"\x28\xb5\x2f\xfd", "zst", "Zstandard frame", None),
    (b"PAR1", "parquet", "Parquet", None),
    (b"\x27\x05\x19\x56", "pyc", "Python bytecode", None),
]
# containers detected at a fixed offset inside a window
MAGICS_OFFSET = [
    (4, b"ftyp", "mp4", "MP4/QuickTime"),
    (257, b"ustar", "tar", "TAR archive"),
]
B64_MAGIC_PREFIXES = {
    b"iVBORw0KGgo": "png", b"/9j/": "jpg", b"R0lGOD": "gif",
    b"UEsDB": "zip", b"JVBERi0": "pdf", b"H4sI": "gz",
    b"7Z": "7z", b"Qlpo": "bz2", b"f0VMRg": "elf",
    b"U1FMaXRl": "sqlite",
}

CRED_LINE_RE = re.compile(
    rb"(?im)^[^\r\n]{0,80}?\b(user(?:name)?|login|pass(?:word|wd)?|pwd|"
    rb"auth|token|api[_-]?key|secret|apikey)\b\s*[:=]\s*(\S{1,120})"
)
FTP_RE = re.compile(rb"(?im)^(USER|PASS|ACCT|RETR|STOR|APPE)\s+(.+?)\r?$")
SMTP_RE = re.compile(rb"(?im)^(AUTH\s+\S+|MAIL FROM:\s*\S+|RCPT TO:\s*\S+)")
POP3_RE = re.compile(rb"(?im)^(USER|PASS|APOP)\s+(\S+)")
IMAP_RE = re.compile(rb"(?im)^\S+\s+(LOGIN|AUTHENTICATE)\s+(\S+)(?:\s+(\S+))?")
HTTP_AUTH_RE = re.compile(rb"(?i)^authorization:\s*(\S+)\s*(\S+)?")
SETCOOKIE_RE = re.compile(rb"(?i)^set-cookie:\s*([^=;\s]+)=([^;\r\n]+)")
COOKIE_RE = re.compile(rb"(?i)^cookie:\s*(.+)$")

BASE64_RUN_RE = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
HEX_RUN_RE = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")
PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING_LEN)
UTF16_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN)
HID_ADDR_RE = re.compile(r"^\d+\.\d+\.\d+$")

USB_LINKTYPES = {189, 220, 249}
LINKTYPE_NAMES = {
    0: "NULL", 1: "EN10MB", 101: "RAW", 105: "IEEE802_11", 113: "LINUX_SLL",
    127: "IEEE802_11_RADIOTAP", 189: "USB_LINUX", 195: "IEEE802_11_PPI",
    220: "USB_LINUX_MMAPPED", 228: "IPV4", 229: "IPV6", 249: "USBPCAP",
    251: "LINUX_SLL2", 276: "LINUX_SLL2_ALT",
}


# ==========================================================================
# small helpers
# ==========================================================================
def sanitize(data) -> str:
    """bytes/str -> single-line ASCII-safe display string."""
    if isinstance(data, bytes):
        s = data.decode("utf-8", "replace")
    else:
        s = data
    out = []
    for ch in s:
        if ch in "\r\n\t":
            out.append(" ")
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            out.append(".")
    return "".join(out)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def hx(data: bytes, limit: int = 32) -> str:
    h = data[:limit].hex()
    return h + ("..." if len(data) > limit else "")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def try_b64(data: bytes):
    """Decode b64/b64url/b32; return the most plausible (bytes, codec)."""
    s = re.sub(rb"\s+", b"", data)
    if not s:
        return None, None
    cands = []
    for name, rx, fn in (
        ("base64", re.compile(rb"^[A-Za-z0-9+/]+={0,2}$"),
         lambda x: base64.b64decode(x + b"=" * (-len(x) % 4), validate=True)),
        ("base64url", re.compile(rb"^[A-Za-z0-9_-]+={0,2}$"),
         lambda x: base64.urlsafe_b64decode(
             x.replace(b"-", b"+").replace(b"_", b"/") + b"=" * (-len(x) % 4))),
        ("base32", re.compile(rb"^[A-Za-z2-7]+={0,6}$"),
         lambda x: base64.b32decode(x.upper() + b"=" * (-len(x) % 8))),
    ):
        if not rx.match(s):          # never decode arbitrary prose
            continue
        try:
            out = fn(s)
        except Exception:
            continue
        if not out or len(out) < 4:
            continue
        pr = printable_ratio(out)
        magic = sniff_magic(out)
        has_flag = bool(find_flags(out))
        if pr < 0.85 and not magic and not has_flag:
            continue                 # garbage decode, discard
        score = pr + (3 if magic else 0) + (10 if has_flag else 0)
        cands.append((score, out, name))
    if not cands:
        return None, None
    cands.sort(key=lambda c: -c[0])
    return cands[0][1], cands[0][2]


def try_hex(data: bytes):
    s = re.sub(rb"\s+", b"", data)
    if len(s) < 8 or len(s) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", s):
        return None
    try:
        return bytes.fromhex(s.decode())
    except ValueError:
        return None


def xor_single(data: bytes):
    """Yield (key, plaintext) for printable single-byte XOR candidates."""
    for k in range(1, 256):
        pt = bytes(b ^ k for b in data)
        if printable_ratio(pt) > 0.92:
            yield k, pt


def find_flags(data: bytes):
    if data.find(b"{") < 0:          # cheap pre-filter, called for every blob
        return []
    found = []
    for m in FLAG_RE.finditer(data):
        found.append(m.group(0))
    for m in FLAG_RE_LOOSE.finditer(data):
        cand = m.group(0)
        inner = cand[cand.find(b"{") + 1:cand.rfind(b"}")]
        if b"{" in inner or not inner:
            continue
        if any(c in cand for c in b'"\\<>=;'):
            continue
        found.append(cand)
    out, seen = [], set()
    for f in found:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def sniff_magic(data: bytes):
    """Classify a blob by leading bytes. -> (ext, friendly) or None."""
    for magic, ext, friendly, _ in MAGICS:
        if data.startswith(magic):
            return ext, friendly
    for off, magic, ext, friendly in MAGICS_OFFSET:
        if len(data) >= off + len(magic) and data[off:off + len(magic)] == magic:
            return ext, friendly
    if data[:4] in (b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3"):
        return "mpg", "MPEG video"
    return None


def decode_content(body: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    if "gzip" in enc:
        for fn in (gzip.decompress, lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS)):
            try:
                return fn(body)
            except Exception:
                pass
    if "deflate" in enc:
        for fn in (zlib.decompress, lambda b: zlib.decompress(b, -zlib.MAX_WBITS)):
            try:
                return fn(body)
            except Exception:
                pass
    if "br" in enc:
        try:
            import brotli  # type: ignore
            return brotli.decompress(body)
        except Exception:
            pass
    return body


def which_tshark():
    for cand in TSHARK_PATHS:
        p = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if p:
            return p
    return None


# ==========================================================================
# USB HID
# ==========================================================================
HID_KEYMAP = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f",
    0x0A: "g", 0x0B: "h", 0x0C: "i", 0x0D: "j", 0x0E: "k", 0x0F: "l",
    0x10: "m", 0x11: "n", 0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r",
    0x16: "s", 0x17: "t", 0x18: "u", 0x19: "v", 0x1A: "w", 0x1B: "x",
    0x1C: "y", 0x1D: "z",
    0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6",
    0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x29: "\x1b", 0x2A: "\b", 0x2B: "\t", 0x2C: " ",
    0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\", 0x32: "#",
    0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
    0x39: "", 0x54: "/", 0x55: "*", 0x56: "-", 0x57: "+", 0x58: "\n",
    0x59: "1", 0x5A: "2", 0x5B: "3", 0x5C: "4", 0x5D: "5", 0x5E: "6",
    0x5F: "7", 0x60: "8", 0x61: "9", 0x62: "0", 0x63: ".",
}
HID_SHIFT = {
    0x1E: "!", 0x1F: "@", 0x20: "#", 0x21: "$", 0x22: "%", 0x23: "^",
    0x24: "&", 0x25: "*", 0x26: "(", 0x27: ")", 0x2D: "_", 0x2E: "+",
    0x2F: "{", 0x30: "}", 0x31: "|", 0x32: "~", 0x33: ":", 0x34: '"',
    0x35: "~", 0x36: "<", 0x37: ">", 0x38: "?",
}


def decode_keyboard_reports(reports):
    """reports: list[bytes] (boot keyboard, 8/9 byte). -> typed text."""
    out = []
    prev_keys = set()
    for rep in reports:
        if len(rep) < 3:
            continue
        mod = rep[0]
        keys = [k for k in rep[2:8] if k]
        if not keys:
            prev_keys = set()
            continue
        shifted = bool(mod & 0x22)
        caps = bool(mod & 0x02) and False  # caps-lock tracking needs state
        for k in keys:
            if k in prev_keys:
                continue
            if k == 0x2A:            # backspace
                if out:
                    out.pop()
                continue
            ch = (HID_SHIFT if shifted else HID_KEYMAP).get(k, "")
            if not ch:
                ch = HID_KEYMAP.get(k, "")
            if ch:
                out.append(ch)
        prev_keys = set(keys)
    return "".join(out)


def decode_mouse_reports(reports):
    """-> list[(buttons, dx, dy, wheel)] with dx/dy as signed bytes."""
    pts = []
    for rep in reports:
        if len(rep) == 3:
            pts.append((rep[0], struct.unpack("b", rep[1:2])[0],
                        struct.unpack("b", rep[2:3])[0], 0))
        elif len(rep) >= 4:
            pts.append((rep[0], struct.unpack("b", rep[1:2])[0],
                        struct.unpack("b", rep[2:3])[0],
                        struct.unpack("b", rep[3:4])[0]))
    return pts


# ==========================================================================
# HTTP
# ==========================================================================
def parse_headers(head: bytes):
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        hdrs.setdefault(k.strip().lower().decode("latin-1"), []).append(
            v.strip().decode("latin-1"))
    return hdrs


def hget(hdrs, name, default=""):
    v = hdrs.get(name)
    return v[0] if v else default


def read_chunked(blob: bytes, start: int):
    out = bytearray()
    pos = start
    while True:
        eol = blob.find(b"\r\n", pos)
        if eol < 0:
            return bytes(out), len(blob) - start, False
        try:
            size = int(blob[pos:eol].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return bytes(out), eol + 2 - start, False
        pos = eol + 2
        if size == 0:
            end = blob.find(b"\r\n", pos)
            return bytes(out), (end + 2 if end >= 0 else len(blob)) - start, True
        out += blob[pos:pos + size]
        pos += size + 2


def parse_http(blob: bytes):
    """-> list of dicts {kind, first_line, hdrs, body, offset}."""
    msgs = []
    pos = 0
    n = len(blob)
    while pos < n and len(msgs) < MAX_HTTP_MSGS:
        hdr_end = blob.find(b"\r\n\r\n", pos)
        if hdr_end < 0:
            break
        head = blob[pos:hdr_end]
        first = head.split(b"\r\n", 1)[0]
        is_resp = first.startswith(b"HTTP/")
        is_req = any(first.startswith(m) for m in HTTP_METHODS)
        if not (is_resp or is_req):
            pos = hdr_end + 4
            continue
        hdrs = parse_headers(head)
        body_start = hdr_end + 4
        te = hget(hdrs, "transfer-encoding").lower()
        cl_raw = hget(hdrs, "content-length")
        body = b""
        consumed = 0
        if "chunked" in te:
            body, consumed, _ = read_chunked(blob, body_start)
        elif cl_raw.isdigit():
            cl = int(cl_raw)
            body = blob[body_start:body_start + cl]
            consumed = min(cl, max(0, n - body_start))
        elif is_resp:
            body = blob[body_start:]
            consumed = len(body)
        msgs.append({
            "kind": "response" if is_resp else "request",
            "first_line": sanitize(first[:200]),
            "hdrs": hdrs,
            "body": body,
            "offset": pos,
        })
        pos = body_start + consumed
        if consumed == 0 and is_req:
            # request without body: next message starts right here (pipelining)
            continue
    return msgs


def parse_form(body: bytes):
    """-> dict from urlencoded or multipart-ish bodies."""
    out = {}
    if not body:
        return out
    try:
        text = body.decode("latin-1")
    except Exception:
        return out
    if "=" in text and ("&" in text or len(text) < 4096):
        for part in re.split(r"[&\r\n]", text):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()[:64]
            if not k:
                continue
            out[k] = v[:200]
    return out


def parse_json_keys(body: bytes):
    out = {}
    try:
        obj = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return out
    stack = [obj]
    while stack and len(out) < 40:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, (dict, list)):
                    stack.append(v)
                elif isinstance(v, (str, int, float, bool)):
                    out[str(k)[:64]] = str(v)[:200]
        elif isinstance(cur, list):
            stack.extend(cur[:20])
    return out


# ==========================================================================
# data holders
# ==========================================================================
@dataclass
class Stream:
    sid: str
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    data: bytearray = field(default_factory=bytearray)
    base: int | None = None
    next_off: int = 0
    packets: int = 0
    gaps: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    truncated: bool = False


@dataclass
class Finding:
    score: int
    kind: str
    text: str


@dataclass
class Carved:
    path: Path
    ext: str
    friendly: str
    size: int
    source: str
    digest: str


# ==========================================================================
# analyzer
# ==========================================================================
class Analyzer:
    def __init__(self, path: Path, args):
        self.path = path
        self.args = args
        self.linktype = None
        self.file_format = "?"
        self.packets = 0
        self.bytes_seen = 0
        self.first_ts = None
        self.last_ts = None
        self.errors = 0

        self.proto_counter = Counter()
        self.conv_counter = Counter()
        self.port_counter = Counter()
        self.suspicious = Counter()
        self.ethertypes = Counter()

        self.dns_queries = []          # (ts, qname)
        self.dns_answers = []          # (ts, name, rrtype, rdata)
        self.dns_txt = []              # (ts, qname, text)
        self.dns_names = Counter()

        self.http = []                 # dicts
        self.http_hosts = Counter()
        self.upload_files = []         # (url, filename, blob)

        self.creds = []                # (proto, detail)
        self.flags = {}                # flag -> context
        self.findings = []

        self.icmp = defaultdict(list)  # (src,dst,icmp_id) -> [(seq, data)]
        self.covert = defaultdict(list)  # name -> [bytes-ish]
        self.ttl_seq = defaultdict(list)
        self.tcpseq_seq = defaultdict(list)

        self.streams = {}              # sid -> Stream
        self.total_stream_bytes = 0
        self.streams_truncated = 0

        self.usb_reports = defaultdict(list)   # dev -> [report bytes]
        self.usb_note = ""
        self.usb_text = {}
        self.ssids = {}
        self.eapol = 0
        self.arp_table = defaultdict(set)
        self.arp_spoof = []

        self.strings = {}              # text -> [count, first source]
        self.occurrences = []          # (source, offset, text) in discovery order
        self.occurrence_dropped = 0
        self.seen_carved = {}
        self.carved = []
        self.notes = []

        self._epochs = {}              # canonical 4-tuple -> connection epoch
        self._http_seen = set()
        self.dns_suspects = []
        self.covert_hits = []
        self.icmp_reassembled = []

        self.outdir = Path(args.out or (path.stem + "_analysis"))
        self.carvedir = self.outdir / "carved"
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.carvedir.mkdir(parents=True, exist_ok=True)

    # ---------------- collection ----------------
    def add_flag(self, raw, where: str):
        for f in find_flags(raw if isinstance(raw, bytes) else raw.encode()):
            key = f.decode("utf-8", "replace")
            if key not in self.flags:
                self.flags[key] = where
                self.findings.append(Finding(100, "flag", key))

    def record_string(self, text: str, where: str, offset: int):
        text = text.strip()
        if not text:
            return
        if len(self.occurrences) < MAX_OCCURRENCES:
            self.occurrences.append((where, offset, text))
        else:
            self.occurrence_dropped += 1
        self.add_string(text, where)

    def add_string(self, text: str, where: str):
        text = text.strip()
        if len(text) < MIN_STRING_LEN or len(text) > 4000:
            return
        if text in self.strings:
            self.strings[text][0] += 1
            return
        if len(self.strings) >= MAX_STRINGS:
            return
        self.strings[text] = [1, where]

    def scan_blob(self, blob: bytes, where: str, collect_strings=True,
                  encoded=True):
        """Flag hunt + string harvest + base64/hex auto-decode."""
        if not blob:
            return
        self.add_flag(blob, where)
        if collect_strings:
            for m in PRINTABLE_RUN_RE.finditer(blob):
                self.record_string(m.group(0).decode("latin-1"), where, m.start())
            if b"\x00" in blob:
                for m in UTF16_RUN_RE.finditer(blob):
                    self.record_string(m.group(0).decode("utf-16-le", "ignore"),
                                       where + "/utf16", m.start())
            if encoded:
                self.scan_encoded(blob, where)

    def scan_encoded(self, blob: bytes, where: str):
        for m in BASE64_RUN_RE.finditer(blob):
            dec, enc = try_b64(m.group(0))
            if not dec:
                continue
            if b"=" in m.group(0) or printable_ratio(dec) > 0.9 or sniff_magic(dec):
                self.add_string("[%s] %s" % (enc, sanitize(dec[:400])), where)
                self.add_flag(dec, where + " (b64)")
                mm = sniff_magic(dec)
                if mm:
                    self.save_carved(dec, mm[0], mm[1], where + " (b64)")
        if self.args.deep:
            for m in HEX_RUN_RE.finditer(blob):
                dec = try_hex(m.group(0))
                if dec and (printable_ratio(dec) > 0.9 or sniff_magic(dec)):
                    self.add_string("[hex] " + sanitize(dec[:400]), where)
                    self.add_flag(dec, where + " (hex)")

    def save_carved(self, blob: bytes, ext: str, friendly: str, source: str):
        if not blob:
            return
        if len(self.carved) >= 400:
            self.notes.append("carve cap (400) reached; skipped %s @%s" % (friendly, source))
            return
        blob = blob[:MAX_CARVE_BYTES]
        digest = sha256(blob)
        if digest in self.seen_carved:
            self.seen_carved[digest][1] += 1
            return
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", source)[:60]
        fname = "%s_%08x_%s.%s" % (safe, int(time_counter()), digest[:8], ext)
        dest = self.carvedir / fname
        try:
            dest.write_bytes(blob)
        except OSError as exc:
            self.notes.append("carve write failed: %s" % exc)
            return
        item = Carved(dest, ext, friendly, len(blob), source, digest)
        self.seen_carved[digest] = [item, 1]
        self.carved.append(item)
        self.findings.append(Finding(60, "carved", "%s (%s, %d bytes)" %
                                     (dest.name, friendly, len(blob))))
        self.add_flag(blob, "carved:%s" % dest.name)
        if ext in ("gz", "bz2", "xz", "zip"):
            self.expand_archive(dest, blob)

    def expand_archive(self, dest: Path, blob: bytes):
        members = []
        try:
            if dest.suffix == ".gz":
                members.append(("gz", gzip.decompress(blob)))
            elif dest.suffix == ".xz" and lzma:
                members.append(("xz", lzma.decompress(blob)))
            elif dest.suffix == ".bz2" and bz2:
                members.append(("bz2", bz2.decompress(blob)))
            elif dest.suffix == ".zip":
                import io as _io
                import zipfile
                with zipfile.ZipFile(_io.BytesIO(blob)) as zf:
                    for info in zf.infolist()[:40]:
                        members.append((info.filename, zf.read(info)))
        except Exception as exc:
            self.notes.append("archive %s not expandable (%s)" % (dest.name, exc))
            return
        for name, data in members:
            mm = sniff_magic(data)
            if mm:
                self.save_carved(data, mm[0], mm[1], dest.stem + "!" + str(name))
            else:
                self.add_flag(data, "archive:%s!%s" % (dest.name, name))
                if printable_ratio(data) > 0.7:
                    self.scan_blob(data, "archive:%s!%s" % (dest.name, name))

    # ---------------- per packet ----------------
    def feed(self, pkt):
        self.packets += 1
        try:
            ts = float(pkt.time)
        except Exception:
            ts = 0.0
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts

        try:
            self.dispatch(pkt, ts)
        except Exception:
            self.errors += 1

    def dispatch(self, pkt, ts):
        layers = pkt.layers()        # single traversal, then O(1) lookups
        # link layer bookkeeping
        if Dot11 in layers:
            self.proto_counter["802.11"] += 1
            if Dot11Beacon in pkt:
                self.proto_counter["802.11 Beacon"] += 1
                try:
                    elt = pkt[Dot11Elt]
                    ssid = ""
                    while elt is not None and hasattr(elt, "ID"):
                        if elt.ID == 0:
                            ssid = elt.info.decode("latin-1", "replace")
                            break
                        elt = elt.payload.getlayer(Dot11Elt)
                    bssid = pkt[Dot11].addr3
                    self.ssids[(bssid, ssid)] = self.ssids.get((bssid, ssid), 0) + 1
                except Exception:
                    self.errors += 1
        if EAPOL in layers:
            self.eapol += 1
            self.proto_counter["EAPOL"] += 1

        if ARP in layers:
            self.proto_counter["ARP"] += 1
            a = pkt[ARP]
            self.arp_table[a.psrc].add(a.hwsrc)
            if a.op == 2:
                self.conv_counter[("ARP", a.psrc, a.pdst)] += 1

        if IP in layers:
            ip = pkt[IP]
            self.proto_counter["IPv4"] += 1
            l4 = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else
                                           ("ICMP" if ICMP in pkt else "IP/%d" % ip.proto))
            self.proto_counter[l4] += 1
            self.conv_counter[(l4, ip.src, ip.dst)] += 1
            self.ttl_seq[(ip.src, ip.dst)].append(ip.ttl & 0xFF)
            # covert channel: IP identification field
            if ip.id:
                self.covert[("ipid", ip.src, ip.dst)].append(ip.id & 0xFF)
                if ip.id >> 8:
                    self.covert[("ipid_hi", ip.src, ip.dst)].append(ip.id >> 8)
        elif IPv6 in layers:
            self.proto_counter["IPv6"] += 1
            ip6 = pkt[IPv6]
            l4 = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else
                                           ("ICMPv6" if pkt.haslayer("ICMPv6EchoRequest")
                                            or pkt.haslayer("ICMPv6EchoReply") else "IPv6/%d" % ip6.nh))
            self.proto_counter[l4] += 1
            self.conv_counter[(l4, ip6.src, ip6.dst)] += 1

        # ---- DNS ----
        if DNS in layers:
            self.handle_dns(pkt[DNS], ts)

        # ---- TCP ----
        if TCP in layers:
            self.handle_tcp(pkt, ts, layers)

        # ---- UDP ----
        if UDP in layers:
            self.handle_udp(pkt, ts, layers)

        # ---- ICMP ----
        if ICMP in layers:
            self.handle_icmp(pkt, ts, layers)

        # ---- any other raw payload (link-layer protocols, etc.) ----
        if Raw in layers and not (IP in layers or IPv6 in layers):
            payload = bytes(pkt[Raw].load)
            self.proto_counter["raw"] += 1
            self.scan_blob(payload, "link@ts%.3f" % ts, encoded=False)

    def handle_dns(self, dns, ts):
        if dns.qd is not None and not int(getattr(dns, "qr", 0) or 0):
            try:
                q = dns.qd
                name = q.qname.decode("latin-1", "replace").rstrip(".")
                self.dns_names[name] += 1
                self.dns_queries.append((ts, name))
                self.proto_counter["DNS"] += 1
                self.scan_blob(name.encode(), "dns-query")
            except Exception:
                self.errors += 1
        if dns.ancount:
            for i in range(min(int(dns.ancount), 50)):
                try:
                    rr = dns.an[i]
                except Exception:
                    break
                if rr is None or not hasattr(rr, "type"):
                    continue
                rdata = b""
                if rr.type == 16:  # TXT
                    try:
                        rdata = b"".join(rr.rdata if isinstance(rr.rdata, list)
                                         else [rr.rdata])
                    except Exception:
                        rdata = bytes(rr.rdata)
                    self.dns_txt.append((ts, sanitize(rr.rrname or b""), sanitize(rdata)))
                    self.scan_blob(rdata, "dns-txt")
                elif rr.type in (1, 28, 5, 12, 2):
                    try:
                        rdata = bytes(rr.rdata) if not isinstance(rr.rdata, bytes) else rr.rdata
                    except Exception:
                        rdata = b""
                    self.scan_blob(rdata, "dns-answer")
                try:
                    self.dns_answers.append((ts, str(getattr(rr, "rrname", "")),
                                             int(rr.type), sanitize(rdata)[:120]))
                except Exception:
                    pass

    def handle_tcp(self, pkt, ts, layers):
        tcp = pkt[TCP]
        ip = pkt[IP] if IP in layers else (pkt[IPv6] if IPv6 in layers else None)
        src = ip.src if ip is not None else "?"
        dst = ip.dst if ip is not None else "?"
        sport, dport = int(tcp.sport), int(tcp.dport)
        payload = bytes(tcp.payload) if tcp.payload else b""
        self.port_counter[sport] += 1
        self.port_counter[dport] += 1
        if sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS:
            self.suspicious[(src, sport, dst, dport)] += 1

        flags = tcp.flags
        if payload and flags & 0x02 and not flags & 0x10:   # SYN with data (rare)
            pass
        if flags & 0x02 and not flags & 0x10:               # new connection epoch
            ck = tuple(sorted([(src, sport), (dst, dport)]))
            self._epochs[ck] = self._epochs.get(ck, 0) + 1

        # seq covert channel: low byte of pure ACKs / no payload
        if not payload:
            self.tcpseq_seq[(src, dst)].append(int(tcp.seq) & 0xFF)

        sid = "T:%s:%d->%s:%d#%d" % (src, sport, dst, dport,
                                     self._epochs.get(
                                         tuple(sorted([(src, sport), (dst, dport)])), 0))
        st = self.streams.get(sid)
        if st is None:
            if self.total_stream_bytes > MAX_TOTAL_STREAM_BYTES:
                self.streams_truncated += 1
                return
            st = Stream(sid, src, sport, dst, dport, "TCP")
            self.streams[sid] = st
            st.first_ts = ts
        st.last_ts = ts
        st.packets += 1

        if payload:
            self.relay_payload(st, int(tcp.seq), payload)
            # protocol-specific live parsing (headers arrive early)
            self.inspect_tcp_live(payload, sport, dport, src, dst, ts, sid)

    def relay_payload(self, st: Stream, seq: int, payload: bytes):
        if st.base is None:
            st.base = seq
        rel = (seq - st.base) & 0xFFFFFFFF
        if rel > 0x7FFFFFFF:          # older than base: clamp
            rel = 0
        if len(st.data) + len(payload) > MAX_STREAM_BYTES:
            st.truncated = True
            return
        if rel > st.next_off:
            gap = rel - st.next_off
            if gap <= 0xFFFF:
                st.data.extend(b"\x00" * gap)
                st.next_off = rel
            else:
                st.gaps += 1
                st.base = seq
                rel = 0
                st.next_off = 0
                st.data = bytearray()
        end = rel + len(payload)
        if end > len(st.data):
            st.data.extend(b"\x00" * (rel - len(st.data)))
            st.data.extend(payload)
            st.next_off = max(st.next_off, end)
            self.total_stream_bytes += len(payload)

    def inspect_tcp_live(self, payload, sport, dport, src, dst, ts, sid):
        low = payload[:4096]
        # TLS ClientHello / SNI
        if low[:1] == b"\x16" and (dport in TLS_PORTS or sport in TLS_PORTS
                                   or low[1:2] == b"\x03"):
            sni = parse_tls_sni(low)
            if sni:
                self.add_string("TLS-SNI " + sni, sid)
                self.findings.append(Finding(25, "sni", sni))
            self.proto_counter["TLS"] += 1
        # SSH banner
        if low.startswith(SSH_HINT):
            self.proto_counter["SSH"] += 1
            self.add_string(sanitize(low.split(b"\r\n")[0]), sid)
            self.findings.append(Finding(20, "ssh", sanitize(low.split(b"\r\n")[0])))
        # cleartext protocol creds
        if (sport, dport) in ((21, 21),) or 21 in (sport, dport):
            for m in FTP_RE.finditer(low):
                self.creds.append(("FTP", "%s %s" % (
                    m.group(1).decode(), sanitize(m.group(2)))))
                self.findings.append(Finding(80, "cred", "FTP %s %s" % (
                    m.group(1).decode(), sanitize(m.group(2)))))
        for proto, rx, ports in (("SMTP", SMTP_RE, {25, 465, 587}),
                                 ("POP3", POP3_RE, {110, 995}),
                                 ("IMAP", IMAP_RE, {143, 993})):
            if ports & {sport, dport}:
                for m in rx.finditer(low):
                    line = sanitize(b" ".join(g for g in m.groups() if g))
                    self.creds.append((proto, line))
                    self.findings.append(Finding(80, "cred", "%s %s" % (proto, line)))
        if 23 in (sport, dport):
            for line in low.splitlines():
                s = sanitize(line)
                if s and not s.startswith("\x1b"):
                    self.add_string("telnet: " + s, sid)
        # generic KEY=VALUE credential lines only for text-ish payloads
        if printable_ratio(low) > 0.9:
            for m in CRED_LINE_RE.finditer(low):
                val = sanitize(m.group(2))
                if len(val) >= 3:
                    key = m.group(1).decode("latin-1")
                    self.creds.append(("HTTP/text", "%s=%s" % (key, val)))
                    self.findings.append(Finding(70, "cred", "%s=%s" % (key, val)))
        # HTTP messages are parsed from the fully reassembled stream in
        # _post_streams(), and the same pass harvests every string; scanning
        # the payload again here would double the work and the count.

    def record_http(self, msg, sid, sport, dport):
        hdrs = msg["hdrs"]
        host = hget(hdrs, "host")
        if host:
            self.http_hosts[host] += 1
        auth = hget(hdrs, "authorization")
        if auth.lower().startswith("basic "):
            dec, _ = try_b64(auth.split(None, 1)[1].encode())
            if dec:
                self.creds.append(("HTTP Basic", sanitize(dec)))
                self.findings.append(Finding(80, "cred", "HTTP Basic " + sanitize(dec)))
        if auth.lower().startswith("bearer "):
            self.creds.append(("HTTP Bearer", auth[7:][:200]))
            self.findings.append(Finding(70, "cred", "HTTP Bearer " + auth[7:][:80]))
        for sc in hdrs.get("set-cookie", [])[:10]:
            self.add_string("Set-Cookie " + sc[:300], sid)
        for ck in hdrs.get("cookie", [])[:5]:
            self.add_string("Cookie " + ck[:300], sid)
        body = msg["body"]
        enc = hget(hdrs, "content-encoding")
        if body and enc:
            dec = decode_content(body, enc)
            if dec is not body:
                self.add_string("[http %s] %s" % (enc, sanitize(dec[:300])), sid)
                self.scan_blob(dec, sid + " (http-decoded)")
                mm = sniff_magic(dec)
                if mm:
                    self.save_carved(dec, mm[0], mm[1], sid)
        if body:
            self.scan_blob(body[:65536], sid + " (http-body)")
            mm = sniff_magic(body)
            if mm:
                fn = ""
                cd = hget(hdrs, "content-disposition")
                m = re.search(r'filename\*?="?([^";]+)', cd)
                if m:
                    fn = m.group(1)
                self.save_carved(body, mm[0], mm[1], fn or sid)
            if msg["kind"] == "request" and body:
                ctype = hget(hdrs, "content-type").lower()
                fields = {}
                if "json" in ctype:
                    fields = parse_json_keys(body)
                else:
                    fields = parse_form(body)
                if fields:
                    interesting = {k: v for k, v in fields.items()
                                   if re.search(r"(?i)user|pass|pwd|token|key|secret|auth|login|mail", k)}
                    if interesting:
                        detail = "; ".join("%s=%s" % (k, v) for k, v in interesting.items())
                        self.creds.append(("HTTP form", detail))
                        self.findings.append(Finding(80, "cred", "HTTP form " + detail[:160]))
                cd = hget(hdrs, "content-disposition")
                m = re.search(r'filename\*?="?([^";]+)', cd)
                if m:
                    self.upload_files.append((msg["first_line"], m.group(1), body[:4096]))

        self.http.append({
            "stream": sid,
            "kind": msg["kind"],
            "line": msg["first_line"],
            "host": host,
            "ctype": hget(hdrs, "content-type"),
            "clen": hget(hdrs, "content-length"),
            "body_len": len(body),
        })

    def handle_udp(self, pkt, ts, layers):
        udp = pkt[UDP]
        ip = pkt[IP] if IP in layers else (pkt[IPv6] if IPv6 in layers else None)
        src = ip.src if ip is not None else "?"
        dst = ip.dst if ip is not None else "?"
        sport, dport = int(udp.sport), int(udp.dport)
        self.port_counter[sport] += 1
        self.port_counter[dport] += 1
        payload = bytes(udp.payload) if udp.payload else b""
        if not payload or DNS in layers or SNMP in layers:
            if SNMP in layers:
                try:
                    com = pkt[SNMP].community
                    community = com.decode("latin-1", "replace") if isinstance(com, bytes) else str(com)
                    self.creds.append(("SNMP", "community=%s" % community))
                    self.findings.append(Finding(60, "cred", "SNMP community=%s" % community))
                except Exception:
                    pass
            return
        sid = "U:%s:%d->%s:%d" % (src, sport, dst, dport)
        st = self.streams.get(sid)
        if st is None:
            if self.total_stream_bytes > MAX_TOTAL_STREAM_BYTES:
                return
            st = Stream(sid, src, sport, dst, dport, "UDP")
            self.streams[sid] = st
            st.first_ts = ts
        st.last_ts = ts
        st.packets += 1
        if len(st.data) + len(payload) <= MAX_STREAM_BYTES:
            st.data.extend(payload)
            self.total_stream_bytes += len(payload)
        self.scan_blob(payload[:16384], sid, encoded=False)

    def handle_icmp(self, pkt, ts, layers):
        icmp = pkt[ICMP]
        ip = pkt[IP] if IP in layers else None
        src = ip.src if ip is not None else "?"
        dst = ip.dst if ip is not None else "?"
        data = bytes(icmp.payload) if icmp.payload else b""
        if not data:
            return
        key = (src, dst, int(icmp.id or 0))
        self.icmp[key].append((int(icmp.seq or 0), data))
        self.scan_blob(data[:4096], "icmp:%s->%s seq=%d" % (src, dst, icmp.seq or 0))

    # ---------------- post pass ----------------
    def finish(self):
        self._post_streams()
        self._post_dns()
        self._post_covert()
        self._post_arp()
        self._usb()
        # run the decoder over everything harvested, before rendering
        self.decode_count = write_decodes(self, self.outdir / "decodes.txt")

    def _post_streams(self):
        """Analyse every reassembled stream: carve, http, strings."""
        for sid, st in self.streams.items():
            if not st.data:
                continue
            blob = bytes(st.data)
            self.scan_blob(blob, sid + " (stream)")
            self.find_stream_files(blob, sid)
            if st.proto == "TCP" and (st.sport in HTTP_PORTS or st.dport in HTTP_PORTS
                                      or blob.startswith(b"HTTP/")
                                      or any(blob.startswith(m) for m in HTTP_METHODS)):
                for msg in parse_http(blob):
                    self.record_http(msg, sid, st.sport, st.dport)
            if self.args.dump_streams:
                d = self.outdir / "streams"
                d.mkdir(exist_ok=True)
                (d / (sid.replace(":", "_").replace(">", "-").replace("#", "e")
                      + ".bin")).write_bytes(blob)

    def find_stream_files(self, blob: bytes, sid: str):
        if len(blob) < 8:
            return
        covered = []                       # (start, end) already carved

        def overlaps(off, end):
            return any(off < e and end > s for s, e in covered)

        def emit(off, chunk, ext, friendly):
            if overlaps(off, off + len(chunk)):
                return
            if not validate_carve(chunk, ext):
                return
            covered.append((off, off + len(chunk)))
            self.save_carved(chunk, ext, friendly, "%s_off%d" % (sid, off))

        for magic, ext, friendly, endmarker in MAGICS:
            start = 0
            while True:
                off = blob.find(magic, start)
                if off < 0:
                    break
                start = off + 1
                chunk = blob[off:]
                if endmarker:
                    e = chunk.find(endmarker)
                    if e >= 0:
                        chunk = chunk[:e + len(endmarker) + (4 if ext == "png" else 2)]
                emit(off, chunk, ext, friendly)
        for off_fixed, magic, ext, friendly in MAGICS_OFFSET:
            start = 0
            while True:
                pos = blob.find(magic, start)
                if pos < 0:
                    break
                start = pos + 1
                hit = pos - off_fixed
                if hit < 0:
                    continue
                emit(hit, blob[hit:], ext, friendly)
        # extract non-gzip-compressed alternate streams
        if blob[:2] == b"\x1f\x8b" and len(blob) > 18:
            try:
                self.expand_archive(Path("inline.gz"), blob)
            except Exception:
                pass

    def _post_dns(self):
        # per-base-domain label chains -> exfil candidates
        chains = defaultdict(list)
        for ts, name in self.dns_queries:
            labels = name.split(".")
            if len(labels) >= 3:
                base = ".".join(labels[-2:])
                chains[base].append((ts, labels[:-2], name))
        suspects = []
        for base, items in chains.items():
            if len(items) < 3:
                continue
            labels_all = [l for _, ls, _ in items for l in ls]
            joined = "".join(labels_all)
            if len(joined) < 16:
                continue
            dec, enc = None, None
            # try the whole chain, the first label of each query, and the
            # last label before the base domain (common exfil layouts)
            cands = [joined]
            first_labels = [ls[0] for _, ls, _ in items if ls]
            last_labels = [ls[-1] for _, ls, _ in items if ls]
            if first_labels and "".join(first_labels) != joined:
                cands.append("".join(first_labels))
            if last_labels and "".join(last_labels) not in cands:
                cands.append("".join(last_labels))
            for cand in cands:
                dec, enc = try_b64(cand.encode())
                if dec is None:
                    dec = try_hex(cand.encode())
                    enc = "hex" if dec else None
                if dec:
                    joined = cand
                    break
            suspicion = 0
            if len(set(n for _, _, n in items)) >= 5:
                suspicion += 1
            if any(len(l) > 25 for l in labels_all):
                suspicion += 1
            if entropy(joined.encode()) > 3.8:
                suspicion += 1
            suspects.append((suspicion, base, len(items), joined[:160], dec, enc))
        suspects.sort(key=lambda x: (-x[0], -x[2]))
        self.dns_suspects = [s for s in suspects if s[0] >= 1]
        for susp, base, cnt, joined, dec, enc in self.dns_suspects[:10]:
            line = "DNS tunnel? %s (%d queries) chain=%s" % (base, cnt, joined[:100])
            self.findings.append(Finding(50, "dns-tunnel", line))
            if dec:
                self.findings.append(Finding(85, "dns-decoded",
                                             "%s -> [%s] %s" % (base, enc, sanitize(dec[:300]))))
                self.add_flag(dec, "dns-exfil:%s" % base)
        # answers already scanned; keep TXT visible
        if self.dns_txt:
            for ts, q, txt in self.dns_txt[:20]:
                self.findings.append(Finding(40, "dns-txt", "%s TXT=%s" % (q, txt[:200])))

    def _post_covert(self):
        self.covert_hits = []
        for key, values in list(self.covert.items()):
            name, a, b = key
            if len(values) < 8:
                continue
            s = self._printable_from_bytes(values)
            if s:
                self.covert_hits.append("%s %s->%s: %s" % (name, a, b, s))
                self.findings.append(Finding(55, "covert", "IP-ID %s->%s: %s" % (a, b, s)))
        for (a, b), values in self.ttl_seq.items():
            if len(values) < 8:
                continue
            s = self._printable_from_bytes(values)
            if s:
                self.covert_hits.append("TTL %s->%s: %s" % (a, b, s))
                self.findings.append(Finding(55, "covert", "TTL %s->%s: %s" % (a, b, s)))
        for (a, b), values in self.tcpseq_seq.items():
            if len(values) < 8:
                continue
            s = self._printable_from_bytes(values)
            if s:
                self.covert_hits.append("TCPseq %s->%s: %s" % (a, b, s))
                self.findings.append(Finding(55, "covert", "TCPseq %s->%s: %s" % (a, b, s)))
        # ICMP tunnel reassembly
        self.icmp_reassembled = []
        for (src, dst, iid), chunks in self.icmp.items():
            if len(chunks) < 2:
                continue
            chunks.sort(key=lambda c: c[0])
            blob = b"".join(c[1] for c in chunks)
            self.icmp_reassembled.append((src, dst, iid, len(chunks), blob))
            self.scan_blob(blob[:200000], "icmp-reassembled:%s->%s" % (src, dst))
            self.findings.append(Finding(65, "icmp-tunnel",
                                         "ICMP %s->%s id=%d: %d packets, %d bytes: %s"
                                         % (src, dst, iid, len(chunks), len(blob),
                                            sanitize(blob[:120]))))
            mm = sniff_magic(blob)
            if mm:
                self.save_carved(blob, mm[0], mm[1], "icmp_%s_%s" % (src, dst))
            elif printable_ratio(blob) > 0.8:
                (self.outdir / ("icmp_%s_%s.bin" % (sanitize(src), sanitize(dst)))).write_bytes(blob)

    @staticmethod
    def _printable_from_bytes(values):
        chars = []
        for v in values:
            if 32 <= v < 127:
                chars.append(chr(v))
        if len(chars) >= 6 and len(chars) / len(values) > 0.85:
            joined = "".join(chars)
            if len(set(joined)) < 3:      # constant field, not a channel
                return None
            return joined
        return None

    def _post_arp(self):
        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                self.arp_spoof.append((ip, sorted(macs)))
                self.findings.append(Finding(45, "arp-spoof",
                                             "%s claimed by %s" % (ip, ", ".join(sorted(macs)))))

    def _usb(self):
        tshark = which_tshark()
        reports = defaultdict(list)
        if tshark and self.linktype is not None and self.linktype not in USB_LINKTYPES:
            return
        if tshark:
            try:
                cmd = [tshark, "-r", str(self.path), "-Y",
                       "usb.capdata || usbhid.data", "-T", "fields",
                       "-e", "usb.src", "-e", "usb.dst", "-e", "usb.capdata",
                       "-e", "usbhid.data", "-e", "usb.transfer_type"]
                res = subprocess.run(cmd, capture_output=True, timeout=180,
                                     creationflags=(0x08000000 if os.name == "nt" else 0))
                text = res.stdout.decode("utf-8", "replace")
                for line in text.splitlines():
                    parts = line.split("\t")
                    if len(parts) < 4:
                        continue
                    src, dst, cap, hid = parts[0], parts[1], parts[2], parts[3]
                    dev = src if HID_ADDR_RE.match(src) else dst
                    raw = (cap or hid or "").strip()
                    if not raw:
                        continue
                    try:
                        data = bytes(int(b, 16) for b in raw.split(":") if b)
                    except ValueError:
                        continue
                    if data:
                        reports[dev].append(data)
            except Exception as exc:
                self.notes.append("tshark USB extraction failed: %s" % exc)
        if not reports:
            reports = self._usb_raw_fallback()
        if not reports:
            return
        self.usb_note = "extracted %d report groups" % len(reports)
        for dev, reps in reports.items():
            if len(reps) < 2:
                continue
            lens = Counter(len(r) for r in reps)
            mode = self.args.usb_mode
            if mode == "auto":
                mode = "keyboard" if lens.get(8, 0) + lens.get(9, 0) >= max(1, len(reps) // 2) else "mouse"
            if mode == "keyboard":
                text = decode_keyboard_reports(reps)
                if text.strip():
                    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", dev)
                    (self.outdir / ("usb_kbd_%s.txt" % safe)).write_text(text, encoding="utf-8")
                    self.add_flag(text.encode(), "usb-keyboard:%s" % dev)
                    self.scan_blob(text.encode(), "usb-keyboard:%s" % dev)
                    preview = text.replace("\n", "\\n")[:400]
                    self.findings.append(Finding(90, "usb-keyboard",
                                                 "dev %s typed: %s" % (dev, preview)))
                    self.usb_text = getattr(self, "usb_text", {})
                    self.usb_text[dev] = text
            else:
                pts = decode_mouse_reports(reps)
                if pts:
                    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", dev)
                    csv = self.outdir / ("usb_mouse_%s.csv" % safe)
                    x = y = 0
                    lines = ["x,y,buttons,wheel"]
                    for btn, dx, dy, wh in pts:
                        x += dx
                        y += dy
                        lines.append("%d,%d,%d,%d" % (x, y, btn, wh))
                    csv.write_text("\n".join(lines), encoding="utf-8")
                    self.findings.append(Finding(50, "usb-mouse",
                                                 "dev %s: %d moves -> %s" % (dev, len(pts), csv.name)))

    def _usb_raw_fallback(self):
        """Parse usbmon / usbpcap captures without tshark."""
        out = defaultdict(list)
        lt = self.linktype
        if lt not in USB_LINKTYPES:
            return out
        try:
            reader = _open_reader(self.path)
        except Exception:
            return out
        try:
            for pkt in reader:
                raw = bytes(pkt) if not isinstance(pkt, bytes) else pkt
                if lt == 220 and len(raw) > 64:
                    epnum = raw[11]
                    xfer = raw[9]
                    ln = struct.unpack("<I", raw[60:64])[0]
                    if xfer in (1, 3) and epnum & 0x80 and 0 < ln <= len(raw) - 64:
                        out["dev%d" % raw[10]].append(raw[64:64 + ln])
                elif lt == 249 and len(raw) > 32:
                    dev, ep = raw[19], raw[22]
                    ln = struct.unpack("<I", raw[23:27])[0]
                    if ep & 0x80 and 0 < ln <= len(raw) - 27:
                        out["dev%d" % dev].append(raw[27:27 + ln])
        except Exception:
            pass
        finally:
            try:
                reader.close()
            except Exception:
                pass
        return out


# --------------------------------------------------------------------------
# carve validation
# --------------------------------------------------------------------------
def validate_carve(blob: bytes, ext: str) -> bool:
    """Reject fragments that merely start with a magic but do not parse."""
    try:
        if ext == "gz":
            gzip.decompress(blob)
            return True
        if ext == "bz2":
            if bz2 is None:
                return True
            bz2.decompress(blob)
            return True
        if ext == "xz":
            if lzma is None:
                return True
            lzma.decompress(blob)
            return True
        if ext == "zip":
            import io as _io
            import zipfile
            return zipfile.is_zipfile(_io.BytesIO(blob))
        if ext == "png":
            return blob.rstrip(b"\x00")[-8:].startswith(b"\x00\x00\x00\x00IEND") or b"IEND" in blob[-64:]
        if ext == "jpg":
            return blob.rstrip(b"\x00")[-2:] == b"\xff\xd9"
        if ext == "pdf":
            return b"%%EOF" in blob[-2048:]
        if ext in ("elf", "exe"):
            return len(blob) >= 64
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------
# TLS SNI
# --------------------------------------------------------------------------
def parse_tls_sni(data: bytes):
    if len(data) < 43 or data[0] != 0x16:
        return None
    hs = data[5:]
    if not hs or hs[0] != 0x01:
        return None
    if len(hs) < 38:
        return None
    p = 34
    sid_len = hs[p]
    p += 1 + sid_len
    if p + 2 > len(hs):
        return None
    p += 2 + int.from_bytes(hs[p:p + 2], "big")
    if p + 1 > len(hs):
        return None
    p += 1 + hs[p]
    if p + 2 > len(hs):
        return None
    ext_len = int.from_bytes(hs[p:p + 2], "big")
    p += 2
    end = min(len(hs), p + ext_len)
    while p + 4 <= end:
        et = int.from_bytes(hs[p:p + 2], "big")
        el = int.from_bytes(hs[p + 2:p + 4], "big")
        p += 4
        if p + el > end:
            break
        if et == 0x00 and el > 5:
            sn = hs[p:p + el]
            nl = int.from_bytes(sn[3:5], "big")
            if 5 + nl <= len(sn):
                return sn[5:5 + nl].decode("ascii", "replace")
        p += el
    return None


# --------------------------------------------------------------------------
# readers
# --------------------------------------------------------------------------
_TS_COUNTER = [0]


def time_counter():
    _TS_COUNTER[0] += 1
    return _TS_COUNTER[0]


def detect_linktype(path: Path):
    try:
        with open(path, "rb") as f:
            head = f.read(32)
    except OSError:
        return None, "?"
    if len(head) < 4:
        return None, "empty"
    magic = head[:4]
    if len(head) >= 24 and magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        return struct.unpack("<I", head[20:24])[0], "pcap"
    if len(head) >= 24 and magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return struct.unpack(">I", head[20:24])[0], "pcap"
    if magic == b"\x0a\x0d\x0d\x0a":
        return None, "pcapng"
    return None, "unknown"


def _open_reader(path: Path):
    _, fmt = detect_linktype(path)
    if fmt == "pcapng":
        return PcapNgReader(str(path))
    return PcapReader(str(path))


def linktype_name(lt):
    if lt is None:
        return "?"
    return "%s (%d)" % (LINKTYPE_NAMES.get(lt, "DLT_%d" % lt), lt)


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
class Reporter:
    def __init__(self, outdir: Path, quiet: bool = False):
        self.lines = []
        self.quiet = quiet

    def p(self, line=""):
        self.lines.append(line)
        if not self.quiet:
            try:
                print(line)
            except UnicodeEncodeError:
                print(sanitize(line))

    def hdr(self, title):
        self.p("")
        self.p("=" * 78)
        self.p("  " + title)
        self.p("=" * 78)

    def sub(self, title):
        self.p("")
        self.p("-- %s %s" % (title, "-" * max(0, 72 - len(title))))

    def write(self, path: Path):
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8", errors="replace")


def render(an: Analyzer, args) -> Reporter:
    r = Reporter(an.outdir, quiet=args.quiet)
    dur = (an.last_ts - an.first_ts) if (an.first_ts is not None and an.last_ts) else 0

    r.p("=" * 78)
    r.p(" CTF PCAP TRIAGE  v%s" % VERSION)
    r.p(" file      : %s" % an.path)
    r.p(" size      : %.1f KiB" % (an.path.stat().st_size / 1024.0 if an.path.exists() else 0))
    r.p(" format    : %s   linktype: %s" % (an.file_format, linktype_name(an.linktype)))
    r.p(" packets   : %d   parse errors: %d" % (an.packets, an.errors))
    r.p(" duration  : %.3f s" % dur)
    r.p(" output    : %s" % an.outdir)
    r.p("=" * 78)

    # ---- findings ranking ----
    findings = sorted(an.findings, key=lambda f: -f.score)
    seen = set()
    uniq = []
    for f in findings:
        k = (f.kind, f.text)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)

    r.hdr("TOP FINDINGS")
    if an.flags:
        for flag, where in an.flags.items():
            r.p("  [FLAG]  %s" % flag)
            r.p("          via %s" % where)
    if not [x for x in uniq if x.kind != "flag"]:
        r.p("  (nothing high-signal; scroll to the sections below)")
    for f in [x for x in uniq if x.kind != "flag"][:40]:
        tag = {"flag": "FLAG", "cred": "CRED", "carved": "FILE", "covert": "COVERT",
               "dns-tunnel": "DNS", "dns-decoded": "DNS", "dns-txt": "DNS",
               "icmp-tunnel": "ICMP", "usb-keyboard": "USB", "usb-mouse": "USB",
               "arp-spoof": "ARP", "sni": "TLS", "ssh": "SSH"}.get(f.kind, f.kind.upper())
        r.p("  [%-6s] %s" % (tag, f.text))

    if args.quiet:
        r.write(an.outdir / "report.txt")
        return r

    # ---- protocol mix ----
    r.hdr("PROTOCOL MIX")
    for name, cnt in an.proto_counter.most_common(25):
        r.p("  %-16s %d" % (name, cnt))
    if an.streams_truncated:
        r.p("  [!] %d streams skipped (memory cap)" % an.streams_truncated)

    r.sub("Top conversations")
    for (proto, a, b), cnt in an.conv_counter.most_common(15):
        r.p("  %-6s %-22s <-> %-22s %d pkts" % (proto, a, b, cnt))

    r.sub("Top ports")
    r.p("  " + ", ".join("%d(%d)" % (p, c) for p, c in an.port_counter.most_common(20)))
    if an.suspicious:
        r.p("  [!] suspicious ports: " + ", ".join(
            "%s:%d->%s:%d x%d" % (s[0], s[1], s[2], s[3], c)
            for s, c in an.suspicious.most_common(10)))

    # ---- DNS ----
    r.hdr("DNS  (%d queries, %d answers)" % (len(an.dns_queries), len(an.dns_answers)))
    for name, cnt in an.dns_names.most_common(30):
        r.p("  %-70s x%d" % (name[:70], cnt))
    if len(an.dns_names) > 30:
        r.p("  ... %d more unique names (see report for full list)"
            % (len(an.dns_names) - 30))
    if an.dns_txt:
        r.sub("TXT records")
        for ts, q, txt in an.dns_txt[:20]:
            r.p("  %s  TXT %s" % (q[:40], txt[:200]))
    if getattr(an, "dns_suspects", None):
        r.sub("Tunneling / exfil candidates")
        for susp, base, cnt, joined, dec, enc in an.dns_suspects[:10]:
            r.p("  %s  (%d queries, %d bytes of labels)" % (base, cnt, len(joined)))
            r.p("    chain: %s" % joined[:150])
            if dec:
                r.p("    decoded[%s]: %s" % (enc, sanitize(dec[:400])))

    # ---- HTTP ----
    r.hdr("HTTP  (%d messages)" % len(an.http))
    if an.http_hosts:
        r.p("  hosts: " + ", ".join("%s(%d)" % (h, c) for h, c in an.http_hosts.most_common(10)))
    reqs = [m for m in an.http if m["kind"] == "request"]
    seen_lines = set()
    for m in reqs[:40]:
        key = (m["line"], m["host"])
        if key in seen_lines:
            continue
        seen_lines.add(key)
        r.p("  %-58s %s" % (m["line"][:58], m["host"][:18]))
    if len(reqs) > 40:
        r.p("  ... %d more requests" % (len(reqs) - 40))
    if an.upload_files:
        r.sub("Uploads")
        for url, fname, blob in an.upload_files[:10]:
            r.p("  %s -> %s (%d bytes preview)" % (url[:50], fname, len(blob)))

    # ---- TLS ----
    snis = [f.text for f in uniq if f.kind == "sni"]
    if snis:
        r.hdr("TLS SNI")
        for s in dict.fromkeys(snis):
            r.p("  " + s)

    # ---- credentials ----
    r.hdr("CREDENTIALS / SECRETS  (%d)" % len(an.creds))
    seen_creds = set()
    for proto, detail in an.creds:
        d = "%s: %s" % (proto, detail)
        if d in seen_creds:
            continue
        seen_creds.add(d)
        r.p("  " + d[:200])
    if not an.creds:
        r.p("  (none found)")

    # ---- covert ----
    r.hdr("COVERT CHANNELS / TUNNELS")
    if getattr(an, "icmp_reassembled", None):
        for src, dst, iid, n, blob in an.icmp_reassembled[:10]:
            r.p("  ICMP %s->%s id=%d: %d pkts, %d bytes" % (src, dst, iid, n, len(blob)))
            r.p("    %s" % sanitize(blob[:200]))
    else:
        r.p("  no ICMP payloads to reassemble")
    for hit in getattr(an, "covert_hits", [])[:15]:
        r.p("  " + hit[:300])
    if an.arp_spoof:
        r.p("  [!] ARP: " + "; ".join("%s -> %s" % (ip, ",".join(macs))
                                      for ip, macs in an.arp_spoof[:5]))

    # ---- 802.11 ----
    if an.ssids or an.eapol:
        r.hdr("802.11")
        for (bssid, ssid), cnt in list(an.ssids.items())[:20]:
            r.p("  SSID %-32s bssid=%s x%d" % (ssid or "<hidden>", bssid, cnt))
        if an.eapol:
            r.p("  EAPOL frames: %d  -> WPA handshake material present; "
                "use hcxtools/aircrack-ng to crack" % an.eapol)

    # ---- carved ----
    r.hdr("CARVED FILES  (%d)" % len(an.carved))
    for c in an.carved[:60]:
        r.p("  %-46s %8d B  %-22s  <- %s" % (c.path.name[:46], c.size,
                                            c.friendly[:22], c.source[:40]))
    if len(an.carved) > 60:
        r.p("  ... %d more" % (len(an.carved) - 60))
    if not an.carved:
        r.p("  (no known file magic found in payloads)")

    # ---- USB ----
    if getattr(an, "usb_text", None) or an.usb_note:
        r.hdr("USB HID")
        if an.usb_note:
            r.p("  " + an.usb_note)
        for dev, text in getattr(an, "usb_text", {}).items():
            r.p("  dev %s typed:" % dev)
            r.p("  " + repr(text[:800]))

    # ---- strings ----
    r.hdr("STRINGS  (%d unique, %d occurrences)" % (len(an.strings), len(an.occurrences)))
    ranked = [(string_score(text), cnt, text, where)
              for text, (cnt, where) in an.strings.items()]
    ranked.sort(key=lambda x: (-x[0], -x[1]))
    show = len(ranked) if args.all_strings else 200
    for score, cnt, text, where in ranked[:show]:
        r.p("  [%3d] %-110s  x%d  @%s" % (score, text[:110], cnt, where[:40]))
    if len(ranked) > show:
        r.p("  ... %d more -> strings.txt / strings_raw.txt" % (len(ranked) - show))

    # every unique string, ranked (never filtered out)
    with open(an.outdir / "strings.txt", "w", encoding="utf-8", errors="replace") as fh:
        fh.write("# score\tcount\tsource\tstring\n")
        for score, cnt, text, where in ranked:
            fh.write("%d\t%d\t%s\t%s\n" % (score, cnt, where, text))
    # every occurrence with exact location, discovery order (raw material)
    with open(an.outdir / "strings_raw.txt", "w", encoding="utf-8", errors="replace") as fh:
        for where, off, text in an.occurrences:
            fh.write("%s:+%d\t%s\n" % (where, off, text))
    r.p("  strings.txt      : all %d unique strings" % len(ranked))
    r.p("  strings_raw.txt  : all %d occurrences with offsets" % len(an.occurrences))
    if an.occurrence_dropped:
        r.p("  [!] %d occurrences past the cap were not written" % an.occurrence_dropped)

    # auto-decode attempts are produced in Analyzer.finish()
    r.p("  decodes.txt      : %d decode attempts (b64/hex/rot13/xor/reverse)"
        % getattr(an, "decode_count", 0))

    # ---- notes ----
    if an.notes:
        r.hdr("NOTES / ANOMALIES")
        for n in an.notes:
            r.p("  " + n)

    r.hdr("NEXT STEPS")
    r.p("  * carved/  holds every recognised file; check `file` / `binwalk` on odd ones")
    r.p("  * streams/ (with --dump-streams) holds raw reassembled TCP/UDP payloads")
    r.p("  * TLS/SSH/802.11 traffic needs keys; check the challenge description")
    if an.streams:
        biggest = sorted(an.streams.items(), key=lambda kv: -len(kv[1].data))[:5]
        r.p("  * largest streams:")
        for sid, st in biggest:
            r.p("      %-46s %8d bytes  %d pkts" % (sid[:46], len(st.data), st.packets))

    r.write(an.outdir / "report.txt")
    return r


def write_decodes(an: "Analyzer", path: Path, limit: int = 3000) -> int:
    """Write automated decode attempts for every harvested string."""
    import codecs
    out = []
    attempts = 0
    for text, (cnt, where) in an.strings.items():
        if attempts >= limit:
            break
        row = []
        raw = text.encode("latin-1", "ignore")
        # strip our own annotation prefixes before decoding
        core = text
        for pre in ("[base64] ", "[hex] "):
            if core.startswith(pre):
                core = core[len(pre):]
        cbytes = core.encode("latin-1", "ignore")
        dec, enc = try_b64(cbytes)
        if dec:
            row.append(("b64/" + str(enc), sanitize(dec[:300])))
        dec = try_hex(cbytes)
        if dec and (printable_ratio(dec) > 0.85 or sniff_magic(dec)):
            row.append(("hex", sanitize(dec[:300])))
        if re.fullmatch(r"[A-Za-z ]+", core) and len(core) >= 8:
            row.append(("rot13", codecs.encode(core, "rot13")))
            row.append(("reverse", core[::-1]))
        # single-byte xor only for compact, no-space blobs
        if len(cbytes) >= 8 and b" " not in cbytes and printable_ratio(cbytes) > 0.95:
            hits = list(xor_single(cbytes))[:2]
            for k, pt in hits:
                row.append(("xor 0x%02x" % k, sanitize(pt[:300])))
        if not row:
            continue
        attempts += 1
        out.append("==" * 30)
        out.append("%s  x%d  @%s" % (sanitize(text[:200]), cnt, where))
        for label, val in row:
            out.append("  %-12s %s" % (label, val))
        for f in find_flags(b"".join(
                v.encode("latin-1", "ignore") for _, v in row)):
            out.append("  !! FLAG      %s" % f.decode("utf-8", "replace"))
            an.add_flag(f, "decode:" + where)
    path.write_text("\n".join(out) + "\n", encoding="utf-8", errors="replace")
    return attempts


def string_score(text: str) -> int:
    score = 0
    b = text.encode("utf-8", "ignore")
    if FLAG_RE.search(b) or FLAG_RE_LOOSE.search(b):
        score += 100
    low = text.lower()
    for kw in ("flag", "secret", "password", "passwd", "token", "api_key",
               "apikey", "ctf{", "passphrase", "private key", "BEGIN RSA"):
        if kw in low:
            score += 25
            break
    if len(text) >= 16 and entropy(b) > 4.3:
        score += 12
    if re.fullmatch(r"[A-Za-z0-9+/_-]{24,}={0,2}", text) and \
            any(c.isupper() for c in text) and any(c.isdigit() for c in text):
        score += 10
    if re.fullmatch(r"[0-9a-fA-F]{32,}", text):
        score += 8
    if text.startswith("[base64]") or text.startswith("[hex]"):
        score += 20
    if "Set-Cookie" in text or "Cookie " in text:
        score += 5
    return score


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="One-shot triage for CTF pcap/pcapng challenges.")
    ap.add_argument("pcap", help="capture file (.pcap/.pcapng/.cap)")
    ap.add_argument("-o", "--out", help="output directory (default: <name>_analysis)")
    ap.add_argument("--json", action="store_true", help="also write report.json")
    ap.add_argument("--quiet", action="store_true", help="only top findings")
    ap.add_argument("--dump-streams", action="store_true",
                    help="write every reassembled stream to streams/")
    ap.add_argument("--all-strings", action="store_true",
                    help="print every ranked string in the terminal too "
                         "(strings.txt/strings_raw.txt are always written)")
    ap.add_argument("--deep", action="store_true",
                    help="extra decoders (hex) -- noisier, slower")
    ap.add_argument("--usb-mode", choices=("auto", "keyboard", "mouse"),
                    default="auto", help="force USB HID interpretation")
    ap.add_argument("--tshark-expert", action="store_true",
                    help="append tshark io,phs + expert summary")
    args = ap.parse_args(argv)

    path = Path(args.pcap)
    if not path.exists():
        sys.exit("no such file: %s" % path)

    lt, fmt = detect_linktype(path)
    an = Analyzer(path, args)
    an.linktype = lt
    an.file_format = fmt
    if lt is None and fmt == "pcapng":
        an.notes.append("pcapng: linktype per interface (USB detection via tshark)")
    if lt is not None and lt in USB_LINKTYPES:
        an.notes.append("USB link-layer capture (linktype %d)" % lt)
    print("[*] reading %s (%s/%s) ..." % (path.name, fmt, linktype_name(lt)),
          file=sys.stderr)
    reader = _open_reader(path)
    try:
        for pkt in reader:
            an.feed(pkt)
    except Exception as exc:
        an.notes.append("reader stopped early: %s" % exc)
    finally:
        try:
            reader.close()
        except Exception:
            pass

    print("[*] %d packets, %d streams, %d payload bytes; analysing ..."
          % (an.packets, len(an.streams), an.total_stream_bytes), file=sys.stderr)
    an.finish()
    r = render(an, args)

    if args.tshark_expert:
        tshark = which_tshark()
        if tshark:
            try:
                res = subprocess.run(
                    [tshark, "-r", str(path), "-q", "-z", "io,phs", "-z", "expert"],
                    capture_output=True, timeout=300,
                    creationflags=(0x08000000 if os.name == "nt" else 0))
                extra = res.stdout.decode("utf-8", "replace")
                (an.outdir / "tshark_summary.txt").write_text(extra, encoding="utf-8")
                r.p("")
                r.p("[tshark summary -> %s]" % (an.outdir / "tshark_summary.txt"))
            except Exception as exc:
                print("[!] tshark expert failed: %s" % exc, file=sys.stderr)
        else:
            print("[!] tshark not found; --tshark-expert skipped", file=sys.stderr)

    if args.json:
        payload = {
            "file": str(path),
            "format": fmt,
            "linktype": lt,
            "packets": an.packets,
            "parse_errors": an.errors,
            "flags": an.flags,
            "credentials": an.creds,
            "http_hosts": dict(an.http_hosts),
            "http": an.http[:500],
            "dns_names": an.dns_names.most_common(200),
            "dns_txt": an.dns_txt[:100],
            "dns_suspects": [
                {"base": b, "queries": c, "chain": j, "decoded": sanitize(d)[:400]}
                for _, b, c, j, d, _e in getattr(an, "dns_suspects", [])
            ],
            "carved": [{"path": str(c.path), "type": c.friendly, "size": c.size,
                        "source": c.source} for c in an.carved],
            "covert": getattr(an, "covert_hits", []),
            "usb_text": getattr(an, "usb_text", {}),
            "strings": sorted(
                ({"score": string_score(t), "count": c, "where": w, "text": t}
                 for t, (c, w) in an.strings.items()),
                key=lambda x: -x["score"])[:300],
            "notes": an.notes,
        }
        (an.outdir / "report.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n[*] done. report -> %s" % (an.outdir / "report.txt"), file=sys.stderr)
    if an.flags:
        print("[*] FLAGS: %s" % ", ".join(an.flags), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
