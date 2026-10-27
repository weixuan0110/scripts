#!/usr/bin/env python3
"""ctf_misc.py -- misc challenge toolkit.

  python ctf_misc.py sniff  mystery.bin         # real type + polyglots
  python ctf_misc.py scan   mystery.bin         # flags, base64/hex layers, xor
  python ctf_misc.py nested archive.zip         # recursive extraction
  python ctf_misc.py zipcrack secret.zip --wordlist rockyou.txt
  python ctf_misc.py zipcrack secret.zip --digits 6
  python ctf_misc.py brainfuck code.txt         # also auto-detects Ook
  python ctf_misc.py all    mystery.bin

Designed for the "MISC" bucket: unknown files, esolangs, nested archives,
password-protected zips, and text hiding in plain sight.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bz2
import gzip
import hashlib
import io
import lzma
import os
import re
import shutil
import struct
import sys
import tarfile
import time
import zipfile
from pathlib import Path

FLAG_RE = re.compile(
    rb"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    rb"pctf|hitcon|idek|sekai|buckeye|utflag|lactf|byuctf|tjctf|damctf|sctf|"
    rb"justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    rb"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"), (b"%PDF-", "PDF document"), (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b\x08", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-zip"), (b"Rar!\x1a\x07", "RAR"),
    (b"\x7fELF", "ELF binary"), (b"MZ", "PE executable"),
    (b"\x00asm", "WebAssembly"), (b"OggS", "Ogg"), (b"fLaC", "FLAC"),
    (b"RIFF", "RIFF (wav/avi/webp)"), (b"SQLite format 3\x00", "SQLite"),
    (b"dex\n", "Dalvik dex"), (b"\x1aE\xdf\xa3", "Matroska/WebM"),
    (b"\xfe\xed\xfa", "Mach-O"), (b"\xcf\xfa\xed\xfe", "Mach-O 64"),
    (b"ustar", "TAR"), (b"hsqs", "SquashFS"), (b"ANDROID!", "Android boot image"),
    (b"\xd0\xcf\x11\xe0", "OLE (doc/xls)"), (b"{\\rtf", "RTF"),
]


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


class Log:
    def __init__(self):
        self.lines = []

    def p(self, s=""):
        self.lines.append(s)
        try:
            print(s)
        except UnicodeEncodeError:
            print(s.encode("ascii", "replace").decode())

    def hdr(self, t):
        self.p("")
        self.p("=" * 76)
        self.p("  " + t)
        self.p("=" * 76)

    def save(self, p: Path):
        p.write_text("\n".join(self.lines) + "\n", encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
def sniff(data: bytes):
    hits = []
    for magic, name in MAGICS:
        if data.startswith(magic):
            hits.append((0, name))
    # polyglots: a second format further in
    for magic, name in MAGICS:
        off = data.find(magic, 4)
        if off > 0:
            hits.append((off, name))
    return hits


def print_sniff(data: bytes, log: Log):
    hits = sniff(data)
    if not hits:
        log.p("  type     : unknown / raw data")
        if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:200]):
            log.p("  hint     : looks like text -> try ctf_crypto.py decode")
        return hits
    log.p("  type     : %s" % hits[0][1])
    extra = [h for h in hits if h[0] > 0]
    if extra:
        log.p("  [POLYGLOT] additional formats inside:")
        for off, name in extra[:8]:
            log.p("    +%#x %s" % (off, name))
    return hits


# --------------------------------------------------------------------------
def scan_flags(data: bytes, log: Log, where="file", depth=0, outdir=None):
    found = set()
    for m in FLAG_RE.finditer(data):
        s = m.group(0).decode("latin-1")
        if s not in found:
            found.add(s)
            log.p("  [FLAG] %s   (%s)" % (s, where))
    if depth < 2:
        for m in re.finditer(rb"[A-Za-z0-9+/]{24,}={0,2}", data):
            blob = m.group(0)
            try:
                dec = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
            except Exception:
                continue
            if FLAG_RE.search(dec):
                scan_flags(dec, log, where + " (base64)", depth + 1, outdir)
        for m in re.finditer(rb"(?<![\w])[0-9a-fA-F]{24,}(?![\w])", data):
            try:
                dec = bytes.fromhex(m.group(0).decode())
            except ValueError:
                continue
            if FLAG_RE.search(dec) or (b"{" in dec and b"}" in dec):
                scan_flags(dec, log, where + " (hex)", depth + 1, outdir)
    return found


def xor_preview(data: bytes, log: Log):
    """Cheap single-byte XOR pass; good for obfuscated text files."""
    best = []
    for k in range(1, 256):
        pt = bytes(b ^ k for b in data[:4096])
        pr = sum(1 for c in pt if 32 <= c < 127) / len(pt)
        if pr > 0.9:
            best.append((pr, k, pt))
    best.sort(key=lambda x: -x[0])
    for pr, k, pt in best[:3]:
        m = FLAG_RE.search(pt)
        log.p("  xor 0x%02x  %s" % (k, (m.group(0).decode("latin-1") if m else pt[:90].decode("latin-1", "replace"))))


# --------------------------------------------------------------------------
# brainfuck / Ook
# --------------------------------------------------------------------------
BF_OK = set("+-<>[].,")
OOK_MAP = {
    "Ook. Ook.": ">", "Ook? Ook.": "<", "Ook. Ook?": "+", "Ook? Ook?": "-",
    "Ook! Ook!": ".", "Ook! Ook.": ",", "Ook? Ook!": "[", "Ook! Ook?": "]",
}


def ook_to_bf(text: str):
    pairs = re.findall(r"Ook[.!?]\s*Ook[.!?]", text)
    return "".join(OOK_MAP.get(re.sub(r"\s+", " ", p), "") for p in pairs)


def run_bf(code: str, stdin="", limit=50_000_000):
    code = "".join(c for c in code if c in BF_OK)
    if code.count("[") != code.count("]"):
        return None, "unbalanced brackets"
    tape = [0] * 30000
    ptr = 0
    pc = 0
    out = []
    taken = 0
    stack = []
    jumps = {}
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None, "unbalanced ]"
            j = stack.pop()
            jumps[i] = j
            jumps[j] = i
    inp = list(stdin.encode())
    steps = 0
    while pc < len(code) and steps < limit:
        c = code[pc]
        steps += 1
        if c == ">":
            ptr = (ptr + 1) % len(tape)
        elif c == "<":
            ptr = (ptr - 1) % len(tape)
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ".":
            out.append(tape[ptr])
        elif c == ",":
            tape[ptr] = inp.pop(0) if inp else 0
        elif c == "[":
            if tape[ptr] == 0:
                pc = jumps[pc]
        elif c == "]":
            if tape[ptr] != 0:
                pc = jumps[pc]
        pc += 1
    if steps >= limit:
        return bytes(out), "step limit hit"
    return bytes(out), None


def brainfuck_cmd(path: Path, stdin: str, log: Log):
    text = path.read_text(encoding="utf-8", errors="replace")
    log.hdr("ESOLANG  %s" % path.name)
    if "Ook" in text:
        log.p("  detected: Ook! -> translating to Brainfuck")
        text = ook_to_bf(text)
    ratio = sum(1 for c in text if c in BF_OK) / max(1, len(text))
    log.p("  brainfuck char ratio: %.2f" % ratio)
    out, err = run_bf(text, stdin)
    if out is None:
        log.p("  [!] %s" % err)
        return None
    log.p("  output (%d bytes):" % len(out))
    log.p("  " + out[:2000].decode("latin-1", "replace"))
    for m in FLAG_RE.finditer(out):
        log.p("  [FLAG] %s" % m.group(0).decode("latin-1"))
    (path.parent / (path.stem + "_bf_output.bin")).write_bytes(out)
    return out


# --------------------------------------------------------------------------
# nested archives
# --------------------------------------------------------------------------
def nested(path: Path, outdir: Path, log: Log, depth=0, max_depth=6):
    outdir.mkdir(exist_ok=True)
    found = set()
    if depth > max_depth:
        return found
    data = path.read_bytes()
    for m in FLAG_RE.finditer(data):
        s = m.group(0).decode("latin-1")
        if s not in found:
            found.add(s)
            log.p("  [FLAG] %s   (%s)" % (s, path.name))
    base = outdir / ("%d_%s" % (depth, re.sub(r"[^A-Za-z0-9_.-]", "_", path.name)))[:120]
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    target = base / re.sub(r"[^A-Za-z0-9_.-]", "_", info.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        blob = zf.read(info)
                    except RuntimeError:
                        log.p("  [!] %s is encrypted" % info.filename)
                        continue
                    target.write_bytes(blob)
                    log.p("  extracted: %s (%s)" % (info.filename, human(len(blob))))
                    found |= nested(target, outdir, log, depth + 1, max_depth)
        except zipfile.BadZipFile:
            pass
        return found
    if data[:2] == b"\x1f\x8b":
        try:
            blob = gzip.decompress(data)
        except OSError:
            return found
    elif data[:3] == b"BZh":
        try:
            blob = bz2.decompress(data)
        except OSError:
            return found
    elif data[:6] == b"\xfd7zXZ\x00":
        try:
            blob = lzma.decompress(data)
        except lzma.LZMAError:
            return found
    elif tarfile.is_tarfile(path):
        try:
            with tarfile.open(path) as tf:
                for member in tf.getmembers()[:200]:
                    if not member.isfile():
                        continue
                    f = tf.extractfile(member)
                    if not f:
                        continue
                    target = base / re.sub(r"[^A-Za-z0-9_.-]", "_", member.name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(f.read())
                    log.p("  extracted: %s" % member.name)
                    found |= nested(target, outdir, log, depth + 1, max_depth)
        except tarfile.TarError:
            pass
        return found
    else:
        return found
    target = base.with_suffix(base.suffix + ".out")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(blob)
    log.p("  decompressed: %s (%s)" % (target.name, human(len(blob))))
    found |= nested(target, outdir, log, depth + 1, max_depth)
    return found


# --------------------------------------------------------------------------
# zip password
# --------------------------------------------------------------------------
COMMON = ["password", "123456", "12345678", "admin", "letmein", "qwerty",
          "secret", "flag", "ctf", "infected", "malware", "root", "toor",
          "1234", "12345", "1234567890", "abc123", "iloveyou", "monkey"]


def zip_crack(path: Path, log: Log, wordlist=None, digits=0):
    log.hdr("ZIP PASSWORD  %s" % path.name)
    if not zipfile.is_zipfile(path):
        log.p("  not a zip")
        return None
    with zipfile.ZipFile(path) as zf:
        enc = [i for i in zf.infolist() if i.flag_bits & 0x1]
        if not enc:
            log.p("  archive is not encrypted")
            return None
        if any(i.compress_type == 99 for i in enc):
            log.p("  [!] AES-encrypted entry: python zipfile cannot test AES; use bkcrack/7z")
        target = enc[0]

        def attempt(pwd: bytes):
            try:
                zf.read(target, pwd=pwd)
                return True
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError, ValueError):
                return False

        tried = 0
        cands = []
        if wordlist:
            with open(wordlist, "r", encoding="utf-8", errors="replace") as fh:
                cands = [l.rstrip("\r\n").encode() for l in fh if l.strip()]
        else:
            cands = [c.encode() for c in COMMON]
        for pwd in cands:
            tried += 1
            if attempt(pwd):
                log.p("  [CRACKED] password = %r  (%d tries)" % (pwd.decode("latin-1"), tried))
                return pwd
        if digits:
            deadline = time.time() + 600
            for i in range(10 ** digits):
                if time.time() > deadline:
                    log.p("  time budget hit after %d tries" % tried)
                    break
                pwd = str(i).zfill(digits).encode()
                tried += 1
                if attempt(pwd):
                    log.p("  [CRACKED] password = %r  (%d tries)" % (pwd.decode(), tried))
                    return pwd
                if tried % 100000 == 0:
                    log.p("  ... %d tries" % tried)
    log.p("  not found (%d tried)" % tried)
    return None


# --------------------------------------------------------------------------
def scan_cmd(path: Path, outdir: Path, log: Log):
    data = path.read_bytes()
    log.hdr("SCAN  %s (%s)" % (path.name, human(len(data))))
    print_sniff(data, log)
    log.p("")
    log.p("  sha256: %s" % hashlib.sha256(data).hexdigest())
    log.p("  -- flags --")
    found = scan_flags(data, log, path.name, 0, outdir)
    if not found:
        log.p("  (none in raw bytes; trying xor pass)")
        xor_preview(data[:1 << 16], log)
    log.p("")
    log.p("  -- strings --")
    shown = 0
    seen = set()
    for m in re.finditer(rb"[\x20-\x7e]{8,}", data):
        s = m.group(0).decode("latin-1")
        if s in seen:
            continue
        seen.add(s)
        if re.search(r"(?i)flag|ctf|key|secret|pass|token|http", s):
            log.p("  %08x %s" % (m.start(), s[:160]))
            shown += 1
            if shown >= 30:
                break
    log.save(outdir / "scan.txt")


def main(argv=None):
    ap = argparse.ArgumentParser(description="misc challenge toolkit")
    ap.add_argument("command", choices=("sniff", "scan", "nested", "zipcrack",
                                        "brainfuck", "all"))
    ap.add_argument("target")
    ap.add_argument("-o", "--out")
    ap.add_argument("--wordlist")
    ap.add_argument("--digits", type=int, default=0)
    ap.add_argument("--input", default="", help="stdin for brainfuck")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    path = Path(args.target)
    if not path.exists():
        sys.exit("no such file: %s" % path)
    outdir = Path(args.out or (path.stem + "_misc"))
    outdir.mkdir(parents=True, exist_ok=True)
    log = Log()

    if args.command == "sniff":
        log.hdr("SNIFF  %s" % path.name)
        print_sniff(path.read_bytes(), log)
        log.save(outdir / "sniff.txt")
        return 0
    if args.command == "scan":
        scan_cmd(path, outdir, log)
        return 0
    if args.command == "nested":
        log.hdr("NESTED EXTRACTION  %s" % path.name)
        found = nested(path, outdir / "nested", log)
        log.p("")
        log.p("  flags: %s" % (", ".join(sorted(found)) or "none"))
        log.save(outdir / "nested.txt")
        return 0
    if args.command == "zipcrack":
        pwd = zip_crack(path, log, Path(args.wordlist) if args.wordlist else None,
                        args.digits)
        log.save(outdir / "zipcrack.txt")
        return 0 if pwd else 1
    if args.command == "brainfuck":
        brainfuck_cmd(path, args.input, log)
        log.save(outdir / "brainfuck.txt")
        return 0
    if args.command == "all":
        scan_cmd(path, outdir, log)
        log.hdr("NESTED EXTRACTION")
        nested(path, outdir / "nested", log)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
