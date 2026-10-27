#!/usr/bin/env python3
"""ctf_stegano.py -- steganography toolkit for CTF images/audio.

  python ctf_stegano.py analyze  image.png          # everything, ranked
  python ctf_stegano.py chunks   image.png          # PNG/GIF/JPEG structure + trailing data
  python ctf_stegano.py lsb      image.png          # zsteg-style bitplane sweep
  python ctf_stegano.py wav      sound.wav          # PCM LSB + trailing data
  python ctf_stegano.py raw      blob.bin --bits 0  # LSB of arbitrary bytes
  python ctf_stegano.py zero     text.txt           # zero-width characters
  python ctf_stegano.py white    text.txt           # whitespace/tab encoding
  python ctf_stegano.py all      image.png

Bitplane sweep tries every (channel set) x (bit 0..7) x (bit order) and keeps
anything that decodes to >=70% printable text or contains a flag.
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import zlib
from pathlib import Path

FLAG_RE = re.compile(
    rb"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    rb"pctf|hitcon|idek|sekai|buckeye|utflag|lactf|byuctf|tjctf|damctf|sctf|"
    rb"justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    rb"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
PRINT_RE = re.compile(rb"[\x20-\x7e\t]{6,}")
ZERO_WIDTH = {"\u200b": "0", "\u200c": "1", "\u200d": "2", "\ufeff": "3",
              "\u2060": "4", "\u180e": "5"}


def human(n):
    for unit in ("B", "KiB", "MiB"):
        if n < 1024 or unit == "MiB":
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


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------
def png_chunks(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None, None
    chunks = []
    i = 8
    while i + 8 <= len(data):
        length = struct.unpack_from(">I", data, i)[0]
        ctype = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + length]
        crc = data[i + 8 + length:i + 12 + length]
        ok = len(crc) == 4 and struct.unpack(">I", crc)[0] == zlib.crc32(ctype + body) & 0xffffffff
        chunks.append({"type": ctype.decode("latin-1"), "len": length,
                       "body": body, "off": i, "crc_ok": ok})
        i += 12 + length
        if ctype == b"IEND":
            break
    return chunks, data[i:]


def png_pixels(chunks):
    """-> (width, height, bitdepth, colortype, raw_scanlines_unfiltered, channels)."""
    ihdr = next((c for c in chunks if c["type"] == "IHDR"), None)
    if not ihdr:
        return None
    w, h, depth, ctype, comp, filt, interlace = struct.unpack(">IIBBBBB", ihdr["body"][:13])
    if interlace or depth != 8:
        return {"interlaced_or_deep": True, "w": w, "h": h}
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype, 3)
    idat = b"".join(c["body"] for c in chunks if c["type"] == "IDAT")
    plt = next((c["body"] for c in chunks if c["type"] == "PLTE"), b"")
    trns = next((c["body"] for c in chunks if c["type"] == "tRNS"), b"")
    try:
        raw = zlib.decompress(idat)
    except zlib.error:
        return None
    stride = w * channels
    out = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _y in range(h):
        if pos >= len(raw):
            break
        f = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if len(line) < stride:
            line.extend(b"\x00" * (stride - len(line)))
        if f == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif f == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif f == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        out.extend(line)
        prev = line
    return {"w": w, "h": h, "channels": channels, "pixels": bytes(out),
            "colortype": ctype, "palette": plt, "trns": trns}


def bits_to_bytes(bits: list) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def lsb_sweep(pixels: bytes, channels: int, log: Log, tag="", min_bytes=16):
    """Every channel-set / bit / order that yields text or a flag."""
    hits = []
    chans = list(range(channels))
    sets = []
    for mask in range(1, 1 << channels):
        sets.append([c for c in chans if mask & (1 << c)])
    step = len(sets) * 8 * 2
    n = (len(pixels) // channels) * channels
    for cs in sets:
        for bit in range(8):
            for order in ("msb", "lsb"):
                bits = []
                for i in range(0, n - channels + 1, channels):
                    for c in cs:
                        byte = pixels[i + c]
                        bits.append((byte >> bit) & 1 if order == "msb" else (byte >> (7 - bit)) & 1)
                payload = bits_to_bytes(bits)
                if len(payload) < min_bytes:
                    continue
                if FLAG_RE.search(payload):
                    hits.append((100, cs, bit, order, payload))
                elif printable_ratio(payload[:4096]) > 0.85:
                    hits.append((60, cs, bit, order, payload))
    hits.sort(key=lambda h: -h[0])
    for score, cs, bit, order, payload in hits[:8]:
        label = "".join("rgba"[c] for c in cs)
        sample = PRINT_RE.findall(payload[:4096])
        text = sample[0].decode("latin-1", "replace")[:200] if sample else ""
        log.p("  [%3d] %s bit=%d %s : %s" % (score, label, bit, order, text))
        for m in FLAG_RE.finditer(payload):
            log.p("  [FLAG] %s   (%s bit=%d)" % (m.group(0).decode("latin-1"), label, bit))
    if not hits:
        log.p("  no readable LSB payload in %s" % (tag or "pixels"))
    return hits


# --------------------------------------------------------------------------
# other formats
# --------------------------------------------------------------------------
def bmp_pixels(data: bytes):
    if data[:2] != b"BM":
        return None
    off = struct.unpack_from("<I", data, 10)[0]
    w = struct.unpack_from("<i", data, 18)[0]
    h = struct.unpack_from("<i", data, 22)[0]
    bpp = struct.unpack_from("<H", data, 28)[0]
    if bpp not in (8, 24, 32):
        return None
    channels = bpp // 8
    stride = ((w * channels + 3) // 4) * 4
    rows = []
    for y in range(abs(h)):
        row = data[off + y * stride: off + y * stride + w * channels]
        rows.append(row)
    return {"w": w, "h": abs(h), "channels": channels, "pixels": b"".join(rows)}


def wav_info(data: bytes):
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    pos = 12
    info = {"fmt": None, "samples": b"", "data_off": 0, "data_len": 0, "trailing": b""}
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        size = struct.unpack_from("<I", data, pos + 4)[0]
        body = data[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            info["fmt"] = struct.unpack_from("<HHIIHH", body[:16])
        elif cid == b"data":
            info["samples"] = body
            info["data_off"] = pos + 8
            info["data_len"] = size
            info["trailing"] = data[pos + 8 + size:]
        pos += 8 + size + (size & 1)
    return info


def scan_bytes(buf: bytes, log: Log, tag: str):
    for m in FLAG_RE.finditer(buf):
        log.p("  [FLAG] %s   (%s)" % (m.group(0).decode("latin-1"), tag))
    strs = PRINT_RE.findall(buf[:1 << 20])
    for s in strs[:5]:
        log.p("  text  : %s" % s.decode("latin-1", "replace")[:160])


# --------------------------------------------------------------------------
def analyze(path: Path, outdir: Path, log: Log):
    data = path.read_bytes()
    log.hdr("STEGANO  %s (%s)" % (path.name, human(len(data))))
    chunks, trailing = png_chunks(data)
    if chunks:
        log.p("  PNG chunks:")
        for c in chunks:
            extra = ""
            if c["type"] in ("tEXt", "zTXt", "iTXt"):
                k, _, v = c["body"].partition(b"\x00")
                if c["type"] == "zTXt":
                    try:
                        v = zlib.decompress(v[1:])
                    except zlib.error:
                        pass
                extra = " %s = %s" % (k.decode("latin-1", "replace"), v[:200].decode("latin-1", "replace"))
            log.p("    %-6s len=%-8d crc=%s%s" % (c["type"], c["len"],
                                                 "ok" if c["crc_ok"] else "BAD", extra))
            if not c["crc_ok"]:
                log.p("      [!] CRC mismatch -> data was edited after the fact")
            if c["type"] in ("tEXt", "iTXt", "zTXt"):
                scan_bytes(c["body"], log, "chunk " + c["type"])
        if trailing:
            log.p("  [!] %d bytes after IEND -> trailing.bin" % len(trailing))
            (outdir / "trailing.bin").write_bytes(trailing)
            scan_bytes(trailing, log, "trailing data")
        px = png_pixels(chunks)
        if px and "pixels" in px:
            log.p("  pixels   : %dx%d, %d channels" % (px["w"], px["h"], px["channels"]))
            log.p("")
            log.p("  -- bitplane sweep --")
            lsb_sweep(px["pixels"], px["channels"], log, "PNG")
        elif px:
            log.p("  [!] %s" % ("interlaced/16-bit PNG: use zsteg or convert first"))
    elif data[:2] == b"BM":
        px = bmp_pixels(data)
        if px:
            log.p("  BMP %dx%d %d channels" % (px["w"], px["h"], px["channels"]))
            lsb_sweep(px["pixels"], px["channels"], log, "BMP")
        if len(data) < 14:
            pass
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        log.p("  GIF: comment extensions + trailing data")
        pos = 6
        try:
            w, h, flags = struct.unpack_from("<HHB", data, pos)
            log.p("  size %dx%d" % (w, h))
            if flags & 0x80:
                pos += 3 * (2 << (flags & 7))
            pos += 3
            while pos < len(data):
                if data[pos] == 0x21 and data[pos + 1] == 0xFE:
                    pos += 2
                    out = bytearray()
                    while data[pos]:
                        ln = data[pos]
                        out += data[pos + 1:pos + 1 + ln]
                        pos += 1 + ln
                    pos += 1
                    log.p("  comment: %s" % out[:300].decode("latin-1", "replace"))
                    scan_bytes(bytes(out), log, "gif comment")
                    continue
                if data[pos] == 0x3B:
                    tail = data[pos + 1:]
                    if tail:
                        log.p("  [!] %d bytes after GIF trailer" % len(tail))
                        (outdir / "trailing.bin").write_bytes(tail)
                        scan_bytes(tail, log, "gif trailing")
                    break
                pos += 1
        except struct.error:
            pass
    elif data[:2] == b"\xff\xd8":
        log.p("  JPEG segments:")
        i = 2
        while i + 4 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                if marker == 0xD9:
                    tail = data[i + 2:]
                    if tail:
                        log.p("  [!] %d bytes after EOI -> trailing.bin" % len(tail))
                        (outdir / "trailing.bin").write_bytes(tail)
                        scan_bytes(tail, log, "jpeg trailing")
                    break
                i += 2
                continue
            seglen = struct.unpack_from(">H", data, i + 2)[0]
            seg = data[i + 4:i + 2 + seglen]
            log.p("    APP/SEG 0x%02x len=%d" % (marker, seglen))
            if marker == 0xFE:
                log.p("      comment: %s" % seg[:250].decode("latin-1", "replace"))
                scan_bytes(seg, log, "jpeg comment")
            if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
                scan_bytes(seg, log, "jpeg exif")
            if marker == 0xDA:
                break
            i += 2 + seglen
    elif wav_info(data):
        w = wav_info(data)
        fmt = w["fmt"] or (0, 0, 0, 0, 0, 0)
        log.p("  WAV fmt: channels=%d rate=%d bits=%d" % (fmt[1], fmt[2], fmt[5]))
        if fmt[5] == 16:
            samples = w["samples"]
            bits = []
            for i in range(0, len(samples) - 1, 2):
                v = struct.unpack_from("<h", samples, i)[0]
                bits.append(v & 1)
            payload = bits_to_bytes(bits)
            if printable_ratio(payload[:2000]) > 0.8 or FLAG_RE.search(payload):
                log.p("  -- 16-bit LSB --")
                log.p("  " + PRINT_RE.findall(payload[:2000])[0][:200].decode("latin-1") if PRINT_RE.findall(payload[:2000]) else "")
                scan_bytes(payload, log, "wav lsb")
                (outdir / "wav_lsb.bin").write_bytes(payload)
        if w["trailing"]:
            log.p("  [!] %d bytes after data chunk -> trailing.bin" % len(w["trailing"]))
            (outdir / "trailing.bin").write_bytes(w["trailing"])
            scan_bytes(w["trailing"], log, "wav trailing")
    else:
        log.p("  generic file: byte strings + trailing scan")
        scan_bytes(data, log, "file")

    # generic: printable strings worth a look
    log.p("")
    log.p("  -- noteworthy strings --")
    seen = set()
    shown = 0
    for m in PRINT_RE.finditer(data):
        s = m.group(0).decode("latin-1")
        if s in seen:
            continue
        seen.add(s)
        if FLAG_RE.search(s.encode("latin-1", "ignore")) or re.search(r"(?i)flag|secret|key|pass", s):
            log.p("  %08x %s" % (m.start(), s[:160]))
            shown += 1
            if shown >= 20:
                break
    log.save(outdir / "report.txt")


def raw_lsb(path: Path, outdir: Path, log: Log, bits=None, order="msb"):
    data = path.read_bytes()
    log.hdr("RAW LSB  %s" % path.name)
    planes = [bits] if bits is not None else range(8)
    for bit in planes:
        b = []
        for byte in data:
            b.append((byte >> bit) & 1 if order == "msb" else (byte >> (7 - bit)) & 1)
        payload = bits_to_bytes(b)
        if FLAG_RE.search(payload) or printable_ratio(payload[:2000]) > 0.85:
            log.p("  bit=%d %s : %s" % (bit, order,
                  (PRINT_RE.findall(payload[:2000])[0][:200].decode("latin-1", "replace")
                   if PRINT_RE.findall(payload[:2000]) else "")))
            scan_bytes(payload, log, "raw lsb bit %d" % bit)
            (outdir / ("lsb_bit%d_%s.bin" % (bit, order))).write_bytes(payload)
    log.save(outdir / "lsb.txt")


def zero_width(path: Path, outdir: Path, log: Log):
    text = path.read_text(encoding="utf-8", errors="replace")
    log.hdr("ZERO-WIDTH  %s" % path.name)
    bits = [ZERO_WIDTH[ch] for ch in text if ch in ZERO_WIDTH]
    log.p("  hidden chars: %d" % len(bits))
    if bits:
        payload = "".join(bits)
        log.p("  digits: %s" % payload[:200])
        # try binary (0/1), ternary/quaternary, and direct utf-8 bytes
        if set(payload) <= {"0", "1"}:
            try:
                dec = bytes(int(payload[i:i + 8], 2) for i in range(0, len(payload) - 7, 8))
                log.p("  decoded: %s" % dec[:300].decode("latin-1", "replace"))
                scan_bytes(dec, log, "zero-width binary")
                (outdir / "zero_width.bin").write_bytes(dec)
            except ValueError:
                pass
        if set(payload) <= {"0", "1", "2", "3"}:
            try:
                dec = bytes(int(payload[i:i + 4], 4) for i in range(0, len(payload) - 3, 4))
                log.p("  base4  : %s" % dec[:300].decode("latin-1", "replace"))
                scan_bytes(dec, log, "zero-width base4")
            except ValueError:
                pass
    log.save(outdir / "zero.txt")


def whitespace(path: Path, outdir: Path, log: Log):
    log.hdr("WHITESPACE STEG  %s" % path.name)
    text = path.read_text(encoding="utf-8", errors="replace")
    bits = []
    for line in text.splitlines():
        trail = line[len(line.rstrip(" \t")):]
        for ch in trail:
            bits.append(1 if ch == "\t" else 0)
    log.p("  trailing space/tab chars: %d" % len(bits))
    payload = bits_to_bytes(bits)
    if FLAG_RE.search(payload) or printable_ratio(payload[:200]) > 0.7:
        log.p("  decoded: %s" % payload[:400].decode("latin-1", "replace"))
        scan_bytes(payload, log, "whitespace")
        (outdir / "whitespace.bin").write_bytes(payload)
    else:
        log.p("  (no clean ASCII payload; try snow -C or adjust bits)")
    log.save(outdir / "whitespace.txt")


def main(argv=None):
    ap = argparse.ArgumentParser(description="steganography toolkit")
    ap.add_argument("command", choices=("analyze", "chunks", "lsb", "wav", "raw",
                                        "zero", "white", "all"))
    ap.add_argument("target")
    ap.add_argument("-o", "--out")
    ap.add_argument("--bits", type=int, help="single bitplane for `raw`")
    ap.add_argument("--order", default="msb", choices=("msb", "lsb"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    path = Path(args.target)
    if not path.exists():
        sys.exit("no such file: %s" % path)
    outdir = Path(args.out or (path.stem + "_steg"))
    outdir.mkdir(parents=True, exist_ok=True)
    log = Log()

    if args.command in ("analyze", "all", "chunks", "wav", "lsb"):
        if args.command == "lsb" and path.suffix.lower() in (".bin", ".raw", ".dat"):
            raw_lsb(path, outdir, log, args.bits, args.order)
        else:
            analyze(path, outdir, log)
        return 0
    if args.command == "raw":
        raw_lsb(path, outdir, log, args.bits, args.order)
        return 0
    if args.command == "zero":
        zero_width(path, outdir, log)
        return 0
    if args.command == "white":
        whitespace(path, outdir, log)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
