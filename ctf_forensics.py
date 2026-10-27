#!/usr/bin/env python3
"""ctf_forensics.py -- forensics challenge toolkit.

Works on disk images, memory dumps, single files and archives. Pure stdlib;
works on multi-GB images through mmap.

  python ctf_forensics.py triage  disk.img
  python ctf_forensics.py carve   disk.img            # -> carved/ with exact sizes
  python ctf_forensics.py strings disk.img
  python ctf_forensics.py layout  disk.img            # entropy / slack map
  python ctf_forensics.py exif    photo.jpg
  python ctf_forensics.py pdf     doc.pdf
  python ctf_forensics.py zipmeta archive.zip         # docx/xlsx => full text too
  python ctf_forensics.py all     disk.img

Everything lands in <name>_forensics/: report.txt, strings.txt, carved/**, meta.json
"""

from __future__ import annotations

import argparse
import binascii
import gzip
import hashlib
import io
import json
import math
import mmap
import os
import re
import struct
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree

FLAG_RE = re.compile(
    rb"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    rb"pctf|hitcon|idek|sekai|buckeye|utflag|lactf|byuctf|tjctf|damctf|sctf|"
    rb"justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    rb"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
HEX_RUN = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")

# (magic, ext, friendly, detector)
SIGS = [
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff\xe0", "jpg", "JPEG (JFIF)"),
    (b"\xff\xd8\xff\xe1", "jpg", "JPEG (EXIF)"),
    (b"\xff\xd8\xff\xdb", "jpg", "JPEG"),
    (b"GIF87a", "gif", "GIF87a"), (b"GIF89a", "gif", "GIF89a"),
    (b"%PDF-", "pdf", "PDF document"),
    (b"PK\x03\x04", "zip", "ZIP/JAR/APK/DOCX"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-zip archive"),
    (b"Rar!\x1a\x07\x00", "rar", "RAR4 archive"),
    (b"Rar!\x1a\x07\x01\x00", "rar", "RAR5 archive"),
    (b"\x1f\x8b\x08", "gz", "gzip stream"),
    (b"BZh9", "bz2", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz", "xz stream"),
    (b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (b"\x7fELF", "elf", "ELF binary"),
    (b"MZ", "exe", "PE executable"),
    (b"\x00\x00\x01\xba", "mpg", "MPEG program stream"),
    (b"OggS", "ogg", "Ogg stream"),
    (b"RIFF", "riff", "RIFF (wav/avi/webp)"),
    (b"fLaC", "flac", "FLAC audio"),
    (b"ID3", "mp3", "MP3 (ID3)"),
    (b"\x1aE\xdf\xa3", "mkv", "Matroska/WebM"),
    (b"\xca\xfe\xba\xbe", "class", "Java class / Mach-O fat"),
    (b"regf", "regf", "Windows registry hive"),
    (b"LUKS\xba\xbe", "luks", "LUKS container"),
    (b"\xd0\xcf\x11\xe0", "ole", "OLE (legacy Office)"),
    (b"hsqs", "squashfs", "SquashFS"),
    (b"\x53\xef", "ext", "ext2/3/4 superblock"),
    (b"NTFS    ", "ntfs", "NTFS boot sector"),
    (b"CD001", "iso", "ISO9660"),   # checked at 0x8001
]
FSTYPES = [
    (0x438, b"\x53\xef", "ext2/3/4"),
    (0x3, b"NTFS", "NTFS"),
    (0x52, b"FAT32", "FAT32"),
    (0x36, b"FAT", "FAT12/16"),
    (0x0, b"hsqs", "SquashFS"),
    (0x40, b"NXSB", "APFS"),
    (0x400, b"H+", "HFS+"),
    (0x0, b"LUKS", "LUKS"),
]
FS_MAGIC_AT = [(0x36, b"FAT"), (0x52, b"FAT32"), (0x3, b"NTFS    "),
               (0x438, b"\x53\xef"), (0x0, b"hsqs"), (0x20, b"NXSB"),
               (0x400, b"H+"), (0x0, b"LUKS\xba\xbe")]


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


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
# sizes of embedded files (so carvings are exact, not "rest of image")
# --------------------------------------------------------------------------
def pe_size(mm, off):
    try:
        if mm[off:off + 2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", mm, off + 0x3C)[0]
        pe = off + e_lfanew
        if mm[pe:pe + 4] != b"PE\0\0":
            return None
        nsec = struct.unpack_from("<H", mm, pe + 6)[0]
        opt_size = struct.unpack_from("<H", mm, pe + 20)[0]
        opt = pe + 24
        end = opt + opt_size + nsec * 40
        sec = opt + opt_size
        for i in range(nsec):
            raw_size, raw_ptr = struct.unpack_from("<II", mm, sec + i * 40 + 16)
            end = max(end, off + raw_ptr + raw_size)
        return end - off
    except (struct.error, IndexError):
        return None


def elf_size(mm, off):
    try:
        if mm[off:off + 4] != b"\x7fELF":
            return None
        is64 = mm[off + 4] == 2
        end = "<" if mm[off + 5] == 1 else ">"
        if is64:
            phoff = struct.unpack_from(end + "Q", mm, off + 32)[0]
            phentsize, phnum = struct.unpack_from(end + "HH", mm, off + 54)
        else:
            phoff = struct.unpack_from(end + "I", mm, off + 28)[0]
            phentsize, phnum = struct.unpack_from(end + "HH", mm, off + 42)
        total = 0
        for i in range(min(phnum, 100)):
            o = off + phoff + i * phentsize
            if is64:
                p_off, p_filesz = struct.unpack_from(end + "QQ", mm, o + 8)[0], \
                    struct.unpack_from(end + "Q", mm, o + 32)[0]
            else:
                p_off, p_filesz = struct.unpack_from(end + "II", mm, o + 4)[0], \
                    struct.unpack_from(end + "I", mm, o + 16)[0]
            total = max(total, p_off + p_filesz)
        return total or None
    except (struct.error, IndexError):
        return None


def zip_size(mm, off, limit=64 << 20):
    """End of the archive = EOCD end (+comment), searching forward."""
    end = min(len(mm), off + limit)
    pos = off
    last = None
    while True:
        i = mm.find(b"PK\x05\x06", pos, end)
        if i < 0:
            break
        try:
            clen = struct.unpack_from("<H", mm, i + 20)[0]
        except struct.error:
            break
        last = i + 22 + clen - off
        pos = i + 4
    return last


def gz_size(mm, off, limit=256 << 20):
    d = zlib.decompressobj(31)
    step = 1 << 20
    pos = off
    end = min(len(mm), off + limit)
    try:
        while pos < end:
            chunk = mm[pos:min(pos + step, end)]
            d.decompress(chunk)
            pos += len(chunk)
            if d.eof:
                return pos - off - len(d.unused_data)
        return None
    except zlib.error:
        return None


def marker_size(mm, off, marker, extra=0, limit=256 << 20):
    end = min(len(mm), off + limit)
    i = mm.find(marker, off, end)
    return (i + len(marker) + extra - off) if i >= 0 else None


def guess_size(mm, off, ext):
    if ext == "zip":
        return zip_size(mm, off)
    if ext == "gz":
        return gz_size(mm, off)
    if ext == "png":
        return marker_size(mm, off, b"IEND", 4)
    if ext == "jpg":
        return marker_size(mm, off, b"\xff\xd9", 0)
    if ext == "pdf":
        return marker_size(mm, off, b"%%EOF", 2)
    if ext == "exe":
        return pe_size(mm, off)
    if ext == "elf":
        return elf_size(mm, off)
    return None


# --------------------------------------------------------------------------
# partitions
# --------------------------------------------------------------------------
def mbr_table(mm):
    if len(mm) < 512 or mm[510:512] != b"\x55\xaa":
        return None
    parts = []
    for i in range(4):
        o = 0x1BE + i * 16
        status = mm[o]
        ptype = mm[o + 4]
        lba, sectors = struct.unpack_from("<II", mm, o + 8)
        if ptype:
            parts.append({"slot": i + 1, "boot": status == 0x80,
                          "type": "0x%02x" % ptype, "lba": lba,
                          "sectors": sectors, "offset": lba * 512,
                          "size": sectors * 512})
    return parts


def gpt_table(mm, parts):
    for p in parts or []:
        if p["type"] == "0xee":
            hdr = p["offset"]
            if mm[hdr:hdr + 8] != b"EFI PART":
                return None
            entries_lba = struct.unpack_from("<Q", mm, hdr + 72)[0]
            n_entries = struct.unpack_from("<I", mm, hdr + 80)[0]
            esize = struct.unpack_from("<I", mm, hdr + 84)[0]
            out = []
            base = entries_lba * 512
            for i in range(min(n_entries, 128)):
                e = base + i * esize
                if e + 128 > len(mm):
                    break
                tguid = mm[e:e + 16]
                if tguid == b"\x00" * 16:
                    continue
                first, last = struct.unpack_from("<QQ", mm, e + 32)
                name = mm[e + 56:e + 128].decode("utf-16-le", "ignore").rstrip("\x00")
                out.append({"slot": i + 1, "type": tguid.hex(), "name": name,
                            "lba": first, "sectors": last - first + 1,
                            "offset": first * 512, "size": (last - first + 1) * 512})
            return out
    return None


def fs_at(mm, offset):
    for rel, magic in FS_MAGIC_AT:
        try:
            if mm[offset + rel:offset + rel + len(magic)] == magic:
                return FS_MAGIC_AT_NAME.get(magic, magic.decode("latin-1"))
        except (IndexError, ValueError):
            pass
    return None


FS_MAGIC_AT_NAME = {b"FAT": "FAT12/16", b"FAT32": "FAT32", b"NTFS    ": "NTFS",
                    b"\x53\xef": "ext2/3/4", b"hsqs": "SquashFS",
                    b"NXSB": "APFS", b"H+": "HFS+", b"LUKS\xba\xbe": "LUKS"}


# --------------------------------------------------------------------------
# carving
# --------------------------------------------------------------------------
def carve(mm, outdir: Path, log: Log, min_size=32, max_carve=512 << 20,
          want=None, limit_hits=3000):
    carved = outdir / "carved"
    carved.mkdir(exist_ok=True)
    seen = set()
    items = []
    want = set(want) if want else None
    for magic, ext, friendly in SIGS:
        if want and ext not in want:
            continue
        pos = 0
        while len(items) < limit_hits:
            off = mm.find(magic, pos)
            if off < 0:
                break
            pos = off + 1
            # sanity: magic must be plausible at this offset
            size = guess_size(mm, off, ext)
            if size is None:
                # unknown end: take to EOF but cap, and skip if it is the whole image
                size = min(len(mm) - off, max_carve)
            if size < min_size:
                continue
            blob = mm[off:off + size]
            h = hashlib.sha256(blob).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            name = "%s_%08x_%s.%s" % (outdir.name[:20], off, h[:8], ext)
            dest = carved / name
            dest.write_bytes(blob)
            items.append({"path": str(dest), "type": friendly, "offset": off,
                          "size": size})
            log.p("  + %-55s off=%#x size=%s" % (name[:55], off, human(size)))
    (outdir / "carved.json").write_text(json.dumps(items, indent=1), encoding="utf-8")
    # scan carved text-ish files for flags
    for it in items:
        p = Path(it["path"])
        try:
            data = p.read_bytes()[:8 << 20]
        except OSError:
            continue
        for m in FLAG_RE.finditer(data):
            log.p("  [FLAG] %s  in %s" % (m.group(0).decode("latin-1"), p.name))
    return items


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------
def strings_scan(mm, outdir: Path, log: Log, chunk=8 << 20, minlen=4):
    found = []
    seen = set()
    overlap = 256
    pos = 0
    n = len(mm)
    while pos < n:
        buf = mm[pos:min(pos + chunk, n)]
        for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % minlen, buf):
            s = m.group(0).decode("latin-1")
            if s not in seen:
                seen.add(s)
                found.append((pos + m.start(), s))
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, buf):
            s = m.group(0).decode("utf-16-le", "ignore")
            if s and s not in seen:
                seen.add(s)
                found.append((pos + m.start(), s))
        if len(found) > 400000:
            break
        pos += chunk - overlap
    def score(item):
        off, s = item
        b = s.encode("latin-1", "ignore")
        v = 100 if FLAG_RE.search(b) else 0
        if re.search(rb"(?i)flag|secret|pass|token|key|admin", b):
            v += 20
        if b"{" in b and b"}" in b:
            v += 15
        return -v
    found.sort(key=score)
    with open(outdir / "strings.txt", "w", encoding="utf-8", errors="replace") as fh:
        for off, s in found:
            fh.write("%08x\t%s\n" % (off, s))
    log.p("  strings written: %d unique -> strings.txt" % len(found))
    for off, s in found[:25]:
        log.p("  %08x %s" % (off, s[:140]))
    return found


# --------------------------------------------------------------------------
# exif
# --------------------------------------------------------------------------
EXIF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation", 0x011A: "XResolution",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright",
    0x8769: "ExifIFD", 0x8825: "GPSIFD", 0x9286: "UserComment",
    0x9003: "DateTimeOriginal", 0x010E: "ImageDescription", 0x0100: "ImageWidth",
    0x0101: "ImageHeight", 0xA002: "PixelX", 0xA003: "PixelY",
}
GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef",
            4: "GPSLongitude", 5: "GPSAltitudeRef", 6: "GPSAltitude",
            7: "GPSTimeStamp", 29: "GPSDateStamp"}


def tiff_ifd(data, base, off, out, depth=0, tagmap=None, end="<"):
    tagmap = tagmap or EXIF_TAGS
    try:
        count = struct.unpack_from(end + "H", data, base + off)[0]
    except struct.error:
        return
    for i in range(min(count, 256)):
        e = base + off + 2 + i * 12
        try:
            tag, typ, cnt = struct.unpack_from(end + "HHI", data, e)
        except struct.error:
            return
        size_map = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 11: 4, 12: 8}
        unit = size_map.get(typ, 1)
        total = unit * cnt
        vpos = e + 8 if total <= 4 else base + struct.unpack_from(end + "I", data, e + 8)[0]
        raw = data[vpos:vpos + total]
        if typ == 2:
            val = raw.split(b"\x00")[0].decode("latin-1", "replace")
        elif typ in (5, 10):
            nums = struct.unpack_from(end + ("II" if typ == 5 else "ii") * min(cnt, 4), data, vpos)
            val = " ".join("%d/%d" % (nums[k], nums[k + 1]) for k in range(0, len(nums), 2))
        elif typ in (3, 4, 9):
            fmt = {3: "H", 4: "I", 9: "i"}[typ]
            nums = struct.unpack_from(end + fmt * min(cnt, 8), data, vpos)
            val = ",".join(str(x) for x in nums)
        else:
            val = raw[:80].hex()
        name = tagmap.get(tag, "tag_0x%04x" % tag)
        out[name] = val
        if tag in (0x8769, 0x8825) and depth < 2:
            sub = struct.unpack_from(end + "I", data, e + 8)[0]
            tiff_ifd(data, base, sub, out, depth + 1,
                     EXIF_TAGS if tag == 0x8769 else GPS_TAGS, end)


def exif(path: Path, outdir: Path, log: Log):
    data = path.read_bytes()
    log.hdr("EXIF / METADATA  %s" % path.name)
    tags = {}
    if data[:2] == b"\xff\xd8":
        i = 2
        while i < len(data) - 4:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            seglen = struct.unpack_from(">H", data, i + 2)[0]
            seg = data[i + 4:i + 2 + seglen]
            if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
                tiff = seg[6:]
                end = "<" if tiff[:2] == b"II" else ">"
                ifd0 = struct.unpack_from(end + "I", tiff, 4)[0]
                tiff_ifd(tiff, 0, ifd0, tags, end=end)
                break
            if marker == 0xDA:
                break
            i += 2 + seglen
        if b"http" in data[:1 << 20]:
            for m in re.finditer(rb"http[s]?://[^\x00\"'<>\s]{6,200}", data[:1 << 20]):
                tags.setdefault("XMP_url", m.group(0).decode("latin-1"))
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        i = 8
        while i + 8 < len(data):
            length = struct.unpack_from(">I", data, i)[0]
            ctype = data[i + 4:i + 8]
            body = data[i + 8:i + 8 + length]
            if ctype in (b"tEXt", b"iTXt", b"zTXt"):
                k, _, v = body.partition(b"\x00")
                if ctype == b"zTXt":
                    try:
                        v = zlib.decompress(v[1:])
                    except zlib.error:
                        pass
                tags["png:" + k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")[:300]
            if ctype == b"eXIf":
                end = "<" if body[:2] == b"II" else ">"
                tiff_ifd(body, 0, struct.unpack_from(end + "I", body, 4)[0], tags, end=end)
            if ctype == b"IEND":
                if i + 12 < len(data):
                    log.p("  [!] %d bytes after IEND (appended data)" % (len(data) - (i + 12)))
                    (outdir / "appended_after_iend.bin").write_bytes(data[i + 12:])
                break
            i += 12 + length
    for k, v in tags.items():
        log.p("  %-22s %s" % (k, str(v)[:160]))
    if not tags:
        log.p("  (no EXIF/metadata found)")
    for k, v in tags.items():
        for m in FLAG_RE.finditer(str(v).encode("latin-1", "ignore")):
            log.p("  [FLAG] %s (in %s)" % (m.group(0).decode("latin-1"), k))
    (outdir / "exif.json").write_text(json.dumps(tags, indent=1, default=str), encoding="utf-8")
    log.save(outdir / "exif.txt")
    return tags


# --------------------------------------------------------------------------
# pdf
# --------------------------------------------------------------------------
def pdf_scan(path: Path, outdir: Path, log: Log):
    data = path.read_bytes()
    log.hdr("PDF  %s (%s)" % (path.name, human(len(data))))
    text = data.decode("latin-1", "replace")
    objs = re.findall(r"(\d+)\s+(\d+)\s+obj(.*?)endobj", text, re.S)
    log.p("  objects        : %d" % len(objs))
    for kw in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
               "/URI", "/RichMedia", "/XFA", "/GoToR", "/SubmitForm"):
        n = text.count(kw)
        if n:
            log.p("  %-14s : %d" % (kw, n))
    streams = re.findall(rb"stream\r?\n(.*?)endstream", data, re.S)
    log.p("  streams        : %d" % len(streams))
    dumped = outdir / "pdf_streams"
    dumped.mkdir(exist_ok=True)
    hits = 0
    for i, s in enumerate(streams):
        out = None
        for fn in (lambda b: zlib.decompress(b),
                   lambda b: zlib.decompress(b, -15),
                   lambda b: __import__("base64").a85decode(b, adobe=True),
                   lambda b: __import__("base64").b64decode(b, validate=False)):
            try:
                out = fn(s.strip())
                if out:
                    break
            except Exception:
                continue
        if out is None:
            out = s
            if sum(1 for b in out[:200] if 32 <= b < 127) < len(out[:200]) * 0.7:
                continue
        (dumped / ("stream_%03d.bin" % i)).write_bytes(out)
        hits += 1
        for m in FLAG_RE.finditer(out):
            log.p("  [FLAG] stream %d: %s" % (i, m.group(0).decode("latin-1")))
    log.p("  decoded streams: %d -> pdf_streams/" % hits)
    fonts = re.findall(r"/BaseFont\s*/([A-Za-z0-9+\-]+)", text)
    if fonts:
        log.p("  fonts          : %s" % ", ".join(sorted(set(fonts))[:10]))
    log.save(outdir / "pdf.txt")
    return {"objects": len(objs), "streams": hits}


# --------------------------------------------------------------------------
# zip / office
# --------------------------------------------------------------------------
def zipmeta(path: Path, outdir: Path, log: Log):
    log.hdr("ARCHIVE METADATA  %s" % path.name)
    if not zipfile.is_zipfile(path):
        log.p("  not a zip archive (nothing to report)")
        log.save(outdir / "zipmeta.txt")
        return []
    details = []
    with zipfile.ZipFile(path) as zf:
        if zf.comment:
            c = zf.comment.decode("latin-1", "replace")
            log.p("  [COMMENT] %s" % c[:500])
            details.append({"comment": c})
        for info in zf.infolist():
            d = {"name": info.filename, "size": info.file_size,
                 "csize": info.compress_size, "date": str(info.date_time),
                 "crc": "%08x" % info.CRC, "encrypted": bool(info.flag_bits & 1),
                 "method": info.compress_type, "extra": info.extra.hex()}
            details.append(d)
            if info.comment:
                log.p("  [ENTRY COMMENT] %s: %s" % (info.filename, info.comment[:200]))
        # office text
        names = zf.namelist()
        if any(n.startswith("word/") or n.startswith("docProps/") for n in names):
            for target in ("docProps/core.xml", "docProps/app.xml", "word/document.xml",
                           "word/comments.xml", "word/footnotes.xml", "xl/sharedStrings.xml"):
                if target in names:
                    try:
                        xml = zf.read(target)
                    except Exception:
                        continue
                    txt = " ".join(ElementTree.fromstring(xml).itertext())
                    txt = re.sub(r"\s+", " ", txt).strip()
                    if txt:
                        log.p("  %-24s %s" % (target, txt[:400]))
                        for m in FLAG_RE.finditer(txt.encode("utf-8", "ignore")):
                            log.p("  [FLAG] %s (in %s)" % (m.group(0).decode("latin-1"), target))
        # nested archives / raw text
        for info in zf.infolist():
            if info.file_size > (32 << 20):
                continue
            try:
                blob = zf.read(info)
            except Exception:
                continue
            for m in FLAG_RE.finditer(blob):
                log.p("  [FLAG] %s (in %s)" % (m.group(0).decode("latin-1"), info.filename))
            if blob[:4] == b"PK\x03\x04":
                nested = outdir / ("nested_" + re.sub(r"[^A-Za-z0-9_.-]", "_", info.filename) + ".zip")
                nested.write_bytes(blob)
                log.p("  nested archive -> %s" % nested.name)
            for m in BASE64_RUN.finditer(blob):
                try:
                    dec = __import__("base64").b64decode(m.group(0) + b"=" * (-len(m.group(0)) % 4))
                except Exception:
                    continue
                if FLAG_RE.search(dec):
                    log.p("  [FLAG b64] %s (in %s)" % (FLAG_RE.search(dec).group(0).decode("latin-1"), info.filename))
    log.p("  entries: %d" % len(details))
    (outdir / "zipmeta.json").write_text(json.dumps(details, indent=1), encoding="utf-8")
    log.save(outdir / "zipmeta.txt")
    return details


# --------------------------------------------------------------------------
# layout
# --------------------------------------------------------------------------
def layout(mm, log: Log, block=4096, max_blocks=200000):
    n = len(mm)
    rows = []
    nonempty = 0
    for off in range(0, min(n, block * max_blocks), block):
        chunk = mm[off:off + block]
        e = entropy(chunk)
        pr = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13)) / len(chunk)
        rows.append((off, e, pr))
        if pr < 0.98:
            nonempty += 1
    text_blocks = [r for r in rows if r[2] > 0.95 and r[1] < 5.5]
    high = [r for r in rows if r[1] > 7.5]
    zero = [r for r in rows if r[1] == 0.0]
    log.p("  blocks          : %d x %d bytes" % (len(rows), block))
    log.p("  text-like blocks: %d" % len(text_blocks))
    log.p("  high entropy    : %d (>7.5, compressed/encrypted/packed)" % len(high))
    log.p("  all-zero        : %d (slack / unallocated)" % len(zero))
    if text_blocks:
        log.p("  first text block: %#x" % text_blocks[0][0])
    if high:
        log.p("  first high block: %#x" % high[0][0])
    return {"blocks": len(rows), "text": len(text_blocks),
            "high": len(high), "zero": len(zero)}


# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------
def open_mm(path: Path):
    f = open(path, "rb")
    try:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    except ValueError:
        return f, None
    return f, mm


def triage(path: Path, outdir: Path, log: Log, deep=True):
    log.hdr("FORENSICS TRIAGE  %s" % path.name)
    log.p("  size     : %s" % human(path.stat().st_size))
    log.p("  sha256   : %s" % hashlib.sha256(path.read_bytes()[:64 << 20]).hexdigest())
    f, mm = open_mm(path)
    if mm is None:
        log.p("  [!] empty file")
        f.close()
        return {}
    try:
        head = mm[:4096]
        kind = "raw"
        for magic, ext, friendly in SIGS:
            if head.startswith(magic):
                kind = friendly
                break
        if head[0x8001:0x8006] == b"CD001":
            kind = "ISO9660 image"
        parts = mbr_table(mm)
        if parts:
            kind = "MBR disk image"
        log.p("  type     : %s" % kind)
        gpt = gpt_table(mm, parts) if parts else None
        if parts:
            log.p("")
            log.p("  -- MBR partition table --")
            for p in parts:
                fs = fs_at(mm, p["offset"]) if p["offset"] < len(mm) else None
                log.p("  #%d type=%-4s off=%#-12x size=%-10s fs=%s" % (
                    p["slot"], p["type"], p["offset"], human(p["size"]), fs or "?"))
            if gpt:
                log.p("")
                log.p("  -- GPT entries --")
                for g in gpt:
                    fs = fs_at(mm, g["offset"]) if g["offset"] < len(mm) else None
                    log.p("  #%d %-30s off=%#-12x size=%-10s fs=%s" % (
                        g["slot"], g["name"] or "(unnamed)", g["offset"],
                        human(g["size"]), fs or "?"))
        fs0 = fs_at(mm, 0)
        if fs0 and not parts:
            log.p("  filesystem: %s at offset 0" % fs0)
        if deep:
            log.p("")
            log.p("  -- layout --")
            layout(mm, log)
        return {"kind": kind, "partitions": parts, "gpt": gpt}
    finally:
        try:
            mm.close()
        finally:
            f.close()


def all_cmd(path: Path, outdir: Path, log: Log, do_carve=True):
    info = triage(path, outdir, log)
    f, mm = open_mm(path)
    if mm is None:
        return info
    try:
        log.p("")
        log.p("  -- strings --")
        strings_scan(mm, outdir, log)
        if do_carve:
            log.p("")
            log.p("  -- carving --")
            carve(mm, outdir, log)
    finally:
        mm.close()
        f.close()
    if path.suffix.lower() in (".pdf",):
        pdf_scan(path, outdir, log)
    if path.suffix.lower() in (".jpg", ".jpeg", ".png", ".tif", ".tiff"):
        exif(path, outdir, log)
    if zipfile.is_zipfile(path):
        zipmeta(path, outdir, log)
    log.save(outdir / "report.txt")
    return info


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Forensics / carving toolkit")
    ap.add_argument("command", choices=("triage", "carve", "strings", "layout",
                                        "exif", "pdf", "zipmeta", "all"))
    ap.add_argument("target")
    ap.add_argument("-o", "--out")
    ap.add_argument("--types", help="carve only these extensions (comma list)")
    ap.add_argument("--min-size", type=int, default=32)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    path = Path(args.target)
    if not path.exists():
        sys.exit("no such file: %s" % path)
    outdir = Path(args.out or (path.stem + "_forensics"))
    outdir.mkdir(parents=True, exist_ok=True)
    log = Log()

    if args.command == "all":
        info = all_cmd(path, outdir, log)
        if args.json:
            print(json.dumps(info, indent=1, default=str))
        return 0

    if args.command == "triage":
        info = triage(path, outdir, log)
        log.save(outdir / "report.txt")
        if args.json:
            print(json.dumps(info, indent=1, default=str))
        return 0

    if args.command == "exif":
        r = exif(path, outdir, log)
        if args.json:
            print(json.dumps(r, indent=1, default=str))
        return 0

    if args.command == "pdf":
        r = pdf_scan(path, outdir, log)
        if args.json:
            print(json.dumps(r, indent=1))
        return 0

    if args.command == "zipmeta":
        r = zipmeta(path, outdir, log)
        if args.json:
            print(json.dumps(r, indent=1, default=str))
        return 0

    f, mm = open_mm(path)
    if mm is None:
        return 1
    try:
        if args.command == "carve":
            want = [x.strip() for x in args.types.split(",")] if args.types else None
            items = carve(mm, outdir, log, args.min_size, want=want)
            log.save(outdir / "carve.txt")
            if args.json:
                print(json.dumps(items, indent=1))
        elif args.command == "strings":
            strings_scan(mm, outdir, log)
        elif args.command == "layout":
            layout(mm, log)
            log.save(outdir / "layout.txt")
    finally:
        mm.close()
        f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
