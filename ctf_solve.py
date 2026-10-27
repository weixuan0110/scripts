#!/usr/bin/env python3
"""ctf_solve.py -- one entry point for every challenge category.

  python ctf_solve.py mystery_file          # detect type, run the right tools
  python ctf_solve.py capture.pcap
  python ctf_solve.py app.apk
  python ctf_solve.py app.ipa
  python ctf_solve.py disk.img
  python ctf_solve.py crackme.exe
  python ctf_solve.py photo.png
  python ctf_solve.py nested.zip
  python ctf_solve.py doctor               # what is installed / what is missing
  python ctf_solve.py --list               # routing table

Each module stays usable on its own:
  ctf_pcap.py    network captures (DNS/HTTP/TLS/ICMP tunnels/USB HID/carving)
  re_solve.py    binaries: triage -> decompile (Ghidra/IDA/CFR/ILSpy) -> patch/rebuild
  ctf_apk.py     APK: triage/decompile/rebuild/sign/install
  ctf_ipa.py     IPA: triage/class dump/decompile/patch/repack
  ctf_forensics.py  disk images, carving, EXIF, PDF, zip/office metadata
  ctf_stegano.py    PNG/BMP/WAV LSB, bitplanes, chunks, zero-width, whitespace
  ctf_crypto.py     encoding chains, XOR, RSA, hashes, classical ciphers
  ctf_misc.py       unknown files, polyglots, nested archives, zip cracking, brainfuck
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable

FLAG_RE = re.compile(
    r"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    r"pctf|hitcon|idek|sekai|buckeye|utflag|lactf|byuctf|tjctf|damctf|sctf|"
    r"justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    r"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)

MODULES = ["ctf_pcap.py", "re_solve.py", "ctf_apk.py", "ctf_ipa.py",
           "ctf_forensics.py", "ctf_stegano.py", "ctf_crypto.py", "ctf_misc.py"]


# --------------------------------------------------------------------------
def classify(path: Path) -> str:
    """Category routing: pcap | apk | ipa | native | java | dotnet | pyc |
       disk | image | audio | archive | pdf | text."""
    head = path.read_bytes()[:16]
    ext = path.suffix.lower()
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                    b"\x0a\x0d\x0d\x0a") or ext in (".pcap", ".pcapng", ".cap", ".erf"):
        return "pcap"
    if ext in (".apk", ".xapk", ".apks", ".aab"):
        return "apk"
    if ext == ".ipa":
        return "ipa"
    if head[:4] == b"\x7fELF" or head[:2] == b"MZ" or \
            head[:4] in (b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        if head[:2] == b"MZ":
            try:
                import re_solve
                if re_solve.classify(path).get("kind") == "dotnet":
                    return "dotnet"
            except Exception:
                pass
        return "native"
    if ext == ".jar" or head[:4] == b"PK\x03\x04" and ext in (".jar", ".class"):
        return "java"
    if head[:4] == b"dex\n" or ext == ".dex":
        return "android-dex"
    if ext == ".pyc" or (len(head) >= 4 and head[2:4] == b"\r\n"):
        return "pyc"
    if ext in (".img", ".dd", ".raw", ".iso", ".dmg", ".vhd", ".vmdk", ".e01",
               ".001", ".ad1", ".mem", ".vmem"):
        return "disk"
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or \
            head[:4] in (b"GIF8", b"BM") or ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff"):
        return "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE" or ext in (".wav", ".flac", ".mp3", ".ogg"):
        return "audio"
    if ext == ".pdf" or head[:5] == b"%PDF-":
        return "pdf"
    if head[:4] == b"PK\x03\x04" or ext in (".zip", ".gz", ".tar", ".7z", ".rar",
                                            ".bz2", ".xz", ".tgz", ".docx", ".xlsx", ".pptx"):
        return "archive"
    try:
        text = path.read_bytes()[:4096].decode("utf-8")
        if text and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.9:
            return "text"
    except (UnicodeDecodeError, ZeroDivisionError):
        pass
    return "unknown"


def run_step(label: str, cmd, findings: list, quiet=False):
    print("\n$ %s" % " ".join(str(c) for c in cmd), flush=True)
    try:
        p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                           errors="replace", timeout=7200)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        print("  [!] timeout")
        return 124
    for m in FLAG_RE.finditer(out):
        if m.group(0) not in findings:
            findings.append(m.group(0))
    if not quiet:
        for line in out.splitlines():
            print(line)
    print("  -> rc=%d, %d line(s)" % (p.returncode, len(out.splitlines())))
    return p.returncode


def plan(category: str, target: Path, out: Path):
    """Return the module invocations for a category."""
    m = lambda name: [PY, str(HERE / name)]
    steps = []
    if category == "pcap":
        steps.append(("network triage", m("ctf_pcap.py") + [target, "-o", out, "--json"]))
    elif category == "apk":
        steps.append(("apk triage", m("ctf_apk.py") + ["triage", target, "-o", out]))
        steps.append(("apk decompile", m("ctf_apk.py") + ["decompile", target, "-o", out]))
    elif category == "ipa":
        steps.append(("ipa triage", m("ctf_ipa.py") + ["triage", target, "-o", out]))
        steps.append(("ipa decompile", m("ctf_ipa.py") + ["decompile", target, "-o", out / "dec"]))
    elif category == "java":
        steps.append(("java decompile", m("re_solve.py") + ["decompile", target, "-o", out]))
    elif category == "android-dex":
        steps.append(("dex strings", m("ctf_misc.py") + ["scan", target, "-o", out]))
        steps.append(("dex decompile hint",
                      [PY, "-c", "print('use: java -jar tools/dex-tools*/d2j-dex2jar.bat "
                                 + str(target) + " -o out.jar && java -jar tools/cfr.jar out.jar')"]))
    elif category in ("native", "dotnet", "pyc"):
        steps.append(("re triage", m("re_solve.py") + ["triage", target, "-o", out]))
        steps.append(("re decompile", m("re_solve.py") + ["decompile", target, "-o", out,
                                                          "--engine", "auto"]))
    elif category == "disk":
        steps.append(("forensics", m("ctf_forensics.py") + ["all", target, "-o", out]))
    elif category == "image":
        steps.append(("stegano", m("ctf_stegano.py") + ["analyze", target, "-o", out]))
        steps.append(("metadata", m("ctf_forensics.py") + ["exif", target, "-o", out]))
    elif category == "audio":
        steps.append(("audio stegano", m("ctf_stegano.py") + ["analyze", target, "-o", out]))
        steps.append(("strings", m("ctf_misc.py") + ["scan", target, "-o", out]))
    elif category == "pdf":
        steps.append(("pdf", m("ctf_forensics.py") + ["all", target, "-o", out]))
    elif category == "archive":
        steps.append(("archive", m("ctf_misc.py") + ["all", target, "-o", out]))
        import zipfile
        if zipfile.is_zipfile(target):
            steps.append(("zip metadata", m("ctf_forensics.py") + ["zipmeta", target, "-o", out]))
    elif category == "text":
        steps.append(("encoding chain", m("ctf_crypto.py") + ["decode", "-f", target,
                                                              "--depth", "6"]))
        steps.append(("scan", m("ctf_misc.py") + ["scan", target, "-o", out]))
    else:  # unknown
        steps.append(("sniff", m("ctf_misc.py") + ["sniff", target, "-o", out]))
        steps.append(("scan", m("ctf_misc.py") + ["scan", target, "-o", out]))
        steps.append(("strings+carve", m("ctf_forensics.py") + ["all", target, "-o", out]))
        steps.append(("encoding chain", m("ctf_crypto.py") + ["decode", "-f", target]))
    return steps


def doctor():
    import shutil
    rows = []
    def add(name, path, note=""):
        rows.append((name, str(path) if path else "MISSING", note))
    add("python", sys.executable, sys.version.split()[0])
    for mod in ("scapy", "keystone", "capstone", "pefile"):
        try:
            __import__(mod)
            add(mod, "ok")
        except ImportError:
            add(mod, "missing", "pip install %s" % mod)
    for exe in ("tshark", "java", "javac", "jar", "dotnet", "gcc", "clang",
                "objdump", "readelf", "7z", "upx", "adb", "binwalk", "exiftool",
                "volatility3", "ash", "binwalk", "apktool", "jadx"):
        add(exe, shutil.which(exe))
    for label, pat in (
        ("ghidra", "*/ghidra*/support/analyzeHeadless.bat"),
        ("ida", "*/IDA*/idat.exe"),
        ("cfr", "tools/cfr.jar"),
        ("dex2jar", "tools/dex-tools*/d2j-dex2jar.bat"),
        ("ilspycmd", "tools/ilspycmd/tools/net*/any/ilspycmd.dll"),
    ):
        import glob
        hits = glob.glob(str(HERE / pat))
        add(label, hits[0] if hits else None)
    width = max(len(r[0]) for r in rows) + 2
    print("%-*s %-58s %s" % (width, "component", "path", "note"))
    print("-" * 100)
    for name, path, note in rows:
        print("%-*s %-58s %s" % (width, name, path, note))
    print("\nMissing native tools degrade gracefully; each module prints what it skipped.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="CTF solver front-end")
    ap.add_argument("target", nargs="?")
    ap.add_argument("-o", "--out")
    ap.add_argument("--category", choices=("pcap", "apk", "ipa", "native", "dotnet",
                                           "pyc", "java", "android-dex", "disk",
                                           "image", "audio", "pdf", "archive",
                                           "text", "unknown"))
    ap.add_argument("--quiet", action="store_true", help="only the flag summary")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("command", nargs="?", default=None,
                    choices=("doctor",), help="doctor | (omit for analysis)")
    args = ap.parse_args(argv)

    if args.command == "doctor":
        doctor()
        return 0
    if args.list:
        print("category    -> module(s)")
        for row in (
            ("pcap", "ctf_pcap.py"), ("apk", "ctf_apk.py"),
            ("ipa", "ctf_ipa.py"), ("native/dotnet/pyc/java", "re_solve.py"),
            ("disk", "ctf_forensics.py"), ("image/audio", "ctf_stegano.py"),
            ("archive/text/unknown", "ctf_misc.py"), ("encodings/crypto", "ctf_crypto.py"),
        ):
            print("  %-24s %s" % row)
        return 0
    if not args.target:
        ap.print_help()
        return 1

    target = Path(args.target)
    if not target.exists():
        sys.exit("no such file: %s" % target)
    category = args.category or classify(target)
    out = Path(args.out or ("%s_ctf" % target.stem))
    out.mkdir(parents=True, exist_ok=True)

    print("=" * 78)
    print("  %s  ->  category=%s" % (target, category))
    print("  output: %s" % out)
    print("=" * 78)

    findings = []
    for label, cmd in plan(category, target.resolve(), out.resolve()):
        if args.quiet:
            print("  running %s ..." % label, flush=True)
        run_step(label, cmd, findings, quiet=args.quiet)

    # harvest flags from every report produced
    for f in out.rglob("*"):
        if f.is_file() and f.suffix in (".txt", ".json", ".md", ".csv"):
            try:
                for m in FLAG_RE.finditer(f.read_text(encoding="utf-8", errors="ignore")):
                    if m.group(0) not in findings:
                        findings.append(m.group(0))
            except OSError:
                pass

    print("\n" + "=" * 78)
    if findings:
        print("  FLAGS FOUND (%d)" % len(set(findings)))
        for f in dict.fromkeys(findings):
            print("    " + f)
    else:
        print("  no flag pattern matched automatically.")
        print("  check the reports: %s" % out)
    print("=" * 78)
    (out / "flags.txt").write_text("\n".join(dict.fromkeys(findings)) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
