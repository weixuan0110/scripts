#!/usr/bin/env python3
"""ctf_ipa.py -- iOS challenge toolkit (IPA / .app bundle).

  python ctf_ipa.py triage    app.ipa
  python ctf_ipa.py decompile app.ipa [--engine auto|ghidra|ida]
  python ctf_ipa.py classes   app.ipa
  python ctf_ipa.py patch     app.ipa --va 0x100003F00 --asm "mov w0, #1; ret"
  python ctf_ipa.py repack    app.ipa -o out            # .app -> .ipa again
  python ctf_ipa.py all       app.ipa

What is possible on each host:
  * triage / class dump / strings / secrets: everywhere (pure python).
  * decompile: Mach-O goes through Ghidra or IDA (re_solve.py) -- both load arm64.
  * patch: assemble + write into the Mach-O, then repack the IPA.
  * install: needs a *signed* app; signing (ldid/codesign) requires macOS or a
    jailbroken device, so this tool repacks and tells you the exact command.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

IS_WIN = os.name == "nt"
CNW = 0x08000000 if IS_WIN else 0
HERE = Path(__file__).resolve().parent

LC = {
    0x1: "LC_SEGMENT", 0x19: "LC_SEGMENT_64", 0x2: "LC_SYMTAB",
    0x2A: "LC_SOURCE_VERSION", 0x1B: "LC_UUID", 0xC: "LC_LOAD_DYLIB",
    0x1D: "LC_CODE_SIGNATURE", 0x21: "LC_ENCRYPTION_INFO",
    0x2C: "LC_ENCRYPTION_INFO_64", 0x32: "LC_BUILD_VERSION",
    0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_VERSION_MIN_MACOSX",
    0x80000022: "LC_DYLD_INFO_ONLY", 0x22: "LC_DYLD_INFO",
    0x1E: "LC_SEGMENT_SPLIT_INFO", 0x26: "LC_FUNCTION_STARTS",
    0x1C: "LC_RPATH", 0x8000001C: "LC_RPATH", 0x6: "LC_SYMSEG",
    0x1A: "LC_DYSYMTAB", 0x80000028: "LC_MAIN",
}
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS",
             6: "macCatalyst", 7: "iOSSimulator", 8: "tvOSSimulator",
             9: "watchOSSimulator", 10: "driverKit", 11: "visionOS"}

FLAG_RE = re.compile(
    rb"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    rb"pctf|hitcon|idek|sekai|buckeye|utflag|lactf|byuctf|tjctf|damctf|sctf|"
    rb"justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    rb"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
SECRETS = [
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("aws_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("firebase", re.compile(rb"https://[a-z0-9-]+\.firebase(?:io|app)\.com")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("basic_auth", re.compile(rb"(?:https?|ftp)://[^/\s:@]+:[^/\s@]+@[^/\s]+")),
    ("api_secret", re.compile(rb"(?i)(?:api[_-]?key|secret|client_secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{12,})")),
]
URL_RE = re.compile(rb"https?://[^\s\"'<>\\]{6,300}")


def run(cmd, cwd=None, timeout=900):
    try:
        p = subprocess.run([str(c) for c in cmd], cwd=str(cwd) if cwd else None,
                           capture_output=True, timeout=timeout, creationflags=CNW)
        return p.returncode, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    except FileNotFoundError as exc:
        return 127, "not found: %s" % exc
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


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
# Mach-O
# --------------------------------------------------------------------------
def macho_info(path: Path):
    """Parse thin or fat Mach-O. Returns dict with slices, sections, flags."""
    data = path.read_bytes()
    if len(data) < 32:
        return None
    magic = struct.unpack(">I", data[:4])[0]
    out = {"slices": [], "fat": False}
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        out["fat"] = True
        n = struct.unpack(">I", data[4:8])[0]
        wide = magic == 0xCAFEBABF
        for i in range(min(n, 32)):
            if wide:
                off = struct.unpack(">Q", data[8 + i * 32 + 8:8 + i * 32 + 16])[0]
                size = struct.unpack(">Q", data[8 + i * 32 + 16:8 + i * 32 + 24])[0]
            else:
                off = struct.unpack(">I", data[8 + i * 20 + 8:8 + i * 20 + 12])[0]
                size = struct.unpack(">I", data[8 + i * 20 + 12:8 + i * 20 + 16])[0]
            sl = parse_thin(data[off:off + size], off)
            if sl:
                out["slices"].append(sl)
        return out
    sl = parse_thin(data, 0)
    if sl:
        out["slices"].append(sl)
        return out
    return None


def parse_thin(data: bytes, base: int):
    if len(data) < 32:
        return None
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xFEEDFACF, 0xFEEDFACE):
        magic_be = struct.unpack(">I", data[:4])[0]
        if magic_be not in (0xFEEDFACF, 0xFEEDFACE):
            return None
        end = ">"
        magic = magic_be
    else:
        end = "<"
    is64 = magic == 0xFEEDFACF
    cputype = struct.unpack(end + "I", data[4:8])[0]
    cpusub = struct.unpack(end + "I", data[8:12])[0]
    filetype = struct.unpack(end + "I", data[12:16])[0]
    ncmds = struct.unpack(end + "I", data[16:20])[0]
    sizeofcmds = struct.unpack(end + "I", data[20:24])[0]
    arch = {0x0100000C: "arm64", 0x01000007: "x86_64", 12: "arm",
            7: "x86", 0x01000012: "arm64e"}.get(cputype, hex(cputype))
    info = {"arch": arch, "is64": is64, "filetype": filetype, "fileoff_base": base,
            "sections": [], "dylibs": [], "uuid": None, "cryptid": None,
            "minos": None, "platform": None, "ncmds": ncmds}
    off = 32 if is64 else 28
    try:
        for _ in range(min(ncmds, 2000)):
            cmd, cmdsize = struct.unpack(end + "II", data[off:off + 8])
            if cmdsize < 8 or off + cmdsize > len(data):
                break
            if cmd == 0x19 and is64:                       # LC_SEGMENT_64
                seg = data[off + 8:off + 24].rstrip(b"\x00").decode("latin-1", "replace")
                fileoff = struct.unpack(end + "Q", data[off + 40:off + 48])[0]
                nsects = struct.unpack(end + "I", data[off + 64:off + 68])[0]
                so = off + 72
                for _s in range(min(nsects, 200)):
                    sect = data[so:so + 16].rstrip(b"\x00").decode("latin-1", "replace")
                    segn = data[so + 16:so + 32].rstrip(b"\x00").decode("latin-1", "replace")
                    addr = struct.unpack(end + "Q", data[so + 32:so + 40])[0]
                    size = struct.unpack(end + "Q", data[so + 40:so + 48])[0]
                    soff = struct.unpack(end + "I", data[so + 48:so + 52])[0]
                    info["sections"].append({"sect": sect, "seg": segn, "addr": addr,
                                             "size": size, "offset": soff})
                    so += 80
            elif cmd == 0x1 and not is64:                  # LC_SEGMENT
                nsects = struct.unpack(end + "I", data[off + 48:off + 52])[0]
                so = off + 56
                for _s in range(min(nsects, 200)):
                    sect = data[so:so + 16].rstrip(b"\x00").decode("latin-1", "replace")
                    segn = data[so + 16:so + 32].rstrip(b"\x00").decode("latin-1", "replace")
                    addr = struct.unpack(end + "I", data[so + 32:so + 36])[0]
                    size = struct.unpack(end + "I", data[so + 36:so + 40])[0]
                    soff = struct.unpack(end + "I", data[so + 40:so + 44])[0]
                    info["sections"].append({"sect": sect, "seg": segn, "addr": addr,
                                             "size": size, "offset": soff})
                    so += 68
            elif cmd in (0x2C, 0x21):                      # encryption info
                info["cryptid"] = struct.unpack(end + "I", data[off + 16:off + 20])[0]
            elif cmd == 0x1B:                              # LC_UUID
                u = data[off + 8:off + 24]
                info["uuid"] = "%s-%s-%s-%s-%s" % (
                    u[:4].hex(), u[4:6].hex(), u[6:8].hex(), u[8:10].hex(), u[10:].hex())
            elif cmd == 0x32:                              # LC_BUILD_VERSION
                info["platform"] = PLATFORMS.get(
                    struct.unpack(end + "I", data[off + 8:off + 12])[0], "?")
                info["minos"] = fmt_version(struct.unpack(end + "I", data[off + 12:off + 16])[0])
            elif cmd == 0x25:                              # LC_VERSION_MIN_IPHONEOS
                info["platform"] = "iOS"
                info["minos"] = fmt_version(struct.unpack(end + "I", data[off + 8:off + 12])[0])
            elif cmd in (0xC, 0x8000001F, 0x8000001C):     # dylib / weak / rpath
                nameoff = struct.unpack(end + "I", data[off + 8:off + 12])[0]
                raw = data[off + nameoff:off + cmdsize].split(b"\x00")[0]
                info["dylibs"].append(raw.decode("latin-1", "replace"))
            off += cmdsize
    except struct.error:
        pass
    return info


def fmt_version(v):
    return "%d.%d.%d" % ((v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)


# --------------------------------------------------------------------------
# bundle
# --------------------------------------------------------------------------
def extract(ipa: Path, outdir: Path, log: Log):
    target = outdir / "app"
    if target.exists():
        return target
    if ipa.is_dir():
        shutil.copytree(ipa, target)
        return target
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ipa) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            dest = target / name
            if name.endswith("/"):
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return target


def find_app(root: Path):
    if root.suffix == ".app" and (root / "Info.plist").exists():
        return root
    for p in root.rglob("*.app"):
        if (p / "Info.plist").exists():
            return p
    return None


def load_plist(path: Path):
    try:
        return plistlib.loads(path.read_bytes())
    except Exception:
        return {}


def provision_info(app: Path):
    p = app / "embedded.mobileprovision"
    if not p.exists():
        return {}
    raw = p.read_bytes()
    start = raw.find(b"<?xml")
    end = raw.find(b"</plist>", start)
    if start < 0 or end < 0:
        return {"format": "CMS (no plist found)"}
    try:
        return plistlib.loads(raw[start:end + 8])
    except Exception:
        return {}


def scan_files(app: Path, outdir: Path):
    """flags, secrets, urls, interesting files across the bundle."""
    flags, secrets, urls, strings = {}, {}, {}, []
    seen = set()
    for f in app.rglob("*"):
        if not f.is_file():
            continue
        try:
            if f.stat().st_size > (32 << 20):
                continue
            data = f.read_bytes()
        except OSError:
            continue
        rel = f.relative_to(app).as_posix()
        for m in FLAG_RE.finditer(data):
            flags[m.group(0)] = rel
        for name, rx in SECRETS:
            for m in rx.finditer(data):
                secrets.setdefault(name, set()).add(m.group(0)[:200])
        for m in URL_RE.finditer(data):
            u = m.group(0).decode("latin-1").rstrip(".,);")
            if "apple.com/DTDs" in u or "w3.org" in u:
                continue
            if len(u) < 200 and u not in urls:
                urls[u] = rel
        for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
            s = m.group(0).decode("latin-1")
            if s not in seen:
                seen.add(s)
                strings.append((rel, s))
    for kind, vals in secrets.items():
        pass
    with open(outdir / "strings.txt", "w", encoding="utf-8", errors="replace") as fh:
        for rel, s in strings:
            fh.write("%s\t%s\n" % (rel, s))
    with open(outdir / "secrets.txt", "w", encoding="utf-8", errors="replace") as fh:
        for kind, vals in secrets.items():
            for v in sorted(vals):
                fh.write("%s\t%s\n" % (kind, v.decode("latin-1")))
    with open(outdir / "urls.txt", "w", encoding="utf-8", errors="replace") as fh:
        for u, rel in urls.items():
            fh.write("%s\t%s\n" % (u, rel))
    return {"flags": flags, "secrets": secrets, "urls": urls, "strings": strings}


def detect_frameworks(app: Path):
    names = {p.name for p in app.rglob("*") if p.is_dir()}
    found = []
    if "Flutter.framework" in names:
        found.append("Flutter (App.framework/flutter_assets -> Dart AOT; use Blutter)")
    if "UnityFramework.framework" in names or (app / "Data" / "Managed").exists():
        found.append("Unity (Data/Managed/*.dll -> ilspycmd)")
    if (app / "main.jsbundle").exists():
        found.append("React Native (main.jsbundle -> JS bundle)")
    if (app / "www").exists():
        found.append("Cordova/Capacitor (www/ web assets)")
    if any(p.name.startswith("libmonosgen") for p in app.rglob("*")):
        found.append("Xamarin (managed assemblies in .app)")
    if (app / "GoogleService-Info.plist").exists():
        found.append("Firebase (GoogleService-Info.plist)")
    return found


def objc_classes(binary: Path, info):
    """Class names from __objc_classname + swift symbols from the string table."""
    names = set()
    try:
        data = binary.read_bytes()
    except OSError:
        return []
    wanted = ("__objc_classname", "__objc_methname", "__objc_classrefs",
              "__cstring", "__const", "__ustring")
    for sec in info.get("sections", []):
        if sec["sect"] not in wanted or not sec["size"]:
            continue
        chunk = data[sec["offset"]:sec["offset"] + sec["size"]]
        for part in chunk.split(b"\x00"):
            s = part.decode("latin-1", "replace")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:.$]{1,120}", s):
                continue
            if sec["sect"] in ("__cstring", "__const", "__ustring"):
                # keep selectors and CamelCase identifiers, skip prose
                if not (s.endswith(":") or re.match(r"^[A-Z][a-z0-9]+[A-Z]", s)
                        or s.startswith(("NS", "UI", "CF", "WK", "SK"))):
                    continue
            names.add(s)
    for m in re.finditer(rb"_OBJC_CLASS_\$_([A-Za-z_][A-Za-z0-9_]{1,80})", data[:8 << 20]):
        names.add(m.group(1).decode("latin-1"))
    for m in re.finditer(rb"\$s([A-Za-z0-9_]{6,80})", data[:8 << 20]):
        names.add("swift:$s" + m.group(1).decode("latin-1")[:60])
    return sorted(names)


# --------------------------------------------------------------------------
def triage(ipa: Path, outdir: Path, log: Log):
    log.hdr("IPA TRIAGE  %s" % ipa.name)
    log.p("  size     : %s" % human(ipa.stat().st_size if ipa.is_file() else 0))
    app = extract(ipa, outdir, log)
    real_app = find_app(app)
    if not real_app:
        log.p("  [!] no .app bundle with Info.plist found")
        return {}
    info = load_plist(real_app / "Info.plist")
    exe = info.get("CFBundleExecutable", "")
    binp = real_app / exe
    log.p("  bundle   : %s" % info.get("CFBundleIdentifier", "?"))
    log.p("  version  : %s (%s)" % (info.get("CFBundleShortVersionString", "?"),
                                     info.get("CFBundleVersion", "?")))
    log.p("  min ios  : %s   executable: %s" % (info.get("MinimumOSVersion", "?"), exe))
    if info.get("CFBundleURLTypes"):
        schemes = [s.get("CFBundleURLSchemes", []) for s in info["CFBundleURLTypes"]]
        log.p("  urls     : %s" % ", ".join(x for group in schemes for x in group))
    ats = info.get("NSAppTransportSecurity", {})
    if ats:
        log.p("  ATS      : %s" % json.dumps(ats, default=str)[:160])
    for key in ("UIFileSharingEnabled", "NSAllowsArbitraryLoads"):
        if info.get(key):
            log.p("  %-8s : %s" % (key, info[key]))
    usage = sorted(k for k in info if k.endswith("UsageDescription"))
    if usage:
        log.p("  privacy  : %s" % ", ".join(usage))
    if info.get("LSApplicationQueriesSchemes"):
        log.p("  queries  : %s" % ", ".join(info["LSApplicationQueriesSchemes"]))

    prov = provision_info(real_app)
    if prov:
        log.p("")
        log.p("  -- provisioning profile --")
        ent = prov.get("Entitlements", {})
        log.p("  name     : %s   team: %s" % (prov.get("Name", "?"), prov.get("TeamName", "?")))
        log.p("  expires  : %s   devices: %s" % (prov.get("ExpirationDate", "?"),
                                                  len(prov.get("ProvisionedDevices", []) or [])))
        for k in ("get-task-allow", "application-identifier", "aps-environment"):
            if k in ent:
                log.p("  %-22s %s" % (k, ent[k]))
        if prov.get("DeveloperCertificates"):
            log.p("  certs    : %d embedded developer certificate(s)" % len(prov["DeveloperCertificates"]))

    fws = detect_frameworks(real_app)
    if fws:
        log.p("")
        log.p("  -- runtime / framework --")
        for f in fws:
            log.p("  " + f)

    if binp.exists():
        mi = macho_info(binp)
        if mi:
            for sl in mi["slices"]:
                log.p("")
                log.p("  -- Mach-O %s%s --" % (sl["arch"], " (fat slice)" if mi["fat"] else ""))
                log.p("  uuid=%s platform=%s minos=%s filetype=%d ncmds=%d" % (
                    sl["uuid"], sl["platform"], sl["minos"], sl["filetype"], sl["ncmds"]))
                if sl["cryptid"] is not None:
                    log.p("  cryptid=%d %s" % (sl["cryptid"],
                           "ENCRYPTED (App Store) - decrypt dump from device first" if sl["cryptid"]
                           else "not encrypted"))
                keep = [s for s in sl["sections"] if s["sect"] in
                        ("__text", "__cstring", "__objc_classname", "__objc_methname",
                         "__const", "__data", "__auth_stubs", "__swift5_typeref")]
                for s in keep[:12]:
                    log.p("  %-22s %-25s addr=%#x size=%d" % (s["seg"], s["sect"], s["addr"], s["size"]))
                if sl["dylibs"]:
                    log.p("  dylibs   : %s" % ", ".join(x.split("/")[-1] for x in sl["dylibs"][:12]))
    else:
        log.p("  [!] executable %r missing from bundle" % exe)

    scan = scan_files(real_app, outdir)
    if scan["flags"]:
        log.p("")
        for f, where in scan["flags"].items():
            log.p("  [FLAG] %s   (%s)" % (f.decode("latin-1"), where))
    if scan["secrets"]:
        log.p("")
        log.p("  -- hardcoded secrets --")
        for kind, vals in scan["secrets"].items():
            for v in sorted(vals)[:5]:
                log.p("  %-14s %s" % (kind, v.decode("latin-1")[:120]))
    if scan["urls"]:
        log.p("")
        log.p("  -- endpoints (top 15 of %d) --" % len(scan["urls"]))
        for u in list(scan["urls"])[:15]:
            log.p("  " + u[:140])

    if binp.exists():
        cls = objc_classes(binp, macho_info(binp)["slices"][0] if macho_info(binp) else {})
        if cls:
            log.p("")
            log.p("  -- classes / symbols (top 25 of %d) --" % len(cls))
            for c in cls[:25]:
                log.p("  " + c)
            (outdir / "classes.txt").write_text("\n".join(cls), encoding="utf-8", errors="replace")

    log.p("")
    log.p("  next:")
    log.p("    python ctf_ipa.py decompile %s      # Mach-O -> Ghidra/IDA C" % ipa.name)
    log.p("    python ctf_ipa.py patch %s --va 0xADDR --asm \"...\"" % ipa.name)
    log.save(outdir / "report.txt")
    return {"bundle": info.get("CFBundleIdentifier"),
            "flags": [f.decode("latin-1") for f in scan["flags"]]}


def decompile(ipa: Path, outdir: Path, log: Log, engine="auto", timeout=900):
    log.hdr("IPA DECOMPILE")
    app = find_app(extract(ipa, outdir, log))
    if not app:
        log.p("  [!] no app bundle")
        return None
    info = load_plist(app / "Info.plist")
    exe = app / info.get("CFBundleExecutable", "")
    if not exe.exists():
        log.p("  [!] executable missing")
        return None
    re_solve = HERE / "re_solve.py"
    out = outdir / "decompiled"
    cmd = [sys.executable, str(re_solve), "decompile", str(exe), "-o", str(out),
           "--engine", engine, "--timeout", str(timeout)]
    rc, o = run(cmd, timeout=timeout + 300)
    log.p(o.strip()[-1500:])
    log.p("")
    log.p("  output: %s" % (out / "pseudocode.c"))
    log.save(outdir / "decompile.txt")
    return out


def patch(ipa: Path, outdir: Path, va: int, asm: str, raw: str, log: Log):
    log.hdr("IPA PATCH")
    app = find_app(extract(ipa, outdir, log))
    if not app:
        log.p("  [!] no app bundle")
        return None
    info = load_plist(app / "Info.plist")
    exe = app / info.get("CFBundleExecutable", "")
    mi = macho_info(exe)
    if not mi or not mi["slices"]:
        log.p("  [!] not a Mach-O")
        return None
    pieces = []
    try:
        from keystone import (Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86,
                              KS_MODE_32, KS_MODE_64, KS_MODE_ARM,
                              KS_MODE_LITTLE_ENDIAN)
    except ImportError:
        log.p("  [!] pip install keystone-engine")
        return None
    code = b""
    if raw:
        code = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", raw))
    else:
        arch = mi["slices"][0]["arch"]
        karch = {"arm64": KS_ARCH_ARM64, "arm64e": KS_ARCH_ARM64,
                 "x86_64": KS_ARCH_X86, "arm": KS_ARCH_ARM}.get(arch, KS_ARCH_ARM64)
        kmode = {"arm64": KS_MODE_LITTLE_ENDIAN, "arm64e": KS_MODE_LITTLE_ENDIAN,
                 "x86_64": KS_MODE_64, "arm": KS_MODE_ARM}.get(arch, KS_MODE_LITTLE_ENDIAN)
        code = bytes(Ks(karch, kmode).asm(asm, addr=va)[0])
    data = bytearray(exe.read_bytes())
    target = None
    for sl in mi["slices"]:
        for s in sl["sections"]:
            if s["size"] and s["addr"] <= va < s["addr"] + s["size"]:
                target = s["offset"] + (va - s["addr"])
                break
        if target is not None:
            break
    if target is None:
        log.p("  [!] VA %#x not inside a section" % va)
        return None
    data[target:target + len(code)] = code
    exe.write_bytes(bytes(data))
    log.p("  patched  : %s +%#x (%d bytes)" % (exe.name, target, len(code)))
    out_ipa = outdir / ("%s_patched.ipa" % ipa.stem)
    repack(app, out_ipa)
    log.p("  ipa      : %s" % out_ipa)
    log.p("  sign     : macOS: codesign -f -s - Payload/*.app   |   device: ldid -S <binary>")
    log.save(outdir / "patch.txt")
    return out_ipa


def repack(app: Path, out_ipa: Path):
    payload = app.parent if app.parent.name == "Payload" else app.parent
    root = app.parent
    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(app.rglob("*")):
            if f.is_file():
                zf.write(f, Path("Payload") / app.name / f.relative_to(app))


def main(argv=None):
    ap = argparse.ArgumentParser(description="iOS IPA challenge toolkit")
    ap.add_argument("command", choices=("triage", "decompile", "classes", "patch", "repack", "all"))
    ap.add_argument("ipa")
    ap.add_argument("-o", "--out")
    ap.add_argument("--engine", default="auto", choices=("auto", "ghidra", "ida"))
    ap.add_argument("--va")
    ap.add_argument("--asm")
    ap.add_argument("--bytes")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ipa = Path(args.ipa)
    if not ipa.exists():
        sys.exit("no such file: %s" % ipa)
    outdir = Path(args.out or (ipa.stem + "_ipa"))
    outdir.mkdir(parents=True, exist_ok=True)
    log = Log()

    if args.command in ("triage", "all"):
        res = triage(ipa, outdir, log)
        if args.command == "all":
            decompile(ipa, outdir, log, args.engine, args.timeout)
        if args.json:
            print(json.dumps(res, int="default") if False else json.dumps(res, default=str, indent=1))
        return 0
    if args.command == "decompile":
        return 0 if decompile(ipa, outdir, log, args.engine, args.timeout) else 1
    if args.command == "classes":
        app = find_app(extract(ipa, outdir, log))
        if not app:
            return 1
        info = load_plist(app / "Info.plist")
        exe = app / info.get("CFBundleExecutable", "")
        mi = macho_info(exe)
        names = objc_classes(exe, mi["slices"][0] if mi else {})
        for n in names:
            log.p(n)
        return 0
    if args.command == "patch":
        if not args.va or not (args.asm or args.bytes):
            sys.exit("--va plus --asm or --bytes required")
        return 0 if patch(ipa, outdir, int(args.va, 0), args.asm or "",
                          args.bytes or "", log) else 1
    if args.command == "repack":
        app = find_app(extract(ipa, outdir, log))
        if not app:
            return 1
        out = outdir / ("%s_repacked.ipa" % ipa.stem)
        repack(app, out)
        log.p("repacked -> %s" % out)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
