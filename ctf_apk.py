#!/usr/bin/env python3
"""ctf_apk.py -- Android challenge toolkit (triage / decompile / rebuild / sign / install).

Runs with the Android SDK build-tools, apktool, jadx and a JDK already on the box;
each is auto-detected and the tool degrades gracefully when one is missing.

  python ctf_apk.py triage    app.apk
  python ctf_apk.py decompile app.apk          # jadx java + apktool smali/resources
  python ctf_apk.py rebuild   app.apk          # apktool b + zipalign + apksigner
  python ctf_apk.py sign      patched.apk      # debug keystore, v1+v2+v3
  python ctf_apk.py install   patched.apk --serial emulator-5554
  python ctf_apk.py all       app.apk          # triage + decompile

Everything is written under <name>_apk/ ; the original file is never modified.
Outputs: report.txt, strings.txt, secrets.txt, jadx/sources/**, apktool/**,
         rebuild/*.apk (signed), cert.txt
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

IS_WIN = os.name == "nt"
CNW = 0x08000000 if IS_WIN else 0
HERE = Path(__file__).resolve().parent

ANDROID_GLOBS = [
    os.environ.get("ANDROID_HOME", ""),
    os.environ.get("ANDROID_SDK_ROOT", ""),
    "C:/Users/*/AppData/Local/Android/Sdk",
    str(Path.home() / "Android/Sdk"),
    str(Path.home() / "Library/Android/sdk"),
    "/opt/android-sdk",
]
APKTOOL_GLOBS = ["C:/apktool/apktool.jar", "C:/apktool/apktool.bat",
                 str(Path.home() / "apktool*.jar"), "/usr/local/bin/apktool",
                 "/usr/share/apktool/apktool.jar", "/opt/apktool/apktool.jar"]
JADX_GLOBS = [str(Path.home() / "Downloads/CTF Tools/jadx*/lib/jadx-*-all.jar"),
              "C:/Users/*/Downloads/CTF Tools/jadx*/lib/jadx-*-all.jar",
              str(Path.home() / "jadx*/lib/jadx-*-all.jar"),
              "C:/jadx*/lib/jadx-*-all.jar", "/opt/jadx*/lib/jadx-*-all.jar",
              "/usr/share/jadx/lib/jadx-*-all.jar"]

DANGEROUS_PERMS = {
    "android.permission.INTERNET": "network",
    "android.permission.READ_EXTERNAL_STORAGE": "files",
    "android.permission.WRITE_EXTERNAL_STORAGE": "files",
    "android.permission.READ_SMS": "sms",
    "android.permission.RECEIVE_SMS": "sms",
    "android.permission.SEND_SMS": "sms",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.CAMERA": "camera",
    "android.permission.RECORD_AUDIO": "mic",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility (keylogging)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "sideload",
    "android.permission.QUERY_ALL_PACKAGES": "package enumeration",
    "android.permission.READ_PHONE_STATE": "device id",
    "android.permission.POST_NOTIFICATIONS": "notifications",
    "android.permission.USE_BIOMETRIC": "biometric",
}

SECRET_RES = [
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("aws_secret", re.compile(rb"(?i)aws.{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]")),
    ("stripe_live", re.compile(rb"sk_live_[0-9a-zA-Z]{24,}")),
    ("slack_webhook", re.compile(rb"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("firebase_db", re.compile(rb"https://[a-z0-9-]+\.firebaseio\.com")),
    ("firebase_url", re.compile(rb"https://[a-z0-9-]+\.firebaseapp\.com")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("basic_auth_url", re.compile(rb"(?:https?|ftp)://[^/\s:@]+:[^/\s@]+@[^/\s]+")),
    ("google_oauth", re.compile(rb"[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com")),
    ("s3_bucket", re.compile(rb"[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com")),
]
URL_RE = re.compile(rb"https?://[^\s\"'<>\\]{6,200}")
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FLAG_RE = re.compile(
    rb"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    rb"pctf|hitcon|n1ctf|idek|sekai|vsctf|buckeye|utflag|lactf|byuctf|tjctf|"
    rb"damctf|sctf|justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    rb"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
ANTI = {
    b"frida-gadget": "frida gadget", b"frida_server": "frida server",
    b"re.frida.server": "frida server", b"de.robv.android.xposed": "xposed",
    b"com.saurik.substrate": "substrate", b"magisk": "magisk/root",
    b"isDebuggerConnected": "anti-debug", b"CertificatePinner": "cert pinning",
    b"/system/bin/su": "root check", b"/system/xbin/su": "root check",
    b"ptrace": "anti-debug",
}


# --------------------------------------------------------------------------
def run(cmd, cwd=None, timeout=900, env=None):
    try:
        p = subprocess.run([str(c) for c in cmd], cwd=str(cwd) if cwd else None,
                           capture_output=True, timeout=timeout,
                           creationflags=CNW, env=env)
        return p.returncode, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    except FileNotFoundError as exc:
        return 127, "not found: %s" % exc
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def find_android(name):
    exts = [".exe", ".bat", "", ".cmd"] if IS_WIN else [""]
    for base in ANDROID_GLOBS:
        if not base:
            continue
        for pattern in (os.path.join(base, "build-tools", "*"),
                        os.path.join(base, "platform-tools")):
            dirs = sorted(glob.glob(pattern), reverse=True)
            for d in dirs:
                for ext in exts:
                    cand = Path(d) / (name + ext)
                    if cand.is_file():          # exact binary, never a prefix match
                        return cand
        for ext in exts:
            cand = Path(base) / (name + ext)
            if cand.is_file():
                return cand
    w = shutil.which(name)
    return Path(w) if w else None


def find_jar(globs, env_var=None):
    if env_var and os.environ.get(env_var):
        p = Path(os.environ[env_var])
        if p.is_dir():
            hits = sorted(glob.glob(str(p / "**" / "*.jar"), recursive=True))
            if hits:
                return Path(hits[0])
        elif p.exists():
            return p
    for pat in globs:
        hits = sorted(glob.glob(pat))
        if hits:
            return Path(hits[0])
    w = shutil.which(Path(globs[0]).stem if "." not in Path(globs[0]).stem else "apktool")
    return Path(w) if w else None


def java():
    j = shutil.which("java")
    if j:
        return j
    for p in ("C:/Program Files/Java/*/bin/java.exe", "/usr/bin/java"):
        hits = sorted(glob.glob(p))
        if hits:
            return hits[-1]
    return "java"


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


def entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    import math
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
# manifest via aapt (fast, no full decode)
# --------------------------------------------------------------------------
def parse_xmltree(text):
    """aapt dump xmltree -> [{name, attrs, children, depth}] with exported flag."""
    root = {"name": "ROOT", "attrs": {}, "children": [], "depth": -1}
    stack = [root]
    for line in text.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        depth = indent // 2
        body = line.strip()
        while stack and stack[-1]["depth"] >= depth:
            stack.pop()
        if body.startswith("E: "):
            name = body[3:].split("(")[0].strip()
            node = {"name": name, "attrs": {}, "children": [], "depth": depth}
            stack[-1]["children"].append(node)
            stack.append(node)
        elif body.startswith("A: ") and stack:
            m = re.match(r"A: ([^=]+?)(?:\(0x[0-9a-f]+\))?=(.*)", body)
            if m:
                key = m.group(1).split(":")[-1].strip()
                val = re.sub(r"\s*\(Raw:.*$", "", m.group(2)).strip().strip('"')
                stack[-1]["attrs"][key] = val
    return root


def walk(node, want, out=None):
    out = out if out is not None else []
    if node["name"] == want:
        out.append(node)
    for c in node["children"]:
        walk(c, want, out)
    return out


def xml_to_tree_text(xml: str) -> str:
    """Minimal plain-XML to aapt-xmltree-style text for parse_xmltree()."""
    import xml.etree.ElementTree as ET
    lines = ["E: manifest"]
    try:
        root = ET.fromstring(xml)
    except Exception:
        return ""
    def walk(node, depth):
        for child in node:
            if not isinstance(child.tag, str):
                continue
            name = child.tag.split("}")[-1]
            lines.append("  " * depth + "E: " + name)
            for k, v in child.attrib.items():
                key = k.split("}")[-1]
                lines.append("  " * (depth + 1) + "A: http://schemas.android.com/apk/res/android:%s=%s" % (key, v))
            walk(child, depth + 1)
    walk(root, 1)
    return "\n".join(lines)


def truthy(v):
    return v in ("0xffffffff", "-1", "true", "1", "(type 0x12)0xffffffff")


def badging(aapt, apk):
    if not aapt:
        return {}
    rc, out = run([aapt, "dump", "badging", apk])
    info = {"raw": out}
    m = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", out)
    if m:
        info["name"], info["version_code"], info["version_name"] = m.groups()
    info["permissions"] = re.findall(r"(?m)^uses-permission: name='([^']+)'", out)
    info["sdk"] = re.findall(r"(?m)^sdkVersion:'([^']+)'", out)
    info["target_sdk"] = re.findall(r"(?m)^targetSdkVersion:'([^']+)'", out)
    info["launchable"] = re.findall(r"(?m)^launchable-activity: name='([^']+)'", out)
    info["label"] = re.findall(r"(?m)^application-label:'([^']*)'", out)
    abis = re.search(r"(?m)^native-code:(.*)$", out)
    info["abis"] = re.findall(r"'([^']+)'", abis.group(1)) if abis else []
    return info


def manifest_flags(aapt, apk, outdir=None):
    out = ""
    if aapt:
        rc, out = run([aapt, "dump", "xmltree", apk, "AndroidManifest.xml"])
        if "E: manifest" not in out:
            out = ""
    if not out:
        aapt2 = find_android("aapt2")
        if aapt2:
            rc, out = run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk])
            if "E: manifest" not in out:
                out = ""
    if not out and outdir is not None:
        dec = outdir / "apktool" / "AndroidManifest.xml"
        if not dec.exists():
            apktool = find_jar(APKTOOL_GLOBS, "APKTOOL_HOME")
            if apktool:
                run([java(), "-jar", str(apktool), "d", "-f", "-s",
                     "-o", str(outdir / "apktool"), str(apk)], timeout=600)
        if dec.exists():
            # convert plain XML into the aapt xmltree shape the parser expects
            out = xml_to_tree_text(dec.read_text(encoding="utf-8", errors="replace"))
    if not out:
        return {}
    tree = parse_xmltree(out)
    app = walk(tree, "application")
    flags = {}
    if app:
        a = app[0]["attrs"]
        flags["debuggable"] = truthy(a.get("debuggable", ""))
        flags["allowBackup"] = truthy(a.get("allowBackup", ""))
        flags["networkSecurityConfig"] = a.get("networkSecurityConfig", "")
        flags["usesCleartextTraffic"] = truthy(a.get("usesCleartextTraffic", ""))
        flags["app_name"] = a.get("label", "")
    exported = []
    for comp in ("activity", "activity-alias", "service", "receiver", "provider"):
        for node in walk(tree, comp):
            a = node["attrs"]
            has_filter = any(c["name"] == "intent-filter" for c in node["children"])
            is_exported = truthy(a.get("exported", ""))
            if a.get("exported") and not is_exported:
                continue
            if is_exported or has_filter:
                exported.append({"type": comp, "name": a.get("name", "?"),
                                 "exported": is_exported, "intent_filter": has_filter,
                                 "permission": a.get("permission", "")})
    flags["exported_components"] = exported
    perms = []
    for node in walk(tree, "uses-permission"):
        perms.append(node["attrs"].get("name", ""))
    flags["permissions"] = perms
    return flags


# --------------------------------------------------------------------------
# entry scanning
# --------------------------------------------------------------------------
def entry_bytes(zf, info, limit=64 << 20):
    if info.file_size > limit:
        return b""
    try:
        return zf.read(info)
    except Exception:
        return b""


def scan_entries(apk: Path, outdir: Path, log: Log):
    """strings/secrets/flags across every entry (dex, assets, res, lib)."""
    strings, secrets, flags, urls, ips, anti, entries = [], {}, {}, {}, {}, {}, []
    seen = set()
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            data = entry_bytes(zf, info)
            entries.append({"name": info.filename, "size": info.file_size,
                            "comp": info.compress_type,
                            "entropy": round(entropy(data), 2) if data else 0})
            if not data:
                continue
            for m in FLAG_RE.finditer(data):
                flags[m.group(0)] = info.filename
            for name, rx in SECRET_RES:
                for m in rx.finditer(data):
                    secrets.setdefault(name, set()).add(m.group(0)[:200])
            for m in URL_RE.finditer(data):
                u = m.group(0).decode("latin-1").rstrip(".,);")
                if len(u) > 200 or "schemas.android.com/apk" in u:
                    continue
                if "android.googlesource.com" in u or "youtrack.jetbrains.com" in u:
                    continue
                if sum(1 for ch in u if not (32 <= ord(ch) < 127)) > 2:
                    continue
                if u not in urls:
                    urls[u] = info.filename
            for m in IP_RE.finditer(data[:4 << 20]):
                ips.setdefault(m.group(0).decode(), info.filename)
            for sig, why in ANTI.items():
                if sig.lower() in data.lower() and sig.decode("latin-1", "ignore") not in anti:
                    anti[sig.decode("latin-1", "ignore")] = why
            # printable strings (dex strings are length-prefixed but plain runs work)
            for m in re.finditer(rb"[\x20-\x7e]{4,}", data[:8 << 20]):
                s = m.group(0).decode("latin-1")
                if s not in seen:
                    seen.add(s)
                    strings.append((info.filename, s))
    # rank
    def score(item):
        entry, s = item
        b = s.encode("latin-1", "ignore")
        v = 100 if FLAG_RE.search(b) else 0
        if re.search(rb"(?i)flag|secret|password|passwd|token|api[_-]?key|admin|root|serial", b):
            v += 25
        if b"{" in b and b"}" in b:
            v += 15
        return -v
    strings.sort(key=score)
    with open(outdir / "strings.txt", "w", encoding="utf-8", errors="replace") as fh:
        for entry, s in strings:
            fh.write("%s\t%s\n" % (entry, s))
    with open(outdir / "secrets.txt", "w", encoding="utf-8", errors="replace") as fh:
        for kind, vals in secrets.items():
            for v in sorted(vals):
                fh.write("%s\t%s\n" % (kind, v))
    (outdir / "entries.json").write_text(json.dumps(entries, indent=1), encoding="utf-8")
    with open(outdir / "urls.txt", "w", encoding="utf-8", errors="replace") as fh:
        for u, e in urls.items():
            fh.write("%s\t%s\n" % (u, e))
    return {"strings": strings, "secrets": secrets, "flags": flags,
            "urls": urls, "ips": ips, "anti": anti, "entries": entries}


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------
def cert_report(apk: Path, outdir: Path):
    lines = []
    apksigner = find_android("apksigner")
    if apksigner:
        rc, out = run([apksigner, "verify", "--print-certs", "-v", str(apk)], timeout=120)
        lines.append("$ apksigner verify --print-certs")
        lines.append(out.strip())
    keytool = shutil.which("keytool")
    if keytool:
        rc, out = run([keytool, "-printcert", "-jarfile", str(apk)], timeout=120)
        if "Owner:" in out:
            lines.append("\n$ keytool -printcert -jarfile")
            lines.append(out.strip())
    text = "\n".join(lines)
    (outdir / "cert.txt").write_text(text, encoding="utf-8", errors="replace")
    return text


# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------
def triage(apk: Path, outdir: Path, log: Log):
    aapt = find_android("aapt")
    log.hdr("APK TRIAGE  %s" % apk.name)
    log.p("  size     : %s" % human(apk.stat().st_size))
    log.p("  sha256   : %s" % hashlib.sha256(apk.read_bytes()).hexdigest())
    if not zipfile.is_zipfile(apk):
        log.p("  [!] not a zip/apk")
        return {}

    bad = badging(aapt, apk)
    log.p("  package  : %s" % bad.get("name", "?"))
    log.p("  version  : %s (%s)" % (bad.get("version_name", "?"), bad.get("version_code", "?")))
    log.p("  sdk      : min=%s target=%s" % (
        ",".join(bad.get("sdk", [])) or "?",
        ",".join(bad.get("target_sdk", [])) or "?"))
    if bad.get("launchable"):
        log.p("  activity : %s" % bad["launchable"][0])
    log.p("  abis     : %s" % (", ".join(bad.get("abis", [])) or "none"))

    mflags = manifest_flags(aapt, apk, outdir)
    if mflags:
        log.p("")
        log.p("  debuggable=%s  allowBackup=%s  cleartextTraffic=%s" % (
            mflags.get("debuggable"), mflags.get("allowBackup"),
            mflags.get("usesCleartextTraffic")))
        if mflags.get("networkSecurityConfig"):
            log.p("  networkSecurityConfig=%s" % mflags["networkSecurityConfig"])
        if mflags.get("permissions"):
            log.p("  permissions:")
            for p in mflags["permissions"]:
                tag = DANGEROUS_PERMS.get(p, "")
                log.p("    %-60s %s" % (p, ("<- " + tag) if tag else ""))
        if mflags.get("exported_components"):
            log.p("  exported components (attack surface):")
            for c in mflags["exported_components"]:
                log.p("    %-10s %-55s exported=%s filter=%s" % (
                    c["type"], c["name"][:55], c["exported"], c["intent_filter"]))
    else:
        log.p("  [!] manifest not parsed (need aapt/aapt2 from Android build-tools, or apktool)")

    scan = scan_entries(apk, outdir, log)
    log.p("")
    log.p("  entries  : %d  (dex=%d, libs=%d, assets=%d)" % (
        len(scan["entries"]),
        sum(1 for e in scan["entries"] if e["name"].endswith(".dex")),
        sum(1 for e in scan["entries"] if "/lib/" in e["name"] and e["name"].endswith(".so")),
        sum(1 for e in scan["entries"] if e["name"].startswith("assets/"))))
    if scan["flags"]:
        log.p("")
        for f, where in scan["flags"].items():
            log.p("  [FLAG] %s   (%s)" % (f.decode("latin-1"), where))
    if scan["secrets"]:
        log.p("")
        log.p("  -- hardcoded secrets --")
        for kind, vals in scan["secrets"].items():
            for v in sorted(vals)[:6]:
                log.p("  %-14s %s" % (kind, v.decode("latin-1")[:120]))
    if scan["anti"]:
        log.p("")
        log.p("  -- anti-analysis / protection --")
        for sig, why in scan["anti"].items():
            log.p("  %-24s %s" % (sig[:24], why))
    if scan["urls"]:
        log.p("")
        log.p("  -- endpoints (top 20 of %d) --" % len(scan["urls"]))
        for u in list(scan["urls"])[:20]:
            log.p("  " + u[:140])
    log.p("")
    log.p("  -- interesting strings --")
    for entry, s in scan["strings"][:30]:
        log.p("  %-28s %s" % (entry[-28:], s[:110]))

    cert = cert_report(apk, outdir)
    if cert:
        log.p("")
        log.p("  -- signing certificate --")
        for line in cert.splitlines()[:12]:
            log.p("  " + line[:140])
    log.save(outdir / "report.txt")
    return {"package": bad.get("name"), "flags": [f.decode("latin-1") for f in scan["flags"]],
            "secrets": {k: sorted(v)[:3] for k, v in scan["secrets"].items()}}


# --------------------------------------------------------------------------
# decompile
# --------------------------------------------------------------------------
def find_dex2jar():
    pats = [str(HERE / "tools/dex-tools*/d2j-dex2jar.bat"),
            str(HERE / "tools/dex-tools*/d2j-dex2jar.sh"),
            str(Path.cwd() / "tools/dex-tools*/d2j-dex2jar.bat"),
            "/opt/dex-tools*/d2j-dex2jar.sh",
            str(Path.home() / "tools/dex-tools*/d2j-dex2jar.sh")]
    for pat in pats:
        hits = sorted(glob.glob(pat))
        if hits:
            return Path(hits[0])
    w = shutil.which("d2j-dex2jar")
    return Path(w) if w else None


def find_cfr_local():
    for cand in (HERE / "tools" / "cfr.jar", Path.cwd() / "tools" / "cfr.jar",
                 Path("/opt/cfr/cfr.jar")):
        if cand.exists():
            return cand
    return None


def dex_to_java(apk: Path, outdir: Path, log: Log, timeout=900):
    """dex2jar + CFR: fast, JDK-agnostic Java recovery from classes*.dex."""
    d2j = find_dex2jar()
    cfr = find_cfr_local()
    if not d2j or not cfr:
        return 0, "dex2jar/cfr.jar missing (tools/)"
    work = outdir / "dex"
    work.mkdir(exist_ok=True)
    with zipfile.ZipFile(apk) as zf:
        dexes = [n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
        for name in dexes:
            (work / name).write_bytes(zf.read(name))
    if not dexes:
        return 0, "no classes*.dex"
    jars = []
    for name in dexes:
        jar = work / (name + ".jar")
        # relative paths + cwd: the .bat wrapper mangles quoted absolute paths
        cmd = [str(d2j), name, "-o", name + ".jar"]
        rc, out = run(cmd, cwd=work, timeout=timeout)
        (outdir / ("dex2jar_%s.log" % name)).write_text(out, encoding="utf-8", errors="replace")
        if (work / (name + ".jar")).exists():
            jars.append(work / (name + ".jar"))
        else:
            log.p("    dex2jar failed on %s: %s" % (name, out.strip().splitlines()[-1][:120] if out.strip() else "?"))
    src = outdir / "java"
    src.mkdir(exist_ok=True)
    total = 0
    for jar in jars:
        rc, out = run([java(), "-jar", str(cfr), str(jar), "--outputdir", str(src)],
                      timeout=timeout)
        (outdir / ("cfr_%s.log" % jar.name)).write_text(out, encoding="utf-8", errors="replace")
        total = len(list(src.rglob("*.java")))
    return total, "%d dex -> %d java" % (len(jars), total)


def decompile(apk: Path, outdir: Path, log: Log, timeout=900, jadx=False, apktool_slow=False):
    log.hdr("APK DECOMPILE")
    apktool = find_jar(APKTOOL_GLOBS, "APKTOOL_HOME")

    # 1) Java sources: dex2jar + CFR (works on any JDK; jadx 1.5.3 hangs on JDK 24)
    n_java, note = dex_to_java(apk, outdir, log, timeout)
    log.p("  java      : %s%s" % (note, "" if n_java else "  <- no sources"))

    # 2) jadx only when asked (or when dex2jar found nothing)
    if jadx or n_java == 0:
        jadx_path = find_jar(JADX_GLOBS, "JADX_HOME")
        if jadx_path:
            src = outdir / "jadx"
            cache = outdir / "jadx_cache"
            cache.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ)
            env["JADX_CACHE_DIR"] = str(cache)
            cmd = ([java(), "-jar", str(jadx_path)] if jadx_path.suffix == ".jar"
                   else [str(jadx_path)]) + ["-d", str(src), "-j", "2", str(apk)]
            rc, out = run(cmd, timeout=min(timeout, 240), env=env)
            (outdir / "jadx.log").write_text(out, encoding="utf-8", errors="replace")
            files = len(list(src.rglob("*.java"))) if src.exists() else 0
            log.p("  jadx      : %s (%d files)" % ("ok" if files else "failed/hung", files))
        else:
            log.p("  jadx      : not installed")

    # 3) manifest + resources (fast: -s skips smali; rebuild does the full decode)
    if apktool:
        dec = outdir / "apktool"
        cmd = [java(), "-jar", str(apktool), "d", "-f", "-s", "-o", str(dec), str(apk)]
        rc, out = run(cmd, timeout=timeout)
        (outdir / "apktool.log").write_text(out, encoding="utf-8", errors="replace")
        ok = (dec / "apktool.yml").exists()
        log.p("  apktool   : %s (manifest + resources in apktool/)" % ("ok" if ok else "FAILED"))
        if ok:
            log.p("  manifest  : %s" % (dec / "AndroidManifest.xml"))
            if not apktool_slow:
                log.p("  smali     : not disassembled here; `rebuild` does the full decode")
    else:
        log.p("  apktool   : not found (needed for rebuild/smali editing)")

    log.p("")
    log.p("  edit Java in java/**, then rebuild an installable APK with:")
    log.p("    python ctf_apk.py rebuild %s -o %s" % (apk.name, outdir))
    log.p("    (smali-only edits: run with --smali, edit apktool/smali*/, then rebuild)")
    log.save(outdir / "decompile.txt")
    return [("java", n_java)]


# --------------------------------------------------------------------------
# rebuild / sign
# --------------------------------------------------------------------------
def keystore_path():
    ks = Path.home() / ".ctf_tools" / "debug.keystore"
    ks.parent.mkdir(parents=True, exist_ok=True)
    if not ks.exists():
        keytool = shutil.which("keytool")
        if not keytool:
            return None
        rc, out = run([keytool, "-genkeypair", "-v", "-keystore", str(ks),
                       "-storepass", "android", "-keypass", "android",
                       "-alias", "androiddebugkey", "-keyalg", "RSA",
                       "-keysize", "2048", "-validity", "10000",
                       "-dname", "CN=Android Debug,O=Android,C=US"], timeout=180)
        if rc != 0:
            return None
    return ks


def sign_apk(apk: Path, log: Log, outdir=None):
    apksigner = find_android("apksigner")
    zipalign = find_android("zipalign")
    ks = keystore_path()
    dest = Path(outdir) if outdir else apk.parent
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / (apk.stem + "_signed.apk")
    work = apk
    if zipalign:
        aligned = dest / (apk.stem + "_aligned.apk")
        rc, o = run([zipalign, "-p", "-f", "4", str(apk), str(aligned)], timeout=300)
        if rc == 0:
            work = aligned
            log.p("  zipalign  : ok")
        else:
            log.p("  zipalign  : failed (%s)" % o.strip()[:120])
    if apksigner and ks:
        rc, o = run([apksigner, "sign", "--ks", str(ks), "--ks-pass", "pass:android",
                     "--key-pass", "pass:android", "--ks-key-alias", "androiddebugkey",
                     "--out", str(out), str(work)], timeout=600)
        log.p("  apksigner : %s" % ("ok" if rc == 0 and out.exists() else "FAILED"))
        if rc != 0:
            log.p("    " + o.strip()[:300])
        if out.exists():
            rc2, o2 = run([apksigner, "verify", "--print-certs", str(out)], timeout=180)
            log.p("  verify    : %s" % ("ok" if rc2 == 0 else "FAILED"))
            return out
        return None
    jarsigner = shutil.which("jarsigner")
    if jarsigner and ks:
        shutil.copyfile(apk, out)
        rc, o = run([jarsigner, "-keystore", str(ks), "-storepass", "android",
                     "-keypass", "android", "-sigalg", "SHA256withRSA",
                     "-digestalg", "SHA-256", str(out), "androiddebugkey"], timeout=600)
        log.p("  jarsigner : %s (v1 only -- Android 11+ needs apksigner)" % ("ok" if rc == 0 else "FAILED"))
        return out if rc == 0 else None
    log.p("  [!] no apksigner/jarsigner -- install Android build-tools")
    return None


def rebuild(apk: Path, outdir: Path, log: Log, source=None, timeout=900):
    log.hdr("APK REBUILD")
    apktool = find_jar(APKTOOL_GLOBS, "APKTOOL_HOME")
    dec = Path(source) if source else (outdir / "apktool")
    if not (dec / "apktool.yml").exists():
        if not apktool:
            log.p("  [!] apktool not found")
            return None
        log.p("  decoding with apktool ...")
        rc, out = run([java(), "-jar", str(apktool), "d", "-f", "-o", str(dec), str(apk)],
                      timeout=timeout)
        if not (dec / "apktool.yml").exists():
            log.p("  [!] apktool d failed: " + out.strip()[-200:])
            return None
    build = outdir / "rebuild"
    build.mkdir(parents=True, exist_ok=True)
    out_apk = build / (apk.stem + "_patched.apk")
    rc, out = run([java(), "-jar", str(apktool), "b", str(dec), "-o", str(out_apk)],
                  timeout=timeout)
    (outdir / "apktool_build.log").write_text(out, encoding="utf-8", errors="replace")
    if rc != 0 or not out_apk.exists():
        log.p("  [!] apktool b failed:")
        for line in out.strip().splitlines()[-8:]:
            log.p("    " + line[:180])
        return None
    log.p("  built     : %s (%s)" % (out_apk.name, human(out_apk.stat().st_size)))
    signed = sign_apk(out_apk, log, outdir)
    if signed:
        log.p("  signed    : %s" % signed)
        log.p("  install   : adb install -r %s" % signed.name)
    log.save(build / "rebuild.txt")
    return signed


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Android APK challenge toolkit")
    ap.add_argument("command", choices=("triage", "decompile", "rebuild", "sign", "install", "all"))
    ap.add_argument("apk")
    ap.add_argument("-o", "--out")
    ap.add_argument("--source", help="decoded apktool dir (default: <out>/apktool)")
    ap.add_argument("--serial", help="adb device serial")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--jadx", action="store_true", help="also run jadx (slow on JDK 24)")
    ap.add_argument("--smali", action="store_true", help="full apktool decode incl. smali")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    apk = Path(args.apk)
    if not apk.exists():
        sys.exit("no such file: %s" % apk)
    outdir = Path(args.out or (apk.stem + "_apk"))
    outdir.mkdir(parents=True, exist_ok=True)
    log = Log()

    if args.command in ("triage", "all"):
        res = triage(apk, outdir, log)
        if args.command == "all":
            decompile(apk, outdir, log, args.timeout, args.jadx, args.smali)
        if args.json:
            print(json.dumps(res, indent=1, default=str))
        return 0

    if args.command == "decompile":
        decompile(apk, outdir, log, args.timeout, args.jadx, args.smali)
        return 0

    if args.command == "rebuild":
        ok = rebuild(apk, outdir, log, args.source, args.timeout)
        return 0 if ok else 1

    if args.command == "sign":
        signed = sign_apk(apk, log, outdir)
        if args.json:
            print(json.dumps({"signed": str(signed) if signed else None}))
        return 0 if signed else 1

    if args.command == "install":
        adb = find_android("adb") or (Path(shutil.which("adb")) if shutil.which("adb") else None)
        if not adb:
            log.p("[!] adb not found")
            return 1
        cmd = [adb] + (["-s", args.serial] if args.serial else []) + ["install", "-r", str(apk)]
        rc, out = run(cmd, timeout=300)
        log.p(out.strip())
        return 0 if rc == 0 else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
