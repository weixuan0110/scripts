#!/usr/bin/env python3
"""re_solve.py -- CTF reverse-engineering: triage -> decompile -> edit -> rebuild.

Formats and what "compile it back" means for each:

  .NET exe/dll   decompile C# (dnSpy / ilspycmd)  -> rebuild with csc / dotnet build
  JAR / .class   decompile Java (jadx)            -> rebuild with javac + jar
  APK / DEX      decompile Java/smali (jadx/apktool) -> rebuild with apktool b
  .pyc           decompile (pycdc/decompyle3) or dis -> rebuild with py_compile
  native ELF/PE  decompile to pseudo-C (Ghidra/IDA) -> patch with Keystone, or
                 reimplement and compile with gcc/clang (same file type)

Native pseudo-C is a *reference*, not compilable source: decompilers do not
recover types, macros or the original build. For native targets the tool gives
you a real edit path (assembly patch) plus the exact rebuild command.

  python re_solve.py doctor
  python re_solve.py triage   challenge.exe
  python re_solve.py decompile challenge.exe -o chal_re
  python re_solve.py decompile app.apk --kind apk
  python re_solve.py rebuild  chal_re --source chal_re/decompiled
  python re_solve.py patch    challenge.exe --va 0x401234 --asm "test eax,eax"
  python re_solve.py patch    challenge.exe --va 0x401234 --bytes 90909090

Requires: python 3.9+.  Optional engines, auto-detected:
  Ghidra (analyzeHeadless), IDA Pro (idat64/idat), jadx, apktool, dnSpy.Console,
  ilspycmd, csc (.NET Framework), dotnet SDK, javac/jar, gcc/clang, keystone-engine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

IS_WIN = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0

HOME = Path.home()
HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------
FLAG_RE = re.compile(
    rb"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|kctf|"
    rb"actf|pctf|asis|hitcon|n1ctf|zer0pts|idek|sekai|maple|vsctf|buckeye|"
    rb"utflag|udctf|lactf|byuctf|tjctf|damctf|sctf|justctf|midnight|kalmar|"
    rb"wolvctf|swampctf|angstrom|bronco|irisctf|hkcert|hxp|rwctf|bi0s|csaw|"
    rb"naham|defcon|0ctf|seccon|utctf|dice|rarctf)[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
KEY_RE = re.compile(
    rb"(?i)(?:secret|password|passwd|passphrase|token|api[_-]?key|license|"
    rb"serial|correct|valid|invalid|wrong|denied|granted|access|admin|key)"
)

INTERESTING_API = {
    # comparing user input -> the checker
    "strcmp": "string compare (input validation)", "strncmp": "string compare",
    "memcmp": "buffer compare (input validation)", "strcasecmp": "compare",
    "stricmp": "compare", "wcsncmp": "wide compare", "lstrcmp": "compare",
    "fmod": "float math (flag math)", "pow": "math", "sin": "math", "cos": "math",
    "sqrt": "math", "exp": "math",
    # crypto / encoding
    "MD5": "hash", "SHA1": "hash", "SHA256": "hash", "sha256": "hash",
    "AES": "crypto", "RC4": "crypto", "XOR": "crypto", "base64": "encoding",
    "EVP_": "openssl crypto", "Crypt": "windows crypto",
    "BCrypt": "windows crypto", "rand": "prng (seedable)",
    "srand": "prng seed", "time": "time-based seed",
    # anti-debug / obfuscation
    "IsDebuggerPresent": "anti-debug", "CheckRemoteDebugger": "anti-debug",
    "NtQueryInformationProcess": "anti-debug", "ptrace": "anti-debug/anti-trace",
    "GetTickCount": "timing check", "QueryPerformanceCounter": "timing check",
    "rdtsc": "timing check", "VirtualProtect": "self-modifying/smc",
    "mprotect": "self-modifying/smc", "VirtualAlloc": "dynamic code",
    "mmap": "dynamic code", "IsProcessorFeaturePresent": "anti-debug",
    # execution / environment
    "system": "command execution", "popen": "command execution",
    "execve": "command execution", "CreateProcess": "spawn process",
    "WinExec": "spawn process", "ShellExecute": "spawn process",
    "dlopen": "dynamic loading", "dlsym": "dynamic loading",
    "LoadLibrary": "dynamic loading", "GetProcAddress": "dynamic loading",
    "getenv": "environment read (env key)", "SetUnhandledExceptionFilter": "anti-debug",
    # io
    "scanf": "input", "gets": "input", "fgets": "input", "read": "input",
    "getchar": "input", "argv": "cli input", "socket": "network",
    "connect": "network", "recv": "network", "send": "network",
    "ptrace_": "anti-debug",
}

PACKER_SIGNS = {
    b"UPX!": "UPX", b"UPX0": "UPX", b"UPX1": "UPX",
    b".aspack": "ASPack", b"ASPack": "ASPack",
    b"MPRESS": "MPRESS", b".themida": "Themida",
    b"VProtect": "VProtect", b".vmp": "VMProtect", b"VMProtect": "VMProtect",
    b"MEI\x0c\x0b\x0a\x0b\x0e": "PyInstaller",
}

PYC_MAGIC = {
    0x550D0D0A: "3.8", 0x610D0D0A: "3.9", 0x6F0D0D0A: "3.10",
    0xA70D0D0A: "3.11", 0xCB0D0D0A: "3.12",
}

TOOL_GLOBS = {
    "ghidra": [
        "C:/ghidra*/support/analyzeHeadless.bat",
        "C:/Users/*/Downloads/CTF Tools/ghidra*/support/analyzeHeadless.bat",
        "C:/Users/*/Downloads/ghidra*/support/analyzeHeadless.bat",
        "C:/Program Files/ghidra*/support/analyzeHeadless.bat",
        str(HOME / "ghidra*/support/analyzeHeadless.bat"),
        str(HOME / "Downloads/ghidra*/support/analyzeHeadless.bat"),
        str(HOME / "tools/ghidra*/support/analyzeHeadless.bat"),
        str(HERE / ".tmp_ghidra/ghidra*/support/analyzeHeadless.bat"),
        "/opt/ghidra*/support/analyzeHeadless",
        "/usr/share/ghidra*/support/analyzeHeadless",
        str(HOME / "ghidra*/support/analyzeHeadless"),
    ],
    "ida": [
        "C:/Program Files/IDA*/idat64.exe",
        "C:/Program Files/IDA*/idat.exe",
        "C:/Program Files (x86)/IDA*/idat64.exe",
        "C:/Program Files (x86)/IDA*/idat.exe",
        "/opt/ida*/idat64", "/opt/ida*/idat",
        str(HOME / "ida*/idat64"),
    ],
    "jadx": [
        str(HOME / "Downloads/CTF Tools/jadx*/lib/jadx-*-all.jar"),
        "C:/Users/*/Downloads/CTF Tools/jadx*/lib/jadx-*-all.jar",
        "C:/jadx*/lib/jadx-*-all.jar",
        str(HOME / "jadx*/lib/jadx-*-all.jar"),
        "/opt/jadx*/lib/jadx-*-all.jar",
        "/usr/share/jadx/lib/jadx-*-all.jar",
        "/usr/local/bin/jadx",
    ],
    "apktool": [
        "C:/apktool/apktool.jar", "C:/apktool/apktool.bat",
        str(HOME / "apktool*.jar"), "/usr/local/bin/apktool",
        "/usr/share/apktool/apktool.jar",
    ],
    "dnspy": [
        "C:/Users/*/Desktop/CTF/dnSpy*/dnSpy.Console.exe",
        str(HOME / "Desktop/CTF/dnSpy*/dnSpy.Console.exe"),
        str(HOME / "dnSpy*/dnSpy.Console.exe"),
        "C:/dnSpy*/dnSpy.Console.exe",
        "C:/Tools/dnSpy*/dnSpy.Console.exe",
    ],
    "csc": [
        "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe",
        "C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe",
        "/usr/bin/mcs", "/usr/bin/csc",
    ],
    "ilspycmd": [
        str(HOME / ".dotnet/tools/ilspycmd.exe"),
        str(HOME / ".dotnet/tools/ilspycmd"),
    ],
}


# --------------------------------------------------------------------------
# basics
# --------------------------------------------------------------------------
def run(cmd, cwd=None, timeout=900, env=None):
    """Run a command quietly; return (rc, stdout+stderr)."""
    try:
        p = subprocess.run([str(c) for c in cmd], cwd=str(cwd) if cwd else None,
                           capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW, env=env)
        out = (p.stdout or b"") + (p.stderr or b"")
        return p.returncode, out.decode("utf-8", "replace")
    except FileNotFoundError as exc:
        return 127, "not found: %s" % exc
    except subprocess.TimeoutExpired:
        return 124, "timeout after %ss" % timeout


def find_tool(name):
    """First existing path for a tool from TOOL_GLOBS / PATH."""
    import glob
    for pat in TOOL_GLOBS.get(name, []):
        hits = sorted(glob.glob(pat, recursive=False))
        for h in hits:
            if Path(h).exists():
                return Path(h)
    exe = {"ghidra": ["analyzeHeadless"], "ida": ["idat64", "idat"],
           "jadx": ["jadx"], "apktool": ["apktool"], "dnspy": ["dnSpy.Console"],
           "csc": ["csc", "mcs"], "ilspycmd": ["ilspycmd"]}.get(name, [name])
    for e in exe:
        w = shutil.which(e)
        if w:
            return Path(w)
    return None


def have(binary):
    return shutil.which(binary) or find_tool(binary)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0
    return str(n)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    import math
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def printable(b: int) -> bool:
    return 32 <= b < 127 or b in (9, 10, 13)


# --------------------------------------------------------------------------
# binary format parsing (no third-party deps)
# --------------------------------------------------------------------------
def pe_info(path: Path):
    data = path.read_bytes()[:0x1000]
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    hdr = path.read_bytes()
    if hdr[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    coff = e_lfanew + 4
    machine, nsec = struct.unpack("<H", hdr[coff:coff + 2])[0], struct.unpack("<H", hdr[coff + 2:coff + 4])[0]
    opt_size = struct.unpack("<H", hdr[coff + 16:coff + 18])[0]
    opt = coff + 20
    magic = struct.unpack("<H", hdr[opt:opt + 2])[0]
    is64 = magic == 0x20B
    image_base = struct.unpack("<Q", hdr[opt + 24:opt + 32])[0] if is64 else \
        struct.unpack("<I", hdr[opt + 28:opt + 32])[0]
    checksum_off = opt + 64
    dd = opt + (112 if is64 else 96)
    clr_rva = struct.unpack("<I", hdr[dd + 14 * 8:dd + 14 * 8 + 4])[0] if opt_size > 128 else 0
    sections = []
    sec = opt + opt_size
    for i in range(nsec):
        o = sec + i * 40
        name = hdr[o:o + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack("<IIII", hdr[o + 8:o + 24])
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                         "rawptr": rptr, "rawsize": rsize,
                         "entropy": entropy(hdr[rptr:rptr + rsize]) if rsize else 0.0})
    machine_name = {0x8664: "x86-64", 0x14C: "x86", 0xAA64: "arm64",
                    0x1C0: "arm", 0x1C4: "arm-thumb"}.get(machine, hex(machine))
    return {"kind": "pe", "bits": 64 if is64 else 32, "arch": machine_name,
            "image_base": image_base, "sections": sections,
            "clr_rva": clr_rva, "checksum_off": checksum_off,
            "checksum": struct.unpack("<I", hdr[checksum_off:checksum_off + 4])[0],
            "size": len(hdr)}


def pe_rva_to_off(pe, rva):
    for s in pe["sections"]:
        span = max(s["vsize"], s["rawsize"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            delta = rva - s["vaddr"]
            if delta < s["rawsize"]:
                return s["rawptr"] + delta
    return None


def pe_fix_checksum(data: bytearray, checksum_off: int):
    if len(data) < checksum_off + 4:
        return
    struct.pack_into("<I", data, checksum_off, 0)
    total = 0
    end = len(data) & ~1
    for i in range(0, end, 2):
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if len(data) & 1:
        total += data[-1]
    total = (total & 0xFFFF) + (total >> 16)
    total += len(data)
    struct.pack_into("<I", data, checksum_off, total & 0xFFFFFFFF)


def elf_info(path: Path):
    hdr = path.read_bytes()
    if len(hdr) < 0x40 or hdr[:4] != b"\x7fELF":
        return None
    is64 = hdr[4] == 2
    little = hdr[5] == 1
    e = "<" if little else ">"
    machine = struct.unpack(e + "H", hdr[18:20])[0]
    machine_name = {0x3E: "x86-64", 0x03: "x86", 0xB7: "arm64", 0x28: "arm",
                    0xF3: "riscv", 0x08: "mips"}.get(machine, hex(machine))
    if is64:
        phoff = struct.unpack(e + "Q", hdr[32:40])[0]
        phentsize, phnum = struct.unpack(e + "HH", hdr[54:58])
    else:
        phoff = struct.unpack(e + "I", hdr[28:32])[0]
        phentsize, phnum = struct.unpack(e + "HH", hdr[42:46])
    segs = []
    for i in range(phnum):
        o = phoff + i * phentsize
        if is64:
            p_type = struct.unpack(e + "I", hdr[o:o + 4])[0]
            p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack(
                e + "QQQQQ", hdr[o + 8:o + 48])
        else:
            p_type = struct.unpack(e + "I", hdr[o:o + 4])[0]
            p_offset, p_vaddr = struct.unpack(e + "II", hdr[o + 4:o + 12])
            p_filesz, p_memsz = struct.unpack(e + "II", hdr[o + 16:o + 24])
        if p_type == 1:
            segs.append({"off": p_offset, "vaddr": p_vaddr,
                         "filesz": p_filesz, "memsz": p_memsz})
    return {"kind": "elf", "bits": 64 if is64 else 32, "arch": machine_name,
            "segments": segs, "size": len(hdr)}


def elf_vaddr_to_off(elf, va):
    for s in elf["segments"]:
        if s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return s["off"] + (va - s["vaddr"])
    return None


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------
def classify(path: Path) -> dict:
    info = {"path": str(path), "size": path.stat().st_size,
            "sha256": sha256_file(path), "kind": "unknown", "notes": []}
    head = path.read_bytes()[:4096]

    pe = pe_info(path)
    if pe:
        info.update(pe)
        info["kind"] = "pe"
        if pe["clr_rva"]:
            info["kind"] = "dotnet"
            info["notes"].append(".NET assembly (CLR header present)")
        return info

    elf = elf_info(path)
    if elf:
        info.update(elf)
        info["kind"] = "elf"
        return info

    if head[:2] == b"MZ":
        info["kind"] = "dos"
        return info
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        info["kind"] = "macho"
        return info
    if head[:4] == b"\x00asm":
        info["kind"] = "wasm"
        return info
    if head[:4] == b"dex\n":
        info["kind"] = "dex"
        return info
    if head[:4] == b"\x1f\x8b" or head[:2] == b"BZ":
        info["kind"] = "compressed"
        return info

    if head[:4] == b"PK\x03\x04":
        names, mf_text = [], ""
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                try:
                    mf_text = zf.read("META-INF/MANIFEST.MF").decode("latin-1", "replace")
                except Exception:
                    mf_text = ""
        except Exception:
            names = []
        base = [Path(n).name for n in names]
        if "AndroidManifest.xml" in base and any(b.startswith("classes") and b.endswith(".dex") for b in base):
            info["kind"] = "apk"
            info["entries"] = len(names)
            info["dex"] = sum(1 for b in base if b.endswith(".dex"))
            return info
        if any(b.endswith(".class") for b in base):
            info["kind"] = "jar"
            info["entries"] = len(names)
            info["classes"] = sum(1 for b in base if b.endswith(".class"))
            m = re.search(r"(?im)^Main-Class:\s*(\S+)", mf_text)
            if m:
                info["main_class"] = m.group(1).strip()
            return info
        info["kind"] = "zip"
        info["entries"] = len(names)
        return info

    if len(head) >= 4:
        magic = struct.unpack("<I", head[:4])[0]
        if magic in PYC_MAGIC or head[2:4] == b"\r\n":
            info["kind"] = "pyc"
            info["py_version"] = PYC_MAGIC.get(magic, "unknown")
            info["magic"] = hex(magic)
            return info

    # packer / runtime hints on any file
    for sig, name in PACKER_SIGNS.items():
        if sig in head:
            info["notes"].append("packer/runtime signature: %s" % name)
            info["packer"] = name
    low = head
    if b"Go build ID:" in low or b"go1." in low:
        info["notes"].append("likely Go binary (goroutines; decompiles poorly)")
    if b"rustc" in low or b"/rustc/" in low:
        info["notes"].append("likely Rust binary")
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in low:
        info["kind"] = "pyinstaller"

    # text fallbacks
    try:
        text = head.decode("utf-8")
        if text.lstrip().startswith(("<?php", "#!/usr/bin/env python", "#!", "import ", "from ",
                                      "function ", "const ", "var ", "public class", "using ",
                                      "import java", "package ")):
            info["kind"] = "source"
    except UnicodeDecodeError:
        pass
    return info


# --------------------------------------------------------------------------
# strings & imports
# --------------------------------------------------------------------------
def extract_strings(path: Path, min_len=4):
    data = path.read_bytes()
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\t?\x00){%d,}" % min_len)
    out = []
    seen = set()
    for m in ascii_re.finditer(data):
        s = m.group(0).decode("latin-1")
        if s not in seen:
            seen.add(s)
            out.append((m.start(), "ascii", s))
    for m in utf16_re.finditer(data):
        s = m.group(0).decode("utf-16-le", "ignore")
        if s and s not in seen:
            seen.add(s)
            out.append((m.start(), "utf16", s))
    return out


def rank_strings(strings):
    def score(item):
        off, enc, s = item
        b = s.encode("latin-1", "ignore")
        v = 0
        if FLAG_RE.search(b):
            v += 100
        if KEY_RE.search(b):
            v += 20
        if len(s) >= 8:
            v += 5
        if b"{" in b and b"}" in b:
            v += 15
        if enc == "utf16":
            v += 3
        return (-v, off)
    return sorted(strings, key=score)


def read_imports(path: Path, info: dict):
    lines = []
    objdump = shutil.which("objdump")
    readelf = shutil.which("readelf")
    if info["kind"] in ("pe", "dotnet") and objdump:
        rc, out = run([objdump, "-p", path])
        lines = [l.strip() for l in out.splitlines()
                 if "DLL Name:" in l or re.match(r"\s+\d+\s+\w+\s+$", l)]
        lines = [l for l in out.splitlines() if l.strip().startswith(("DLL Name:", "\t"))]
        lines = [l.strip() for l in out.splitlines() if "DLL Name:" in l]
    elif info["kind"] == "elf" and readelf:
        rc, out = run([readelf, "-d", "-s", "--wide", path])
        lines = [l.strip() for l in out.splitlines()
                 if "NEEDED" in l or "UND" in l]
    return lines


# --------------------------------------------------------------------------
# decompile: provider dispatch
# --------------------------------------------------------------------------
def decompile_native(path: Path, outdir: Path, engine: str, timeout: int) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    ghidra = find_tool("ghidra")
    ida = find_tool("ida")
    order = []
    if engine == "auto":
        if ghidra:
            order.append("ghidra")
        if ida:
            order.append("ida")
        order.append("objdump")
    else:
        order = [engine]
    errors = []
    for eng in order:
        if eng == "ghidra":
            if not ghidra:
                errors.append("ghidra not found")
                continue
            ok, res = run_ghidra(ghidra, path, outdir, timeout)
        elif eng == "ida":
            if not ida:
                errors.append("ida not found")
                continue
            ok, res = run_ida(ida, path, outdir, timeout)
        elif eng == "objdump":
            ok, res = run_objdump(path, outdir)
        else:
            errors.append("unknown engine %s" % eng)
            continue
        if ok:
            res["engine"] = eng
            return res
        errors.append("%s failed: %s" % (eng, res))
    return {"engine": "none", "errors": errors, "functions": []}


def run_ghidra(headless: Path, path: Path, outdir: Path, timeout: int):
    script = HERE / "ReExport.java"
    if not script.exists():
        return False, "ReExport.java missing next to re_solve.py"
    proj = outdir / "ghidra_proj"
    proj.mkdir(parents=True, exist_ok=True)
    cmd = [headless, str(proj), "ctf", "-import", str(path.resolve()),
           "-scriptPath", str(HERE), "-postScript", "ReExport.java",
           str(outdir.resolve()), "-deleteProject",
           "-analysisTimeoutPerFile", str(timeout)]
    rc, out = run(cmd, timeout=timeout + 300)
    (outdir / "ghidra.log").write_text(out, encoding="utf-8", errors="replace")
    meta = outdir / "meta.json"
    if meta.exists():
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            return True, {"functions": data.get("functions", []),
                          "count": len(data.get("functions", [])),
                          "log": str(outdir / "ghidra.log")}
        except Exception as exc:
            return False, "bad meta.json: %s" % exc
    return False, "no meta.json (see ghidra.log); rc=%s" % rc


def run_ida(idat: Path, path: Path, outdir: Path, timeout: int):
    script_src = HERE / "re_ida_export.py"
    if not script_src.exists():
        return False, "re_ida_export.py missing next to re_solve.py"
    outdir.mkdir(parents=True, exist_ok=True)
    script = outdir / "_re_ida_export.py"
    shutil.copyfile(script_src, script)
    # work on a private copy so concurrent/running IDA instances cannot lock the
    # challenge file and the .i64 database never lands next to it
    work = outdir / ("_target" + (path.suffix or ".bin"))
    shutil.copyfile(path, work)
    log = outdir / "ida.log"
    cmd = [idat, "-A", "-c", "-S_re_ida_export.py", "-L%s" % log.name,
           work.name]
    rc, out = run(cmd, cwd=outdir, timeout=timeout + 300)
    for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".idb"):
        try:
            (outdir / (work.name + ext)).unlink()
        except OSError:
            pass
    (outdir / "ida.stdout.txt").write_text(out, encoding="utf-8", errors="replace")
    meta = outdir / "meta.json"
    if meta.exists():
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            return True, {"functions": data.get("functions", []),
                          "count": len(data.get("functions", [])),
                          "log": str(log)}
        except Exception as exc:
            return False, "bad meta.json: %s" % exc
    return False, "no meta.json (see ida.stdout.txt); rc=%s" % rc


def run_objdump(path: Path, outdir: Path):
    od = shutil.which("objdump")
    if not od:
        return False, "objdump not found"
    rc, dis = run([od, "-d", "--no-show-raw-insn", path])
    rc2, hdrs = run([od, "-x", path])
    if rc != 0 and not dis:
        return False, dis[:400]
    (outdir / "disassembly.txt").write_text(dis, encoding="utf-8", errors="replace")
    (outdir / "headers.txt").write_text(hdrs, encoding="utf-8", errors="replace")
    funcs = []
    cur = None
    for line in dis.splitlines():
        m = re.match(r"^([0-9a-f]+) <([^>]+)>:", line)
        if m:
            cur = {"name": m.group(2), "addr": m.group(1), "body": []}
            funcs.append(cur)
        elif cur is not None and line.strip():
            cur["body"].append(line.strip())
    for f in funcs:
        f["pseudocode"] = "\n".join(f.pop("body"))
    # write per-function assembly files
    fdir = outdir / "decompiled"
    fdir.mkdir(exist_ok=True)
    for f in funcs:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f["name"])[:80]
        (fdir / ("%s_%s.asm" % (f["addr"], safe))).write_text(
            "/* %s @ %s (assembly only) */\n%s\n" % (f["name"], f["addr"], f["pseudocode"]),
            encoding="utf-8", errors="replace")
    return True, {"functions": funcs, "count": len(funcs),
                  "note": "objdump only: assembly, no C pseudocode"}


def write_pseudocode(outdir: Path, info: dict, res: dict, source_label: str):
    funcs = res.get("functions", [])
    parts = ["/*",
             " * PSEUDOCODE (reference only) -- %s" % source_label,
             " * target: %s" % info["path"],
             " * NOTE: this is decompiler output, NOT compilable source.",
             " *       Types/macros/globals are reconstructed guesses.",
             " *       Edit behaviour with `re_solve.py patch` or rebuild from your",
             " *       own C in `re_solve.py rebuild --source your.c`.",
             " */", ""]
    for f in funcs:
        parts.append("/* ---- %s @ %s ---- */" % (f.get("name", "?"), f.get("addr", f.get("ea", "?"))))
        parts.append(f.get("pseudocode", "") or "")
        parts.append("")
    (outdir / "pseudocode.c").write_text("\n".join(parts), encoding="utf-8", errors="replace")

    fdir = outdir / "decompiled"
    fdir.mkdir(exist_ok=True)
    for f in funcs:
        addr = f.get("addr", f.get("ea", "0")).replace("0x", "")
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", f.get("name", "fn"))[:80]
        (fdir / ("%s_%s.c" % (addr, name))).write_text(
            f.get("pseudocode", ""), encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
# decompile: managed / script formats
# --------------------------------------------------------------------------
def find_ilspy_dll():
    """ilspycmd shipped as a portable dll (tools/ilspycmd/.../ilspycmd.dll)."""
    import glob as _glob
    for pat in (str(HERE / "tools/ilspycmd/tools/net*/any/ilspycmd.dll"),
                str(Path.cwd() / "tools/ilspycmd/tools/net*/any/ilspycmd.dll"),
                str(HOME / "tools/ilspycmd/tools/net*/any/ilspycmd.dll")):
        hits = sorted(_glob.glob(pat), reverse=True)
        if hits:
            return Path(hits[0])
    return None


def decompile_dotnet(path: Path, outdir: Path, timeout: int) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    src = outdir / "decompiled"
    dnspy = find_tool("dnspy")
    ilspy = find_tool("ilspycmd")
    dll = find_ilspy_dll()
    dotnet = shutil.which("dotnet")
    # portable ilspycmd dll first: headless-safe (dnSpy.Console needs a real console)
    if dll and dotnet:
        rc, out = run([dotnet, "exec", str(dll), str(path.resolve()),
                       "-o", str(src)], timeout=timeout)
        (outdir / "ilspy.log").write_text(out, encoding="utf-8", errors="replace")
        if src.exists() and any(src.rglob("*.cs")):
            return {"engine": "ilspycmd", "sources": str(src),
                    "files": len(list(src.rglob("*.cs")))}
    if dnspy:
        rc, out = run([dnspy, "-o", str(src), str(path.resolve())], timeout=timeout)
        (outdir / "dnspy.log").write_text(out, encoding="utf-8", errors="replace")
        if src.exists() and any(src.rglob("*.cs")):
            return {"engine": "dnspy", "sources": str(src),
                    "files": len(list(src.rglob("*.cs")))}
    if ilspy:
        rc, out = run([ilspy, "-o", str(src), str(path.resolve())], timeout=timeout)
        (outdir / "ilspy.log").write_text(out, encoding="utf-8", errors="replace")
        if src.exists() and any(src.rglob("*.cs")):
            return {"engine": "ilspycmd", "sources": str(src),
                    "files": len(list(src.rglob("*.cs")))}
    return {"engine": "none",
            "errors": ["need dnSpy.Console.exe or ilspycmd (dotnet tool install -g ilspycmd)"]}


def find_cfr():
    for cand in (HERE / "tools" / "cfr.jar", Path.cwd() / "tools" / "cfr.jar",
                 HOME / "tools" / "cfr.jar", Path("/opt/cfr/cfr.jar")):
        if cand.exists():
            return cand
    return None


def decompile_java(path: Path, outdir: Path, timeout: int, is_apk=False) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java") or "java"
    outdir.mkdir(parents=True, exist_ok=True)

    # 1) CFR: single jar, no cache, no daemon -- most reliable for .jar/.class
    cfr = find_cfr()
    if cfr and not is_apk:
        src = outdir / "cfr"
        src.mkdir(exist_ok=True)
        rc, out = run([java, "-jar", str(cfr), str(path.resolve()),
                       "--outputdir", str(src)], timeout=timeout)
        (outdir / "cfr.log").write_text(out, encoding="utf-8", errors="replace")
        files = list(src.rglob("*.java"))
        if files:
            return {"engine": "cfr", "sources": str(src), "files": len(files)}

    src = outdir / "jadx"
    jadx = find_tool("jadx")
    if not jadx:
        return {"engine": "none",
                "errors": ["no Java decompiler: put cfr.jar in tools/ "
                           "(or install jadx)"]}
    cache = outdir / "jadx_cache"
    cache.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["JADX_CACHE_DIR"] = str(cache)
    base = [java, "-jar", str(jadx)] if jadx.suffix.lower() == ".jar" else [str(jadx)]
    cmd = base + ["-d", str(src), "--no-res", "-j", "2", str(path.resolve())]
    rc, out = run(cmd, timeout=timeout, env=env)
    (outdir / "jadx.log").write_text(out, encoding="utf-8", errors="replace")
    files = list(src.rglob("*.java")) if src.exists() else []
    if files:
        return {"engine": "jadx", "sources": str(src / "sources"), "files": len(files)}
    return {"engine": "jadx", "errors": [out[-800:] or "no java produced"]}


def decompile_pyc(path: Path, outdir: Path, timeout: int) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    src = outdir / "decompiled"
    src.mkdir(exist_ok=True)
    data = path.read_bytes()
    magic = struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0
    ver = PYC_MAGIC.get(magic, "unknown")
    pycdc = shutil.which("pycdc")
    if pycdc:
        rc, out = run([pycdc, str(path)])
        if rc == 0 and out.strip():
            (src / (path.stem + "_pycdc.py")).write_text(out, encoding="utf-8", errors="replace")
            return {"engine": "pycdc", "sources": str(src), "files": 1, "version": ver}
    for mod in ("decompyle3", "uncompyle6"):
        if run([sys.executable, "-c", "import %s" % mod])[0] == 0:
            out_py = src / (path.stem + "_%s.py" % mod)
            rc, out = run([sys.executable, "-m", mod, "-o", str(out_py), str(path)])
            if rc == 0 and out_py.exists():
                return {"engine": mod, "sources": str(src), "files": 1, "version": ver}
    # fallback: disassembly + strings, still fully editable round-trip via py_compile
    rc, out = run([sys.executable, "-m", "dis", str(path)])
    (src / (path.stem + "_dis.txt")).write_text(out, encoding="utf-8", errors="replace")
    consts = []
    for m in re.finditer(r"LOAD_CONST\s+\d+\s+\(([^)]{1,200})\)", out):
        consts.append(m.group(1))
    (src / (path.stem + "_consts.txt")).write_text("\n".join(consts), encoding="utf-8")
    return {"engine": "dis", "sources": str(src), "files": 1, "version": ver,
            "errors": ["no python decompiler installed for %s; wrote bytecode+consts instead "
                       "(pip install decompyle3 works for <=3.8, else use pycdc)" % ver]}


# --------------------------------------------------------------------------
# rebuild
# --------------------------------------------------------------------------
def rebuild(path: Path, info: dict, outdir: Path, source: Path, timeout: int) -> dict:
    kind = info["kind"]
    build = outdir / "rebuild"
    build.mkdir(parents=True, exist_ok=True)
    out_name = "%s_patched%s" % (path.stem, path.suffix)
    out = build / out_name

    if kind == "jar":
        srcs = list(source.rglob("*.java"))
        if not srcs:
            return {"ok": False, "error": "no .java sources under %s" % source}
        classes = build / "classes"
        classes.mkdir(exist_ok=True)
        javac = shutil.which("javac")
        if not javac:
            return {"ok": False, "error": "javac not found"}
        rc, log = run([javac, "-nowarn", "-d", str(classes)] + [str(s) for s in srcs], timeout=timeout)
        if rc != 0:
            return {"ok": False, "error": "javac failed", "log": log[-3000:]}
        jar = shutil.which("jar")
        mf = build / "MANIFEST.MF"
        main_class = info.get("main_class") or guess_main_class(srcs)
        body = "Manifest-Version: 1.0\r\n"
        if main_class:
            body += "Main-Class: %s\r\n" % main_class
        body += "\r\n"
        with open(mf, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        rc, log = run([jar, "cfm", str(out), str(mf), "-C", str(classes), "."], timeout=timeout)
        if rc != 0:
            return {"ok": False, "error": "jar failed", "log": log[-2000:]}
        return run_verify(out, ["java", "-jar", str(out)], timeout)

    if kind == "dotnet":
        srcs = list(source.rglob("*.cs"))
        if not srcs:
            return {"ok": False, "error": "no .cs sources under %s" % source}
        csc = find_tool("csc")
        if csc and csc.name.lower() == "csc.exe":
            cmd = [csc, "/nologo", "/target:exe", "/out:%s" % out] + [str(s) for s in srcs]
            rc, log = run(cmd, timeout=timeout)
            if rc != 0:
                return {"ok": False, "error": "csc failed", "log": log[-4000:]}
            return run_verify(out, [str(out)], timeout)
        sdk = run([shutil.which("dotnet") or "dotnet", "--list-sdks"])[1].strip()
        if sdk:
            proj = build / "proj"
            proj.mkdir(exist_ok=True)
            (proj / "p.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                '<AssemblyName>%s</AssemblyName></PropertyGroup>'
                '<ItemGroup><Compile Include="%s/**/*.cs" /></ItemGroup></Project>'
                % (path.stem, str(source).replace("\\", "/")), encoding="utf-8")
            rc, log = run([shutil.which("dotnet") or "dotnet", "build", "-c", "Release",
                           "-o", str(out.parent)], cwd=proj, timeout=timeout)
            built = out.parent / (path.stem + ".dll")
            if built.exists():
                out = built
                return run_verify(out, [shutil.which("dotnet") or "dotnet", str(out)], timeout)
            return {"ok": False, "error": "dotnet build failed", "log": log[-3000:]}
        return {"ok": False, "error": "no C# compiler: install .NET SDK or use "
                                      "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe"}

    if kind == "pyc":
        py = source if source.is_file() else next(iter(source.rglob("*.py")), None)
        if not py:
            return {"ok": False, "error": "no .py source under %s" % source}
        out = build / "%s_patched.pyc" % path.stem
        rc, log = run([sys.executable, "-m", "py_compile", str(py)])
        if rc != 0:
            return {"ok": False, "error": "py_compile failed", "log": log[-2000:]}
        cache = Path(str(py) + "c") if Path(str(py) + "c").exists() else None
        if cache is None:
            cache_dir = Path(str(py)).parent / "__pycache__"
            cands = list(cache_dir.glob(Path(py).stem + "*.pyc")) if cache_dir.exists() else []
            cache = cands[0] if cands else None
        if cache:
            shutil.copyfile(cache, out)
        return {"ok": out.exists(), "output": str(out)}

    if kind == "apk":
        apktool = find_tool("apktool")
        if not apktool:
            return {"ok": False, "error": "apktool not found"}
        decoded = source if source.is_dir() else build / "apk_decoded"
        if not (decoded / "apktool.yml").exists():
            rc, log = run([shutil.which("java") or "java", "-jar", str(apktool) if apktool.suffix == ".jar" else str(apktool),
                           "d", "-f", "-o", str(decoded), str(path.resolve())], timeout=timeout)
            if rc != 0:
                return {"ok": False, "error": "apktool d failed", "log": log[-3000:]}
        out = build / ("%s_patched.apk" % path.stem)
        rc, log = run([shutil.which("java") or "java", "-jar", str(apktool),
                       "b", str(decoded), "-o", str(out)], timeout=timeout)
        if rc != 0 or not out.exists():
            return {"ok": False, "error": "apktool b failed", "log": log[-3000:]}
        return run_verify(out, [str(out)], timeout)

    if kind in ("pe", "elf"):
        if not source.exists():
            return {"ok": False, "error": "native targets need --source (your own .c); "
                                          "see NOTES.md for patch mode"}
        if source.is_dir():
            srcs = list(source.glob("*.c"))
            if not srcs:
                return {"ok": False, "error": "no .c files in %s" % source}
        else:
            srcs = [source]
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            return {"ok": False, "error": "no gcc/clang"}
        bits = info.get("bits", 64)
        cmd = [cc, "-O0"]
        if bits == 32 and shutil.which("gcc"):
            cmd.append("-m32")
        cmd += ["-o", str(out)] + [str(s) for s in srcs]
        rc, log = run(cmd, timeout=timeout)
        if rc != 0:
            return {"ok": False, "error": "compile failed", "log": log[-3000:]}
        warn = None
        if kind == "elf":
            warn = ("note: host compiler produced %s; for a Linux ELF use "
                    "x86_64-linux-gnu-gcc or build inside WSL/container" %
                    ("PE on Windows" if IS_WIN else "native ELF"))
        return run_verify(out, [str(out)], timeout, warn)

    return {"ok": False, "error": "rebuild not implemented for kind=%s" % kind}


def guess_main_class(srcs):
    """Class name (package-qualified) of the file declaring `public static void main`."""
    for s in srcs:
        try:
            text = s.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"static\s+void\s+main\s*\(", text):
            pkg = re.search(r"(?m)^\s*package\s+([\w.]+)\s*;", text)
            cls = re.search(r"(?m)^\s*(?:public\s+)?(?:final\s+)?class\s+(\w+)", text)
            name = cls.group(1) if cls else s.stem
            return (pkg.group(1) + "." + name) if pkg else name
    return ""


def run_verify(out: Path, cmd, timeout, warn=None):
    res = {"ok": True, "output": str(out), "size": out.stat().st_size if out.exists() else 0}
    if warn:
        res["warning"] = warn
    rc, log = run(cmd, timeout=60)
    res["run_rc"] = rc
    res["run_output"] = log.strip()[:1500]
    return res


# --------------------------------------------------------------------------
# patch (native)
# --------------------------------------------------------------------------
def arch_mode(info):
    arch = (info.get("arch") or "").lower()
    bits = info.get("bits", 64)
    if "x86-64" in arch or arch in ("x86_64", "amd64"):
        return "x86", 64
    if arch.startswith("x86"):
        return "x86", 32
    if "arm64" in arch or arch == "aarch64":
        return "arm64", 64
    if arch.startswith("arm"):
        return "arm", 32
    return None, bits


def patch(path: Path, info: dict, va: int, asm: str, raw_bytes: str,
          outdir: Path, max_len: int, base_override: int):
    try:
        from keystone import (Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86,
                             KS_MODE_ARM, KS_MODE_LITTLE_ENDIAN,
                             KS_MODE_32, KS_MODE_64)
    except ImportError:
        return {"ok": False, "error": "keystone-engine missing: pip install keystone-engine"}
    arch, bits = arch_mode(info)
    if arch is None:
        return {"ok": False, "error": "unsupported arch for patching: %s" % info.get("arch")}
    if raw_bytes:
        try:
            code = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", raw_bytes))
        except ValueError:
            return {"ok": False, "error": "bad --bytes hex"}
    else:
        ks_arch = {"x86": KS_ARCH_X86, "arm": KS_ARCH_ARM,
                   "arm64": KS_ARCH_ARM64}[arch]
        ks_mode = {"x86": KS_MODE_64 if bits == 64 else KS_MODE_32,
                   "arm": KS_MODE_ARM, "arm64": KS_MODE_LITTLE_ENDIAN}[arch]
        try:
            ks = Ks(ks_arch, ks_mode)
            enc, _ = ks.asm(asm, addr=va)
        except Exception as exc:
            return {"ok": False, "error": "assemble failed: %s" % exc}
        code = bytes(enc)
    if len(code) > max_len:
        return {"ok": False, "error": "patch is %d bytes, max_len=%d" % (len(code), max_len)}

    data = bytearray(path.read_bytes())
    if info["kind"] == "pe":
        base = base_override or info["image_base"]
        off = pe_rva_to_off(info, va - base)
    elif info["kind"] == "elf":
        off = elf_vaddr_to_off(info, va)
    else:
        off = None
    if off is None or off + len(code) > len(data):
        return {"ok": False, "error": "cannot map VA %#x to a file offset" % va}
    before = bytes(data[off:off + len(code)])
    data[off:off + len(code)] = code
    if info["kind"] == "pe":
        pe_fix_checksum(data, info["checksum_off"])
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / ("%s.patched%s" % (path.stem, path.suffix))
    out.write_bytes(bytes(data))
    return {"ok": True, "output": str(out), "offset": off,
            "old": before.hex(), "new": code.hex(), "size": len(code)}


# --------------------------------------------------------------------------
# report helpers
# --------------------------------------------------------------------------
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

    def save(self, path: Path):
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8", errors="replace")


def do_triage(path: Path, info: dict, outdir: Path, log: Log):
    outdir.mkdir(parents=True, exist_ok=True)
    log.hdr("TRIAGE  %s" % path.name)
    log.p("  kind     : %s" % info["kind"])
    log.p("  size     : %s" % human(info["size"]))
    log.p("  sha256   : %s" % info["sha256"])
    for k in ("arch", "bits", "py_version", "main_class", "entries", "classes", "dex", "packer"):
        if info.get(k):
            log.p("  %-8s : %s" % (k, info[k]))
    for n in info.get("notes", []):
        log.p("  note     : %s" % n)
    if info.get("sections"):
        log.p("")
        log.p("  %-10s %10s %10s %8s" % ("section", "vaddr", "rawsize", "entropy"))
        for s in info["sections"]:
            log.p("  %-10s %10x %10d %8.2f%s" % (s["name"], s["vaddr"], s["rawsize"],
                                                  s["entropy"],
                                                  "   <- packed?" if s["entropy"] > 7.2 else ""))
    if info.get("segments"):
        log.p("  PT_LOAD segments: " + ", ".join(
            "%#x@%#x" % (s["memsz"], s["vaddr"]) for s in info["segments"][:8]))

    strings = rank_strings(extract_strings(path))
    try:
        text = path.read_bytes()[:8 << 20].decode("utf-8", "ignore")
    except Exception:
        text = ""
    flags = set()
    for _, _, s in strings:
        for m in FLAG_RE.finditer(s.encode("latin-1", "ignore")):
            flags.add(m.group(0).decode("latin-1"))
    log.p("")
    log.p("  strings  : %d (all written to strings.txt)" % len(strings))
    if flags:
        for f in sorted(flags):
            log.p("  [FLAG]   %s" % f)
    log.p("")
    log.p("  -- top strings --")
    for off, enc, s in strings[:40]:
        log.p("  %08x %-5s %s" % (off, enc, s[:150]))

    with open(outdir / "strings.txt", "w", encoding="utf-8", errors="replace") as fh:
        for off, enc, s in strings:
            fh.write("%08x\t%s\t%s\n" % (off, enc, s))

    imports = read_imports(path, info)
    if imports:
        log.p("")
        log.p("  -- imports / dynamic symbols --")
        for line in imports[:40]:
            log.p("  " + line[:150])
        (outdir / "imports.txt").write_text("\n".join(imports), encoding="utf-8", errors="replace")

    hits = []
    for api, why in INTERESTING_API.items():
        if re.search(rb"(?<![A-Za-z0-9_])" + re.escape(api.encode()) + rb"(?![A-Za-z0-9_])",
                     path.read_bytes()[:16 << 20]):
            hits.append("%s (%s)" % (api, why))
    if hits:
        log.p("")
        log.p("  -- interesting APIs present --")
        for h in dict.fromkeys(hits):
            log.p("  " + h)
    log.save(outdir / "triage.txt")
    return {"flags": sorted(flags), "string_count": len(strings), "api_hits": hits}


def do_decompile(path: Path, info: dict, outdir: Path, engine: str, timeout: int, log: Log):
    outdir.mkdir(parents=True, exist_ok=True)
    kind = info["kind"]
    if kind == "dotnet":
        res = decompile_dotnet(path, outdir, timeout)
    elif kind in ("jar", "class"):
        res = decompile_java(path, outdir, timeout, is_apk=False)
    elif kind in ("apk", "dex"):
        res = decompile_java(path, outdir, timeout, is_apk=True)
    elif kind == "pyc":
        res = decompile_pyc(path, outdir, timeout)
    elif kind in ("pe", "elf", "macho", "dos"):
        res = decompile_native(path, outdir, engine, timeout)
        if res.get("functions"):
            write_pseudocode(outdir, info, res, res.get("engine", "?"))
    else:
        res = {"engine": "none", "errors": ["unsupported kind %s for decompilation" % kind]}

    (outdir / "meta.json").write_text(json.dumps(
        {"target": str(path), "kind": kind, "engine": res.get("engine"),
         "count": res.get("count"), "errors": res.get("errors", []),
         "functions": [{"name": f.get("name"), "addr": f.get("addr", f.get("ea")),
                        "size": f.get("size"), "calls": f.get("calls", [])[:40]}
                       for f in res.get("functions", [])][:20000]},
        indent=1), encoding="utf-8")

    log.hdr("DECOMPILE  %s" % path.name)
    log.p("  engine   : %s" % res.get("engine"))
    if res.get("count"):
        log.p("  functions: %d" % res["count"])
    if res.get("sources"):
        log.p("  sources  : %s" % res["sources"])
    for e in res.get("errors", []):
        log.p("  [!] %s" % e)
    if res.get("functions"):
        log.p("")
        for f in sorted(res["functions"], key=lambda x: -(x.get("size") or 0))[:15]:
            log.p("  %-12s %-40s %s bytes" % (f.get("addr", f.get("ea", "?")),
                                              (f.get("name") or "?")[:40], f.get("size", "?")))
    log.p("")
    log.p("  next: edit a copy, then")
    log.p("    python re_solve.py rebuild %s --source <edited fs>   # managed/script" % outdir)
    log.p("    python re_solve.py patch   %s --va 0xADDR --asm \"...\"  # native" % path.name)
    log.save(outdir / "decompile.txt")
    return res


NOTES = """# {name} -- how to edit and put it back

Target: `{target}` (kind: **{kind}**, engine: **{engine}**)

## What you got

| path | contents |
|---|---|
| `triageref` | `triage.txt`, `strings.txt`, `imports.txt` |
| `pseudocode.c` / `decompiled/` | decompiler output, one file per function |
| `meta.json` | function table (name, address, size, calls) |
| `decompiled/` (managed) | **compilable** C# / Java sources |

## {heading}

{how}

## Rules that matter

* Decompiled native C is a **reference**, not source: types/macros/ABI are
  reconstructed. Recompiling it will not reproduce the original binary.
* Managed decompilers (C#/Java) round-trip well because the bytecode keeps
  types and names.
* Always keep the original file untouched; this tool only writes new files.
"""


def write_notes(outdir: Path, path: Path, info: dict, res: dict):
    kind = info["kind"]
    src = outdir / "decompiled"
    if kind in ("dotnet", "jar", "apk", "pyc"):
        heading = "Compile edited source back to the original type"
        how = {
            "dotnet": "`python re_solve.py rebuild %s --source %s` uses csc.exe "
                      "(or `dotnet build`) and runs the result.\n"
                      "If csc complains about missing references, add them with "
                      "`/r:...`." % (outdir.name, src),
            "jar": "`python re_solve.py rebuild %s --source %s` runs javac + jar and "
                   "reuses the original Main-Class.\nRun: `java -jar rebuild/*_patched.jar`."
                   % (outdir.name, src),
            "apk": "`python re_solve.py rebuild %s --source %s` rebuilds with apktool "
                   "(smali) then re-sign with apksigner before installing." % (outdir.name, src),
            "pyc": "`python re_solve.py rebuild %s --source %s` compiles your .py with "
                   "py_compile to a .pyc of the same type." % (outdir.name, src),
        }.get(kind, "")
    else:
        heading = "Editing a native binary (no true round-trip)"
        how = ("Native decompiler output cannot be recompiled into the same binary. "
               "Two real paths:\n\n"
               "1. **Patch an instruction** (keeps file type byte-exact):\n"
               "   `python re_solve.py patch {t} --va 0x401234 --asm \"jmp 0x401300\"`\n"
               "   `python re_solve.py patch {t} --va 0x401234 --bytes 90909090`\n\n"
               "2. **Reimplement** the routine in C from `pseudocode.c`, then:\n"
               "   `python re_solve.py rebuild {d} --source my.c`\n").format(
                   t=path.name, d=outdir.name)
    (outdir / "NOTES.md").write_text(NOTES.format(
        name=path.stem, target=path.name, kind=kind,
        engine=res.get("engine", "?"), heading=heading, how=how),
        encoding="utf-8")


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------
TOOL_HELP = {
    "ghidra": "download https://github.com/NationalSecurityAgency/ghidra/releases "
              "and set GHIDRA_HOME, or put it in C:/ghidra_*",
    "ida": "install IDA Pro (idat.exe/idat64.exe on PATH)",
    "jadx": "https://github.com/skylot/jadx/releases (jadx-*-all.jar)",
    "apktool": "https://apktool.org (apktool.jar + java)",
    "dnspy": "https://github.com/dnSpyEx/dnSpy/releases (dnSpy.Console.exe)",
    "ilspycmd": "dotnet tool install -g ilspycmd",
    "csc": "already ships with .NET Framework: C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe",
    "javac": "install a JDK",
    "jar": "install a JDK",
    "java": "install a JRE/JDK",
    "java": "install a JRE/JDK",
}


def do_doctor(log: Log):
    log.hdr("DOCTOR -- tool detection")
    checks = [
        ("ghidra", find_tool("ghidra"), "native decompile (preferred)"),
        ("ida", find_tool("ida"), "native decompile (fallback)"),
        ("jadx", find_tool("jadx"), "JAR/APK decompile"),
        ("apktool", find_tool("apktool"), "APK rebuild"),
        ("dnspy", find_tool("dnspy"), ".NET decompile"),
        ("ilspycmd", find_tool("ilspycmd"), ".NET decompile"),
        ("csc", find_tool("csc"), ".NET rebuild"),
    ]
    for label, p in [("java", shutil.which("java")), ("javac", shutil.which("javac")),
                     ("jar", shutil.which("jar")), ("dotnet", shutil.which("dotnet")),
                     ("gcc", shutil.which("gcc")), ("clang", shutil.which("clang")),
                     ("objdump", shutil.which("objdump")), ("readelf", shutil.which("readelf")),
                     ("upx", shutil.which("upx")), ("pycdc", shutil.which("pycdc")),
                     ("strings", shutil.which("strings"))]:
        checks.append((label, Path(p) if p else None, ""))
    for label, p, why in checks:
        log.p("  %-10s %-70s %s" % (label, str(p) if p else "MISSING", why if not p else ""))
        if not p and label in TOOL_HELP:
            log.p("  %-10s -> %s" % ("", TOOL_HELP[label]))
    try:
        import keystone
        log.p("  %-10s %s" % ("keystone", "OK %s (patching enabled)" % keystone.__version__))
    except ImportError:
        log.p("  %-10s %s" % ("keystone", "MISSING (pip install keystone-engine)"))
    log.p("")
    log.p("  python   : %s" % sys.version.split()[0])
    log.p("  platform : %s" % sys.platform)
    try:
        import pefile  # noqa: F401
        log.p("  pefile   : OK (extra PE detail)")
    except ImportError:
        log.p("  pefile   : missing (optional)")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="CTF reverse-engineering pipeline")
    ap.add_argument("command", choices=("doctor", "triage", "decompile", "rebuild", "patch"))
    ap.add_argument("target", nargs="?", help="binary / archive / directory")
    ap.add_argument("-o", "--out", help="output directory")
    ap.add_argument("--source", help="edited source dir or .c file for rebuild")
    ap.add_argument("--engine", default="auto", choices=("auto", "ghidra", "ida", "objdump"))
    ap.add_argument("--kind", help="override detected kind")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--va", help="virtual address to patch (hex)")
    ap.add_argument("--asm", help="assembly text to assemble into --va")
    ap.add_argument("--bytes", help="raw bytes (hex) to write at --va")
    ap.add_argument("--max-len", type=int, default=16, help="max patch length in bytes")
    ap.add_argument("--base", type=int, default=0, help="override image base (PE)")
    ap.add_argument("--main-class", help="JAR Main-Class override")
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args(argv)
    log = Log()

    if args.command == "doctor":
        do_doctor(log)
        if args.json:
            print(json.dumps({"tools": {k: bool(find_tool(k)) for k in TOOL_GLOBS}}))
        return 0

    if not args.target:
        sys.exit("need a target file")

    path = Path(args.target)
    if not path.exists():
        sys.exit("no such file: %s" % path)
    info = classify(path)
    if args.kind:
        info["kind"] = args.kind
    outdir = Path(args.out or ("%s_re" % path.stem))

    if args.command == "triage":
        res = do_triage(path, info, outdir, log)
        if args.json:
            print(json.dumps(res, indent=1))
        return 0

    if args.command == "decompile":
        res = do_decompile(path, info, outdir, args.engine, args.timeout, log)
        write_notes(outdir, path, info, res)
        if args.json:
            print(json.dumps({"engine": res.get("engine"), "count": res.get("count"),
                              "errors": res.get("errors", []), "out": str(outdir)}, indent=1))
        return 0 if res.get("engine") not in (None, "none") else 2

    if args.command == "rebuild":
        if not args.source:
            sys.exit("--source is required (edited sources or your own .c)")
        log.hdr("REBUILD  %s" % path.name)
        if args.main_class:
            info["main_class"] = args.main_class
        res = rebuild(path, info, outdir, Path(args.source), args.timeout)
        for k, v in res.items():
            log.p("  %-10s %s" % (k, v))
        if args.json:
            print(json.dumps(res, indent=1))
        return 0 if res.get("ok") else 1

    if args.command == "patch":
        if not args.va or not (args.asm or args.bytes):
            sys.exit("--va plus --asm or --bytes required")
        log.hdr("PATCH  %s" % path.name)
        res = patch(path, info, int(args.va, 0), args.asm or "", args.bytes or "",
                    outdir, args.max_len, args.base)
        for k, v in res.items():
            log.p("  %-8s %s" % (k, v))
        if args.json:
            print(json.dumps(res, indent=1))
        return 0 if res.get("ok") else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
