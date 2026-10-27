# CTF toolkit

One entry point plus one tool per challenge category. Everything is
stdlib-first, auto-detects the tools already on the machine, and writes a
report + artefacts into `<target>_*` so you can keep digging by hand.

```
python ctf_solve.py mystery.bin      # detect + route
python ctf_solve.py doctor           # what is installed / what is missing
python ctf_solve.py --list           # routing table
```

| module | category | what it does |
|---|---|---|
| `ctf_pcap.py` | Network | DNS/HTTP/TLS/ICMP/USB-HID analysis, creds, covert channels, file carving |
| `re_solve.py` | Reversing | triage → decompile (Ghidra/IDA/CFR/ILSpy/dnSpy) → patch or rebuild |
| `ctf_apk.py` | Android | manifest/exported components/secrets, dex→Java, rebuild + sign |
| `ctf_ipa.py` | iOS | Info.plist/Mach-O/entitlements/class dump, Mach-O patch, repack |
| `ctf_forensics.py` | Forensics | disk images (MBR/GPT), exact-size carving, EXIF, PDF, zip/Office metadata |
| `ctf_stegano.py` | Stego | PNG/BMP/WAV LSB + every bitplane, chunks, trailing data, zero-width, whitespace |
| `ctf_crypto.py` | Crypto | encoding chains, XOR (single/repeating/crib), RSA (fermat/Wiener/small-e), hashes |
| `ctf_misc.py` | Misc | unknown files, polyglots, nested archives, zip cracking, Brainfuck/Ook |

Flags are hunted everywhere: raw bytes, DNS TXT, HTTP bodies (gzip/chunked
decoded), carved files, archive members, EXIF/PDF streams, LSB planes,
zero-width text, decoder chains.

---

## Install

```bash
pip install scapy keystone-engine        # keystone only needed for patching
```

Optional but strongly recommended (auto-detected, nothing is required):

| tool | used by | note |
|---|---|---|
| Wireshark `tshark` | pcap | USB HID extraction, expert info |
| Ghidra `analyzeHeadless` | re_solve | best free native decompiler |
| IDA Pro `idat64` | re_solve | native decompiler (Hex-Rays) |
| Android SDK build-tools | ctf_apk | aapt/apksigner/zipalign |
| `apktool.jar` | ctf_apk | rebuild + smali |
| `jadx` | ctf_apk | optional (1.5.3 hangs on JDK 24; dex2jar is used instead) |
| JDK (`javac`,`jar`,`keytool`) | ctf_apk, re_solve | JAR rebuild + signing |
| `tools/cfr.jar` | re_solve, ctf_apk | bundled; JAR/dex→jar decompiler |
| `tools/dex-tools*/` | ctf_apk | bundled; dex→jar |
| `tools/ilspycmd/` | re_solve | bundled; .NET → C# (runs on the .NET 6 runtime) |
| `csc.exe` (.NET Framework) | re_solve | rebuild C# |
| `gcc`/`clang` | re_solve | rebuild reimplemented native code |

`python ctf_solve.py doctor` prints exactly which of these your box has.

---

## Reversing: what "compile it back" means per format

This is the part most tooling lies about, so it is explicit here:

| target | decompile | rebuild to the original type | verified |
|---|---|---|---|
| .NET exe/dll | `ilspycmd` (bundled) or dnSpy | `csc` → new exe, runs | **yes**: edited the base64 flag, rebuilt, new flag accepted, old rejected |
| `.jar` / `.class` | CFR (bundled) | `javac` + `jar` (manifest/Main-Class preserved) | **yes**: same test, `java -jar` verified |
| APK / DEX | dex2jar + CFR → Java, apktool → manifest/smali | `apktool b` + zipalign + apksigner | **yes**: full decode → build → zipalign → sign → verify on a real 14 MiB APK (package/sdk preserved) |
| IPA (Mach-O) | Ghidra/IDA | patch the Mach-O → repack IPA (signing needs macOS/`ldid`) | **yes**: arm64 `ret` patched into `__text`, IPA repacked |
| `.pyc` | `pycdc`/`decompyle3` if present, else bytecode+consts | `py_compile` → `.pyc` | mechanics verified |
| native ELF/PE | Ghidra or IDA → pseudo-C | **not recompilable**; use `patch` (byte-exact) or reimplement in C and `rebuild` | **yes**: patched `check()` to `mov eax,1; ret`, binary now accepts any input |

```bash
# native edit that keeps the file type byte-exact
python re_solve.py patch crackme.exe --va 0x140001450 --asm "mov eax,1; ret"
python re_solve.py patch crackme.exe --va 0x401234 --bytes 90909090

# decompile with a chosen engine
python re_solve.py decompile crackme.exe -o crackme_re --engine ghidra
python re_solve.py decompile app.jar  -o app_re        # CFR, no engine flag needed
```

Why native pseudo-C is not compilable: decompilers invent types, drop macros
and cannot recover the original build/ABI. Ghidra/IDA output is a *reference*.
Two real paths exist and both are implemented: instruction patching (exact
bytes, keeps checksums valid) and reimplementation in C.

---

## Network (pcap)

```bash
python ctf_pcap.py cap.pcap            # full report
python ctf_pcap.py cap.pcap --dump-streams --all-strings --json
```

Single streaming pass. Reports sections are ordered by signal: FLAGS → creds →
covert channels → DNS exfil → carved files → strings. Extras:

* HTTP: gzip/deflate/chunked bodies decoded, Basic/Bearer auth, form/JSON
  creds, uploads, served files carved with `Content-Disposition` names.
* DNS: label-chain reassembly, base32/base64/hex decode, TXT contents.
* Covert: ICMP payload reassembly, IP-ID/TTL/TCP-seq low-byte channels.
* Carving: magic-validated (gzip inflates, zip opens, PNG ends at IEND),
  overlap suppression, nested archives expanded and re-scanned.
* USB HID: keyboard decoding and mouse delta traces.
* Every string with its offset is written to `strings_raw.txt`; automatic
  base64/hex/rot13/xor attempts go to `decodes.txt` so nothing needs decoding
  by hand first.

---

## Android

```bash
python ctf_apk.py triage    app.apk     # package, sdk, permissions, exported, secrets
python ctf_apk.py decompile app.apk     # dex2jar+CFR -> app_apk/java/**, apktool -> manifest/res
python ctf_apk.py decompile app.apk --smali   # full apktool decode (slow) for smali edits
python ctf_apk.py rebuild   app.apk     # apktool b + zipalign + apksigner (debug keystore)
python ctf_apk.py install   app_signed.apk --serial emulator-5554
```

`triage` needs no decompilation: it scans every zip entry (dex, assets, res,
native libs) for flags, API keys, Firebase/S3 URLs, JWT/private keys, and
anti-analysis signatures, and prints exported components plus the signing cert.

## iOS

```bash
python ctf_ipa.py triage    app.ipa
python ctf_ipa.py decompile app.ipa --engine ghidra
python ctf_ipa.py classes   app.ipa
python ctf_ipa.py patch     app.ipa --va 0x100003F00 --asm "mov w0, #0; ret"
```

Parses Info.plist (ATS, URL schemes, privacy strings), the provisioning
profile entitlements, fat/thin Mach-O (arch, UUID, cryptid, sections,
dylibs), and detects Flutter/Unity/RN/Xamarin. Encrypted App Store binaries
(`cryptid != 0`) must be dumped from a device first — the report says so.

## Forensics

```bash
python ctf_forensics.py all    disk.img
python ctf_forensics.py carve  disk.img --types png,jpg,zip,pdf --min-size 64
python ctf_forensics.py exif   photo.jpg
python ctf_forensics.py pdf    doc.pdf
python ctf_forensics.py zipmeta archive.zip   # docx/xlsx text extracted too
```

mmap-based, so multi-GB images are fine. Carvings have **exact sizes** where
the format allows it (PE section table, ELF program headers, ZIP EOCD, gzip
end-of-stream, PNG IEND, PDF %%EOF) instead of "rest of the image".

## Stego

```bash
python ctf_stegano.py analyze image.png     # chunks + LSB sweep + trailing data
python ctf_stegano.py raw     blob.bin --bits 0
python ctf_stegano.py zero    text.txt
python ctf_stegano.py white   text.txt
```

The sweep tries every channel subset × bit 0-7 × bit order and keeps payloads
that are ≥85% printable or contain a flag.

## Crypto

```bash
python ctf_crypto.py decode "ZmxhZ3s...=="      # BFS over 18 decoders, 6 layers
python ctf_crypto.py xor -f enc.bin --brute
python ctf_crypto.py xor -f enc.bin --crib "flag{"
python ctf_crypto.py rsa --n 0x.. --e 3 --c 0x..
python ctf_crypto.py hash 5f4dcc3b... --wordlist rockyou.txt
python ctf_crypto.py caesar "Sdvvh{...}"
python ctf_crypto.py vigenere "..." --key LEMON
```

RSA covers trial-division/2-prime factoring, Fermat (close primes), Wiener's
attack (small d), small-e nth root, and decrypts to bytes with flag detection.

## Misc

```bash
python ctf_misc.py sniff   mystery.bin     # polyglot detection
python ctf_misc.py scan    mystery.bin     # flags, base64/hex layers, xor preview
python ctf_misc.py nested  archive.zip     # recursive extraction
python ctf_misc.py zipcrack secret.zip --wordlist rockyou.txt --digits 6
python ctf_misc.py brainfuck code.txt      # also translates Ook!
```

---

## Verification (what was actually run)

Every path below was executed on this machine, not just written:

| test | result |
|---|---|
| pcapng input (converted capture) | same 7/7 flags as the pcap run |
| synthetic pcap (80 pkts) with DNS exfil, TXT flag, gzip+chunked HTTP, Basic auth, form creds, FTP/SMTP creds, SNI, SSH, ICMP tunnel, IP-ID and TCP-seq channels, ARP spoof, PNG/ZIP payloads | 7/7 flags + all creds + all covert channels found; carved ZIP opens, PNG valid |
| 100k-packet / 14 MiB pcap | completes end-to-end (scapy dissection dominates runtime) |
| PE crackme via IDA → 85 functions, real C | `check`/`main` recovered |
| same PE via Ghidra 11.4.2 | 86 functions, `check` body present |
| arm64 Mach-O object via IDA | `_check`/`_main` recovered |
| keystone patch of `check()` in PE | patched exe accepts a wrong password (VA→offset + PE checksum) |
| .NET crackme → ilspycmd → edit → `csc` | new flag accepted, old rejected |
| JAR crackme → CFR → edit → `javac`+`jar` | new flag accepted, old rejected |
| APK signing path | zipalign + apksigner + `apksigner verify` all ok |
| synthetic IPA (arm64 Mach-O, plist, provisioning, Firebase plist) | plist/ATS/Mach-O/flag/secrets parsed; `ret` patched at 0x1000; IPA repacked |
| real APK (FridayCake.apk, 14 MiB) | package/sdk/permissions/exported/cert/900 entries; dex2jar+CFR → 2980 Java files; apktool manifest; full rebuild+sign verified (apksigner verify ok, debug cert) |
| synthetic 4 MiB disk image (MBR, FAT32, PNG/JPEG+EXIF/ZIP/PDF payloads) | partition+fs detected, all four files carved at exact sizes, EXIF/PDF/ZIP flags found |
| PNG with LSB payload + tEXt + trailing data, zero-width file, whitespace file | all three flags recovered |
| base64→hex chain, single-byte XOR, RSA with Fermat-factorable n, Caesar | all recovered |

Known environment notes: jadx 1.5.3 hangs on JDK 24 (dex2jar+CFR used instead),
`dnSpy.Console` needs a real console (ilspycmd used instead), Ghidra 12.x needs
JDK 25 while Ghidra 11.4.2 works with JDK 24. None of these block the tools.

## Layout

```
ctf_solve.py        front-end router
ctf_pcap.py         network
re_solve.py         reversing + ReExport.java (Ghidra) + re_ida_export.py (IDA)
ctf_apk.py          Android
ctf_ipa.py          iOS
ctf_forensics.py    forensics
ctf_stegano.py      steganography
ctf_crypto.py       crypto/encoding
ctf_misc.py         misc
tools/cfr.jar       Java decompiler
tools/dex-tools*/   dex → jar
tools/ilspycmd/     .NET → C# (portable, net6.0)
```

Output directories are disposable; the originals are never modified.
