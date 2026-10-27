#!/usr/bin/env python3
"""ctf_crypto.py -- crypto / encoding challenge toolkit.

  python ctf_crypto.py decode "ZmxhZ3s...=="        # auto chain, up to 6 layers
  python ctf_crypto.py decode -f cipher.txt --out decoded.txt
  python ctf_crypto.py xor   -f enc.bin --brute
  python ctf_crypto.py xor   -f enc.bin --crib "flag{"
  python ctf_crypto.py xor   -f enc.bin --key 0x42
  python ctf_crypto.py xor   -f enc.bin --key "ICE"
  python ctf_crypto.py rsa   --n 0x.. --e 3 --c 0x..
  python ctf_crypto.py hash  5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
  python ctf_crypto.py caesar "Wklv lv d..."
  python ctf_crypto.py vigenere "..." --key LEMON

Every command prints candidates ranked by plausibility (flag pattern, English
score, printability) so the right layer is on top instead of buried.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import math
import re
import string
import sys
from collections import Counter
from pathlib import Path

FLAG_RE = re.compile(
    r"(?i)(?:flag|ctf|htb|thm|picoctf|uiuctf|ictf|ductf|corctf|grey|wctf|actf|"
    r"pctf|hitcon|idek|sekai|buckeye|utflag|lactf|byuctf|tjctf|damctf|sctf|"
    r"justctf|hxp|rwctf|bi0s|csaw|naham|0ctf|seccon|utctf|dice)"
    r"[a-z0-9_-]*\{[^}\r\n\x00]{1,200}\}"
)
ENGLISH = "etaoin shrdlu cmfwyp vbgkjqxz"


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c in string.printable and c not in "\x0b\x0c") / len(s)


def english_score(s: str) -> float:
    """Higher = more like English (or a flag)."""
    if not s:
        return -1e9
    score = 0.0
    low = s.lower()
    if FLAG_RE.search(s):
        score += 500
    for w in ("the ", " and ", "ing", "ion", "flag", "ctf", "key", "pass",
              "secret", "you", "that", "this", "with", "have"):
        if w in low:
            score += 25
    freq = Counter(c for c in low if c.isalpha())
    total = sum(freq.values()) or 1
    score += sum(freq.get(c, 0) / total * (26 - i) for i, c in enumerate(ENGLISH)) * 40
    score += printable_ratio(s) * 40
    score -= abs(len(low.split()) - max(1, len(low) // 6)) * 2
    return score


# --------------------------------------------------------------------------
# single-layer decoders: name -> callable(text) -> bytes|None
# --------------------------------------------------------------------------
def _b(fn):
    def inner(s: str):
        try:
            return fn(s)
        except Exception:
            return None
    return inner


def dec_base64(s):
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", t) or len(t) < 8:
        return None
    return base64.b64decode(t + "=" * (-len(t) % 4), validate=True)


def dec_base64url(s):
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", t) or len(t) < 8:
        return None
    return base64.urlsafe_b64decode(t.replace("-", "+").replace("_", "/") + "=" * (-len(t) % 4))


def dec_base32(s):
    t = re.sub(r"\s+", "", s).upper()
    if not re.fullmatch(r"[A-Z2-7]*={0,6}", t) or len(t) < 8:
        return None
    return base64.b32decode(t + "=" * (-len(t) % 8))


def dec_base85(s):
    t = re.sub(r"\s+", "", s)
    if len(t) < 8:
        return None
    return base64.b85decode(t.encode())


def dec_ascii85(s):
    t = re.sub(r"\s+", "", s)
    if len(t) < 8:
        return None
    return base64.a85decode(t.encode(), adobe=False)


def dec_hex(s):
    t = re.sub(r"(?i)0x|\s|:", "", s).strip()
    if len(t) < 8 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    return bytes.fromhex(t)


def dec_binary(s):
    t = re.sub(r"[^01]", "", s)
    if len(t) < 8 or len(re.findall(r"[01]+", s)[0]) < 4:
        return None
    chunks = re.findall(r"[01]{8}", s)
    if len(chunks) < 2:
        return None
    return bytes(int(c, 2) for c in chunks)


def dec_octal(s):
    parts = re.findall(r"\b[0-7]{3}\b", s)
    if len(parts) < 4:
        return None
    return bytes(int(p, 8) for p in parts if int(p, 8) < 256)


def dec_decimal(s):
    parts = re.findall(r"\b\d{2,3}\b", s)
    if len(parts) < 4 or not all(int(p) < 256 for p in parts):
        return None
    return bytes(int(p) for p in parts)


def dec_rot13(s):
    return _rot(s, 13)


def dec_rot47(s):
    return "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in s)


def _rot(s, n):
    out = []
    for c in s:
        if c.islower():
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif c.isupper():
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def dec_atbash(s):
    out = []
    for c in s:
        if c.islower():
            out.append(chr(219 - ord(c)))
        elif c.isupper():
            out.append(chr(155 - ord(c)))
        else:
            out.append(c)
    return "".join(out)


def dec_url(s):
    if "%" not in s:
        return None
    from urllib.parse import unquote
    out = unquote(s)
    return out if out != s else None


def dec_html(s):
    if "&" not in s:
        return None
    import html
    out = html.unescape(s)
    return out if out != s else None


def dec_reverse(s):
    return s[::-1]


MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
         "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
         "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
         "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
         "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
         "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
         "-..-.": "/", "-....-": "-", ".--.-.": "@"}


def dec_morse(s):
    if not re.fullmatch(r"[.\-/\s_|]+", s.strip()):
        return None
    out = []
    for word in re.split(r"\s{2,}|/|\|", s.strip()):
        for code in word.split():
            out.append(MORSE.get(code, "?"))
        out.append(" ")
    res = "".join(out).strip()
    return res if "?" not in res and len(res) > 2 else None


def dec_bacon(s):
    letters = re.sub(r"[^A-Za-z]", "", s)
    if len(letters) < 5 or not set(letters.upper()) <= set("AB"):
        return None
    out = []
    for i in range(0, len(letters) - 4, 5):
        chunk = letters[i:i + 5].upper()
        out.append(chr(int("".join("1" if c == "B" else "0" for c in chunk), 2) + 65))
    return "".join(out)


def dec_a1z26(s):
    parts = [int(x) for x in re.findall(r"\b\d{1,2}\b", s)]
    if len(parts) < 4 or not all(1 <= p <= 26 for p in parts):
        return None
    return "".join(chr(p + 96) for p in parts)


DECODERS = [
    ("base64", _b(dec_base64)), ("base64url", _b(dec_base64url)),
    ("base32", _b(dec_base32)), ("hex", _b(dec_hex)),
    ("binary", _b(dec_binary)), ("base85", _b(dec_base85)),
    ("ascii85", _b(dec_ascii85)), ("octal", _b(dec_octal)),
    ("decimal", _b(dec_decimal)), ("rot13", _b(dec_rot13)),
    ("rot47", _b(dec_rot47)), ("atbash", _b(dec_atbash)),
    ("url", _b(dec_url)), ("html", _b(dec_html)), ("morse", _b(dec_morse)),
    ("bacon", _b(dec_bacon)), ("a1z26", _b(dec_a1z26)),
    ("reverse", _b(dec_reverse)),
]


def chain_decode(text: str, max_depth=5, top=12):
    """BFS over decoder chains, best-first by plausibility."""
    results = []
    seen = set()
    frontier = [(0.0, text, [])]
    for depth in range(max_depth):
        nxt = []
        for _score, cur, path in frontier[:40]:
            for name, fn in DECODERS:
                out = fn(cur)
                if out is None:
                    continue
                s = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
                if not s or s == cur or len(s) < 2:
                    continue
                key = (s, tuple(path + [name]))
                if key in seen:
                    continue
                seen.add(key)
                score = english_score(s)
                results.append((score, s, path + [name]))
                if depth + 1 < max_depth:
                    nxt.append((score, s, path + [name]))
        nxt.sort(key=lambda x: -x[0])
        frontier = nxt[:20]
    results.sort(key=lambda r: -r[0])
    dedup, seen_s = [], set()
    for score, s, path in results:
        if s in seen_s:
            continue
        seen_s.add(s)
        dedup.append((score, s, path))
        if len(dedup) >= top:
            break
    return dedup


# --------------------------------------------------------------------------
# xor
# --------------------------------------------------------------------------
def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def crack_single_xor(data: bytes):
    best = []
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        try:
            s = pt.decode("utf-8")
        except UnicodeDecodeError:
            s = pt.decode("latin-1")
        best.append((english_score(s), k, s, pt))
    best.sort(key=lambda x: -x[0])
    return best


def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def crack_repeating_xor(data: bytes, maxlen=32):
    cands = []
    for klen in range(1, min(maxlen, len(data) // 4) + 1):
        blocks = [data[i:i + klen] for i in range(0, min(len(data), klen * 8), klen)]
        if len(blocks) < 3:
            continue
        dists = [hamming(blocks[i], blocks[i + 1]) / klen for i in range(len(blocks) - 1)]
        cands.append((sum(dists) / len(dists), klen))
    cands.sort()
    results = []
    for _d, klen in cands[:5]:
        key = bytearray()
        for i in range(klen):
            col = data[i::klen]
            key.append(crack_single_xor(col)[0][1])
        pt = xor_bytes(data, bytes(key))
        results.append((english_score(pt.decode("latin-1")), bytes(key), pt))
    results.sort(key=lambda x: -x[0])
    return results


def crib_drag(data: bytes, crib: bytes, maxlen=32):
    hits = []
    for klen in range(1, maxlen + 1):
        for off in range(klen):
            key = bytearray(klen)
            ok = True
            for i, c in enumerate(crib):
                pos = off + i
                k = pos % klen
                if key[k] and key[k] != data[pos] ^ c:
                    ok = False
                    break
                key[k] = data[pos] ^ c
            if ok and key.count(0) < klen:
                pt = xor_bytes(data, bytes(key))
                hits.append((english_score(pt.decode("latin-1")), bytes(key), pt))
    hits.sort(key=lambda x: -x[0])
    return hits


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------
def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def factor_small(n: int, limit=5_000_000):
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f * f <= n and f <= limit:
        if n % f == 0:
            return f, n // f
        f += 2
    return None


def fermat(n: int, tries=200000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(tries):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def wiener(n: int, e: int):
    """Wiener's attack: small d."""
    def cont_frac(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b

    def convergents(cf):
        n0, d0, n1, d1 = 0, 1, 1, 0
        for q in cf:
            n0, d0, n1, d1 = n1, d1, q * n1 + n0, q * d1 + d0
            yield n1, d1
    for k, d in convergents(cont_frac(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            t = math.isqrt(disc)
            if t * t == disc:
                return d, (s + t) // 2, (s - t) // 2
    return None


def int_to_bytes(v: int) -> bytes:
    ln = (v.bit_length() + 7) // 8
    return v.to_bytes(ln, "big")


def rsa(args):
    n, e = args.n, args.e
    out = []
    if n is None or e is None:
        print("need --n and --e")
        return 1
    p, q = args.p, args.q
    if not p or not q:
        f = factor_small(n)
        if not f:
            f = fermat(n)
        if f:
            p, q = f
            out.append("factored n -> p=%d q=%d" % (p, q))
    if p and q:
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            out.append("e not invertible mod phi (e|phi?)")
            d = None
        out.append("d = %d" % d if d else "")
        out.append("phi = %d" % phi)
        if args.c is not None:
            m = pow(args.c, d, n) if d else None
            if m is not None:
                raw = int_to_bytes(m)
                out.append("plaintext int  = %d" % m)
                out.append("plaintext text = %r" % raw.decode("latin-1"))
                fm = FLAG_RE.search(raw.decode("latin-1", "ignore"))
                if fm:
                    out.append("[FLAG] %s" % fm.group(0))
            if args.c < n ** 0.5 and e == 3:
                root = round(args.c ** (1 / 3))
                for cand in (root - 1, root, root + 1):
                    if cand ** 3 == args.c:
                        out.append("cube root (no padding) -> %r" % int_to_bytes(cand).decode("latin-1"))
    else:
        out.append("could not factor n (too big for trial/fermat)")
        if args.c is not None and e <= 5:
            r = int(round(args.c ** (1.0 / e)))
            for cand in (r - 2, r - 1, r, r + 1, r + 2):
                if cand > 0 and cand ** e == args.c:
                    out.append("e-th root (no padding) -> %r" % int_to_bytes(cand).decode("latin-1"))
    w = wiener(n, e)
    if w:
        d, p2, q2 = w
        out.append("[wiener] d=%d p=%d q=%d" % (d, p2, q2))
        if args.c is not None:
            out.append("[wiener] plaintext = %r" % int_to_bytes(pow(args.c, d, n)).decode("latin-1"))
    for line in out:
        if line:
            print(line)
    return 0


# --------------------------------------------------------------------------
HASHES = [(32, "MD5"), (40, "SHA1"), (56, "SHA224"), (64, "SHA256"),
          (96, "SHA384"), (128, "SHA512"), (32, "NTLM/MD5"), (13, "DES(crypt)")]


def hash_cmd(value: str, wordlist: Path | None):
    v = value.strip()
    kinds = [name for ln, name in HASHES if len(v) == ln and re.fullmatch(r"[0-9a-fA-F]+", v)]
    if re.fullmatch(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", v):
        kinds = ["bcrypt"]
    print("candidate types:", ", ".join(kinds) or "unknown")
    if not wordlist:
        print("(pass --wordlist to crack)")
        return 0
    algos = {"MD5": hashlib.md5, "SHA1": hashlib.sha1, "SHA224": hashlib.sha224,
             "SHA256": hashlib.sha256, "SHA384": hashlib.sha384, "SHA512": hashlib.sha512,
             "NTLM/MD5": hashlib.md5}
    use = [k for k in kinds if k in algos]
    n = 0
    with open(wordlist, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            w = line.rstrip("\r\n")
            if not w:
                continue
            for k in use:
                if algos[k](w.encode()).hexdigest() == v.lower():
                    print("CRACKED %s = %r" % (k, w))
                    return 0
            n += 1
            if n % 200000 == 0:
                print("... %d candidates" % n, file=sys.stderr)
    print("not in wordlist (%d tried)" % n)
    return 1


def caesar(text: str, top=5):
    res = []
    for shift in range(26):
        s = _rot(text, shift)
        res.append((english_score(s), shift, s))
    res.sort(key=lambda x: -x[0])
    for score, shift, s in res[:top]:
        print("shift=%2d score=%6.1f  %s" % (shift, score, s[:160]))
    return 0


def vigenere(text: str, key: str):
    k = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not k:
        print("bad key")
        return 1
    out = []
    j = 0
    for c in text:
        if c.isalpha():
            base = 97 if c.islower() else 65
            out.append(chr((ord(c) - base - k[j % len(k)]) % 26 + base))
            j += 1
        else:
            out.append(c)
    s = "".join(out)
    print(s)
    m = FLAG_RE.search(s)
    if m:
        print("[FLAG]", m.group(0))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="crypto/encoding toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("decode")
    p.add_argument("text", nargs="?")
    p.add_argument("-f", "--file")
    p.add_argument("--depth", type=int, default=5)
    p.add_argument("--out")

    p = sub.add_parser("xor")
    p.add_argument("data", nargs="?")
    p.add_argument("-f", "--file")
    p.add_argument("--key")
    p.add_argument("--brute", action="store_true")
    p.add_argument("--crib")
    p.add_argument("--hex", action="store_true", help="input text is hex")

    p = sub.add_parser("rsa")
    for name in ("n", "e", "c", "p", "q", "phi"):
        p.add_argument("--" + name, type=lambda x: int(x, 0))

    p = sub.add_parser("hash")
    p.add_argument("value")
    p.add_argument("--wordlist")

    p = sub.add_parser("caesar")
    p.add_argument("text")
    p.add_argument("--top", type=int, default=5)

    p = sub.add_parser("vigenere")
    p.add_argument("text")
    p.add_argument("--key", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "decode":
        if args.file:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        else:
            text = args.text or ""
        if not text:
            sys.exit("no input")
        results = chain_decode(text, args.depth)
        lines = []
        for score, s, path in results:
            line = "[%7.1f] %-32s %s" % (score, "->".join(path), s[:200].replace("\n", "\\n"))
            print(line)
            lines.append(line)
            for m in FLAG_RE.finditer(s):
                print("   [FLAG] %s" % m.group(0))
        best = results[0][1] if results else text
        if args.out:
            Path(args.out).write_text(best, encoding="utf-8")
        return 0

    if args.cmd == "xor":
        if args.file:
            data = Path(args.file).read_bytes()
        else:
            data = (args.data or "").encode()
        if args.hex:
            data = bytes.fromhex(re.sub(r"\s", "", data.decode()))
        if args.key:
            key = bytes.fromhex(re.sub(r"\s", "", args.key[2:])) if args.key.lower().startswith("0x") \
                else args.key.encode()
            pt = xor_bytes(data, key)
            print("key=%r" % key)
            print(pt.decode("latin-1"))
            for m in FLAG_RE.finditer(pt.decode("latin-1", "ignore")):
                print("[FLAG]", m.group(0))
            return 0
        if args.crib:
            for score, key, pt in crib_drag(data, args.crib.encode())[:5]:
                print("key=%r score=%.1f %s" % (key, score, pt[:160].decode("latin-1", "replace")))
            return 0
        print("-- single byte --")
        for score, k, s, pt in crack_single_xor(data)[:5]:
            print("key=0x%02x score=%6.1f %s" % (k, score, s[:160].replace("\n", "\\n")))
            for m in FLAG_RE.finditer(s):
                print("   [FLAG] %s" % m.group(0))
        if len(data) >= 16:
            print("-- repeating key --")
            for score, key, pt in crack_repeating_xor(data)[:5]:
                print("key=%r score=%.1f %s" % (key, score, pt[:160].decode("latin-1", "replace")))
                for m in FLAG_RE.finditer(pt.decode("latin-1", "ignore")):
                    print("   [FLAG] %s" % m.group(0))
        return 0

    if args.cmd == "rsa":
        return rsa(args)
    if args.cmd == "hash":
        return hash_cmd(args.value, Path(args.wordlist) if args.wordlist else None)
    if args.cmd == "caesar":
        return caesar(args.text, args.top)
    if args.cmd == "vigenere":
        return vigenere(args.text, args.key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
