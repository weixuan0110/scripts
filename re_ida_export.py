"""IDA Pro headless export script (IDA 7.x-9.x / IDAPython 3).

Called by re_solve.py as:
    idat64 -A -c -S"re_ida_export.py <outdir>" -Lida.log target

Writes <outdir>/meta.json, <outdir>/pseudocode.c and <outdir>/decompiled/*.c
Falls back to disassembly when Hex-Rays is not available.
"""
import json
import os
import re
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_lines
import ida_nalt
import ida_pro
import idautils

def _outdir():
    """IDA passes script args via idc.ARGV (sys.argv is unreliable)."""
    try:
        import idc
        args = list(getattr(idc, "ARGV", []) or [])[1:]
    except Exception:
        args = []
    for a in args:
        if a and os.path.isdir(a):
            return a
    return "."


OUTDIR = _outdir()


def safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name or "fn")[:80]


def get_strings():
    out = []
    try:
        import ida_strlist
        ida_strlist.build_strlist()
        for i in range(ida_strlist.get_strlist_qty()):
            si = ida_strlist.string_info_t()
            if not ida_strlist.get_strlist_item(si, i):
                continue
            try:
                val = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
            except Exception:
                val = None
            if val:
                out.append({"addr": hex(si.ea), "type": "str", "value": val.decode("latin-1", "replace")})
    except Exception:
        pass
    if not out:
        for ea in idautils.Strings():
            try:
                out.append({"addr": hex(int(ea)), "type": "str", "value": str(ea)})
            except Exception:
                pass
    return out


def get_imports():
    out = []
    try:
        import ida_imports

        def cb(ea, name, ordinal):
            out.append(name or ("ord_%d" % ordinal))
            return True
        for i in range(ida_imports.get_import_module_qty()):
            ida_imports.enum_import_names(i, cb)
    except Exception:
        try:
            for i in range(ida_nalt.get_import_module_qty()):
                def cb2(ea, name, ordinal):
                    out.append(name or ("ord_%d" % ordinal))
                    return True
                ida_nalt.enum_import_names(i, cb2)
        except Exception:
            pass
    return out


def main():
    ida_auto.auto_wait()
    os.makedirs(OUTDIR, exist_ok=True)
    fndir = os.path.join(OUTDIR, "decompiled")
    os.makedirs(fndir, exist_ok=True)

    decay = True
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            decay = False
    except Exception:
        decay = False

    functions = []
    combined = ["/* IDA decompiler output -- reference only, NOT compilable source */", ""]
    n = ida_funcs.get_func_qty()
    for i in range(n):
        f = ida_funcs.getn_func(i)
        if f is None:
            continue
        name = ida_funcs.get_func_name(f.start_ea) or ("sub_%X" % f.start_ea)
        code = ""
        if decay:
            try:
                cf = ida_hexrays.decompile(f)
                code = str(cf) if cf else ""
            except Exception as exc:
                code = "/* decompile error: %r */" % (exc,)
        if not code:
            lines = []
            ea = f.start_ea
            while ea < f.end_ea and len(lines) < 3000:
                line = ida_lines.generate_disasm_line(ea, 0)
                if line:
                    lines.append("%08X  %s" % (ea, ida_lines.tag_remove(line)))
                ea = ida_bytes.next_head(ea, f.end_ea)
                if ea is None or ea == ida_bytes.BADADDR:
                    break
            code = "\n".join(lines)
        calls = []
        for x in idautils.CodeRefsFrom(f.start_ea, 0):
            cn = ida_funcs.get_func_name(x)
            if cn:
                calls.append(cn)
        functions.append({"name": name, "addr": hex(f.start_ea),
                          "size": int(f.end_ea - f.start_ea),
                          "calls": calls[:40]})
        with open(os.path.join(fndir, "%X_%s.c" % (f.start_ea, safe(name))),
                  "w", encoding="utf-8", errors="replace") as fh:
            fh.write("// %s @ %#x  (IDA decompiler output; reference only)\n%s\n"
                     % (name, f.start_ea, code))
        combined.append("/* ---- %s @ %#x ---- */" % (name, f.start_ea))
        combined.append(code)
        combined.append("")

    strings = get_strings()
    imports = get_imports()
    meta = {"program": ida_nalt.get_root_filename(),
            "language": "ida", "imageBase": hex(ida_nalt.get_imagebase()),
            "functions": functions, "strings": strings[:200000], "imports": imports}
    with open(os.path.join(OUTDIR, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False)
    with open(os.path.join(OUTDIR, "pseudocode.c"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(combined))
    print("RE_IDA: %d functions, hexrays=%s, %d strings" % (len(functions), decay, len(strings)))
    ida_pro.qexit(0)


main()
