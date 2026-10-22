# PHP2Shell Checker for Ubuntu + PHP-FPM

`check-php2shell.sh` is a read-only Bash script that checks an Ubuntu server running **PHP-FPM** (behind nginx or Apache) for exposure to, and signs of exploitation of, **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619).

It checks whether your PHP-FPM builds are patched and whether the running processes actually use the patched code. It then looks through logs, session files, the webroot and running processes for indicators of compromise.

> **The script is read-only.** It does not change, delete or restart anything. The only file it writes is its report.

## Requirements

- Ubuntu (or a Debian-based system with the same layout) with PHP-FPM installed under `/etc/php/<version>/fpm`
- nginx and/or Apache with logs in the default locations (`/var/log/nginx`, `/var/log/apache2`)
- Bash 4+, plus standard tools: `zgrep`, `zcat`, `awk`, `find`, `ps`, `ss`, `journalctl`, `dpkg-query`
- Root privileges, because logs and session files are only readable by root

## Usage

```bash
sudo bash check-php2shell.sh [SINCE-DATE] [WEBROOT]
```

| Parameter    | Default      | Description                                                                 |
|--------------|--------------|-----------------------------------------------------------------------------|
| `SINCE-DATE` | `2026-08-01` | Start of the review period (`YYYY-MM-DD`). The default follows Sophos' recommendation. |
| `WEBROOT`    | `/var/www`   | Directory that is scanned for new/modified PHP files and web shells.        |

Example:

```bash
sudo bash check-php2shell.sh 2026-08-01 /var/www
```

Output goes to the terminal (colored when it is a TTY). A copy is saved in the directory you run the script from:

```
./php2shell-report-<YYYYmmdd-HHMMSS>.txt
```

## What it checks

### 1. Installed PHP-FPM versions and patch status
For every PHP version that has an `fpm` directory under `/etc/php`:
- It compares the upstream version against the first fixed release of each branch:

  | Branch | Fixed in |
  |--------|----------|
  | 8.5    | 8.5.12   |
  | 8.4    | 8.4.27   |
  | 8.3    | 8.3.36   |
  | 8.2    | 8.2.35   |

- It looks for the CVE IDs in the Ubuntu package changelog to detect distribution backports.
- It flags branches that are EOL or have no upstream fix.
- It flags an FPM master process that started **before** the binary was installed, or whose binary was deleted/replaced. In both cases the old, vulnerable code is still in memory and a restart is required.
- It prints relevant effective INI values (`memory_limit`, `session.upload_progress.*`, `session.save_path`, logging settings).

### 2. Error logs: memory errors and crashes
It scans PHP-FPM, nginx and Apache error logs, including rotated and gzipped files and custom `error_log` paths from the FPM pools, plus journald, for:
- `Allowed memory size … exhausted` / `Out of memory`
- Errors before script start (`in Unknown on line 0`, `Failed to decode session object`, `PHP Request Startup`), which is a typical exploit pattern
- Worker crashes (`SIGSEGV`, `SIGBUS`, `core dumped`, kernel segfaults)

### 3. Access logs
- Known `php2shell` scanner user agents, with a summary of source IPs
- Requests containing `php://filter`, `php://input`, `PHP_SESSION_UPLOAD_PROGRESS` or session file names
- Clusters of `POST`/`PUT`/`PATCH` requests that returned HTTP 500/502, grouped by IP
- Probes for phpinfo/test files

### 4. Session files
It searches `sess_*` files in `/var/lib/php/sessions`, `/tmp` and every configured `session.save_path` for injected PHP code (`<?php`, `system(`, `shell_exec`, `eval(`, `base64_decode`, …).

### 5. Webroot
- Lists PHP files created/modified since `SINCE-DATE` (up to 50)
- Looks for typical web shell patterns, such as `system($_GET…)` or `eval(base64_decode(…))`
- Lists PHP files inside upload directories

### 6. Running processes
- Shells, interpreters or downloaders (`sh`, `bash`, `python`, `perl`, `curl`, `wget`, `nc`, `socat`, …) running as children of PHP-FPM workers
- Outbound network connections owned by shell processes
- A non-empty crontab for `www-data`

## Reading the results

| Marker   | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| `[OK]`   | Nothing suspicious found for this check.                                |
| `[WARN]` | Worth reviewing. It is often benign, for example PHP files changed by a deployment. |
| `[HIT]`  | Critical finding that needs manual investigation. It counts toward the summary. |

The summary at the end shows the number of critical findings.

**If a compromise is confirmed:**
- Isolate the server. Deleting the web shell alone is not enough.
- Rotate all secrets (database credentials, API keys, TLS keys). CVE-2026-109618 leaks memory.
- Invalidate all sessions by clearing the session directory.
- Update PHP-FPM and **restart** the service: `systemctl restart php<version>-fpm`.

## Limitations

- Request bodies do not appear in access logs. A clean result is **not** proof that the system was not compromised.
- Log analysis only covers logs that still exist. Logs rotated away before `SINCE-DATE` are not included.
- The access-log analysis of methods and status codes assumes the default *combined* log format.
- The pattern matching is heuristic and can produce false positives and false negatives. Always review findings manually.

## License

[MIT](LICENSE)
