#!/usr/bin/env bash
# =============================================================================
# check-php2shell.sh – Check for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
# Target system: Ubuntu + PHP-FPM (nginx or Apache)
#
# This script is read-only: it does not change, delete or restart anything.
# Usage:    sudo bash check-php2shell.sh [SINCE-DATE] [WEBROOT]
# Example:  sudo bash check-php2shell.sh 2026-08-01 /var/www
# Output:   terminal + report at ./php2shell-report-<timestamp>.txt (current directory)
# =============================================================================

set -u

SINCE="${1:-2026-08-01}"           # Start of review period (Sophos recommendation: 2026-08-01)
WEBROOT="${2:-/var/www}"           # Webroot(s) to scan for web shells
REPORT="$PWD/php2shell-report-$(date +%Y%m%d-%H%M%S).txt"
HITS=0

# Fixed upstream patch releases per branch
declare -A FIXED=( [8.5]=12 [8.4]=27 [8.3]=36 [8.2]=35 )

# --- Helper functions --------------------------------------------------------
if [[ -t 1 ]]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1;34m'; N=$'\e[0m'
else R=; G=; Y=; B=; N=; fi

section() { echo; echo "${B}=== $* ===${N}"; }
ok()      { echo "${G}[OK]${N}   $*"; }
warn()    { echo "${Y}[WARN]${N} $*"; }
hit()     { echo "${R}[HIT]${N}  $*"; HITS=$((HITS+1)); }
info()    { echo "       $*"; }

# zgrep across rotated logs (.log, .log.1, .log.2.gz …); only existing files are used
zgrep_logs() {  # $1 = regex, remaining args = file globs
  local re="$1"; shift
  local files=()
  for f in "$@"; do [[ -f "$f" ]] && files+=("$f"); done
  ((${#files[@]})) || return 1
  zgrep -HEi "$re" "${files[@]}" 2>/dev/null
}

if [[ $EUID -ne 0 ]]; then
  echo "Please run with sudo (logs and session files are only readable by root)."
  exit 1
fi

exec > >(tee "$REPORT") 2>&1
echo "PHP2Shell check on $(hostname) – $(date '+%F %T %Z')"
echo "Review period since: $SINCE   Webroot: $WEBROOT"

# =============================================================================
section "1. Installed PHP-FPM versions and patch status"
# =============================================================================
FPM_VERS=()
for d in /etc/php/*/fpm; do
  [[ -d $d ]] && FPM_VERS+=( "$(basename "$(dirname "$d")")" )
done
# Fallback: versions of running master processes ("php-fpm: master process (/etc/php/8.4/fpm/php-fpm.conf)")
while read -r v; do
  [[ " ${FPM_VERS[*]} " == *" $v "* ]] || FPM_VERS+=( "$v" )
done < <(pgrep -a -f 'php-fpm: master process' 2>/dev/null | grep -oE '/php/[0-9]+\.[0-9]+/' | grep -oE '[0-9]+\.[0-9]+' | sort -u)

if ((${#FPM_VERS[@]} == 0)); then
  warn "No PHP-FPM installation found under /etc/php/*/fpm."
fi

for v in "${FPM_VERS[@]}"; do
  bin="/usr/sbin/php-fpm$v"
  pkgver=$(dpkg-query -W -f='${Version}' "php$v-fpm" 2>/dev/null || echo "?")
  upstream=$("$bin" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  info "php$v-fpm  package: $pkgver   binary: ${upstream:-?}"

  patched=0
  # a) Compare upstream version (e.g. ondrej PPA)
  if [[ -n "${upstream:-}" && -n "${FIXED[$v]:-}" ]]; then
    patch=${upstream##*.}
    (( patch >= FIXED[$v] )) && patched=1
  fi
  # b) Ubuntu backport: CVE mentioned in the package changelog?
  cl="/usr/share/doc/php$v-fpm/changelog.Debian.gz"
  [[ -f $cl ]] || cl="/usr/share/doc/php$v-common/changelog.Debian.gz"
  if [[ -f $cl ]] && zgrep -qE "CVE-2026-10961[89]" "$cl" 2>/dev/null; then
    patched=1; info "Fix found in Ubuntu changelog ($cl)."
  fi

  if ((patched)); then ok "php$v-fpm is patched."
  elif [[ -z "${FIXED[$v]:-}" ]]; then
    hit "php$v-fpm: version $v is EOL or has no upstream fix – check changelog/vendor!"
  else
    hit "php$v-fpm: no fix detected (requires $v.${FIXED[$v]} or an Ubuntu backport)."
  fi

  # c) Is the master process still running old code? (started before package install)
  pid=$(pgrep -o -f "php-fpm: master process.*php/$v/" || true)
  if [[ -n "$pid" ]]; then
    started=$(stat -c %Y "/proc/$pid" 2>/dev/null || echo 0)
    installed=$(stat -c %Y "$bin" 2>/dev/null || echo 0)
    if (( started < installed )); then
      hit "php$v-fpm running since $(date -d @"$started" '+%F %T') – OLDER than the binary ($(date -d @"$installed" '+%F %T')). Restart required: systemctl restart php$v-fpm"
    else
      ok "php$v-fpm was restarted after the update ($(date -d @"$started" '+%F %T'))."
    fi
    if ls -l "/proc/$pid/exe" 2>/dev/null | grep -q "(deleted)"; then
      hit "php$v-fpm: running binary was deleted/replaced – old code still in memory!"
    fi
  else
    info "php$v-fpm: no running master process."
  fi

  # d) Relevant INI values (effective FPM configuration)
  if [[ -x $bin ]]; then
    "$bin" -i 2>/dev/null | grep -E "^(memory_limit|session.upload_progress.enabled|session.upload_progress.name|session.save_path|fatal_error_backtraces|log_errors|error_log) " \
      | sed 's/^/       ini: /'
  fi
done

# =============================================================================
section "2. PHP-FPM / web server error logs: memory errors & crashes"
# =============================================================================
ERR_LOGS=( /var/log/php*-fpm.log* /var/log/nginx/error.log* /var/log/apache2/error.log* )
# Add custom error_log paths from the FPM pools
while read -r p; do ERR_LOGS+=( "$p"* ); done < <(
  grep -rhoE "^\s*php_(admin_)?value\[error_log\]\s*=\s*\S+" /etc/php/*/fpm/pool.d/ 2>/dev/null \
  | awk -F= '{gsub(/ /,"",$2); print $2}')

out=$(zgrep_logs "Allowed memory size of [0-9]+ bytes exhausted|Out of memory" "${ERR_LOGS[@]}")
if [[ -n "$out" ]]; then
  n=$(wc -l <<<"$out"); warn "$n memory fatals found (last 20):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "No memory-exhausted messages."; fi

out=$(zgrep_logs "in Unknown on line 0|Failed to decode session object|PHP Request Startup" "${ERR_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "Errors BEFORE script start (typical exploit pattern):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "No pre-startup errors ('Unknown on line 0')."; fi

out=$(zgrep_logs "SIGSEGV|SIGBUS|exited on signal|core dumped|child [0-9]+ .*signal" "${ERR_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "FPM worker crashes found (last 20):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "No worker crashes in the logs."; fi

# journald / kernel (segfaults often only show up here)
out=$(journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -Ei "php-fpm.*segfault")
out+=$(journalctl -u 'php*-fpm*' --since "$SINCE" --no-pager 2>/dev/null \
       | grep -Ei "signal|segfault|memory size|out of memory")
if [[ -n "$out" ]]; then
  hit "journald: crashes/memory errors since $SINCE:"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "journald: no FPM crashes since $SINCE."; fi

# =============================================================================
section "3. Access logs: scanners, POST→500, php://filter"
# =============================================================================
ACC_LOGS=( /var/log/nginx/access.log* /var/log/apache2/access.log* /var/log/apache2/*access*.log* )

out=$(zgrep_logs "php2shell" "${ACC_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "Known PHP2Shell scanner user agents:"
  tail -30 <<<"$out" | sed 's/^/       /'
  info "Source IPs:"; sed 's/^[^:]*://' <<<"$out" | awk '{print $1}' | sort | uniq -c | sort -rn | head | sed 's/^/       /'
else ok "No 'php2shell' user agents."; fi

out=$(zgrep_logs "php://(filter|input)|PHP_SESSION_UPLOAD_PROGRESS|sess_[a-z0-9]{20,}" "${ACC_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "Requests with php://filter / session file paths (web shell retrieval):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "No php://filter or session file requests."; fi

# POST/PUT/PATCH with 500/502 per IP (combined log format: $6=method, $9=status)
out=$(for f in "${ACC_LOGS[@]}"; do [[ -f $f ]] && zcat -f "$f"; done 2>/dev/null \
  | awk '$6 ~ /"(POST|PUT|PATCH)/ && ($9==500 || $9==502) {print $1}' | sort | uniq -c | sort -rn | head -15)
if [[ -n "$out" ]]; then
  warn "POST/PUT/PATCH with HTTP 500/502 – top IPs (look for clusters):"
  sed 's/^/       /' <<<"$out"
else ok "No POST requests with 500/502."; fi

# Unusual requests for PHP probe files
out=$(zgrep_logs '"(GET|POST) /(php2shell-probe|vuln\.php|phpinfo\.php|info\.php|pi\.php|i\.php)' "${ACC_LOGS[@]}")
[[ -n "$out" ]] && { warn "Probes for phpinfo/test files:"; tail -15 <<<"$out" | sed 's/^/       /'; }

# =============================================================================
section "4. Session files: injected PHP code"
# =============================================================================
SESS_DIRS=( /var/lib/php/sessions /tmp )
for v in "${FPM_VERS[@]}"; do
  d=$(/usr/sbin/php-fpm$v -i 2>/dev/null | awk -F'=> ' '/^session.save_path/{print $2; exit}' | sed 's/^[0-9]*;//; s/ *$//')
  [[ -n "$d" && "$d" != "no value" && -d "$d" ]] && SESS_DIRS+=( "$d" )
done
while read -r d; do [[ -d "$d" ]] && SESS_DIRS+=( "$d" ); done < <(
  grep -rhoE "session.save_path\]\s*=\s*\S+" /etc/php/*/fpm/pool.d/ 2>/dev/null | awk -F= '{gsub(/ /,"",$2);print $2}')

found=0
for d in $(printf '%s\n' "${SESS_DIRS[@]}" | sort -u); do
  res=$(grep -rlaE "<\?php|PWNED::|system\(|shell_exec|passthru|base64_decode|eval\(" \
        --include='sess_*' "$d" 2>/dev/null)
  if [[ -n "$res" ]]; then
    hit "Suspicious code in session files under $d:"; sed 's/^/       /' <<<"$res"; found=1
  fi
done
((found)) || ok "No session files containing PHP code."

# =============================================================================
section "5. Webroot: new/modified PHP files & web shell patterns"
# =============================================================================
if [[ -d $WEBROOT ]]; then
  cnt=$(find "$WEBROOT" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) -newermt "$SINCE" 2>/dev/null | wc -l)
  warn "$cnt PHP files new/modified since $SINCE (normal after deployments – review list, max. 50):"
  find "$WEBROOT" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) -newermt "$SINCE" \
       -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort -r | head -50 | sed 's/^/       /'

  res=$(grep -rlE --include='*.php' --include='*.phtml' --include='*.php[0-9]' \
        "PWNED::|system\(\s*\\\$_(GET|POST|REQUEST)|shell_exec\(\s*\\\$_|passthru\(\s*\\\$_|eval\(\s*(base64_decode|gzinflate|str_rot13)\(" \
        "$WEBROOT" 2>/dev/null | head -50)
  if [[ -n "$res" ]]; then
    hit "Typical web shell patterns found (review manually!):"; sed 's/^/       /' <<<"$res"
  else ok "No typical web shell patterns in the webroot."; fi

  res=$(find "$WEBROOT" -type f -name '*.php' -path '*upload*' 2>/dev/null | head -20)
  [[ -n "$res" ]] && { warn "PHP files inside upload directories:"; sed 's/^/       /' <<<"$res"; }
else
  warn "Webroot $WEBROOT does not exist – pass it as the 2nd parameter."
fi

# =============================================================================
section "6. Running processes: shells/downloaders under PHP-FPM"
# =============================================================================
# Look up worker PIDs with pgrep (it never matches itself), then inspect their direct children.
# Columns: pid ppid user lstart(5 fields) cmd → $9 is the executable.
out=""
pool_pids=$(pgrep -d, -f '^php-fpm: pool' || true)
if [[ -n "$pool_pids" ]]; then
  out=$(ps -o pid,ppid,user,lstart,cmd --ppid "$pool_pids" 2>/dev/null \
    | awk 'NR>1 && $9 ~ /(^|\/)(sh|bash|dash|python[0-9.]*|perl|curl|wget|nc|ncat|socat|base64)$/')
fi
if [[ -n "$out" ]]; then
  hit "Child processes of PHP-FPM workers:"; sed 's/^/       /' <<<"$out"
else ok "No shell/download processes under PHP-FPM."; fi

# Outbound network connections from shell processes
out=$(ss -tnp 2>/dev/null | grep -E 'users:\(\("(sh|bash|perl|python[0-9.]*|nc|socat)"' )
[[ -n "$out" ]] && { hit "Outbound connections from shell processes:"; sed 's/^/       /' <<<"$out"; }

# Cron jobs of the web server user
out=$(crontab -l -u www-data 2>/dev/null)
[[ -n "$out" ]] && { warn "Crontab of www-data (normally empty):"; sed 's/^/       /' <<<"$out"; }

# =============================================================================
section "Summary"
# =============================================================================
if ((HITS)); then
  echo "${R}$HITS critical findings.${N} Review hits manually. If compromise is confirmed:"
  info "- Isolate the server, don't just delete the web shell"
  info "- Rotate all secrets (DB, API keys, TLS keys) – CVE-2026-109618 leaks memory"
  info "- Invalidate sessions (clear the session directory)"
else
  echo "${G}No critical findings.${N} Note: request bodies are not in access logs;"
  info "a negative result is not proof the system is clean."
fi
echo; echo "Report saved: $REPORT"
