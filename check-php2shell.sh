#!/usr/bin/env bash
# =============================================================================
# check-php2shell.sh – Prüfung auf PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
# Zielsystem: Ubuntu + PHP-FPM (nginx oder Apache)
#
# Das Skript ist rein lesend: es ändert, löscht oder startet nichts neu.
# Aufruf:   sudo bash check-php2shell.sh [SEIT-DATUM] [WEBROOT]
# Beispiel: sudo bash check-php2shell.sh 2026-08-01 /var/www
# Ergebnis: Ausgabe im Terminal + Bericht unter /root/php2shell-report-<Zeit>.txt
# =============================================================================

set -u

SINCE="${1:-2026-08-01}"           # Prüfzeitraum ab (Sophos-Empfehlung: 01.08.2026)
WEBROOT="${2:-/var/www}"           # Webroot(s) für Webshell-Suche
REPORT="/root/php2shell-report-$(date +%Y%m%d-%H%M%S).txt"
HITS=0

# Gefixte Upstream-Versionen
declare -A FIXED=( [8.5]=12 [8.4]=27 [8.3]=36 [8.2]=35 )

# --- Hilfsfunktionen ---------------------------------------------------------
if [[ -t 1 ]]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1;34m'; N=$'\e[0m'
else R=; G=; Y=; B=; N=; fi

section() { echo; echo "${B}=== $* ===${N}"; }
ok()      { echo "${G}[OK]${N}   $*"; }
warn()    { echo "${Y}[WARN]${N} $*"; }
hit()     { echo "${R}[FUND]${N} $*"; HITS=$((HITS+1)); }
info()    { echo "       $*"; }

# zgrep über rotierte Logs (.log, .log.1, .log.2.gz …), Dateien müssen existieren
zgrep_logs() {  # $1 = Regex, Rest = Glob-Muster
  local re="$1"; shift
  local files=()
  for f in "$@"; do [[ -f "$f" ]] && files+=("$f"); done
  ((${#files[@]})) || return 1
  zgrep -HEi "$re" "${files[@]}" 2>/dev/null
}

if [[ $EUID -ne 0 ]]; then
  echo "Bitte mit sudo ausführen (Logs und Session-Dateien sind nur für root lesbar)."
  exit 1
fi

exec > >(tee "$REPORT") 2>&1
echo "PHP2Shell-Prüfung auf $(hostname) – $(date '+%F %T %Z')"
echo "Zeitraum ab: $SINCE   Webroot: $WEBROOT"

# =============================================================================
section "1. Installierte PHP-FPM-Versionen und Patch-Stand"
# =============================================================================
mapfile -t FPM_VERS < <(ls -1 /etc/php 2>/dev/null | while read -r v; do
  [[ -d /etc/php/$v/fpm ]] && echo "$v"; done)

if ((${#FPM_VERS[@]} == 0)); then
  warn "Keine PHP-FPM-Installation unter /etc/php/*/fpm gefunden."
fi

for v in "${FPM_VERS[@]}"; do
  bin="/usr/sbin/php-fpm$v"
  pkgver=$(dpkg-query -W -f='${Version}' "php$v-fpm" 2>/dev/null || echo "?")
  upstream=$("$bin" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  info "php$v-fpm  Paket: $pkgver   Binary: ${upstream:-?}"

  patched=0
  # a) Upstream-Version (z. B. ondrej-PPA) vergleichen
  if [[ -n "${upstream:-}" && -n "${FIXED[$v]:-}" ]]; then
    patch=${upstream##*.}
    (( patch >= FIXED[$v] )) && patched=1
  fi
  # b) Ubuntu-Backport: CVE im Paket-Changelog?
  cl="/usr/share/doc/php$v-fpm/changelog.Debian.gz"
  [[ -f $cl ]] || cl="/usr/share/doc/php$v-common/changelog.Debian.gz"
  if [[ -f $cl ]] && zgrep -qE "CVE-2026-10961[89]" "$cl" 2>/dev/null; then
    patched=1; info "Fix im Ubuntu-Changelog gefunden ($cl)."
  fi

  if ((patched)); then ok "php$v-fpm ist gepatcht."
  elif [[ -z "${FIXED[$v]:-}" ]]; then
    hit "php$v-fpm: Version $v ist EOL bzw. ohne Upstream-Fix – Changelog/Anbieter prüfen!"
  else
    hit "php$v-fpm: Kein Fix erkennbar (benötigt $v.${FIXED[$v]} oder Ubuntu-Backport)."
  fi

  # c) Läuft der Master-Prozess noch mit altem Code? (Start vor Paket-Installation)
  pid=$(pgrep -o -f "php-fpm: master process.*php/$v/" || true)
  if [[ -n "$pid" ]]; then
    started=$(stat -c %Y "/proc/$pid" 2>/dev/null || echo 0)
    installed=$(stat -c %Y "$bin" 2>/dev/null || echo 0)
    if (( started < installed )); then
      hit "php$v-fpm läuft seit $(date -d @"$started" '+%F %T') – ÄLTER als das Binary ($(date -d @"$installed" '+%F %T')). Neustart nötig: systemctl restart php$v-fpm"
    else
      ok "php$v-fpm wurde nach dem Update neu gestartet ($(date -d @"$started" '+%F %T'))."
    fi
    if ls -l "/proc/$pid/exe" 2>/dev/null | grep -q "(deleted)"; then
      hit "php$v-fpm: laufendes Binary ist gelöscht/ersetzt – alter Code im Speicher!"
    fi
  else
    info "php$v-fpm: kein laufender Master-Prozess."
  fi

  # d) Relevante INI-Werte (wirksame FPM-Konfiguration)
  if [[ -x $bin ]]; then
    "$bin" -i 2>/dev/null | grep -E "^(memory_limit|session.upload_progress.enabled|session.upload_progress.name|session.save_path|fatal_error_backtraces|log_errors|error_log) " \
      | sed 's/^/       ini: /'
  fi
done

# =============================================================================
section "2. PHP-FPM-/Webserver-Error-Logs: Speicherfehler & Crashes"
# =============================================================================
ERR_LOGS=( /var/log/php*-fpm.log* /var/log/nginx/error.log* /var/log/apache2/error.log* )
# Zusätzlich eigene error_log-Pfade aus den FPM-Pools
while read -r p; do ERR_LOGS+=( "$p"* ); done < <(
  grep -rhoE "^\s*php_(admin_)?value\[error_log\]\s*=\s*\S+" /etc/php/*/fpm/pool.d/ 2>/dev/null \
  | awk -F= '{gsub(/ /,"",$2); print $2}')

out=$(zgrep_logs "Allowed memory size of [0-9]+ bytes exhausted|Out of memory" "${ERR_LOGS[@]}")
if [[ -n "$out" ]]; then
  n=$(wc -l <<<"$out"); warn "$n Speicher-Fatals gefunden (letzte 20):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "Keine Memory-Exhausted-Meldungen."; fi

out=$(zgrep_logs "in Unknown on line 0|Failed to decode session object|PHP Request Startup" "${ERR_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "Fehler VOR Skriptstart (typisches Exploit-Muster):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "Keine Pre-Startup-Fehler ('Unknown on line 0')."; fi

out=$(zgrep_logs "SIGSEGV|SIGBUS|exited on signal|core dumped|child [0-9]+ .*signal" "${ERR_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "FPM-Worker-Crashes gefunden (letzte 20):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "Keine Worker-Crashes in den Logs."; fi

# journald / Kernel (Segfaults landen oft nur hier)
out=$(journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -Ei "php-fpm.*segfault")
out+=$(journalctl -u 'php*-fpm*' --since "$SINCE" --no-pager 2>/dev/null \
       | grep -Ei "signal|segfault|memory size|out of memory")
if [[ -n "$out" ]]; then
  hit "journald: Crashes/Speicherfehler seit $SINCE:"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "journald: keine FPM-Crashes seit $SINCE."; fi

# =============================================================================
section "3. Access-Logs: Scanner, POST→500, php://filter"
# =============================================================================
ACC_LOGS=( /var/log/nginx/access.log* /var/log/apache2/access.log* /var/log/apache2/*access*.log* )

out=$(zgrep_logs "php2shell" "${ACC_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "Bekannte PHP2Shell-Scanner-User-Agents:"
  tail -30 <<<"$out" | sed 's/^/       /'
  info "Quell-IPs:"; sed 's/^[^:]*://' <<<"$out" | awk '{print $1}' | sort | uniq -c | sort -rn | head | sed 's/^/       /'
else ok "Keine 'php2shell'-User-Agents."; fi

out=$(zgrep_logs "php://(filter|input)|PHP_SESSION_UPLOAD_PROGRESS|sess_[a-z0-9]{20,}" "${ACC_LOGS[@]}")
if [[ -n "$out" ]]; then
  hit "Zugriffe mit php://filter / Session-Datei-Pfaden (Webshell-Abruf):"
  tail -20 <<<"$out" | sed 's/^/       /'
else ok "Keine php://filter- oder Session-Datei-Zugriffe."; fi

# POST/PUT/PATCH mit 500/502 je IP (Combined Log Format: $6=Methode, $9=Status)
out=$(for f in "${ACC_LOGS[@]}"; do [[ -f $f ]] && zcat -f "$f"; done 2>/dev/null \
  | awk '$6 ~ /"(POST|PUT|PATCH)/ && ($9==500 || $9==502) {print $1}' | sort | uniq -c | sort -rn | head -15)
if [[ -n "$out" ]]; then
  warn "POST/PUT/PATCH mit HTTP 500/502 – Top-IPs (Häufung prüfen):"
  sed 's/^/       /' <<<"$out"
else ok "Keine POST-Requests mit 500/502."; fi

# Ungewöhnliche Requests auf PHP-Probe-Dateien
out=$(zgrep_logs '"(GET|POST) /(php2shell-probe|vuln\.php|phpinfo\.php|info\.php|pi\.php|i\.php)' "${ACC_LOGS[@]}")
[[ -n "$out" ]] && { warn "Probes auf phpinfo-/Test-Dateien:"; tail -15 <<<"$out" | sed 's/^/       /'; }

# =============================================================================
section "4. Session-Dateien: eingeschleuster PHP-Code"
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
    hit "Verdächtiger Code in Session-Dateien unter $d:"; sed 's/^/       /' <<<"$res"; found=1
  fi
done
((found)) || ok "Keine Session-Dateien mit PHP-Code."

# =============================================================================
section "5. Webroot: neue/geänderte PHP-Dateien & Webshell-Muster"
# =============================================================================
if [[ -d $WEBROOT ]]; then
  cnt=$(find "$WEBROOT" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) -newermt "$SINCE" 2>/dev/null | wc -l)
  warn "$cnt PHP-Dateien seit $SINCE geändert/neu (bei Deployments normal – Liste prüfen, max. 50):"
  find "$WEBROOT" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) -newermt "$SINCE" \
       -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort -r | head -50 | sed 's/^/       /'

  res=$(grep -rlE --include='*.php' --include='*.phtml' --include='*.php[0-9]' \
        "PWNED::|system\(\s*\\\$_(GET|POST|REQUEST)|shell_exec\(\s*\\\$_|passthru\(\s*\\\$_|eval\(\s*(base64_decode|gzinflate|str_rot13)\(" \
        "$WEBROOT" 2>/dev/null | head -50)
  if [[ -n "$res" ]]; then
    hit "Webshell-typische Muster gefunden (manuell prüfen!):"; sed 's/^/       /' <<<"$res"
  else ok "Keine typischen Webshell-Muster im Webroot."; fi

  res=$(find "$WEBROOT" -type f -name '*.php' -path '*upload*' 2>/dev/null | head -20)
  [[ -n "$res" ]] && { warn "PHP-Dateien in Upload-Verzeichnissen:"; sed 's/^/       /' <<<"$res"; }
else
  warn "Webroot $WEBROOT existiert nicht – mit 2. Parameter angeben."
fi

# =============================================================================
section "6. Laufende Prozesse: Shells/Downloader unter PHP-FPM"
# =============================================================================
out=$(ps -eo pid,ppid,user,lstart,cmd --forest 2>/dev/null \
  | awk '/php-fpm: pool/{inpool=1; print; next}
         inpool && /\\_ / && /(sh|bash|dash|python|perl|curl|wget|nc|ncat|socat|base64)( |$)/ {print "  >>> " $0}
         !/\\_ /{inpool=0}' | grep ">>>")
if [[ -n "$out" ]]; then
  hit "Kindprozesse von PHP-FPM-Workern:"; sed 's/^/       /' <<<"$out"
else ok "Keine Shell-/Download-Prozesse unter PHP-FPM."; fi

# Netzwerkverbindungen der www-data-Prozesse nach außen
out=$(ss -tnp 2>/dev/null | grep -E 'users:\(\("(sh|bash|perl|python[0-9.]*|nc|socat)"' )
[[ -n "$out" ]] && { hit "Ausgehende Verbindungen von Shell-Prozessen:"; sed 's/^/       /' <<<"$out"; }

# Cron-Jobs des Webserver-Users
out=$(crontab -l -u www-data 2>/dev/null)
[[ -n "$out" ]] && { warn "Crontab von www-data (normalerweise leer):"; sed 's/^/       /' <<<"$out"; }

# =============================================================================
section "Zusammenfassung"
# =============================================================================
if ((HITS)); then
  echo "${R}$HITS kritische Funde.${N} Treffer manuell bewerten. Bei bestätigter Kompromittierung:"
  info "- Server isolieren, nicht nur Webshell löschen"
  info "- Alle Secrets rotieren (DB, API-Keys, TLS-Keys) – CVE-2026-109618 leakt Speicher"
  info "- Sessions invalidieren (Session-Verzeichnis leeren)"
else
  echo "${G}Keine kritischen Funde.${N} Hinweis: Request-Bodies stehen nicht in Access-Logs;"
  info "ein negatives Ergebnis ist kein Beweis für Sauberkeit."
fi
echo; echo "Bericht gespeichert: $REPORT"
