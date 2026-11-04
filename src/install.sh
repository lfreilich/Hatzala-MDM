#!/usr/bin/env bash
# =============================================================================
#  HBS add-ons for Headwind MDM (community edition)
#  Location (Traccar) · Remote support (RustDesk) · Files/Photos/Contacts (Nextcloud)
#  SIP phone OTA provisioning (Linphone + FreePBX) · DNS filtering (AdGuard Home)
#  2FA for the admin panel (Authelia) · Caddy edge proxy · hbs-bridge glue service
#
#  Usage:  sudo bash install.sh            # interactive install / re-run to update
#          sudo bash install.sh --check    # preflight report only, changes nothing
#          sudo bash install.sh --yes      # don't ask for confirmation (prompts for secrets still shown)
#          sudo bash install.sh --no-edge  # install everything but leave ports 80/443 as they are
# =============================================================================
set -Eeuo pipefail

VERSION="1.1.0"
PREFIX="/opt/hbs-addons"
STACK="$PREFIX/stack"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/var/log/hbs-addons-install.log"
DOMAIN="${DOMAIN:-}"  # --domain, else the installed one, else hatzala-mdm.com (see below)
SUBS=(auth ops map track cloud dns rd)
CHECK_ONLY=0; ASSUME_YES=0; NO_EDGE=0

for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --no-edge) NO_EDGE=1 ;;
    --domain=*) DOMAIN="${a#*=}" ;;
    -h|--help) sed -n 2,13p "$0"; exit 0 ;;
    *) echo "Unknown option $a"; exit 1 ;;
  esac
done

# ----------------------------------------------------------------------------- helpers
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_bld=$'\e[1m'; c_off=$'\e[0m'
say()  { echo "${c_bld}==>${c_off} $*" | tee -a "$LOG"; }
ok()   { echo "  ${c_grn}✓${c_off} $*" | tee -a "$LOG"; }
warn() { echo "  ${c_yel}!${c_off} $*" | tee -a "$LOG"; }
die()  { echo "${c_red}✗ $*${c_off}" | tee -a "$LOG"; exit 1; }
trap 'die "Failed at line $LINENO: $BASH_COMMAND  (full log: $LOG)"' ERR

TTY=/dev/tty; [ -r "$TTY" ] || TTY=/dev/stdin
ask() { # ask VAR "Question" default
  local __v=$1 q=$2 d=${3:-} r
  if [ -n "${!__v:-}" ]; then return; fi
  read -r -p "  $q${d:+ [$d]}: " r < "$TTY" || true
  printf -v "$__v" '%s' "${r:-$d}"
}
ask_secret() { # ask_secret VAR "Question"
  local __v=$1 q=$2 r
  if [ -n "${!__v:-}" ]; then return; fi
  read -r -s -p "  $q: " r < "$TTY" || true; echo
  printf -v "$__v" '%s' "$r"
}
confirm() { [ "$ASSUME_YES" = 1 ] && return 0; local r; read -r -p "  $1 [y/N]: " r < "$TTY" || true; [[ "$r" =~ ^[Yy] ]]; }
rand() { openssl rand -hex "${1:-16}"; }
randpw() { python3 -c "import secrets,string,sys; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(int(sys.argv[1]))), end='')" "${1:-20}"; }
env_get() { [ -f "$STACK/.env" ] && grep -E "^$1=" "$STACK/.env" | tail -1 | cut -d= -f2- || true; }
# Keep the installed domain on reruns. hbs-mdm.cloud is no longer used: Bezeq's SAM filter blocks it.
DOMAIN=${DOMAIN:-$(env_get DOMAIN)}; DOMAIN=${DOMAIN:-hatzala-mdm.com}
retry() { local n=$1 i; shift; for i in $(seq 1 "$n"); do "$@" && return 0; warn "Attempt $i/$n failed: $*. Retrying in 30s"; sleep 30; done; return 1; }
compose() { docker compose --project-directory "$STACK" -f "$STACK/docker-compose.yml" "$@"; }
wait_http() { # wait_http URL seconds [extra curl args]
  local url=$1 t=${2:-120} i=0; shift 2 || true
  until code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" "$url") && [ "$code" != 000 ] && [ "$code" -lt 500 ]; do
    i=$((i+3)); [ $i -ge "$t" ] && return 1; sleep 3
  done
}

[ "$(id -u)" = 0 ] || die "Run as root (sudo bash install.sh)"
mkdir -p "$(dirname "$LOG")"; echo "---- $(date -Is) install v$VERSION $*" >> "$LOG"

# ----------------------------------------------------------------------------- 1. preflight
say "Preflight checks for ${c_bld}$DOMAIN${c_off}"
. /etc/os-release 2>/dev/null || true
case "${ID:-}" in ubuntu|debian) ok "OS: $PRETTY_NAME" ;; *) warn "Untested OS: ${PRETTY_NAME:-unknown} (Ubuntu/Debian expected)";; esac
command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >>"$LOG" 2>&1; }
command -v openssl >/dev/null || apt-get install -y -qq openssl >>"$LOG" 2>&1

PUBLIC_IP=$(curl -4 -s --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')
ok "Public IP: $PUBLIC_IP"
MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
DISK_MB=$(df -Pm / | awk 'NR==2{print $4}')
[ "$MEM_MB" -ge 3500 ] && ok "RAM: ${MEM_MB} MB" || warn "RAM: ${MEM_MB} MB. 4 GB+ recommended for the full stack (it will still try)."
[ "$DISK_MB" -ge 15000 ] && ok "Free disk: ${DISK_MB} MB" || warn "Free disk: ${DISK_MB} MB. 15 GB+ recommended."

# Headwind / Tomcat
TOMCAT_HOME=$(ls -d /var/lib/tomcat* 2>/dev/null | tail -n1 || true)
HMDM_PORT=8080
HMDM_HTTP=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$HMDM_PORT/" || true)
if [[ "$HMDM_HTTP" =~ ^(200|302|301)$ ]]; then ok "Headwind (Tomcat) answers on 127.0.0.1:$HMDM_PORT"
else die "Headwind isn't answering on http://127.0.0.1:$HMDM_PORT (got '$HMDM_HTTP'). Send this output to Claude."; fi
[ -n "$TOMCAT_HOME" ] && ok "Tomcat home: $TOMCAT_HOME"

# Who owns 80/443?
command -v ss >/dev/null || apt-get install -y -qq iproute2 >>"$LOG" 2>&1 || true
owner() { { ss -Hltnp "sport = :$1" 2>/dev/null || true; } | sed -E 's/.*users:\(\("([^"]+)".*/\1/' | head -1; }
O80=$(owner 80); O443=$(owner 443)
REDIR443=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -c -- '--dport 443 .*--to-ports 8443' || true)
REDIR80=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -c -- '--dport 80 .*--to-ports 8080' || true)
EDGE_MODE=""
if [ "$NO_EDGE" = 1 ]; then EDGE_MODE="skip"
elif docker ps --format '{{.Names}}' 2>/dev/null | grep '^hbs-caddy' >/dev/null; then EDGE_MODE="ours"
elif [ -z "$O443" ] && [ "$REDIR443" -gt 0 ]; then EDGE_MODE="iptables"
elif [ -z "$O443" ] && [ -z "$O80" ]; then EDGE_MODE="free"
else EDGE_MODE="unsupported"; fi
case "$EDGE_MODE" in
  iptables) ok "Ports 80/443: iptables redirect to Tomcat (standard Headwind install). Caddy will take over 80/443." ;;
  free)     ok "Ports 80/443: free. Caddy will serve them." ;;
  ours)     ok "Ports 80/443: already served by hbs Caddy." ;;
  skip)     warn "--no-edge: ports 80/443 left alone. Subdomains/2FA won't be live until the edge is enabled." ;;
  *)        warn "Port 443 is used by '${O443}' and port 80 by '${O80}'. Automatic takeover isn't supported for this layout.";;
esac

for p in 853 5055 8082 8083 8084 8085 8090 9091 21115 21116 21117 21118 21119; do
  o=$(owner $p); if [ -n "$o" ] && [[ ! "$o" =~ ^(docker-proxy|hbbs|hbbr|authelia|caddy|uvicorn|python.*)$ ]]; then
    warn "Port $p already used by '$o'"; fi
done

# DNS
DNS_OK=1
for h in "$DOMAIN" "${SUBS[@]/%/.$DOMAIN}"; do
  ip=$({ getent ahostsv4 "$h" || true; } | awk 'NR==1{print $1}')
  if [ "$ip" = "$PUBLIC_IP" ]; then ok "DNS $h → $ip"; else warn "DNS $h → ${ip:-missing}  (needs A record → $PUBLIC_IP)"; DNS_OK=0; fi
done
[ "$DNS_OK" = 1 ] || warn "Add a wildcard record  *.$DOMAIN  A  $PUBLIC_IP  at your DNS provider (Hostinger hPanel → DNS Zone)."

if [ "$CHECK_ONLY" = 1 ]; then say "Preflight only. No changes made."; exit 0; fi
[ "$EDGE_MODE" = unsupported ] && die "Unsupported port 80/443 layout. Re-run with --no-edge, or send this output to Claude."

echo
say "This will install Docker (if needed) and these services in $PREFIX:"
echo "    Traccar · RustDesk server · Nextcloud · AdGuard Home · Authelia 2FA · Caddy · hbs-bridge"
[ "$EDGE_MODE" = iptables ] && echo "    and move ports 80/443 from Tomcat's iptables redirect to Caddy (auto-rollback if Headwind stops answering)."
confirm "Continue?" || die "Aborted by user."

# ----------------------------------------------------------------------------- 2. settings
say "Settings"
mkdir -p "$STACK/secrets" && chmod 700 "$STACK/secrets"
ADMIN_EMAIL=${ADMIN_EMAIL:-$(env_get ADMIN_EMAIL)}
ask ADMIN_EMAIL "Admin e-mail (Let's Encrypt + logins)" ""
[ -n "$ADMIN_EMAIL" ] || die "Admin e-mail is required"

HMDM_LOGIN=${HMDM_LOGIN:-$(env_get HMDM_LOGIN)}
ask HMDM_LOGIN "Headwind admin login" "admin"
if [ ! -s "$STACK/secrets/hmdm_password" ]; then
  ask_secret HMDM_PASSWORD "Headwind password for '$HMDM_LOGIN' (used by the bridge's API)"
  printf '%s' "$HMDM_PASSWORD" > "$STACK/secrets/hmdm_password"; chmod 600 "$STACK/secrets/hmdm_password"
fi
MD5=$(printf '%s' "$(cat "$STACK/secrets/hmdm_password")" | md5sum | awk '{print toupper($1)}')
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d "{\"login\":\"$HMDM_LOGIN\",\"password\":\"$MD5\"}" "http://127.0.0.1:$HMDM_PORT/rest/public/jwt/login")
if [ "$code" = 200 ]; then ok "Headwind API login works"
else rm -f "$STACK/secrets/hmdm_password"; die "Headwind API login failed (HTTP $code). Wrong password? Re-run."; fi

PBX_ENABLED=${PBX_ENABLED:-$(env_get PBX_ENABLED)}
if [ -z "$PBX_ENABLED" ]; then
  if confirm "Connect FreePBX for automatic SIP phone provisioning?"; then PBX_ENABLED=true; else PBX_ENABLED=false; fi
fi
if [ "$PBX_ENABLED" = true ]; then
  PBX_URL=${PBX_URL:-$(env_get PBX_URL)};               ask PBX_URL "FreePBX URL" "https://bandtelecom.org"
  PBX_CLIENT_ID=${PBX_CLIENT_ID:-$(env_get PBX_CLIENT_ID)}; ask PBX_CLIENT_ID "FreePBX API client ID (Admin → API → Applications)" ""
  if [ ! -s "$STACK/secrets/pbx_client_secret" ]; then
    ask_secret PBX_SECRET "FreePBX API client secret"
    printf '%s' "$PBX_SECRET" > "$STACK/secrets/pbx_client_secret"; chmod 600 "$STACK/secrets/pbx_client_secret"
  fi
  SIP_DOMAIN=${SIP_DOMAIN:-$(env_get SIP_DOMAIN)};       ask SIP_DOMAIN "SIP domain phones register to" "$(echo "$PBX_URL" | sed -E 's#https?://##; s#/.*##')"
  SIP_PORT=${SIP_PORT:-$(env_get SIP_PORT)};             ask SIP_PORT "SIP port" "5060"
  SIP_TRANSPORT=${SIP_TRANSPORT:-$(env_get SIP_TRANSPORT)}; ask SIP_TRANSPORT "SIP transport (udp/tcp/tls)" "udp"
  PBX_MANAGE_SECRETS=${PBX_MANAGE_SECRETS:-$(env_get PBX_MANAGE_SECRETS)}
  [ -n "$PBX_MANAGE_SECRETS" ] || { if confirm "Let the bridge set a new random SIP password on each assigned extension? (No = type them in the dashboard)"; then PBX_MANAGE_SECRETS=true; else PBX_MANAGE_SECRETS=false; fi; }
fi

# ----------------------------------------------------------------------------- 3. docker
say "Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh >>"$LOG" 2>&1
  systemctl enable --now docker >>"$LOG" 2>&1
fi
docker compose version >/dev/null 2>&1 || apt-get install -y -qq docker-compose-plugin >>"$LOG" 2>&1
ok "$(docker --version)"

# ----------------------------------------------------------------------------- 4. files + .env
say "Installing files to $PREFIX"
PKG_DIR="$PREFIX/src"   # pristine copy of this package, used by 'hbs-addons update'
mkdir -p "$STACK/caddy" "$STACK/authelia" "$PREFIX/backups"
if [ "$(readlink -f "$SRC_DIR")" != "$(readlink -f "$PKG_DIR")" ]; then
  rm -rf "$PKG_DIR.new"; cp -r "$SRC_DIR" "$PKG_DIR.new"; rm -rf "$PKG_DIR"; mv "$PKG_DIR.new" "$PKG_DIR"
fi
cp -f "$PKG_DIR/stack/docker-compose.yml" "$STACK/"
cp -f "$PKG_DIR/stack/caddy/Caddyfile" "$STACK/caddy/"
cp -f "$PKG_DIR/stack/authelia/configuration.yml.tpl" "$STACK/authelia/"
rm -rf "$PREFIX/bridge"; cp -r "$PKG_DIR/bridge" "$PREFIX/bridge"
install -m 755 "$PKG_DIR/hbs-addons" /usr/local/bin/hbs-addons
mkdir -p "$STACK"/data/{caddy,caddy-config,apk,traccar/data,traccar/logs,rustdesk,nc-db,nextcloud,adguard/work,adguard/conf,bridge}

keep() { local v; v=$(env_get "$1"); echo "${v:-$2}"; }
for s in traccar_admin_password nc_admin_password adguard_password authelia_admin_password; do
  if [ ! -s "$STACK/secrets/$s" ] || ! grep -Eq '^[A-Za-z0-9]{16,}$' "$STACK/secrets/$s"; then
    randpw 20 > "$STACK/secrets/$s"; chmod 600 "$STACK/secrets/$s"
  fi
done
# Settings added after install (WalkieFleet, ElevenLabs, ADMIN_OWNERS, ...) aren't generated below:
# keep a copy so they can be carried over instead of lost.
[ -f "$STACK/.env" ] && cp -p "$STACK/.env" "$STACK/.env.prev"
# Written to .env.new and swapped in: "cat > .env" would empty .env before keep() reads the current values.
cat > "$STACK/.env.new" <<EOF
# Generated by install.sh v$VERSION on $(date -Is). Secrets live in ./secrets
DOMAIN=$DOMAIN
TZ=$(keep TZ Asia/Jerusalem)
ADMIN_EMAIL=$ADMIN_EMAIL
PUBLIC_IP=$PUBLIC_IP
OPS_HOST=ops.$DOMAIN
TRACK_HOST=track.$DOMAIN
MAP_HOST=map.$DOMAIN
NC_HOST=cloud.$DOMAIN
DNS_HOST=dns.$DOMAIN
RUSTDESK_HOST=rd.$DOMAIN

HMDM_INTERNAL_URL=http://127.0.0.1:$HMDM_PORT
HMDM_LOGIN=$HMDM_LOGIN
HMDM_PASSWORD_FILE=/secrets/hmdm_password
HMDM_CONFIG_IDS=$(keep HMDM_CONFIG_IDS all)

TRACCAR_URL=http://127.0.0.1:8082
TRACCAR_ADMIN_EMAIL=$ADMIN_EMAIL
TRACCAR_ADMIN_PASSWORD_FILE=/secrets/traccar_admin_password
TRACKING_INTERVAL=$(keep TRACKING_INTERVAL 60)

NC_URL=http://127.0.0.1:8083
NC_ADMIN_USER=admin
NC_ADMIN_PASSWORD=$(cat "$STACK/secrets/nc_admin_password")
NC_ADMIN_PASSWORD_FILE=/secrets/nc_admin_password
NC_DB_PASSWORD=$(keep NC_DB_PASSWORD "$(rand 16)")

PBX_ENABLED=${PBX_ENABLED:-false}
PBX_URL=${PBX_URL:-}
PBX_CLIENT_ID=${PBX_CLIENT_ID:-}
PBX_CLIENT_SECRET_FILE=/secrets/pbx_client_secret
PBX_MANAGE_SECRETS=${PBX_MANAGE_SECRETS:-false}
SIP_DOMAIN=${SIP_DOMAIN:-}
SIP_PORT=${SIP_PORT:-5060}
SIP_TRANSPORT=${SIP_TRANSPORT:-udp}

APPS=$(keep APPS traccar,linphone,nextcloud,davx5,rustdesk)
BRIDGE_PORT=8090
SYNC_INTERVAL=$(keep SYNC_INTERVAL 300)
AUTHELIA_JWT_SECRET=$(keep AUTHELIA_JWT_SECRET "$(rand 32)")
AUTHELIA_SESSION_SECRET=$(keep AUTHELIA_SESSION_SECRET "$(rand 32)")
AUTHELIA_STORAGE_KEY=$(keep AUTHELIA_STORAGE_KEY "$(rand 32)")
EOF
mv "$STACK/.env.new" "$STACK/.env"
if [ -f "$STACK/.env.prev" ]; then
  while IFS= read -r line; do
    grep -q "^${line%%=*}=" "$STACK/.env" || echo "$line" >> "$STACK/.env"
  done < <(grep -E '^[A-Z0-9_]+=' "$STACK/.env.prev")
  chmod 600 "$STACK/.env.prev"
fi
# Owners approve new admins on the ops Admins page. Only set here, never from the web.
grep -q '^ADMIN_OWNERS=' "$STACK/.env" || echo "ADMIN_OWNERS=$ADMIN_EMAIL" >> "$STACK/.env"
chmod 600 "$STACK/.env"
set -a; . "$STACK/.env"; set +a
ok ".env written"

# Google sign-in gate (oauth2-proxy). Its OAuth client comes from Google Cloud Console, so it can't be generated.
[ -s "$STACK/oauth2-proxy.env" ] || die "Missing $STACK/oauth2-proxy.env (OAUTH2_PROXY_CLIENT_ID, OAUTH2_PROXY_CLIENT_SECRET, OAUTH2_PROXY_COOKIE_SECRET). Create a Google OAuth client with redirect https://auth.$DOMAIN/oauth2/callback first."
[ -s "$STACK/caddy-extra.env" ] || die "Missing $STACK/caddy-extra.env (ADGUARD_BASIC for the DNS admin login)."
mkdir -p "$STACK/oauth2-proxy"
# Google accounts allowed past the gate. The ops Admins page edits this file afterwards.
[ -s "$STACK/oauth2-proxy/allowed-emails.txt" ] || echo "$ADMIN_EMAIL" | tr 'A-Z' 'a-z' > "$STACK/oauth2-proxy/allowed-emails.txt"
ok "Google sign-in gate configured"

# ----------------------------------------------------------------------------- 5. authelia config
say "Configuring Authelia (2FA)"
sed -e "s|__DOMAIN__|$DOMAIN|g" -e "s|__AUTHELIA_JWT_SECRET__|$AUTHELIA_JWT_SECRET|" \
    -e "s|__AUTHELIA_SESSION_SECRET__|$AUTHELIA_SESSION_SECRET|" -e "s|__AUTHELIA_STORAGE_KEY__|$AUTHELIA_STORAGE_KEY|" \
    "$STACK/authelia/configuration.yml.tpl" > "$STACK/authelia/configuration.yml"
if [ ! -s "$STACK/authelia/users_database.yml" ]; then
  HASH=$(docker run --rm authelia/authelia:4.38 authelia crypto hash generate argon2 \
         --password "$(cat "$STACK/secrets/authelia_admin_password")" 2>>"$LOG" | sed -n 's/^Digest: //p')
  [ -n "$HASH" ] || die "Could not hash the Authelia password"
  cat > "$STACK/authelia/users_database.yml" <<EOF
users:
  admin:
    disabled: false
    displayname: "HBS Admin"
    password: "$HASH"
    email: "$ADMIN_EMAIL"
    groups: [admins]
EOF
fi
chmod 600 "$STACK/authelia/"*.yml
ok "Authelia user 'admin' ready"

# ----------------------------------------------------------------------------- 6. core services
say "Starting services (first run pulls images; this can take a few minutes)"
retry 4 compose pull -q >>"$LOG" 2>&1 || warn "Some images could not be pulled yet (Docker Hub rate limit?). Continuing."
[ "${HBS_SKIP_BUILD:-0}" = 1 ] || retry 4 compose build -q bridge >>"$LOG" 2>&1 || die "Could not build the bridge image (see $LOG)"
compose up -d authelia oauth2-proxy traccar hbbs hbbr nc-db nc-redis nextcloud nc-cron adguard >>"$LOG" 2>&1
ok "Containers started"

# Traccar: create the admin, then close public registration
wait_http "http://127.0.0.1:8082/api/server" 180 || die "Traccar did not start (see: hbs-addons logs traccar)"
TC_PW=$(cat "$STACK/secrets/traccar_admin_password")
tc_ok() { [ "$(curl -s -o /dev/null -w '%{http_code}' -u "$ADMIN_EMAIL:$TC_PW" http://127.0.0.1:8082/api/devices)" = 200 ]; }
for i in $(seq 1 30); do
  tc_ok && break
  curl -s -o /dev/null -H 'Content-Type: application/json' \
    -d "{\"name\":\"admin\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$TC_PW\"}" http://127.0.0.1:8082/api/users || true
  sleep 4
done
if tc_ok; then
  curl -s -u "$ADMIN_EMAIL:$TC_PW" http://127.0.0.1:8082/api/server \
   | python3 -c 'import json,sys; s=json.load(sys.stdin); s["registration"]=False; print(json.dumps(s))' \
   | curl -s -o /dev/null -u "$ADMIN_EMAIL:$TC_PW" -X PUT -H 'Content-Type: application/json' -d @- http://127.0.0.1:8082/api/server
  ok "Traccar admin ready (public sign-up disabled)"
else
  warn "Traccar admin login failed. If Traccar already had a different admin, set TRACCAR_ADMIN_EMAIL/secret to match."
fi

# Nextcloud: wait for auto-install, add apps
occ() { compose exec -T -u www-data nextcloud php occ "$@"; }
say "Waiting for Nextcloud to finish installing"
for i in $(seq 1 100); do occ status 2>/dev/null | grep 'installed: true' >/dev/null && break; sleep 6; done
occ status 2>/dev/null | grep 'installed: true' >/dev/null || die "Nextcloud didn't finish installing (hbs-addons logs nextcloud)"
occ app:install contacts >>"$LOG" 2>&1 || occ app:enable contacts >>"$LOG" 2>&1 || true
occ app:install twofactor_totp >>"$LOG" 2>&1 || true
occ background:cron >>"$LOG" 2>&1 || true
occ config:system:set default_phone_region --value=IL >>"$LOG" 2>&1 || true
occ config:system:set overwrite.cli.url --value="https://$NC_HOST" >>"$LOG" 2>&1 || true
occ config:system:set maintenance_window_start --type=integer --value=1 >>"$LOG" 2>&1 || true
occ db:add-missing-indices >>"$LOG" 2>&1 || true
ok "Nextcloud ready (contacts + TOTP apps)"

# AdGuard Home first-run setup via its API
AG_PW=$(cat "$STACK/secrets/adguard_password")
if wait_http "http://127.0.0.1:8084/control/install/get_addresses" 60; then
  curl -s -o /dev/null -H 'Content-Type: application/json' -d "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":80},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":53},\"username\":\"admin\",\"password\":\"$AG_PW\"}" \
    http://127.0.0.1:8084/control/install/configure || true
fi
wait_http "http://127.0.0.1:8085/" 60 && ok "AdGuard Home ready" || warn "AdGuard Home admin not answering yet"

# ----------------------------------------------------------------------------- 7. edge cutover
ROLLBACK_FILE="$PREFIX/backups/edge-rollback.sh"
# A device-facing path must give exactly the same answer through Caddy as from Tomcat directly
# (an Authelia redirect, a 502 or a TLS failure all count as "not working"). The probed path is a
# non-existent file download, which has no side effects in Headwind.
hmdm_via_edge() { # scheme port seconds
  local i=0 path="/files/hbs-edge-check-$$" want got
  want=$(curl -s --max-time 5 -w '|%{http_code}' "http://127.0.0.1:$HMDM_PORT$path" | md5sum)
  while [ $i -lt "$3" ]; do
    got=$(curl -s --max-time 5 -w '|%{http_code}' --resolve "$DOMAIN:$2:127.0.0.1" "$1://$DOMAIN$path" | md5sum)
    [ "$got" = "$want" ] && return 0
    sleep 3; i=$((i+3))
  done
  return 1
}
edge_rollback() {
  warn "Rolling back edge: stopping Caddy and restoring Tomcat's port redirects"
  compose --profile edge stop caddy >>"$LOG" 2>&1 || true
  [ -f "$ROLLBACK_FILE" ] && bash "$ROLLBACK_FILE" >>"$LOG" 2>&1 || true
}
if [[ "$EDGE_MODE" =~ ^(iptables|free|ours)$ ]]; then
  say "Switching ports 80/443 to Caddy"
  TS=$(date +%Y%m%d-%H%M%S)
  if [ "$EDGE_MODE" != ours ]; then
  iptables-save > "$PREFIX/backups/iptables-$TS.rules" 2>/dev/null || true
  crontab -l > "$PREFIX/backups/crontab-$TS.txt" 2>/dev/null || true
  {
    echo "#!/usr/bin/env bash"
    echo "# Restores Headwind's original port layout (created $TS)"
    for chain in PREROUTING OUTPUT; do
      { iptables -t nat -S $chain 2>/dev/null || true; } | { grep -E -- '--dport (80|443) .*--to-ports (8080|8443)' || true; } \
        | sed 's/^-A /iptables -t nat -A /'
    done
    [ -f "$PREFIX/backups/crontab-$TS.txt" ] && echo "crontab '$PREFIX/backups/crontab-$TS.txt'"
  } > "$ROLLBACK_FILE"; chmod 700 "$ROLLBACK_FILE"

  for chain in PREROUTING OUTPUT; do
    while read -r rule; do
      [ -n "$rule" ] && iptables -t nat ${rule/-A /-D } || true
    done < <(iptables -t nat -S $chain 2>/dev/null | grep -E -- '--dport (80|443) .*--to-ports (8080|8443)' || true)
  done
  # Stop the @reboot job re-adding the redirect, and the standalone certbot job that would now fail on :80
  if crontab -l >/dev/null 2>&1; then
    crontab -l | sed -E '/iptables-tomcat\.sh|letsencrypt-ssl\.sh/ s/^([^#])/# disabled by hbs-addons: \1/' | crontab -
  fi
  command -v netfilter-persistent >/dev/null && netfilter-persistent save >>"$LOG" 2>&1 || true
  if command -v ufw >/dev/null && ufw status | grep 'Status: active' >/dev/null; then
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow 853/tcp >/dev/null
    ufw allow 21115:21119/tcp >/dev/null; ufw allow 21116/udp >/dev/null; ok "ufw rules added"
  fi
  fi  # not already ours

  compose --profile edge up -d caddy >>"$LOG" 2>&1
  say "Verifying Headwind through Caddy (waiting for the certificate)"
  if hmdm_via_edge https 443 150 && hmdm_via_edge http 80 30; then
    ok "Headwind reachable via Caddy on 443 and 80. Devices keep syncing."
  else
    edge_rollback
    die "Headwind wasn't reachable through Caddy. Rolled back to the original setup. Log: $LOG"
  fi
else
  warn "Edge not enabled (mode: $EDGE_MODE)"
fi

# AdGuard DNS-over-TLS using Caddy's certificate for dns.<domain> (Let's Encrypt or ZeroSSL directory)
for i in $(seq 1 30); do
  CERT=$(ls "$STACK"/data/caddy/caddy/certificates/*/"dns.$DOMAIN/dns.$DOMAIN.crt" 2>/dev/null | head -1 || true)
  [ -n "$CERT" ] && break; sleep 4
done
if [ -n "$CERT" ]; then
  /usr/local/bin/hbs-addons dot >>"$LOG" 2>&1 && ok "DNS-over-TLS enabled: Private DNS hostname = dns.$DOMAIN" \
    || warn "Could not enable DNS-over-TLS yet (run 'hbs-addons dot' later)"
else
  warn "No certificate for dns.$DOMAIN yet (DNS record missing?). Run 'hbs-addons dot' later."
fi

# ----------------------------------------------------------------------------- 8. bridge
say "Starting hbs-bridge (Headwind sync + OTA provisioning)"
compose up -d bridge >>"$LOG" 2>&1
wait_http "http://127.0.0.1:8090/healthz" 60 && ok "Bridge running" || warn "Bridge not answering yet (hbs-addons logs bridge)"

cat > /etc/cron.d/hbs-addons <<EOF
# hbs-addons maintenance
30 3 * * * root /usr/local/bin/hbs-addons backup >/dev/null 2>&1
15 4 * * 0 root /usr/local/bin/hbs-addons dot >/dev/null 2>&1
EOF

# ----------------------------------------------------------------------------- 9. summary
CREDS="$PREFIX/CREDENTIALS.txt"
cat > "$CREDS" <<EOF
HBS add-ons — credentials ($(date -Is))   KEEP PRIVATE

2FA gate (protects Headwind panel, ops, map, DNS admin)
  https://auth.$DOMAIN   user: admin   password: $(cat "$STACK/secrets/authelia_admin_password")
  First login asks you to register an authenticator app; get the one-time code with:  hbs-addons 2fa-code

Ops dashboard     https://ops.$DOMAIN
Headwind MDM      https://$DOMAIN            (your existing Headwind login, behind 2FA)
Traccar map       https://map.$DOMAIN        user: $ADMIN_EMAIL  password: $(cat "$STACK/secrets/traccar_admin_password")
Nextcloud         https://cloud.$DOMAIN      user: admin  password: $(cat "$STACK/secrets/nc_admin_password")
AdGuard Home      https://dns.$DOMAIN        user: admin  password: $AG_PW
                  Android Private DNS hostname: dns.$DOMAIN
RustDesk server   rd.$DOMAIN   key: $(cat "$STACK/data/rustdesk/id_ed25519.pub" 2>/dev/null || echo "(generated on first start; see ops dashboard)")
EOF
chmod 600 "$CREDS"
echo
say "${c_grn}Done.${c_off} Credentials saved to $CREDS (root only):"
sed 's/^/    /' "$CREDS"
echo
echo "  Next: open https://ops.$DOMAIN. Apps appear in Headwind and install on devices within minutes."
echo "  Commands: hbs-addons status | logs <svc> | 2fa-code | backup | rollback-edge"
