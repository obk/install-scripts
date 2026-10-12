#!/usr/bin/env bash
# Install or update AdGuard Home to the latest GitHub release.
# Installed to /usr/local/sbin/agh-update; run weekly by agh-update.timer and once by bootstrap.sh.
#
# 1. Find the latest release tag; do nothing if it is already installed, and
#    refuse it if it is older than the installed one.
# 2. Verify the download against that same release's checksums.txt, and the
#    binary's signature against AdGuard's pinned release key.
# 3. Run --check-config with the new binary; do not install if it fails.
# 4. Back up the old binary (and config), install the new one, restart.
#    The config backup lives in a root-only directory, see agh_cat below.
# 5. Roll back if the service does not come up or DNS does not answer.
#
# The binary stays root-owned so the service user can never replace it.
set -euo pipefail

REPO_URL=https://github.com/AdguardTeam/AdGuardHome
AGH_DIR=/opt/AdGuardHome
AGH_BIN="$AGH_DIR/AdGuardHome"
AGH_STATE=/var/lib/adguardhome
AGH_CONF="$AGH_STATE/AdGuardHome.yaml"
AGH_BACKUP=/var/backups/adguardhome
# AdGuard's release signing key, installed by bootstrap.sh
# (fingerprint 28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6).
AGH_KEYRING=/usr/local/share/keyrings/adguard-release.gpg

log() { printf 'agh-update: %s\n' "$*"; }
die() { printf 'agh-update: ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
id adguardhome &>/dev/null || die "user adguardhome is missing; run bootstrap.sh first"
[[ -f "$AGH_KEYRING" ]] || die "$AGH_KEYRING is missing; run bootstrap.sh first"

case "$(dpkg --print-architecture)" in
  arm64) arch=arm64 ;;
  armhf) arch=armv7 ;;
  amd64) arch=amd64 ;;
  *) die "unsupported architecture $(dpkg --print-architecture)" ;;
esac
tarball="AdGuardHome_linux_${arch}.tar.gz"

# Bounded so a stalled connection fails the run instead of hanging the timer's service.
CURL=(curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 120)
fetch() { "${CURL[@]}" -o "$1" "$2"; }
# Binaries never run as root here: only as the unprivileged service user.
version_of() { (cd / && runuser -u adguardhome -- "$1" --version 2>/dev/null) | awk '{print $NF}'; }
# Root never opens paths inside $AGH_STATE itself: adguardhome owns that directory
# and could swap any file in it for a symlink to a system file. Go through that user.
agh_cat()   { runuser -u adguardhome -- cat -- "$1"; }
# shellcheck disable=SC2016 # $1 expands in the inner sh
agh_write() { runuser -u adguardhome -- sh -c 'umask 077 && cat > "$1.tmp" && mv -f -- "$1.tmp" "$1"' sh "$1"; }

# --- 1. Latest version -------------------------------------------------------
# releases/latest redirects to releases/tag/<version>.
latest_url="$("${CURL[@]}" -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest")"
latest="${latest_url##*/}"
[[ "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not determine latest version (got '$latest')"

current="$(version_of "$AGH_BIN" || true)"
if [[ "$current" == "$latest" ]]; then
  log "up to date ($current)"
  exit 0
fi
# Every release AdGuard ever signed passes the checks below, so never go back to
# an older, possibly vulnerable one (e.g. a compromised repo marking it latest).
if [[ -n "$current" ]] && ! printf '%s\n' "$current" "$latest" | sort -CV; then
  die "latest release $latest is older than the installed $current; not downgrading"
fi

# --- 2. Download and verify ----------------------------------------------------
# Always under /tmp: a TMPDIR inside a root-only directory (e.g. libpam-tmpdir)
# would keep the adguardhome user from reaching the new binary.
tmp="$(mktemp -d -p /tmp agh-update.XXXXXXXX)"
trap 'rm -rf "$tmp"' EXIT
# The config check below runs as adguardhome, which must be able to reach the
# new binary; root ownership still keeps it from modifying anything here.
chmod 0755 "$tmp"
fetch "$tmp/checksums.txt" "$REPO_URL/releases/download/$latest/checksums.txt"
fetch "$tmp/$tarball"      "$REPO_URL/releases/download/$latest/$tarball"
want="$(awk -v f="./$tarball" '$2 == f {print $1}' "$tmp/checksums.txt")"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "no checksum for $tarball in $latest checksums.txt"
echo "$want  $tmp/$tarball" | sha256sum -c --quiet - || die "checksum mismatch for $tarball"
tar -xzf "$tmp/$tarball" -C "$tmp" --no-same-owner
new_bin="$tmp/AdGuardHome/AdGuardHome"
# checksums.txt comes from the same place as the tarball; the signature does not.
gpgv --keyring "$AGH_KEYRING" "$tmp/AdGuardHome/AdGuardHome.sig" "$new_bin" 2>/dev/null \
  || die "$latest binary is not signed by the AdGuard release key; not installing"
[[ "$(version_of "$new_bin")" == "$latest" ]] || die "downloaded binary does not report $latest"

# First install: no config yet, just put the binary in place.
if [[ ! -f "$AGH_CONF" ]]; then
  install -d -m 0755 -o root -g root "$AGH_DIR"
  install -m 0755 -o root -g root "$new_bin" "$AGH_BIN"
  log "installed $latest"
  exit 0
fi

# --- 3. Test the new binary against the live config ---------------------------
log "updating ${current:-none} -> $latest"
# Test a copy, as the service user, so a schema migration cannot touch the live file.
install -d -m 0700 -o adguardhome -g adguardhome "$tmp/check"
agh_cat "$AGH_CONF" | agh_write "$tmp/check/AdGuardHome.yaml"
runuser -u adguardhome -- "$new_bin" --check-config --no-check-update \
  -c "$tmp/check/AdGuardHome.yaml" -w "$AGH_STATE" >/dev/null 2>&1 \
  || die "$latest rejects the current config; staying on $current"

# --- 4. Back up and install ----------------------------------------------------
# The new version may migrate the config schema on start, so keep the config too.
cp -a "$AGH_BIN" "$AGH_BIN.prev"
install -d -m 0700 "$AGH_BACKUP"
agh_cat "$AGH_CONF" > "$AGH_BACKUP/AdGuardHome.yaml.prev"
systemctl stop adguardhome
install -m 0755 -o root -g root "$new_bin" "$AGH_BIN"
systemctl start adguardhome

# --- 5. Health check, roll back on failure ------------------------------------
# Query a name AdGuard Home answers itself (from /etc/hosts): it checks that the
# server answers, not that the upstreams are reachable at this hour. A public
# name would wait out upstream_timeout (10s) and cause a false rollback offline.
healthy() {
  for _ in $(seq 1 15); do
    if systemctl is-active --quiet adguardhome \
       && [[ "$(dig @127.0.0.1 localhost A +short +time=2 +tries=1 2>/dev/null)" == 127.0.0.1 ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

if healthy; then
  log "updated to $latest"
else
  log "$latest did not come up; rolling back to $current"
  systemctl stop adguardhome
  install -m 0755 -o root -g root "$AGH_BIN.prev" "$AGH_BIN"
  agh_write "$AGH_CONF" < "$AGH_BACKUP/AdGuardHome.yaml.prev"
  systemctl start adguardhome
  die "update to $latest failed and was rolled back"
fi
