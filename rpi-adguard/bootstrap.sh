#!/usr/bin/env bash
# shellcheck disable=SC2317,SC2329 # the is_* validators are only called through ask() (SC2317 before shellcheck 0.11)
# Provision a hardened AdGuard Home DNS server on Raspberry Pi OS Lite.
# Asks for its settings interactively. Defaults come from local.env when present
# (see local.env.example), otherwise from the running system, so a re-run is
# mostly pressing Enter. Idempotent.
#
# Usage: sudo ./bootstrap.sh [--reset-agh-config]
#   --reset-agh-config  re-render AdGuardHome.yaml from the template, discarding
#                       changes made in the web UI (a backup is kept).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES="$REPO_DIR/files"
RESET_AGH_CONFIG=0
[[ "${1:-}" == "--reset-agh-config" ]] && RESET_AGH_CONFIG=1

AGH_DIR=/opt/AdGuardHome
AGH_STATE=/var/lib/adguardhome
AGH_CONF="$AGH_STATE/AdGuardHome.yaml"
# Root-owned, unlike $AGH_STATE: config backups and the web UI certificate.
AGH_BACKUP=/var/backups/adguardhome
AGH_TLS=/etc/adguardhome/tls
# Personal defaults for the questions below; every one is optional. Unset ones
# are derived from the running system once the answers they depend on are known.
DEFAULT_HOST_NAME="" DEFAULT_ADMIN_USER="" DEFAULT_TIMEZONE="" DEFAULT_LAN_CIDR=""
DEFAULT_DNS_SUBNETS="" DEFAULT_ADMIN_SUBNETS="" DEFAULT_TAILSCALE=""
if [[ -f "$REPO_DIR/local.env" ]]; then
  # shellcheck source=local.env.example
  source "$REPO_DIR/local.env"
fi
# The Pi resolves its own lookups (apt, updates, NTP) via Quad9 directly, not via
# its own AdGuard Home, so it keeps working when AdGuard Home is down.
HOST_DNS="9.9.9.9 149.112.112.112"
# Tailscale's address range; tailnet devices query AdGuard Home from it via tailscale0.
TAILNET_CIDR=100.64.0.0/10
TS_SYSCTL=/etc/sysctl.d/91-tailscale-dns.conf

# Answers to the questions below.
HOST_NAME="" TIMEZONE="" ADMIN_USER="" NET_IFACE="" LAN_CIDR="" GATEWAY=""
DNS_SUBNETS="" ADMIN_SUBNETS="" TAILSCALE=""
AGH_ADMIN_USER="" AGH_ADMIN_PASSWORD="" RENDER_AGH_CONFIG=0

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mWARN: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
bad()  { printf '    %s\n' "$*" >&2; return 1; }

# Root never opens paths inside $AGH_STATE itself: adguardhome owns that directory
# and could swap any file in it for a symlink to a system file. Go through that user.
agh_cat()   { runuser -u adguardhome -- cat -- "$1"; }
# shellcheck disable=SC2016 # $1 expands in the inner sh
agh_write() { runuser -u adguardhome -- sh -c 'umask 077 && cat > "$1.tmp" && mv -f -- "$1.tmp" "$1"' sh "$1"; }

# ipcalc CMD ARGS: IPv4 helpers on top of python3's ipaddress module.
#   host ADDR/PREFIX     usable host address, prefix 8-30
#   network ADDR/PREFIX  print the network, e.g. 192.168.1.0/24
#   networks NET...      all are IPv4 networks (no host bits), prefix 8-32
#   within ADDR NET...   ADDR is an IPv4 address inside one of the NETs
ipcalc() {
  python3 -I - "$@" 2>/dev/null <<'EOF'
import ipaddress as ip, sys
cmd, *a = sys.argv[1:]
if cmd == "host":
    i = ip.IPv4Interface(a[0])
    sys.exit(not (8 <= i.network.prefixlen <= 30
                  and i.ip not in (i.network.network_address, i.network.broadcast_address)))
elif cmd == "network":
    print(ip.IPv4Interface(a[0]).network)
elif cmd == "networks":
    sys.exit(not all(ip.IPv4Network(n).prefixlen >= 8 for n in a))
elif cmd == "within":
    sys.exit(not any(ip.IPv4Address(a[0]) in ip.IPv4Network(n) for n in a[1:]))
EOF
}

# ask VAR "question" "default" VALIDATOR: prompt until VALIDATOR accepts the answer.
ask() {
  local var=$1 question=$2 default=$3 check=$4 answer
  while true; do
    read -rp "  $question${default:+ [$default]}: " answer
    answer="${answer:-$default}"
    if [[ -z "$answer" ]]; then bad "a value is required" || continue; fi
    if "$check" "$answer"; then
      printf -v "$var" '%s' "$answer"
      return 0
    fi
  done
}

is_hostname() { [[ $1 =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || bad "use lowercase letters, digits and '-'"; }
is_timezone() { timedatectl list-timezones | grep -xF -- "$1" >/dev/null || bad "unknown timezone (see: timedatectl list-timezones)"; }
is_ssh_user() {
  [[ $1 != root ]] || bad "root login is disabled; use a regular sudo user" || return
  id -- "$1" &>/dev/null || bad "no such user" || return
  [[ -s "$(getent passwd "$1" | cut -d: -f6)/.ssh/authorized_keys" ]] \
    || bad "$1 has no ~/.ssh/authorized_keys; add a key first, password login gets disabled"
}
is_ethernet() {
  [[ -e /sys/class/net/$1 ]] || bad "no such interface" || return
  [[ ! -d /sys/class/net/$1/wireless ]] || bad "$1 is Wi-Fi, which this script disables; use Ethernet"
}
is_lan_cidr() {
  { [[ $1 =~ ^[0-9.]+/[0-9]+$ ]] && ipcalc host "$1"; } \
    || bad "enter a usable IPv4 address with prefix length, e.g. 192.168.1.53/24"
}
is_gateway() {
  ipcalc within "$1" "$LAN_SUBNET" || bad "enter an IPv4 address inside $LAN_SUBNET" || return
  [[ $1 != "$LAN_IP" ]] || bad "the gateway cannot be the Pi's own address"
}
is_subnets() {
  local -a nets
  read -ra nets <<< "$1"
  ipcalc networks "${nets[@]}" || bad "enter space-separated IPv4 networks, e.g. 192.168.20.0/24"
}
# ufw only admits SSH from these subnets; a session from elsewhere would be locked out next time.
is_admin_subnets() {
  local -a nets
  is_subnets "$1" || return
  [[ -n "$SSH_PEER" ]] || return 0
  read -ra nets <<< "$1"
  ipcalc within "$SSH_PEER" "${nets[@]}" \
    || bad "this SSH session comes from $SSH_PEER; include its subnet or the firewall will lock you out"
}
is_yes_no() { [[ $1 == yes || $1 == no ]] || bad "answer yes or no"; }
is_web_user() { [[ $1 =~ ^[A-Za-z0-9._-]{1,32}$ ]] || bad "use letters, digits, '.', '_' or '-'"; }

# Source networks of the ufw rules that currently allow PORT, in rule order;
# empty on a fresh Pi. Lets a re-run keep the networks it configured last time.
ufw_sources() {
  ufw show added 2>/dev/null \
    | awk -v p="$1" '$1 == "ufw" && $2 == "allow" && $3 == "from" && $7 == "port" && $8 == p && !seen[$4]++ {print $4}' \
    | paste -sd' ' || true
}

# Client address of the SSH session running this script, empty on the console.
# sudo's env_reset drops SSH_CONNECTION, so read it from the nearest ancestor.
ssh_client_ip() {
  local pid=$$ conn
  while (( pid > 1 )); do
    conn="$(tr '\0' '\n' 2>/dev/null < "/proc/$pid/environ" | sed -n 's/^SSH_CONNECTION=//p')" || true
    if [[ -n "$conn" ]]; then echo "${conn%% *}"; return; fi
    pid="$(ps -o ppid= -p "$pid" | tr -d ' ')"
  done
}

# password_matches USER PASSWORD: PASSWORD is USER's login password. Both go to
# perl through a pipe, so neither the password nor the hash shows in ps.
password_matches() {
  printf '%s\n%s\n' "$2" "$(getent shadow "$1" | cut -d: -f2)" \
    | perl -e 'chomp(my $p = <STDIN>); chomp(my $h = <STDIN>); exit !($h =~ /^\$/ && crypt($p, $h) eq $h)'
}

# ---------------------------------------------------------------------------
# 0. Questions and preflight
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
[[ -t 0 ]] || die "run from an interactive terminal; the script asks for its settings"

# This script turns IPv6 off immediately, which would cut an SSH session running over it.
SSH_PEER="$(ssh_client_ip)"
[[ "$SSH_PEER" != *:* ]] \
  || die "this SSH session runs over IPv6 ($SSH_PEER) and would drop when IPv6 is disabled; reconnect via the Pi's IPv4 address"

log "Settings (Enter accepts the [default])"

current_tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
default_iface="$(ip -4 route show default | awk 'NR == 1 {print $5}')"
if [[ -z "$default_iface" || -d /sys/class/net/$default_iface/wireless ]]; then
  default_iface=eth0
fi
default_gw="$(ip -4 route show default | awk 'NR == 1 {print $3}')"

# sudo sets SUDO_USER to the account that ran it; root itself can never log in.
sudo_user="${SUDO_USER:-}"
[[ "$sudo_user" != root ]] || sudo_user=""

ask HOST_NAME  "Hostname"                "${DEFAULT_HOST_NAME:-$(hostname)}"  is_hostname
ask TIMEZONE   "Timezone"                "${DEFAULT_TIMEZONE:-${current_tz:-Etc/UTC}}" is_timezone
ask ADMIN_USER "SSH user (key login)"    "${DEFAULT_ADMIN_USER:-$sudo_user}" is_ssh_user
ask NET_IFACE  "Ethernet interface"      "$default_iface"     is_ethernet

# Static address default: local.env, else the one already configured (re-runs),
# else the address the interface has now (from DHCP; reserve it in the router).
cidr_default="$DEFAULT_LAN_CIDR"
if [[ -z "$cidr_default" ]]; then
  nm_con="$(nmcli -g GENERAL.CONNECTION device show "$NET_IFACE" 2>/dev/null || true)"
  if [[ -n "$nm_con" && "$(nmcli -g ipv4.method connection show "$nm_con" 2>/dev/null)" == manual ]]; then
    cidr_default="$(nmcli -g ipv4.addresses connection show "$nm_con" | cut -d, -f1)"
  else
    cidr_default="$(ip -4 -o addr show dev "$NET_IFACE" scope global | awk 'NR == 1 {print $4}')"
  fi
fi
ask LAN_CIDR   "Static IP/prefix"        "$cidr_default"      is_lan_cidr
LAN_IP="${LAN_CIDR%/*}"
LAN_PREFIX="${LAN_CIDR#*/}"
LAN_SUBNET="$(ipcalc network "$LAN_CIDR")"

ask GATEWAY    "Gateway (router)"        "${default_gw:-}"    is_gateway

# Network list defaults: local.env, else what the firewall allows now (re-runs, so
# pressing Enter never drops a VLAN), else only the Pi's own network; add VLANs here.
dns_default="${DEFAULT_DNS_SUBNETS:-$(ufw_sources 53)}"
admin_default="${DEFAULT_ADMIN_SUBNETS:-$(ufw_sources 22)}"
ask DNS_SUBNETS   "Networks allowed to use DNS"       "${dns_default:-$LAN_SUBNET}"   is_subnets
ask ADMIN_SUBNETS "Networks allowed SSH and web UI"   "${admin_default:-$LAN_SUBNET}" is_admin_subnets
read -ra DNS_SUBNET_LIST <<< "$DNS_SUBNETS"
read -ra ADMIN_SUBNET_LIST <<< "$ADMIN_SUBNETS"

# Tailscale default: local.env, else yes when this Pi is already on a tailnet (re-runs).
ts_default="$DEFAULT_TAILSCALE"
if [[ -z "$ts_default" ]]; then
  ts_default=no
  if command -v tailscale >/dev/null && tailscale ip -4 &>/dev/null; then ts_default=yes; fi
fi
ask TAILSCALE "Use Tailscale for ad blocking away from home? (no: Tailscale is not installed)" "$ts_default" is_yes_no
if [[ $TAILSCALE == yes ]]; then
  ts_summary="(installed; DNS only, SSH and web UI stay LAN-only)"
elif command -v tailscale >/dev/null; then
  ts_summary="(the Tailscale already on this Pi is left installed, but gets no DNS)"
else
  ts_summary="(nothing Tailscale-related is installed)"
fi

# Raspberry Pi OS lets the first user run sudo without a password, so a stolen SSH
# key or session is root right away. Require the password instead, but only after
# making sure the user knows it (or sets a new one), or sudo would be lost.
# Only for members of the sudo group: for anyone else that file is their only sudo.
NOPASSWD_FILE=/etc/sudoers.d/010_pi-nopasswd
DROP_NOPASSWD=0 SET_SUDO_PASSWORD=0
if [[ -f $NOPASSWD_FILE && " $(id -nG "$ADMIN_USER") " == *" sudo "* ]]; then
  DROP_NOPASSWD=1
  echo "  sudo will ask for $ADMIN_USER's password from now on (Raspberry Pi OS doesn't by default)."
  if [[ "$(getent shadow "$ADMIN_USER" | cut -d: -f2)" == \$* ]]; then
    while true; do
      read -rsp "  $ADMIN_USER's current password (empty: set a new one): " pw; echo
      if [[ -z "$pw" ]]; then SET_SUDO_PASSWORD=1; break; fi
      password_matches "$ADMIN_USER" "$pw" && break
      bad "wrong password" || true
    done
    unset pw
  else
    SET_SUDO_PASSWORD=1
  fi
fi
if (( SET_SUDO_PASSWORD )); then
  sudo_summary="password required (you set a new one after confirming)"
elif (( DROP_NOPASSWD )); then
  sudo_summary="password required"
else
  sudo_summary="unchanged"
fi

if [[ ! -f "$AGH_CONF" || $RESET_AGH_CONFIG -eq 1 ]]; then
  RENDER_AGH_CONFIG=1
  ask AGH_ADMIN_USER "AdGuard Home web user" "admin" is_web_user
  while true; do
    read -rsp "  AdGuard Home web password (12+ characters): " AGH_ADMIN_PASSWORD; echo
    (( ${#AGH_ADMIN_PASSWORD} >= 12 )) || bad "too short" || continue
    read -rsp "  Repeat password: " pw2; echo
    [[ "$AGH_ADMIN_PASSWORD" == "$pw2" ]] && break
    bad "passwords do not match" || true
  done
  unset pw2
fi

cat <<EOF

  Hostname       $HOST_NAME
  Timezone       $TIMEZONE
  SSH user       $ADMIN_USER
  sudo           $sudo_summary
  Interface      $NET_IFACE
  Static IP      $LAN_IP/$LAN_PREFIX   (LAN $LAN_SUBNET)
  Gateway        $GATEWAY
  DNS clients    $DNS_SUBNETS
  Admin access   $ADMIN_SUBNETS   (SSH, web UI)
  Tailscale      $TAILSCALE   $ts_summary
  Pi's own DNS   $HOST_DNS
  Web UI user    ${AGH_ADMIN_USER:-(keeping the existing AdGuard Home config)}

EOF
read -rp "Apply these settings? [y/N] " confirm
[[ "$confirm" == [yY] ]] || die "aborted; nothing was changed"

# ---------------------------------------------------------------------------
# 1. Base system
# ---------------------------------------------------------------------------
log "Hostname and timezone"
hostnamectl set-hostname "$HOST_NAME"
sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOST_NAME/" /etc/hosts
grep -q '^127\.0\.1\.1' /etc/hosts || printf '127.0.1.1\t%s\n' "$HOST_NAME" >> /etc/hosts
timedatectl set-timezone "$TIMEZONE"

log "Packages"
export DEBIAN_FRONTEND=noninteractive
# Keep locally changed config files instead of stopping at a dpkg prompt.
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
apt-get update
apt-get "${APT_OPTS[@]}" full-upgrade
apt-get "${APT_OPTS[@]}" install --no-install-recommends \
  ca-certificates curl gpgv openssl gettext-base apache2-utils bind9-dnsutils python3-yaml \
  ufw fail2ban python3-systemd unattended-upgrades apt-listchanges \
  auditd acct libpam-tmpdir libpam-pwquality debsums apt-show-versions

# ---------------------------------------------------------------------------
# 2. Attack surface: services, radios, IPv6, kernel
# ---------------------------------------------------------------------------
log "Disabling unneeded services"
for unit in bluetooth.service hciuart.service avahi-daemon.service avahi-daemon.socket \
            triggerhappy.service triggerhappy.socket ModemManager.service \
            wpa_supplicant.service cups.service cups-browsed.service; do
  if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q .; then
    systemctl disable --now "$unit" 2>/dev/null || true
    systemctl mask "$unit"
  fi
done

log "Disabling Wi-Fi and Bluetooth radios (effective after reboot)"
BOOT_CFG=/boot/firmware/config.txt
[[ -f $BOOT_CFG ]] || BOOT_CFG=/boot/config.txt
for overlay in disable-wifi disable-bt; do
  grep -q "^dtoverlay=$overlay\$" "$BOOT_CFG" || printf '\n[all]\ndtoverlay=%s\n' "$overlay" >> "$BOOT_CFG"
done

log "Kernel hardening (sysctl)"
install -m 0644 "$FILES/sysctl/90-hardening.conf" /etc/sysctl.d/90-hardening.conf
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
# 3. Network: static IPv4, no IPv6
# ---------------------------------------------------------------------------
log "Static IP $LAN_IP/$LAN_PREFIX on $NET_IFACE"
NM_CON="$(nmcli -g GENERAL.CONNECTION device show "$NET_IFACE" || true)"
if [[ -z "$NM_CON" ]]; then
  NM_CON="lan-$NET_IFACE"
  nmcli connection add type ethernet ifname "$NET_IFACE" con-name "$NM_CON"
fi
nmcli connection modify "$NM_CON" \
  connection.autoconnect yes \
  ipv4.method manual \
  ipv4.addresses "$LAN_IP/$LAN_PREFIX" \
  ipv4.gateway "$GATEWAY" \
  ipv4.dns "$HOST_DNS" \
  ipv4.ignore-auto-dns yes \
  ipv6.method disabled

# ---------------------------------------------------------------------------
# 4. SSH
# ---------------------------------------------------------------------------
log "SSH hardening"
sed "s/@ADMIN_USER@/$ADMIN_USER/" "$FILES/ssh/10-hardening.conf" > /etc/ssh/sshd_config.d/10-hardening.conf
chmod 0644 /etc/ssh/sshd_config.d/10-hardening.conf
# Drop weak host keys; only ed25519 (and RSA for old clients) are offered.
rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*
sshd -t || die "sshd config test failed; not reloading"
systemctl reload ssh

if (( DROP_NOPASSWD )); then
  log "sudo password"
  if (( SET_SUDO_PASSWORD )); then
    echo "  Set a password for $ADMIN_USER; sudo asks for it from now on."
    until passwd "$ADMIN_USER"; do warn "try again"; done
  fi
  rm -f "$NOPASSWD_FILE"
fi

# ---------------------------------------------------------------------------
# 5. Firewall
# ---------------------------------------------------------------------------
log "Firewall (ufw)"
# IPv6 is off, but keep ufw's default deny on it as a backstop: NetworkManager
# turns IPv6 back on for every connection it creates (e.g. a USB Ethernet
# adapter), and sshd listens on IPv6 too.
sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
for net in "${DNS_SUBNET_LIST[@]}"; do
  ufw allow from "$net" to any port 53 proto udp comment 'dns'
  ufw allow from "$net" to any port 53 proto tcp comment 'dns'
done
for net in "${ADMIN_SUBNET_LIST[@]}"; do
  ufw allow from "$net" to any port 22 proto tcp comment 'ssh'
  ufw allow from "$net" to any port 80 proto tcp comment 'adguard ui redirect'
  ufw allow from "$net" to any port 443 proto tcp comment 'adguard ui'
done
# Only tailnet devices arrive on tailscale0; Tailscale's ACLs decide which ones,
# ufw which ports (tailscaled runs with --netfilter-mode=nodivert, see section 8).
if [[ $TAILSCALE == yes ]]; then
  ufw allow in on tailscale0 to any port 53 proto udp comment 'dns tailnet'
  ufw allow in on tailscale0 to any port 53 proto tcp comment 'dns tailnet'
  # tailscaled's default WireGuard port, so devices connect directly instead of
  # via Tailscale's relays. Without nodivert, tailscaled opens it itself.
  ufw allow 41641/udp comment 'tailscale'
fi
ufw logging low
ufw --force enable
rm -f /etc/ufw/*.rules.[0-9]* # backups left by reset
install -D -m 0644 "$FILES/systemd/ufw-sysctl.conf" /etc/systemd/system/ufw.service.d/10-sysctl.conf
systemctl daemon-reload
sysctl --system >/dev/null # ufw enable just applied its own sysctl.conf

# ---------------------------------------------------------------------------
# 6. fail2ban
# ---------------------------------------------------------------------------
log "fail2ban"
sed "s|@ADMIN_SUBNETS@|$ADMIN_SUBNETS|" "$FILES/fail2ban/sshd.local" > /etc/fail2ban/jail.d/sshd.local
chmod 0644 /etc/fail2ban/jail.d/sshd.local
systemctl enable fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------------
# 7. Automatic security updates
# ---------------------------------------------------------------------------
log "Unattended upgrades"
install -m 0644 "$FILES/apt/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
install -m 0644 "$FILES/apt/52unattended-upgrades-local" /etc/apt/apt.conf.d/52unattended-upgrades-local
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

# ---------------------------------------------------------------------------
# 8. Tailscale (optional): DNS for tailnet devices away from home. Connections
#    are outbound only, so it works behind CGNAT without port forwarding.
# ---------------------------------------------------------------------------
TS_IP=""
if [[ $TAILSCALE == yes ]]; then
  log "Tailscale"
  codename="$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)"
  # Tailscale's repository key (fingerprint 2596A99EAAB33821893C0A79458CA832957F5868),
  # pinned like AdGuard's: fetched on every run, a compromised download server
  # could swap in its own key, and with it packages that install as root.
  install -m 0644 "$FILES/tailscale/tailscale-archive-keyring.gpg" \
    /usr/share/keyrings/tailscale-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian $codename main" \
    > /etc/apt/sources.list.d/tailscale.list
  apt-get update
  apt-get "${APT_OPTS[@]}" install tailscale
  install -m 0644 "$FILES/apt/53unattended-upgrades-tailscale" /etc/apt/apt.conf.d/53unattended-upgrades-tailscale
  systemctl enable --now tailscaled

  # Wait for tailscaled to load its state after a (re)start.
  ts_state=""
  for _ in {1..15}; do
    ts_state="$(tailscale status --json 2>/dev/null \
      | python3 -Ic 'import json, sys; print(json.load(sys.stdin)["BackendState"])' 2>/dev/null || true)"
    [[ -n "$ts_state" && "$ts_state" != NoState ]] && break
    sleep 1
  done
  # --accept-dns=false: the Pi keeps resolving via Quad9, not MagicDNS (which
  # would send its own lookups back to this AdGuard Home).
  # --netfilter-mode=nodivert: by default tailscaled accepts everything arriving
  # on tailscale0 ahead of ufw, which opens SSH to the whole tailnet. This keeps
  # ufw in charge (ignore its warning to hook tailscaled's chains in by hand).
  if [[ "$ts_state" == NeedsLogin || "$ts_state" == Stopped ]]; then
    echo "  Open the login URL below on any device to add this Pi to your tailnet."
    tailscale up --accept-dns=false --netfilter-mode=nodivert
  else
    tailscale set --accept-dns=false --netfilter-mode=nodivert
  fi
  TS_IP="$(tailscale ip -4)" || die "Tailscale has no IPv4 address; check: tailscale status"

  install -m 0644 "$FILES/sysctl/91-tailscale-dns.conf" "$TS_SYSCTL"
  sysctl --system >/dev/null
elif [[ -f "$TS_SYSCTL" ]]; then
  # Disabled on a re-run: AdGuard Home stops listening on the tailnet below.
  # Tailscale itself is left running, it may be used for other things, but
  # behind ufw: earlier versions of this script left it bypassing ufw.
  rm -f "$TS_SYSCTL"
  sysctl -w net.ipv4.ip_nonlocal_bind=0 >/dev/null
  # Still installed, so keep it getting security updates.
  install -m 0644 "$FILES/apt/53unattended-upgrades-tailscale" /etc/apt/apt.conf.d/53unattended-upgrades-tailscale
  tailscale set --netfilter-mode=nodivert \
    || warn "Tailscale may still let tailnet traffic past ufw; run: tailscale set --netfilter-mode=nodivert"
fi

# ---------------------------------------------------------------------------
# 9. AdGuard Home
# ---------------------------------------------------------------------------
log "AdGuard Home"
if ! id adguardhome &>/dev/null; then
  useradd --system --no-create-home --home-dir "$AGH_STATE" --shell /usr/sbin/nologin adguardhome
fi

install -m 0755 "$FILES/adguardhome/agh-update.sh" /usr/local/sbin/agh-update
# agh-update verifies every binary against this key (fingerprint in the README).
install -D -m 0644 "$FILES/adguardhome/adguard-release.gpg" /usr/local/share/keyrings/adguard-release.gpg
install -d -m 0700 "$AGH_BACKUP"
for unit in adguardhome.service agh-update.service agh-update.timer; do
  install -m 0644 "$FILES/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
# Installs the latest release, or updates it on re-runs (with rollback on failure).
/usr/local/sbin/agh-update
systemctl enable --now agh-update.timer

install -d -m 0700 -o adguardhome -g adguardhome "$AGH_STATE"

# Self-signed web UI certificate, root-owned and readable by the service's group.
# Regenerated when it expires within 30 days or no longer covers LAN_IP.
install -d -m 0755 "${AGH_TLS%/*}"
install -d -m 0750 -o root -g adguardhome "$AGH_TLS"
TLS_CERT="$AGH_TLS/cert.pem"
TLS_KEY="$AGH_TLS/key.pem"
if [[ ! -f "$TLS_CERT" ]] \
   || ! openssl x509 -in "$TLS_CERT" -noout -checkend $((30 * 86400)) >/dev/null \
   || ! openssl x509 -in "$TLS_CERT" -noout -ext subjectAltName | grep -q "IP Address:$LAN_IP\b"; then
  log "Generating self-signed certificate for $LAN_IP"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=$HOST_NAME" \
    -addext "subjectAltName=IP:$LAN_IP,DNS:$HOST_NAME" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$TLS_KEY" -out "$TLS_CERT" 2>/dev/null
  chown root:adguardhome "$TLS_KEY" "$TLS_CERT"
  chmod 0640 "$TLS_KEY"
  chmod 0644 "$TLS_CERT"
fi
openssl x509 -in "$TLS_CERT" -noout -fingerprint -sha256

# The config is built in WORK (root only). CHECK belongs to adguardhome: the
# --check-config run there may rewrite its copy while migrating the schema.
WORK="$(mktemp -d -p /tmp agh-config.XXXXXXXX)"
CHECK="$(mktemp -d -p /tmp agh-check.XXXXXXXX)"
trap 'rm -rf "$WORK" "$CHECK"' EXIT
chown adguardhome:adguardhome "$CHECK"
if [[ -f "$AGH_CONF" ]]; then
  agh_cat "$AGH_CONF" > "$WORK/live.yaml"
fi

# install_agh_config: validate $WORK/new.yaml, back up the live config and swap it in.
AGH_CONFIG_CHANGED=0
install_agh_config() {
  agh_write "$CHECK/AdGuardHome.yaml" < "$WORK/new.yaml"
  if ! runuser -u adguardhome -- "$AGH_DIR/AdGuardHome" --check-config \
         -c "$CHECK/AdGuardHome.yaml" -w "$AGH_STATE" --no-check-update; then
    install -m 0600 "$WORK/new.yaml" "$AGH_BACKUP/AdGuardHome.yaml.rejected"
    die "new AdGuardHome.yaml is invalid; kept as $AGH_BACKUP/AdGuardHome.yaml.rejected, live config unchanged"
  fi
  if [[ -f "$WORK/live.yaml" ]]; then
    install -m 0600 "$WORK/live.yaml" "$AGH_BACKUP/AdGuardHome.yaml.$(date +%Y%m%d%H%M%S)"
  fi
  # A running instance writes its in-memory config back over the file on the
  # next web UI change. It is started again below, or at boot.
  systemctl stop adguardhome
  agh_write "$AGH_CONF" < "$WORK/new.yaml"
  AGH_CONFIG_CHANGED=1
}

# agh_healthy: the service is up and answers a name it resolves itself (from
# /etc/hosts), so an internet or upstream outage does not count as a failure.
agh_healthy() {
  for _ in {1..15}; do
    if systemctl is-active --quiet adguardhome \
       && [[ "$(dig @127.0.0.1 localhost A +short +time=2 +tries=1 2>/dev/null)" == 127.0.0.1 ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# Addresses AdGuard Home listens on and networks it answers (127.0.0.1 is always in both).
AGH_BIND_LIST=("$LAN_IP")
AGH_CLIENT_LIST=("${DNS_SUBNET_LIST[@]}")
if [[ -n "$TS_IP" ]]; then
  AGH_BIND_LIST+=("$TS_IP")
  AGH_CLIENT_LIST+=("$TAILNET_CIDR")
fi

if (( RENDER_AGH_CONFIG )); then
  # Read from stdin (-i) so the password never appears in the process list.
  AGH_ADMIN_HASH="$(printf '%s' "$AGH_ADMIN_PASSWORD" | htpasswd -niBC 12 "$AGH_ADMIN_USER" | cut -d: -f2-)"
  unset AGH_ADMIN_PASSWORD
  AGH_BIND_HOSTS="$(printf '    - %s\n' "${AGH_BIND_LIST[@]}")"
  AGH_ALLOWED_CLIENTS="$(printf '    - %s\n' "${AGH_CLIENT_LIST[@]}")"
  export LAN_IP GATEWAY AGH_BIND_HOSTS AGH_ALLOWED_CLIENTS AGH_ADMIN_USER AGH_ADMIN_HASH
  # shellcheck disable=SC2016 # literal variable list for envsubst
  envsubst '${LAN_IP} ${GATEWAY} ${AGH_BIND_HOSTS} ${AGH_ALLOWED_CLIENTS} ${AGH_ADMIN_USER} ${AGH_ADMIN_HASH}' \
    < "$FILES/adguardhome/AdGuardHome.yaml.tmpl" > "$WORK/new.yaml"
  unset AGH_ADMIN_HASH
  if [[ -f "$WORK/live.yaml" ]]; then
    # A reset restores the template's settings but keeps the lists curated in
    # the web UI. They replace the template's lists, so a list removed or
    # disabled there stays that way.
    rc=0
    python3 -I - "$WORK/live.yaml" "$WORK/new.yaml" <<'EOF' || rc=$?
import sys, yaml
old_path, new_path = sys.argv[1:]
with open(old_path) as f:
    old = yaml.safe_load(f)
with open(new_path) as f:
    new = yaml.safe_load(f)
# Keys move between schema versions; copying them across versions could
# silently drop or misplace the lists.
if old.get("schema_version") != new.get("schema_version"):
    print(f"schema {old.get('schema_version')}, template schema {new.get('schema_version')}")
    sys.exit(3)
for path in [("filters",), ("whitelist_filters",), ("user_rules",),
             ("clients", "persistent"), ("filtering", "rewrites")]:
    src, dst = old, new
    for key in path[:-1]:
        src, dst = src.get(key) or {}, dst[key]
    value = src.get(path[-1]) or []
    dst[path[-1]] = value
    print(f"  {'.'.join(path)}: {len(value)} kept")
with open(new_path, "w") as f:
    yaml.safe_dump(new, f, sort_keys=False, allow_unicode=True, width=1 << 30)
EOF
    case $rc in
      0) ;;
      3) warn "the live config's schema differs from the template's; lists, rules, clients and rewrites were NOT carried over (they remain in the $AGH_BACKUP/AdGuardHome.yaml.* backup)" ;;
      *) die "could not carry the lists over from $AGH_CONF; live config unchanged" ;;
    esac
  fi
  install_agh_config
else
  # Keep the existing config (and its web UI changes), but bring the fields this
  # script owns in line with the answers: a stale bind address after a static IP
  # change would keep AdGuard Home from starting at all.
  python3 -I - "$WORK/live.yaml" "$WORK/new.yaml" "$LAN_IP" "$GATEWAY" "${AGH_BIND_LIST[*]}" "${AGH_CLIENT_LIST[*]}" "$TLS_CERT" "$TLS_KEY" <<'EOF'
import sys, yaml
src, dst, lan_ip, gateway, bind_hosts, clients, tls_cert, tls_key = sys.argv[1:]
with open(src) as f:
    conf = yaml.safe_load(f)
want = {
    ("http", "address"): f"{lan_ip}:80",
    ("dns", "bind_hosts"): ["127.0.0.1", *bind_hosts.split()],
    ("dns", "local_ptr_upstreams"): [gateway],
    ("dns", "allowed_clients"): ["127.0.0.1", *clients.split()],
    ("tls", "certificate_path"): tls_cert,
    ("tls", "private_key_path"): tls_key,
}
changed = False
for (section, key), value in want.items():
    if conf[section].get(key) != value:
        print(f"  {section}.{key}: {conf[section].get(key)} -> {value}")
        conf[section][key] = value
        changed = True
if changed:
    with open(dst, "w") as f:
        yaml.safe_dump(conf, f, sort_keys=False, allow_unicode=True, width=1 << 30)
EOF
  if [[ -f "$WORK/new.yaml" ]]; then
    log "Updated AdGuard Home config (other web UI settings kept)"
    install_agh_config
  else
    echo "keeping existing $AGH_CONF, already matches these settings (use --reset-agh-config to re-render)"
  fi
fi
systemctl enable adguardhome
# AdGuard Home binds to LAN_IP; it can only start once that address is configured.
if ip -4 addr show dev "$NET_IFACE" | grep -q "inet $LAN_IP/"; then
  log "Restarting AdGuard Home"
  systemctl restart adguardhome
  NEED_REBOOT=0
  if ! agh_healthy; then
    # The whole network depends on it: put the previous config back. Older configs
    # point at the certificate in $AGH_STATE/tls, which is left in place for this.
    if (( AGH_CONFIG_CHANGED )) && [[ -f "$WORK/live.yaml" ]]; then
      warn "AdGuard Home does not answer with the new config; restoring the previous one"
      install -m 0600 "$WORK/new.yaml" "$AGH_BACKUP/AdGuardHome.yaml.rejected"
      systemctl stop adguardhome
      agh_write "$AGH_CONF" < "$WORK/live.yaml"
      systemctl start adguardhome
      if agh_healthy; then
        die "rolled back; AdGuard Home answers again with the previous config. The new one is in $AGH_BACKUP/AdGuardHome.yaml.rejected, see why: journalctl -u adguardhome -n 50"
      fi
    fi
    die "AdGuard Home does not answer DNS; see: journalctl -u adguardhome -n 50"
  fi
  echo "AdGuard Home answers on 127.0.0.1"
else
  NEED_REBOOT=1
fi

# ---------------------------------------------------------------------------
# 10. Audit and integrity
# ---------------------------------------------------------------------------
log "Audit, accounting and other hardening"
install -m 0644 "$FILES/modprobe/hardening.conf" /etc/modprobe.d/hardening.conf
install -m 0644 "$FILES/security/no-core.conf" /etc/security/limits.d/hardening-no-core.conf
install -D -m 0644 "$FILES/security/pwquality.conf" /etc/security/pwquality.conf.d/hardening.conf
if ! grep -qE '^\s*tmpfs\s+/dev/shm\s' /etc/fstab; then
  echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
  systemctl daemon-reload
  mount -o remount /dev/shm || warn "could not remount /dev/shm; applies after reboot"
fi

# Both need kernel support; rather than a unit failing at every boot, turn off
# what this kernel can't do.
install -m 0640 "$FILES/audit/hardening.rules" /etc/audit/rules.d/hardening.rules
if ! { systemctl enable --now auditd && augenrules --load >/dev/null; }; then
  warn "auditd could not start or load its rules (no kernel support?); turning it off"
  systemctl disable --now auditd 2>/dev/null || true
  systemctl reset-failed auditd 2>/dev/null || true
fi
if ! systemctl enable --now acct; then
  warn "process accounting could not start (no kernel support?); turning it off"
  systemctl disable --now acct 2>/dev/null || true
  systemctl reset-failed acct 2>/dev/null || true
fi

# Weekly check of installed files against their packages (manually: debsums -s).
sed -i 's/^CRON_CHECK=.*/CRON_CHECK=weekly/' /etc/default/debsums
# Only root needs to read cron jobs and the SSH server config.
for f in /etc/crontab /etc/ssh/sshd_config; do
  if [[ -f $f ]]; then chmod 0600 "$f"; fi
done
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d $d ]]; then chmod 0700 "$d"; fi
done

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
log "Done"
cat <<EOF
  DNS:       $LAN_IP:53   (from $DNS_SUBNETS)
${TS_IP:+  Tailnet:   $TS_IP:53   (from Tailscale devices)
}  Web UI:    https://$LAN_IP/   (from $ADMIN_SUBNETS, self-signed${AGH_ADMIN_USER:+, user: $AGH_ADMIN_USER})
             compare the browser's certificate with the SHA-256 fingerprint printed above
  SSH:       ssh $ADMIN_USER@$LAN_IP   (key only, from $ADMIN_SUBNETS)
  Pi's DNS:  $HOST_DNS   (Quad9 directly, not its own AdGuard Home)

Next steps:
  1. Reboot to apply the static IP, radio overlays and IPv6 settings:  sudo reboot
  2. Router: give the Pi the fixed IP $LAN_IP, and make sure its switch port
     is in the $LAN_SUBNET network.
  3. Router: in the DHCP settings of every network ($DNS_SUBNETS),
     set the DNS server to $LAN_IP only. Leave the gateway's own WAN DNS alone;
     pointing it at the Pi hides clients behind the gateway.
  4. Isolated networks (IoT, guest): allow UDP/TCP 53 to $LAN_IP in the router firewall
     *before* pointing their DHCP DNS at the Pi, or they lose DNS entirely.
  5. Verify from a client: dig @${LAN_IP} example.com ; dig @${LAN_IP} doubleclick.net
EOF
if [[ -n "$TS_IP" ]]; then
  cat <<EOF
  6. Tailscale admin console (https://login.tailscale.com/admin):
     - Machines: disable key expiry for this Pi, or it drops off the tailnet in 180 days.
     - DNS: add nameserver $TS_IP and turn on "Override DNS servers".
     Verify from a phone on mobile data with Tailscale on: dig @${TS_IP} doubleclick.net
EOF
fi
if (( NEED_REBOOT )); then
  warn "$LAN_IP is not on $NET_IFACE yet; AdGuard Home will start after reboot. Reboot now."
fi
exit 0
