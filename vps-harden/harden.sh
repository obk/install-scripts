#!/usr/bin/env bash
#
# harden.sh - Interactive hardening for a fresh Ubuntu 22.04 / 24.04 / 26.04 VPS.
#
# Asks for settings (press Enter to accept the [default]), shows a summary,
# and only changes the system after you confirm. Steps:
#   1. Update packages
#   2. Create a sudo user (password required) and copy root's SSH keys to it
#   3. Tailscale (optional): join tailnet, optionally make SSH tailnet-only
#   4. SSH: disable root login / password auth, optional port change
#   5. UFW firewall: deny incoming by default, allow SSH + chosen ports
#   6. Fail2ban for SSH
#   7. Automatic security updates (unattended-upgrades)
#   8. Kernel / sysctl hardening
#   9. Disable unused services
#  10. DNS: Quad9 over DNS-over-TLS (systemd-resolved)
#  11. Extra hardening (from lynis): auditd, process accounting,
#      unused kernel modules blocked, password strength rules, weekly
#      debsums check, cron and sshd_config readable by root only
#
# Usage (as root):
#   bash harden.sh
#   BEFORE closing your current session, open a NEW terminal and check that
#   `ssh <user>@<server>` works and `sudo -v` accepts your password.
#
set -euo pipefail

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*"; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\e[1;36m== %s ==\e[0m\n' "$*"; }

# ask VAR "Question" "default" [validator]
#   Prompts until the validator (a function name) accepts the answer.
ask() {
  local __var=$1 __q=$2 __def=$3 __check=${4:-} __ans
  while true; do
    read -r -p "$__q [$__def]: " __ans
    __ans=${__ans:-$__def}
    if [[ -z "$__check" ]] || "$__check" "$__ans"; then
      printf -v "$__var" '%s' "$__ans"
      return
    fi
  done
}

# ask_yn VAR "Question" y|n  -> sets VAR to "true" / "false"
ask_yn() {
  local __var=$1 __q=$2 __def=$3 __ans __hint
  [[ $__def == y ]] && __hint="Y/n" || __hint="y/N"
  while true; do
    read -r -p "$__q [$__hint]: " __ans
    __ans=${__ans:-$__def}
    case "${__ans,,}" in
      y|yes) printf -v "$__var" true;  return ;;
      n|no)  printf -v "$__var" false; return ;;
      *) warn "Please answer y or n." ;;
    esac
  done
}

# ------------------------------ Validators ----------------------------------

valid_user() {
  [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ && $1 != root ]] && return
  warn "Use lowercase letters, digits, '-' or '_' (max 32 chars, not 'root')."; return 1
}
valid_port() {
  [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) && return
  warn "Enter a port number between 1 and 65535."; return 1
}
valid_int() {
  [[ $1 =~ ^[1-9][0-9]*$ ]] && return
  warn "Enter a positive whole number."; return 1
}
valid_duration() {
  [[ $1 =~ ^[0-9]+[smhdw]?$ ]] && return
  warn "Use a number with optional unit, e.g. 600, 10m, 1h, 1d, 1w."; return 1
}
valid_time() {
  [[ $1 =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] && return
  warn "Use HH:MM (24h), e.g. 04:00."; return 1
}
valid_hostname() {
  [[ $1 =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && return
  warn "Use letters, digits and '-' (max 63 chars, no leading/trailing '-')."; return 1
}
# Space/comma separated list like "80 443/tcp 51820/udp" (empty = none)
valid_ports_list() {
  local p
  for p in ${1//,/ }; do
    [[ $p == none ]] && continue
    if ! [[ $p =~ ^([0-9]+)(/(tcp|udp))?$ ]] || (( BASH_REMATCH[1] < 1 || BASH_REMATCH[1] > 65535 )); then
      warn "Invalid entry '$p'. Use e.g. '80 443' or '443/tcp, 51820/udp'."; return 1
    fi
  done
}

# --------------------------- Preflight checks -------------------------------

[[ $EUID -eq 0 ]] || die "Run this script as root."
[[ -t 0 ]] || die "This script is interactive; run it from a terminal (bash harden.sh)."

# shellcheck source=/dev/null
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || die "This script supports Ubuntu only (found: ${ID:-unknown})."
case "${VERSION_ID:-}" in
  22.04|24.04|26.04) ;;
  *) warn "Untested Ubuntu version ${VERSION_ID:-?}; continuing anyway." ;;
esac

ROOT_KEYS="/root/.ssh/authorized_keys"
HAVE_ROOT_KEYS=false
[[ -s "$ROOT_KEYS" ]] && HAVE_ROOT_KEYS=true

# Check sshd before asking anything: step 4 needs a working `sshd -t`, and
# failing there would leave the system half changed.
command -v sshd &>/dev/null || die "OpenSSH server is not installed (apt-get install openssh-server)."
SSHD_T=$(sshd -T 2>&1) || die "'sshd -T' failed: $SSHD_T"

# Current SSH port, used as the default
CURRENT_SSH_PORT=$(awk '$1=="port"{print $2; exit}' <<<"$SSHD_T")
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}

# ------------------------------ Questions -----------------------------------

printf '\e[1mUbuntu VPS hardening\e[0m — press Enter to accept the [default].\n'

hdr "User"
ask NEW_USER "Name of the sudo user to create/use" "deploy" valid_user

hdr "SSH"
ask SSH_PORT "SSH port" "$CURRENT_SSH_PORT" valid_port
ask_yn SSH_NO_ROOT "Disable root login over SSH?" y
if $HAVE_ROOT_KEYS; then
  ask_yn SSH_KEY_ONLY "Disable password login (SSH keys only)?" y
else
  warn "$ROOT_KEYS is missing or empty: password login will stay enabled"
  warn "to avoid locking you out. Add your key and re-run to enable key-only."
  SSH_KEY_ONLY=false
fi

hdr "Tailscale"
ask_yn DO_TS "Install Tailscale?" n
TS_KEY="" TS_HOSTNAME="" TS_SSH_ONLY=false TS_SSH=false TS_DNS=true TS_TRUST=false TS_EXIT=false TS_AUTOUPDATE=false
if $DO_TS; then
  echo "  Create an auth key at https://login.tailscale.com/admin/settings/keys"
  echo "  (input is hidden; leave empty to log in via a URL instead)"
  while true; do
    read -r -s -p "Tailscale auth key: " TS_KEY; echo
    [[ -z $TS_KEY || $TS_KEY == tskey-* ]] && break
    warn "Auth keys start with 'tskey-'. Try again or leave empty."
  done
  ask TS_HOSTNAME "Hostname on the tailnet" "$(hostname -s)" valid_hostname
  ask_yn TS_SSH_ONLY "Allow SSH ONLY over Tailscale (block public SSH)?" y
  ask_yn TS_SSH "Enable Tailscale SSH (auth via tailnet ACLs instead of keys)?" n
  ask_yn TS_DNS "Accept DNS settings from the tailnet (MagicDNS)?" y
  ask_yn TS_TRUST "Allow ALL incoming traffic from the tailnet (not just SSH)?" n
  ask_yn TS_EXIT "Advertise this server as an exit node?" n
  ask_yn TS_AUTOUPDATE "Enable Tailscale auto-updates?" y
fi

hdr "Firewall (UFW)"
if $TS_SSH_ONLY; then
  log "Firewall is required for Tailscale-only SSH; enabling it."
  DO_FIREWALL=true
else
  ask_yn DO_FIREWALL "Enable UFW firewall (deny incoming by default)?" y
fi
EXTRA_PORTS=""
if $DO_FIREWALL; then
  ask EXTRA_PORTS "Extra ports to open besides SSH (e.g. '80 443', 'none')" "none" valid_ports_list
fi

hdr "Fail2ban"
ask_yn DO_F2B "Install Fail2ban for SSH?" y
if $DO_F2B; then
  ask F2B_MAXRETRY "Failed attempts before ban" "5"   valid_int
  ask F2B_FINDTIME "Time window for counting fails" "10m" valid_duration
  ask F2B_BANTIME  "Ban duration" "1h" valid_duration
fi

hdr "Automatic updates"
DO_AUTOUPDATE=false
ask_yn DO_AUTOUPDATE "Enable automatic security updates?" y
AUTO_REBOOT=false
AUTO_REBOOT_TIME="04:00"
if $DO_AUTOUPDATE; then
  ask_yn AUTO_REBOOT "Automatically reboot when an update requires it?" n
  if $AUTO_REBOOT; then
    ask AUTO_REBOOT_TIME "Reboot time (HH:MM, server time)" "04:00" valid_time
  fi
fi

hdr "System"
ask_yn DO_SYSCTL "Apply kernel/sysctl hardening?" y
ask_yn DO_SERVICES "Disable unused services (rpcbind, avahi, cups, ModemManager, bluetooth)?" y
REMOVE_SNAPD=false
if $DO_SERVICES && command -v snap &>/dev/null; then
  ask_yn REMOVE_SNAPD "Remove snapd (skipped if non-base snaps are installed)?" y
fi
ask_yn DO_DNS "Use Quad9 as the DNS resolver (encrypted with DNS-over-TLS)?" y
ask_yn DO_EXTRA "Extra hardening (auditd, process accounting, block unused kernel modules, password strength rules)?" y

DISABLE_SERVICES=(rpcbind avahi-daemon cups cups-browsed ModemManager bluetooth)

# Normalize extra ports into an array like (80/tcp 443/tcp)
OPEN_PORTS=()
for p in ${EXTRA_PORTS//,/ }; do
  [[ $p == none ]] && continue
  [[ $p == */* ]] || p="$p/tcp"
  OPEN_PORTS+=("$p")
done

# ------------------------------- Summary ------------------------------------

yn() { $1 && echo yes || echo no; }

hdr "Summary"
cat <<EOF
  Sudo user:           $NEW_USER (password required for sudo)
  SSH port:            $SSH_PORT$( [[ $SSH_PORT != "$CURRENT_SSH_PORT" ]] && echo "  (changing from $CURRENT_SSH_PORT)")
  Disable root login:  $(yn "$SSH_NO_ROOT")
  Key-only SSH:        $(yn "$SSH_KEY_ONLY")
  Tailscale:           $(yn "$DO_TS")$($DO_TS && echo "  (hostname: $TS_HOSTNAME, $([[ -n $TS_KEY ]] && echo 'auth key' || echo 'login URL'))")
EOF
if $DO_TS; then cat <<EOF
    SSH only via TS:   $(yn "$TS_SSH_ONLY")
    Tailscale SSH:     $(yn "$TS_SSH")
    Accept DNS:        $(yn "$TS_DNS")
    Trust tailnet:     $(yn "$TS_TRUST")
    Exit node:         $(yn "$TS_EXIT")
    Auto-update:       $(yn "$TS_AUTOUPDATE")
EOF
fi
cat <<EOF
  UFW firewall:        $(yn "$DO_FIREWALL")$($DO_FIREWALL && echo "  (open: $($TS_SSH_ONLY && echo "${SSH_PORT}/tcp on tailscale0 only" || echo "${SSH_PORT}/tcp") ${OPEN_PORTS[*]:-})")
  Fail2ban:            $(yn "$DO_F2B")$($DO_F2B && echo "  ($F2B_MAXRETRY tries / $F2B_FINDTIME -> ban $F2B_BANTIME)")
  Auto updates:        $(yn "$DO_AUTOUPDATE")$($AUTO_REBOOT && echo "  (auto-reboot at $AUTO_REBOOT_TIME)")
  Sysctl hardening:    $(yn "$DO_SYSCTL")
  Disable services:    $(yn "$DO_SERVICES")$($REMOVE_SNAPD && echo "  (+ remove snapd)")
  Quad9 DNS:           $(yn "$DO_DNS")
  Extra hardening:     $(yn "$DO_EXTRA")
EOF

if $SSH_NO_ROOT && ! $HAVE_ROOT_KEYS; then
  warn "Root login will be disabled and no SSH keys exist: you will log in as"
  warn "'$NEW_USER' with its password."
fi

echo
ask_yn CONFIRM "Apply these changes?" n
$CONFIRM || die "Aborted; nothing was changed."

export DEBIAN_FRONTEND=noninteractive

# ----------------------------- 1. Updates -----------------------------------

hdr "1. Updating packages"
PKGS=(sudo)
$DO_TS         && PKGS+=(curl ca-certificates)
$DO_FIREWALL   && PKGS+=(ufw)
$DO_F2B        && PKGS+=(fail2ban)
$DO_AUTOUPDATE && PKGS+=(unattended-upgrades apt-listchanges)
# Installed before step 2 so the new user's password is already strength-checked
$DO_EXTRA      && PKGS+=(auditd acct libpam-tmpdir libpam-pwquality debsums apt-show-versions)
apt-get update -y
apt-get upgrade -y
apt-get install -y "${PKGS[@]}"

# --------------------------- 2. Sudo user -----------------------------------

hdr "2. Sudo user"
if id "$NEW_USER" &>/dev/null; then
  log "User '$NEW_USER' already exists."
else
  log "Creating user '$NEW_USER'..."
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

# Set a password (needed for sudo) if the account doesn't have one yet
if passwd -S "$NEW_USER" | awk '{print $2}' | grep -qE '^(L|NP)$'; then
  log "Set a password for '$NEW_USER' (used for sudo):"
  until passwd "$NEW_USER"; do warn "Try again."; done
else
  ask_yn CHANGE_PW "'$NEW_USER' already has a password. Change it?" n
  if $CHANGE_PW; then
    until passwd "$NEW_USER"; do warn "Try again."; done
  fi
fi

if $HAVE_ROOT_KEYS; then
  log "Copying root's authorized_keys to '$NEW_USER'..."
  USER_HOME=$(getent passwd "$NEW_USER" | cut -d: -f6)
  install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "$USER_HOME/.ssh"
  touch "$USER_HOME/.ssh/authorized_keys"
  # Merge root's keys without duplicating existing ones
  sort -u "$USER_HOME/.ssh/authorized_keys" "$ROOT_KEYS" -o "$USER_HOME/.ssh/authorized_keys"
  chown "$NEW_USER:$NEW_USER" "$USER_HOME/.ssh/authorized_keys"
  chmod 600 "$USER_HOME/.ssh/authorized_keys"
fi

# ---------------------------- 3. Tailscale ----------------------------------

TS_UP=false
TS_IP=""
if $DO_TS; then
  hdr "3. Tailscale"
  if ! command -v tailscale &>/dev/null; then
    log "Adding Tailscale apt repository..."
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.noarmor.gpg" \
      -o /usr/share/keyrings/tailscale-archive-keyring.gpg
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.tailscale-keyring.list" \
      -o /etc/apt/sources.list.d/tailscale.list
    apt-get update -y
    apt-get install -y tailscale
  fi
  systemctl enable --now tailscaled

  if $TS_EXIT; then
    # Exit nodes must forward packets
    cat > /etc/sysctl.d/99-tailscale.conf <<'EOF'
# Managed by harden.sh (Tailscale exit node)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# Strict rp_filter breaks exit-node forwarding; use loose mode
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
    sysctl -p /etc/sysctl.d/99-tailscale.conf >/dev/null
  fi

  TS_ARGS=(--reset --hostname="$TS_HOSTNAME" --accept-dns="$TS_DNS" --ssh="$TS_SSH")
  $TS_EXIT && TS_ARGS+=(--advertise-exit-node)

  if [[ -n $TS_KEY ]]; then
    # Pass the key via a temp file so it never appears in the process list
    TS_KEYFILE=$(mktemp)
    chmod 600 "$TS_KEYFILE"
    printf '%s' "$TS_KEY" > "$TS_KEYFILE"
    TS_ARGS+=(--auth-key="file:$TS_KEYFILE" --timeout=120s)
  else
    log "Open the URL below in your browser to log this server in:"
    TS_ARGS+=(--timeout=600s)
  fi

  if tailscale up "${TS_ARGS[@]}"; then
    TS_IP=$(tailscale ip -4 2>/dev/null | head -n1 || true)
    [[ -n $TS_IP ]] && TS_UP=true
  fi
  [[ -n ${TS_KEYFILE:-} ]] && rm -f "$TS_KEYFILE"
  unset TS_KEY

  if $TS_UP; then
    log "Tailscale connected: $TS_HOSTNAME ($TS_IP)"
    if $TS_AUTOUPDATE; then
      tailscale set --auto-update || warn "Could not enable Tailscale auto-update."
    fi
    $TS_EXIT && warn "Approve the exit node in the Tailscale admin console."
  else
    warn "Tailscale did not come up. Check 'tailscale status' later."
    if $TS_SSH_ONLY; then
      warn "Keeping PUBLIC SSH open to avoid locking you out."
      TS_SSH_ONLY=false
    fi
  fi
fi

# ----------------------------- 4. SSH ---------------------------------------

hdr "4. SSH"
PERMIT_ROOT=$($SSH_NO_ROOT && echo no || echo prohibit-password)
PASS_AUTH=$($SSH_KEY_ONLY && echo no || echo yes)

# Ubuntu reads sshd_config.d/*.conf in lexical order and the FIRST value wins,
# so "00-" overrides cloud-init's 50-cloud-init.conf (which often enables passwords).
cat > /etc/ssh/sshd_config.d/00-hardening.conf <<EOF
# Managed by harden.sh
Port $SSH_PORT
PermitRootLogin $PERMIT_ROOT
PasswordAuthentication $PASS_AUTH
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
UsePAM yes
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 2
LogLevel VERBOSE
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
EOF

sshd -t || die "sshd config test failed; SSH was not restarted."
log "SSH config written (restart happens at the end)."

# ----------------------------- 5. Firewall ----------------------------------

if $DO_FIREWALL; then
  hdr "5. Firewall"
  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  if $TS_SSH_ONLY; then
    ufw limit in on tailscale0 to any port "$SSH_PORT" proto tcp comment 'SSH via Tailscale only'
  else
    ufw limit "${SSH_PORT}/tcp" comment 'SSH (rate-limited)'
  fi
  if $DO_TS; then
    ufw allow 41641/udp comment 'Tailscale direct connections'
    $TS_TRUST && ufw allow in on tailscale0 comment 'Trust tailnet'
    if $TS_EXIT; then
      WAN_IF=$(ip route show default | awk '{print $5; exit}')
      ufw route allow in on tailscale0 out on "$WAN_IF" comment 'Tailscale exit node'
    fi
  fi
  for p in "${OPEN_PORTS[@]}"; do
    ufw allow "$p"
  done
  ufw logging low
  ufw --force enable
  ufw status verbose
fi

# ----------------------------- 6. Fail2ban ----------------------------------

if $DO_F2B; then
  hdr "6. Fail2ban"
  BANACTION=$($DO_FIREWALL && echo ufw || echo iptables-multiport)
  IGNOREIP="127.0.0.1/8 ::1"
  $DO_TS && IGNOREIP+=" 100.64.0.0/10 fd7a:115c:a1e0::/48"   # tailnet ranges
  cat > /etc/fail2ban/jail.local <<EOF
# Managed by harden.sh
[DEFAULT]
bantime   = $F2B_BANTIME
findtime  = $F2B_FINDTIME
maxretry  = $F2B_MAXRETRY
backend   = systemd
banaction = $BANACTION
ignoreip  = $IGNOREIP

[sshd]
enabled = true
port    = $SSH_PORT
EOF
  systemctl enable fail2ban
  systemctl restart fail2ban
  log "Fail2ban active."
fi

# ----------------------- 7. Automatic updates -------------------------------

if $DO_AUTOUPDATE; then
  hdr "7. Automatic updates"
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  cat > /etc/apt/apt.conf.d/52unattended-upgrades-local <<EOF
// Managed by harden.sh
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$AUTO_REBOOT";
Unattended-Upgrade::Automatic-Reboot-Time "$AUTO_REBOOT_TIME";
EOF
  systemctl enable --now unattended-upgrades
  log "Unattended upgrades enabled."
fi

# ----------------------- 8. Kernel / sysctl ---------------------------------

if $DO_SYSCTL; then
  hdr "8. Kernel / sysctl"
  cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Managed by harden.sh

# --- Network: IPv4 ---
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1

# --- Network: IPv6 ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Kernel ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
  # apport sets fs.suid_dumpable=2 whenever it starts; a server doesn't need crash reports
  if systemctl list-unit-files apport.service 2>/dev/null | grep -q '^apport.service'; then
    systemctl disable --now apport.service
    log "Disabled apport (it sets fs.suid_dumpable to 2)."
  fi
  sysctl --system >/dev/null || warn "Some sysctl settings could not be applied (see above)."

  # ufw applies /etc/ufw/sysctl.conf on every start, which sets log_martians back
  # to 0. Re-apply sysctl.d after it (a drop-in leaves ufw's own conffiles untouched).
  if command -v ufw &>/dev/null; then
    mkdir -p /etc/systemd/system/ufw.service.d
    cat > /etc/systemd/system/ufw.service.d/harden-sysctl.conf <<'EOF'
# Managed by harden.sh
[Service]
ExecStartPost=-/usr/lib/systemd/systemd-sysctl
EOF
    systemctl daemon-reload
  fi

  # Disable core dumps for all users
  echo '* hard core 0' > /etc/security/limits.d/99-no-core.conf

  # Mount shared memory without exec/suid/dev
  if ! grep -qE '^\s*tmpfs\s+/dev/shm' /etc/fstab; then
    echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
    systemctl daemon-reload
    mount -o remount /dev/shm || warn "Could not remount /dev/shm; will apply on reboot."
  fi
  log "Kernel hardening applied."
fi

# --------------------- 9. Disable unused services ---------------------------

if $DO_SERVICES; then
  hdr "9. Unused services"
  for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "^${svc}.service"; then
      systemctl disable --now "${svc}.service" "${svc}.socket" 2>/dev/null || true
      log "Disabled $svc"
    fi
  done

  if $REMOVE_SNAPD; then
    # Only remove snapd if nothing beyond base snaps is installed
    EXTRA_SNAPS=$(snap list 2>/dev/null | awk 'NR>1 {print $1}' \
      | grep -vE '^(core[0-9]*|snapd|bare|lxd)$' || true)
    if [[ -n "$EXTRA_SNAPS" ]]; then
      warn "Keeping snapd; these snaps are installed: ${EXTRA_SNAPS//$'\n'/ }"
    else
      log "Removing snapd..."
      apt-get purge -y snapd
      rm -rf /root/snap /snap /var/snap /var/lib/snapd
      # Prevent it from being reinstalled as a dependency
      cat > /etc/apt/preferences.d/no-snapd.pref <<'EOF'
Package: snapd
Pin: release *
Pin-Priority: -10
EOF
    fi
  fi
fi

apt-get autoremove -y

# ------------------------------ 10. DNS -------------------------------------

# quad9_conf yes|opportunistic  -> write the resolved drop-in and restart
quad9_conf() {
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/99-quad9.conf <<EOF
# Managed by harden.sh
# Quad9 blocks known malware domains and validates DNSSEC. "Domains=~." sends
# every lookup here instead of the provider's DNS servers from DHCP.
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
Domains=~.
DNSOverTLS=$1
EOF
  systemctl restart systemd-resolved
}
dns_works() { timeout 20 resolvectl query --cache=no archive.ubuntu.com &>/dev/null; }

if $DO_DNS; then
  hdr "10. DNS (Quad9)"
  if ! systemctl is-active --quiet systemd-resolved; then
    warn "systemd-resolved is not running; DNS left unchanged."
  elif [[ $(readlink -f /etc/resolv.conf) != /run/systemd/resolve/stub-resolv.conf ]]; then
    warn "/etc/resolv.conf does not point to systemd-resolved's stub; DNS left unchanged."
  else
    quad9_conf yes
    if dns_works; then
      log "DNS: Quad9 over TLS."
    else
      warn "DNS-over-TLS (port 853) doesn't work here; allowing plain DNS to Quad9 as fallback."
      quad9_conf opportunistic
      if dns_works; then
        log "DNS: Quad9 (TLS when available)."
      else
        warn "Lookups via Quad9 fail; restoring the previous DNS settings."
        rm -f /etc/systemd/resolved.conf.d/99-quad9.conf
        systemctl restart systemd-resolved
      fi
    fi
  fi
fi

# ------------------------- 11. Extra hardening ------------------------------

if $DO_EXTRA; then
  hdr "11. Extra hardening"

  # Kernel modules a VPS never needs: rare network protocols (old remote bugs),
  # exotic filesystems, USB/FireWire storage
  mkdir -p /etc/modprobe.d
  {
    echo "# Managed by harden.sh"
    for m in dccp sctp rds tipc cramfs freevxfs jffs2 hfs hfsplus usb-storage firewire-core; do
      printf 'blacklist %s\ninstall %s /bin/false\n' "$m" "$m"
    done
  } > /etc/modprobe.d/harden-blacklist.conf
  log "Blocked unused kernel modules."

  # Audit changes to accounts, sudo and SSH settings, and commands that
  # logged-in users run as root. Search with: ausearch -k <key>
  cat > /etc/audit/rules.d/harden.rules <<'EOF'
## Managed by harden.sh
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root-commands
EOF
  if systemctl enable --now auditd && augenrules --load >/dev/null; then
    log "auditd running (ausearch -k identity|sudoers|sshd|root-commands)."
  else
    warn "auditd could not start or load its rules; check 'systemctl status auditd'."
  fi

  # Process accounting: who ran what (lastcomm, sa)
  if systemctl enable --now acct; then
    log "Process accounting running (lastcomm, sa)."
  else
    warn "Could not start process accounting; check 'systemctl status acct'."
  fi

  # Passwords set by users must be at least 12 characters (root only gets a warning)
  mkdir -p /etc/security/pwquality.conf.d
  cat > /etc/security/pwquality.conf.d/harden.conf <<'EOF'
# Managed by harden.sh
minlen = 12
EOF
  # libpam-tmpdir (private $TMPDIR per user) and apt-show-versions need no setup.
  log "Password rules and per-user tmp dirs set up."

  # Weekly check of installed files against their packages (manually: debsums -s)
  sed -i 's/^CRON_CHECK=.*/CRON_CHECK=weekly/' /etc/default/debsums
  log "debsums checks installed files weekly."

  # Only root needs to read cron jobs and the SSH server config
  for f in /etc/crontab /etc/ssh/sshd_config; do
    [[ -f $f ]] && chmod 600 "$f"
  done
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d $d ]] && chmod 700 "$d"
  done
  log "Cron and sshd_config readable by root only."
fi

# ------------------------- Restart SSH last ---------------------------------

hdr "Restarting SSH"
# 24.04 uses socket activation; daemon-reload regenerates ssh.socket's port.
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh.service
log "SSH restarted on port $SSH_PORT."

# ------------------------------- Done ---------------------------------------

hdr "Done"
cat <<EOF
  !! DO NOT close this session yet. In a NEW terminal run:
       ssh -p $SSH_PORT $NEW_USER@$($TS_SSH_ONLY && echo "$TS_IP   (or $TS_HOSTNAME via MagicDNS)" || echo "<server-ip>")
       sudo -v
     Only log out of root once both work.
$($TS_SSH_ONLY && echo "
  Public SSH is BLOCKED. Your computer must be on the tailnet to connect.
  Emergency access: use your VPS provider's web console.")

  Open more ports later:  sudo ufw allow 443/tcp
  A reboot is recommended to apply all kernel settings.
EOF
