#!/usr/bin/env bash
# Keep the SSH user's GitHub keys in step with https://github.com/<user>.keys.
# Installed to /usr/local/sbin/github-keys-sync; run hourly by github-keys-sync.timer.
# Settings (GITHUB_USER, SSH_USER) come from /etc/default/github-keys-sync,
# written by bootstrap.sh.
#
# Keys tagged "github:<user>" in authorized_keys belong to this script: they are
# replaced by the current set from GitHub, so a key added or removed there is
# added or removed here. Keys without that tag are never touched. If GitHub
# can't be reached or lists no usable keys, nothing changes, so an outage or an
# emptied account can't lock you out.
set -euo pipefail

CONF=/etc/default/github-keys-sync

log() { printf 'github-keys-sync: %s\n' "$*"; }
die() { printf 'github-keys-sync: ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f $CONF ]] || die "$CONF is missing; run bootstrap.sh first"
GITHUB_USER="" SSH_USER=""
# shellcheck source=/dev/null
. "$CONF"
[[ $GITHUB_USER =~ ^[A-Za-z0-9](-?[A-Za-z0-9]){0,38}$ ]] || die "GITHUB_USER in $CONF is not a GitHub username"
home="$(getent passwd "$SSH_USER" | cut -d: -f6)" || die "SSH_USER in $CONF is not a user"
[[ -n $SSH_USER && -n $home ]] || die "SSH_USER in $CONF is not a user"

# Only bare "type key" lines of the types sshd accepts here (ed25519, RSA), so
# no authorized_keys options (command=, from=...) can come along.
keys="$(curl -fsS --proto '=https' --max-time 20 "https://github.com/$GITHUB_USER.keys" \
  | grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+=*$' \
  | sed "s/\$/ github:$GITHUB_USER/")" \
  || die "no ed25519 or RSA keys for $GITHUB_USER on GitHub (or github.com unreachable); keeping the current keys"

# Read and written as SSH_USER, so root never follows a link planted in their home.
# shellcheck disable=SC2016 # $1 expands in the inner sh
current="$(runuser -u "$SSH_USER" -- sh -c '[ ! -e "$1" ] || cat -- "$1"' sh "$home/.ssh/authorized_keys")" \
  || die "cannot read $home/.ssh/authorized_keys"

# Drop every github:* key (also those of a GitHub user configured before), keep
# the rest, then add GitHub's current keys that aren't already there untagged.
new="$(awk 'FILENAME == ARGV[1] { if (!(NF == 3 && $3 ~ /^github:/)) { print; have[$1 " " $2] }; next }
            !(($1 " " $2) in have)' <(printf '%s' "$current") - <<< "$keys")"
[[ $new != "$current" ]] || exit 0

# Log what changed, by fingerprint.
tagged() { awk 'NF == 3 && $3 ~ /^github:/' <<< "$1" | sort; }
old_set="$(tagged "$current")" new_set="$(tagged "$new")"
fingerprints() { [[ -z $2 ]] || ssh-keygen -lf - <<< "$2" | sed "s/^/$1 /"; }
fingerprints removed "$(comm -23 <(printf '%s\n' "$old_set") <(printf '%s\n' "$new_set") | sed '/^$/d')"
fingerprints added "$(comm -13 <(printf '%s\n' "$old_set") <(printf '%s\n' "$new_set") | sed '/^$/d')"

# shellcheck disable=SC2016 # $1 expands in the inner sh
runuser -u "$SSH_USER" -- sh -c 'umask 077 && mkdir -p "$1/.ssh" &&
  cat > "$1/.ssh/authorized_keys.tmp" && mv -f -- "$1/.ssh/authorized_keys.tmp" "$1/.ssh/authorized_keys"' \
  sh "$home" <<< "$new"
log "updated $home/.ssh/authorized_keys from github.com/$GITHUB_USER.keys"
