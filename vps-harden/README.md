# vps-harden

A script that locks down a fresh Ubuntu VPS: a sudo user instead of root, key-only SSH, a firewall, fail2ban, automatic security updates, kernel hardening and encrypted DNS. Tailscale is optional.

You need:

- a VPS running **Ubuntu 22.04, 24.04 or 26.04** (other versions get a warning)
- **root** access over SSH
- your **SSH key** in `/root/.ssh/authorized_keys` (most providers put it there when you create the server), or on your GitHub account: the script can import the keys from `https://github.com/<user>.keys`. Without either, password login stays on so you don't get locked out.

## Setup

1. SSH into the server as root and run:

   ```sh
   git clone https://git.obk.dev/install-scripts && cd install-scripts/vps-harden
   bash harden.sh
   ```

   The script asks a few questions, like the name of the sudo user and which ports to open. Each one has a default, so you can usually just press Enter. Nothing changes until you confirm the summary at the end.

2. It asks you to set a password for the new user. You need it for `sudo`.

3. **Don't close the root session yet.** Open a new terminal and check that you can log in and use sudo:

   ```sh
   ssh <user>@<server-ip>
   sudo -v
   ```

   Only log out of root once both work. If something is wrong, you can still fix it from the root session.

4. Reboot so all kernel settings apply.

## What it does

1. **Packages** are updated.
2. **A sudo user** (`deploy` by default) is created. It gets root's SSH keys, plus your GitHub account's public keys if you give a GitHub username, and needs its password for sudo.
3. **Tailscale** (optional) joins your tailnet. You can make SSH reachable over Tailscale only, so it's closed to the internet.
4. **SSH** allows key login only, and root can't log in. Forwarding (agent, TCP, X11) is off, and logins are logged with the key used.
5. **The firewall** (ufw) blocks everything coming in except SSH (rate-limited) and the ports you list.
6. **fail2ban** blocks IPs that keep failing SSH logins (5 tries in 10 minutes → 1 hour ban).
7. **Security updates** install automatically. Automatic reboots are off unless you turn them on.
8. **Kernel settings** are hardened (network, ptrace, BPF, core dumps), and `/dev/shm` can't run programs.
9. **Unused services** are switched off (rpcbind, avahi, cups, ModemManager, bluetooth). snapd can be removed too, if no other snaps are installed.
10. **DNS** goes to Quad9 over an encrypted connection (DNS-over-TLS). Quad9 blocks known malware domains. If port 853 is blocked, it falls back to plain DNS to Quad9.
11. **Extra hardening**, based on [Lynis](https://cisofy.com/lynis/) suggestions:
    - auditd logs changes to users, sudo and SSH settings, and commands run as root
    - process accounting records which commands were run
    - unused kernel modules can't be loaded (rare network protocols and filesystems, USB storage)
    - passwords must be at least 12 characters
    - every user gets a private temp folder
    - debsums checks installed files against their packages every week
    - cron jobs and the SSH config are readable by root only

Every step except 1, 2 and 4 can be turned off with its question.

## Useful commands

```sh
sudo ufw status verbose               # firewall rules
sudo ufw allow 443/tcp                # open another port
sudo fail2ban-client status sshd      # banned IPs
resolvectl status                     # DNS servers in use
sudo ausearch -k root-commands -i     # commands run as root (also: identity, sudoers, sshd)
sudo lastcomm                         # recent commands from process accounting
sudo debsums -s                       # files that differ from their package (no output = fine)
```

## Good to know

- **The firewall is reset.** Existing ufw rules are deleted. On a server that already runs something, list its ports at the "Extra ports" question, e.g. `80 443`.
- **SSH allows 3 attempts per connection.** If your SSH agent holds many keys, the server may disconnect with "Too many authentication failures" before the right key is tried. Use `ssh -o IdentitiesOnly=yes -i <key> ...`.
- **SSH tunnels don't work** (`ssh -L` / `-R`), because TCP forwarding is off.
- **Tailscale-only SSH:** your computer must be on the tailnet to connect. If Tailscale breaks, use your provider's web console.
- **Running it again** is safe, for example to change the SSH port or open ports. Root can't log in anymore, so use `sudo bash harden.sh`. It rebuilds the firewall rules from your answers.
