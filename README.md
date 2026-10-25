# install-scripts

Scripts that set up and lock down small servers. Each one asks a few questions, shows a summary and only changes the system after you confirm.

| Folder | What it sets up | Runs on |
|---|---|---|
| [`rpi-adguard/`](rpi-adguard/) | AdGuard Home DNS server for your home network, with ad blocking and automatic updates | Raspberry Pi OS Lite 64-bit |
| [`vps-harden/`](vps-harden/) | Hardened VPS: sudo user, key-only SSH, firewall, fail2ban, automatic updates, Quad9 DNS, optional Tailscale | Ubuntu 22.04 / 24.04 / 26.04 |

Each folder has its own README with setup steps.

```sh
git clone https://github.com/obk/install-scripts
```
