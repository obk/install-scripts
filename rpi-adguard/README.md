# rpi-adguard

A script that turns a Raspberry Pi into an AdGuard Home DNS server for your whole network and locks the Pi down. Set it up once, and it keeps itself updated.

You need:

- a Raspberry Pi running **Raspberry Pi OS Lite 64-bit**
- an **Ethernet** connection (Wi-Fi gets turned off)
- an **SSH key** (password login gets turned off). The script can import it from your GitHub account (`https://github.com/<user>.keys`, ed25519 and RSA keys only).

## Setup

1. Flash Pi OS Lite with Raspberry Pi Imager. In the settings, set a hostname, create a user and add your SSH public key.
2. Plug the Pi in, SSH into it and run:

   ```sh
   git clone https://git.obk.dev/install-scripts && cd install-scripts/rpi-adguard
   sudo ./bootstrap.sh
   sudo reboot
   ```

   The script asks a few questions, like the hostname, a static IP and a web UI password. Each one has a default, so you can usually just press Enter. Nothing changes until you confirm the summary at the end.

   It also asks for your user's password (the one you set in Imager), because sudo will ask for it from now on. If you don't remember it, leave it empty and set a new one.

3. On your router:
   - Reserve the Pi's IP so it never changes.
   - In DHCP, set the Pi's IP as the only DNS server.
   - If you have separate networks (IoT, guest), allow port 53 from them to the Pi. **Do this before changing DHCP**, or those networks lose DNS.

4. Test it from another device:

   ```sh
   dig @<pi-ip> example.com        # should work
   dig @<pi-ip> doubleclick.net    # should return 0.0.0.0
   ```

The web UI is at `https://<pi-ip>/`. Your browser will warn you about the certificate because it's self-signed. Check that the fingerprint matches the one the script printed, then continue.

## Saving your answers

If you don't want to type the same answers every time, copy `local.env.example` to `local.env` and fill it in. Those values become the defaults. The file is not committed to git.

If you have VLANs, this is also where you list them.

## Running it again

You can run `bootstrap.sh` again at any time, for example to change the IP or add a network. Changes you made in the AdGuard web UI are kept. The old config is backed up to `/var/backups/adguardhome/`. If AdGuard doesn't come back up, the script restores the old config.

To reset the AdGuard config to the default (your filter lists, rules and clients are kept):

```sh
sudo ./bootstrap.sh --reset-agh-config
```

## What it does

- **AdGuard Home** runs as its own user in a locked-down systemd service. It uses Quad9 and Cloudflare over encrypted DNS, with the AdGuard, AdAway and HaGeZi Pro block lists.
- **The Pi itself** uses Quad9 for its own DNS, so it keeps working even if AdGuard is down.
- **SSH** allows key login only, and root can't log in.
- **sudo asks for your password.** Raspberry Pi OS doesn't by default, so a stolen SSH key would be root right away.
- **The firewall** only lets in DNS, SSH and the web UI, and only from the networks you choose.
- **fail2ban** blocks IPs that keep failing SSH logins.
- **Security updates** install automatically, with a reboot at 04:30 if needed.
- **Unused parts are switched off:** IPv6, Wi-Fi, Bluetooth and unneeded services, and kernel modules for rare network protocols and filesystems.
- **Logging and checks:** auditd records changes to users, sudo, SSH and the AdGuard binary, and commands run as root. Process accounting records which commands ran. debsums checks installed files every week. If the Pi's kernel can't do auditd or process accounting, the script turns them off.
- **Smaller things:** passwords must be at least 12 characters, every user gets a private temp folder, no core dumps, `/dev/shm` can't run programs, and cron jobs and the SSH config are readable by root only.

```sh
sudo ausearch -i -k root-commands   # commands run as root (also: identity, sudoers, sshd, adguardhome)
sudo lastcomm                       # recent commands from process accounting
sudo debsums -s                     # files that differ from their package (no output = fine)
```

## AdGuard Home updates

A timer checks for a new AdGuard Home release every Sunday night. Before installing it, the script checks the download's checksum and AdGuard's GPG signature. If the new version doesn't work, it switches back to the old one.

The signing key is in `files/adguardhome/adguard-release.gpg`. Its fingerprint is `2864 5AC9 776E C4C0 0BCE 2AFC 0FE6 41E7 235E 2EC6` (AdGuard <devteam@adguard.com>).

```sh
sudo agh-update            # update now
journalctl -u agh-update   # see past runs
```

## Tailscale (optional)

The script asks whether you want to use Tailscale. Answer `yes` if you also want ad blocking when you're away from home. It works without port forwarding. Answer `no` (the default) and nothing Tailscale-related is installed.

The script prints a login link. Open it to add the Pi to your Tailscale network. Then, in the [Tailscale admin console](https://login.tailscale.com/admin):

1. Turn off key expiry for the Pi.
2. Under DNS, add the Pi's Tailscale IP as a nameserver and turn on "Override DNS servers".

Only DNS is open over Tailscale. SSH and the web UI stay on your home network. The firewall also lets in Tailscale's own port (UDP 41641), so your devices can reach the Pi directly instead of through Tailscale's relays.

## License

[MIT](LICENSE)
