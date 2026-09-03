# ScanIt Progress

Last updated: 2026-09-03

## Project state

- GitHub: https://github.com/rickd-uk/scanit
- Latest commit: `3053710` (`feat: audit writable etc paths`)
- Working tree was clean after the latest push.
- Full test suite: 177 tests passing.
- Runtime: dependency-free Python 3.11+ CLI.
- Current model guidance: Luna low is suitable for routine incremental work; use Terra medium for normal security-check implementation; use Sol high for complex privileged configuration parsing, boot-chain work, automatic remediation, or final security review.

## Completed coverage

- Browser profile, extension, process-flag, and Firefox preference checks.
- Arch updates, package freshness, signatures, foreign packages, and `arch-audit` integration.
- Firewall service state, wildcard listeners, IP forwarding, and network sysctl hardening.
- SSH effective authentication, private-key, host-key, authorization-path, forwarding, and idle-session checks.
- Root encryption, Secure Boot, kernel hardening, LSM/lockdown, UID 0 accounts, and empty passwords.
- Sudoers ownership/drop-in permissions, syntax validation, passwordless rules, broad command rules, and `secure_path` review.
- Systemd unit permissions, debug-shell state, temporary-directory sticky protection, sensitive system-file permissions, user startup paths, and bounded `/etc` writable-path audit.
- JSON/SARIF output, baseline comparison, risk thresholds, area/check filters, CI, README, SECURITY.md, and MIT license.

## Latest real-host findings

Latest system-only scan: risk score `87/100`; coverage `pass:33 fail:8 review:5 unknown:1 not_applicable:3`.

Important findings:

- Vulnerable packages reported by `arch-audit`, including high-risk `linux`, `linux-lts`, `pam`, `grub`, `djvulibre`, and `libxml2`.
- No active firewall service.
- Wildcard listeners included MariaDB, Grafana, Prometheus, node exporter, MiniDLNA, Steam, Syncthing, NTP, mDNS/LLMNR.
- MariaDB was successfully changed to `127.0.0.1:3306` and restarted.
- IPv4 forwarding enabled; IPv6 redirect acceptance enabled.
- Secure Boot disabled, `kernel.kptr_restrict=0`, no active MAC module, kernel lockdown disabled.
- `/etc` audit reported eight non-root-owned or writable paths; review service-owned paths carefully, especially WireGuard and iptables files.
- Sudo `dev ... (rick) NOPASSWD: ALL` was removed. Unowned `/etc/sudoers.d/10-installer` was disabled by renaming it to `10-installer.disabled`. `dev` still has normal `%wheel` sudo access.

## Kernel upgrade preparation

- `IgnorePkg = linux linux-headers` was disabled in `/etc/pacman.conf`.
- Pending update: `linux 6.19.10.arch1-1 -> 7.2.2.arch1-1` and matching headers.
- Current running mainline kernel: `6.19.10-arch1-1`.
- LTS recovery kernel: `6.18.48-1-lts`.
- systemd-boot is active; `arch-mainline.conf` is mainline and `arch.conf` is LTS.
- One-shot boot target was set with `sudo bootctl set-oneshot arch.conf`; reboot into LTS has not yet been completed at the time of this record.
- EFI partition `/dev/nvme1n1p1` is `/boot/efi`, 300 MB total, 68 MB free.
- Mainline `/boot` and EFI kernel/initramfs hashes matched.
- Fallback initramfs images were generated in `/boot`; they are about 209 MB each and cannot fit on the 300 MB EFI partition.
- DKMS modules (`broadcom-wl`, `rtl8821cu`, `scap`) are installed for both current kernels.
- `mkinitcpio -P` completed successfully; `qat_6xxx` firmware warning was non-fatal.

## Exact next steps

1. Verify LTS hashes:

   ```bash
   sudo sha256sum /boot/vmlinuz-linux-lts /boot/efi/EFI/arch/vmlinuz-linux-lts /boot/initramfs-linux-lts.img /boot/efi/EFI/arch/initramfs-linux-lts.img
   ```

2. Reboot into the one-shot LTS entry:

   ```bash
   sudo reboot
   uname -r
   ```

   Expected: `6.18.48-1-lts`.

3. If LTS boots, set mainline as default and upgrade:

   ```bash
   sudo bootctl set-default arch-mainline.conf
   sudo pacman -Syu
   ```

4. Do not reboot after the upgrade if DKMS, `mkinitcpio`, `/boot`, or bootloader errors occur. Validate hashes and `sudo dkms status` first.

5. If the upgraded mainline kernel fails, select `arch.conf` (LTS) in systemd-boot. Keep LTS installed until mainline is confirmed working.

## User conventions

- `c` means continue.
- `y` means yes; `n` means no.
- Keep outputs compact; prefer JSON summaries over full scans.
- Only pause for a model change or a genuine safety/external-state blocker.
