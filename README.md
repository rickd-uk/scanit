# ScanIt

ScanIt is a read-only security posture auditor for Arch Linux workstations. It
reports observable configuration facts, explains their security impact, and
keeps uncertainty visible. It is not an antivirus and does not claim that a
machine is uncompromised.

The 0.2 series is an active rewrite focused on accurate effective-state checks,
stable machine-readable findings, safe failure, and comprehensive tests.

## Current coverage

- Browser profile permissions, powerful extension permissions, dangerous
  process flags, and explicit Firefox security-weakening preferences.
- Pending Arch updates, repository database freshness, package signatures, and
  optional vulnerability matching through `arch-audit`.
- Firewall service activity, wildcard listeners, and effective SSH root/password
  authentication settings.
- Root-volume encryption, Secure Boot, kernel hardening parameters, active Linux
  security modules, and kernel lockdown.
- UID 0 accounts, home-directory write protection, and sudoers permissions.

An extension permission finding means review is warranted; it does not mean the
extension is malicious. Likewise, a listening socket may still be protected by
firewall policy.

## Install

ScanIt requires Python 3.11 or newer and has no Python runtime dependencies.

```bash
python3 -m pip install --user .
scanit --version
```

Run directly from a checkout during development with `python3 -m scanit`.

## Run

```bash
python3 -m scanit
python3 -m scanit --json
python3 -m scanit --sarif
python3 -m scanit --list-checks
python3 -m scanit --browser-only
sudo python3 -m scanit --system-only
python3 -m scanit --area kernel --area network
python3 -m scanit --check system.boot.secure-boot
python3 -m scanit --fail-on high
python3 -m unittest discover -v
```

ScanIt should normally run as the desktop user. Checks that cannot obtain enough
evidence report `unknown` or `error`; they do not silently pass.

For evidence requiring elevated access, run a separate `--system-only` scan with
`sudo`. Do not run browser checks with `sudo`, because that inspects root's home
instead of the desktop user's profiles.

The process exits with status `1` when a finding meets `--fail-on` (default:
`low`), `2` for command-line errors, and `0` otherwise. Use `--fail-on none`
when collecting results without a policy exit code.

## Result states

- `pass`: the tested control met the check's policy.
- `fail`: evidence shows the policy was not met.
- `review`: a potentially high-impact capability or exposure needs human context;
  it does not contribute to the risk score or failure exit status.
- `unknown`: the machine did not provide enough evidence.
- `error`: the check could not complete.
- `not_applicable`: the control does not apply to this machine.

Finding IDs are semantic and stable across runs. The risk score is a triage aid,
not a certification or compliance score.

## Security and privacy boundaries

Normal scans are read-only and do not send scan data anywhere. Evidence is kept
focused, but reports can still contain local usernames, package names, ports,
profile names, and installed extension names. Review output before sharing it.

ScanIt does not scan for malware, prove the absence of compromise, validate every
firewall rule, or guarantee that a passing configuration is secure. Conditional
configuration and controls hidden by permissions can reduce coverage; inspect
all `unknown` and `error` results.

Report security issues using the process in [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m unittest discover -v
python3 -m compileall -q scanit tests
python3 -m scanit --list-checks
```

Each check should be read-only, return a stable ID, preserve uncertainty, redact
unnecessary evidence, and include tests for safe, unsafe, and unavailable states.

Licensed under the MIT License.
