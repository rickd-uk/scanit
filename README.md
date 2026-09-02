# ScanIt

ScanIt is a read-only security posture auditor for Arch Linux workstations. It
reports observable configuration facts, explains their security impact, and
keeps uncertainty visible. It is not an antivirus and does not claim that a
machine is uncompromised.

This repository contains the in-progress 0.2 rewrite. The design priorities are
accurate effective-state checks, stable machine-readable findings, safe failure,
and comprehensive tests.

## Run

```bash
python3 -m scanit
python3 -m scanit --json
python3 -m scanit --list-checks
python3 -m unittest discover -v
```

ScanIt should normally run as the desktop user. Checks that cannot obtain enough
evidence report `unknown` or `error`; they do not silently pass.

## Result states

- `pass`: the tested control met the check's policy.
- `fail`: evidence shows the policy was not met.
- `unknown`: the machine did not provide enough evidence.
- `error`: the check could not complete.
- `not_applicable`: the control does not apply to this machine.

Finding IDs are semantic and stable across runs. The risk score is a triage aid,
not a certification or compliance score.

