"""Audit security-relevant kernel runtime parameters."""

from __future__ import annotations

from dataclasses import dataclass

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


@dataclass(frozen=True, slots=True)
class KernelControl:
    check_id: str
    key: str
    label: str
    minimum: int
    severity: Severity


CONTROLS = (
    KernelControl("system.kernel.aslr", "kernel.randomize_va_space", "Address-space randomization", 2, Severity.HIGH),
    KernelControl("system.kernel.kptr-restrict", "kernel.kptr_restrict", "Kernel pointer exposure", 1, Severity.MEDIUM),
    KernelControl("system.kernel.dmesg-restrict", "kernel.dmesg_restrict", "Kernel log access", 1, Severity.LOW),
    KernelControl("system.kernel.ptrace-scope", "kernel.yama.ptrace_scope", "Cross-process tracing", 1, Severity.MEDIUM),
    KernelControl("system.kernel.perf-restrict", "kernel.perf_event_paranoid", "Performance-event access", 2, Severity.LOW),
    KernelControl("system.kernel.unprivileged-bpf", "kernel.unprivileged_bpf_disabled", "Unprivileged BPF restriction", 1, Severity.MEDIUM),
    KernelControl("system.kernel.protected-hardlinks", "fs.protected_hardlinks", "Hardlink protection", 1, Severity.MEDIUM),
    KernelControl("system.kernel.protected-symlinks", "fs.protected_symlinks", "Symlink protection", 1, Severity.MEDIUM),
    KernelControl("system.kernel.protected-fifos", "fs.protected_fifos", "FIFO protection", 1, Severity.LOW),
    KernelControl("system.kernel.protected-regular", "fs.protected_regular", "Regular-file protection", 1, Severity.LOW),
)


class KernelHardeningCheck:
    check_id = "system.kernel.hardening"
    area = "kernel"

    def run(self, context: ScanContext) -> list[Finding]:
        return [self._evaluate(context, control) for control in CONTROLS]

    @staticmethod
    def _evaluate(context: ScanContext, control: KernelControl) -> Finding:
        path = context.root / "proc/sys" / control.key.replace(".", "/")
        try:
            raw = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return Finding(
                control.check_id, "kernel", f"{control.label} control is unavailable",
                Status.NOT_APPLICABLE, Severity.INFO, f"{control.key} is not exposed by this kernel.",
                confidence=Confidence.MEDIUM,
            )
        except OSError as error:
            return Finding(
                control.check_id, "kernel", f"{control.label} could not be inspected",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )
        try:
            value = int(raw)
        except ValueError:
            return Finding(
                control.check_id, "kernel", f"{control.label} has an invalid value",
                Status.ERROR, Severity.INFO, f"{control.key}={raw!r}", confidence=Confidence.LOW,
            )
        if value >= control.minimum:
            return Finding(
                control.check_id, "kernel", f"{control.label} meets the baseline",
                Status.PASS, Severity.INFO,
                f"{control.key}={value}; expected at least {control.minimum}.",
            )
        return Finding(
            control.check_id, "kernel", f"{control.label} is below the baseline",
            Status.FAIL, control.severity,
            f"{control.key}={value}; expected at least {control.minimum}.",
            remediation=f"Set {control.key} to at least {control.minimum} after checking workload compatibility.",
            confidence=Confidence.HIGH,
        )
