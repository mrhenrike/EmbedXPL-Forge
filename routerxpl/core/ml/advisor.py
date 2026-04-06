"""Attack prioritization, timing hints, and CVSS-aware scoring.

Enhanced advisor with:
- CVSS-based severity scoring from module metadata
- CVE recency boost (newer CVEs scored higher)
- Attack-type weighting (RCE > auth_bypass > info_disclosure)
- Auto-tuning of timing profiles based on scan history
- GPU-accelerated logits via ComputeBackend (A3)

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Version: 0.2.0
"""

from __future__ import annotations

import json
import logging
import math
import re
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Type

from routerxpl.core.exploit.exploit import Protocol

logger = logging.getLogger(__name__)

# CVSS v3 base score ranges
_CVSS_CRITICAL = 9.0
_CVSS_HIGH = 7.0
_CVSS_MEDIUM = 4.0

# Attack type weights (RCE is the most impactful)
_ATTACK_TYPE_WEIGHTS: Dict[str, float] = {
    "rce": 50.0,
    "remote_code_execution": 50.0,
    "command_injection": 45.0,
    "cmd_injection": 45.0,
    "buffer_overflow": 42.0,
    "stack_overflow": 42.0,
    "authentication_bypass": 38.0,
    "auth_bypass": 38.0,
    "authorization_bypass": 38.0,
    "backdoor": 35.0,
    "hardcoded_credentials": 32.0,
    "default_credentials": 30.0,
    "privilege_escalation": 28.0,
    "arbitrary_file_read": 25.0,
    "path_traversal": 25.0,
    "directory_traversal": 25.0,
    "file_upload": 22.0,
    "ssrf": 20.0,
    "xss": 15.0,
    "csrf": 12.0,
    "information_disclosure": 10.0,
    "info_disclosure": 10.0,
    "denial_of_service": 8.0,
    "dos": 8.0,
}

_CVE_YEAR_RE = re.compile(r"CVE[-_](\d{4})[-_]\d+", re.IGNORECASE)


@dataclass(frozen=True)
class AdvisorContext:
    """Snapshot of AutoPwn / scanner knobs used for advisor features."""

    vendor: str
    target_device_class: str
    http_use: bool
    ssh_use: bool
    ftp_use: bool
    telnet_use: bool
    snmp_use: bool
    sftp_use: bool
    tcp_use: bool
    udp_use: bool
    check_exploits: bool
    check_creds: bool
    threads: int


@dataclass
class ScanOutcome:
    """Recorded outcome of a single module execution for auto-tuning."""
    module_path: str
    vendor: str
    timing_template: str
    was_vulnerable: bool
    response_time_s: float
    timestamp: float = field(default_factory=time.time)


def _load_default_config() -> Dict[str, Any]:
    """Load bundled JSON config from package resources."""
    ml_pkg = "routerxpl.resources.ml"
    if hasattr(resources, "files"):
        path = resources.files(ml_pkg).joinpath("default_advisor.json")
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    import importlib

    mod = importlib.import_module(ml_pkg)
    path = Path(mod.__file__).resolve().parent.joinpath("default_advisor.json")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _softmax(logits: Sequence[float]) -> List[float]:
    """Numerically stable softmax over a sequence of logits."""
    if not logits:
        return []
    m = max(logits)
    exps = [math.exp(x - m) for x in logits]
    s = sum(exps)
    if s == 0.0:
        return [1.0 / len(logits)] * len(logits)
    return [e / s for e in exps]


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def build_feature_vector(ctx: AdvisorContext) -> List[float]:
    """Build a fixed-length feature vector for the timing head."""
    vendor_spec = 1.0 if str(ctx.vendor).strip().lower() not in ("", "any") else 0.0
    enabled = [
        float(ctx.http_use),
        float(ctx.ssh_use),
        float(ctx.ftp_use),
        float(ctx.telnet_use),
        float(ctx.snmp_use),
        float(ctx.sftp_use),
        float(ctx.tcp_use),
        float(ctx.udp_use),
        float(ctx.check_exploits),
        float(ctx.check_creds),
    ]
    thr = max(1, min(int(ctx.threads), 300))
    thr_norm = min(1.0, thr / 32.0)
    return [vendor_spec, *enabled, thr_norm]


def logits_for_timing(
    features: Sequence[float],
    timing_cfg: Mapping[str, Any],
    use_gpu: bool,
) -> List[float]:
    """Compute class logits (one per timing template).

    Uses ComputeBackend when use_gpu=True, with torch.cuda fallback.
    """
    bias: Sequence[float] = timing_cfg["bias"]
    rows: Sequence[Sequence[float]] = timing_cfg["weights"]
    if len(features) != len(rows[0]):
        logger.warning("Feature length mismatch; padding or truncating.")
    width = min(len(features), len(rows[0]))
    f = [float(features[i]) for i in range(width)]

    if use_gpu:
        try:
            from routerxpl.core.gpu.backend import auto_select_backend
            import numpy as np
            backend = auto_select_backend(compute_mode="auto")
            if backend.name != "cpu":
                f_arr = np.array([f], dtype=np.float32)
                w_arr = np.array(rows, dtype=np.float32)[:, :width]
                b_arr = np.array(bias, dtype=np.float32)
                f_gpu = backend.array_from_numpy(f_arr)
                w_gpu = backend.array_from_numpy(w_arr)
                result = backend.matmul(w_gpu, f_gpu.T if hasattr(f_gpu, 'T') else f_gpu.t())
                result_np = backend.to_numpy(result).flatten()
                return [float(result_np[i] + bias[i]) for i in range(len(bias))]
        except Exception as exc:
            logger.debug("GPU timing logits fallback: %s", exc)

    out: List[float] = []
    for k, row in enumerate(rows):
        out.append(_dot(f, row[:width]) + float(bias[k]))
    return out


def _extract_cvss(info: Dict[str, Any]) -> float:
    """Extract CVSS score from module __info__ metadata.

    Looks for 'cvss', 'cvss_score', or 'severity' keys.
    """
    for key in ("cvss", "cvss_score", "cvss3_score"):
        val = info.get(key)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass

    severity = str(info.get("severity", "")).lower()
    severity_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}
    return severity_map.get(severity, 0.0)


def _extract_cve_year(info: Dict[str, Any]) -> int:
    """Extract the CVE year from module references or name."""
    refs = info.get("references", ())
    if isinstance(refs, (list, tuple)):
        for ref in refs:
            m = _CVE_YEAR_RE.search(str(ref))
            if m:
                return int(m.group(1))

    name = str(info.get("name", ""))
    m = _CVE_YEAR_RE.search(name)
    if m:
        return int(m.group(1))

    return 0


def _extract_attack_type(info: Dict[str, Any]) -> str:
    """Infer attack type from module name/description."""
    name = str(info.get("name", "")).lower()
    desc = str(info.get("description", "")).lower()
    combined = name + " " + desc

    best_type = ""
    best_weight = 0.0
    for atype, weight in _ATTACK_TYPE_WEIGHTS.items():
        if atype.replace("_", " ") in combined or atype.replace("_", "") in combined:
            if weight > best_weight:
                best_type = atype
                best_weight = weight

    return best_type


class AttackAdvisor:
    """Ranks exploit/credential modules and suggests a timing template.

    Enhanced with CVSS scoring, CVE recency, attack type weighting,
    and auto-tuning from scan history.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or _load_default_config()
        self._scan_history: List[ScanOutcome] = []
        self._timing_stats: Dict[str, Dict[str, float]] = {}

    def suggest_timing_template(self, ctx: AdvisorContext, use_gpu: bool) -> Tuple[str, List[Tuple[str, float]]]:
        """Return best timing key (t0..t5) and softmax probabilities.

        If auto-tuning data is available for this vendor, applies learned
        adjustments to the base logits.
        """
        feats = build_feature_vector(ctx)
        timing = self._config["timing"]
        labels: List[str] = list(timing["labels"])
        logits = logits_for_timing(feats, timing, use_gpu=use_gpu)

        # Auto-tuning adjustment from scan history
        vendor = str(ctx.vendor).strip().lower()
        if vendor in self._timing_stats:
            stats = self._timing_stats[vendor]
            for i, label in enumerate(labels):
                adj = stats.get(label, 0.0)
                logits[i] += adj

        probs = _softmax(logits)
        ranked = sorted(zip(labels, probs), key=lambda x: x[1], reverse=True)
        best = ranked[0][0]
        return best, ranked

    def record_outcome(self, outcome: ScanOutcome) -> None:
        """Record a scan outcome for auto-tuning.

        Args:
            outcome: The result of a module execution.
        """
        self._scan_history.append(outcome)

        if len(self._scan_history) % 50 == 0:
            self._recompute_timing_stats()

    def _recompute_timing_stats(self) -> None:
        """Recompute timing template adjustments from scan history."""
        vendor_template_scores: Dict[str, Dict[str, List[float]]] = {}

        for outcome in self._scan_history:
            vendor = outcome.vendor.lower()
            template = outcome.timing_template.lower()

            if vendor not in vendor_template_scores:
                vendor_template_scores[vendor] = {}
            if template not in vendor_template_scores[vendor]:
                vendor_template_scores[vendor][template] = []

            score = 1.0 if outcome.was_vulnerable else -0.1
            if outcome.response_time_s < 2.0:
                score += 0.2
            elif outcome.response_time_s > 10.0:
                score -= 0.3

            vendor_template_scores[vendor][template].append(score)

        self._timing_stats = {}
        for vendor, templates in vendor_template_scores.items():
            self._timing_stats[vendor] = {}
            for template, scores in templates.items():
                if scores:
                    avg = sum(scores) / len(scores)
                    self._timing_stats[vendor][template] = avg * 0.5

    def score_exploit_class(self, exploit_class: Type[Any], ctx: AdvisorContext) -> float:
        """Enhanced heuristic score: higher = run earlier in AutoPwn.

        Now includes CVSS severity, CVE recency, and attack type weighting.
        """
        mw = self._config["module_weights"]
        path = (getattr(exploit_class, "__module__", "") or "").lower()
        score = 0.0
        vendor = str(ctx.vendor).strip().lower()
        vendor_specific = vendor not in ("", "any")

        # Base vendor/path scoring (original logic)
        if vendor_specific and vendor in path:
            score += float(mw["vendor_in_module_path"])
            if ".creds.routers." in path:
                score += float(mw["creds_routers_when_vendor_specific"])
            if ".exploits.routers." in path:
                score += float(mw["exploits_routers_when_vendor_specific"])
        else:
            if ".creds.generic." in path:
                leaf = path.rsplit(".", 1)[-1]
                if leaf.endswith("default"):
                    score += float(mw.get("creds_generic_default_when_vendor_any", 0))
            if ".exploits.generic." in path:
                score += float(mw.get("exploits_generic_when_vendor_any", 0))

        if ".misc." in path or "modules.exploits.misc" in path or "modules.creds.misc" in path:
            score += float(mw["misc_directory_penalty"])

        # Protocol boost (original logic)
        proto = getattr(exploit_class, "target_protocol", None)
        boost = float(mw["protocol_enabled_boost"])
        if proto == Protocol.HTTP and ctx.http_use:
            score += boost
        elif proto in (Protocol.SSH, Protocol.SFTP) and (ctx.ssh_use or ctx.sftp_use):
            score += boost
        elif proto == Protocol.FTP and ctx.ftp_use:
            score += boost
        elif proto == Protocol.TELNET and ctx.telnet_use:
            score += boost
        elif proto == Protocol.SNMP and ctx.snmp_use:
            score += boost
        elif proto == Protocol.TCP and ctx.tcp_use:
            score += boost * 0.6
        elif proto == Protocol.UDP and ctx.udp_use:
            score += boost * 0.6

        # NEW: CVSS severity scoring
        info = getattr(exploit_class, "__info__", {})
        if isinstance(info, dict):
            cvss = _extract_cvss(info)
            if cvss >= _CVSS_CRITICAL:
                score += 40.0
            elif cvss >= _CVSS_HIGH:
                score += 25.0
            elif cvss >= _CVSS_MEDIUM:
                score += 12.0
            elif cvss > 0:
                score += 5.0

            # NEW: CVE recency boost (newer CVEs are more likely to be unpatched)
            cve_year = _extract_cve_year(info)
            if cve_year >= 2024:
                score += 30.0
            elif cve_year >= 2022:
                score += 20.0
            elif cve_year >= 2020:
                score += 10.0
            elif cve_year >= 2018:
                score += 5.0

            # NEW: Attack type weighting
            attack_type = _extract_attack_type(info)
            if attack_type in _ATTACK_TYPE_WEIGHTS:
                score += _ATTACK_TYPE_WEIGHTS[attack_type]

        return score

    def prioritize_modules(
        self,
        modules: Sequence[Type[Any]],
        ctx: AdvisorContext,
    ) -> List[Type[Any]]:
        """Stable sort: higher advisor score first, preserve original order on ties."""
        indexed: List[Tuple[int, Type[Any]]] = list(enumerate(modules))
        indexed.sort(
            key=lambda t: (-self.score_exploit_class(t[1], ctx), t[0]),
        )
        return [m for _, m in indexed]

    @property
    def scan_history_size(self) -> int:
        """Number of recorded scan outcomes."""
        return len(self._scan_history)

    @property
    def tuned_vendors(self) -> List[str]:
        """Vendors with auto-tuning data available."""
        return list(self._timing_stats.keys())


def advisor_context_from_autopwn(exploit: Any) -> AdvisorContext:
    """Build context from an AutoPwn instance (duck typing, avoids circular imports)."""
    return AdvisorContext(
        vendor=str(getattr(exploit, "vendor", "any")),
        target_device_class=str(getattr(exploit, "target_device_class", "multi")),
        http_use=bool(getattr(exploit, "http_use", True)),
        ssh_use=bool(getattr(exploit, "ssh_use", True)),
        ftp_use=bool(getattr(exploit, "ftp_use", True)),
        telnet_use=bool(getattr(exploit, "telnet_use", True)),
        snmp_use=bool(getattr(exploit, "snmp_use", True)),
        sftp_use=bool(getattr(exploit, "sftp_use", True)),
        tcp_use=bool(getattr(exploit, "tcp_use", True)),
        udp_use=bool(getattr(exploit, "udp_use", True)),
        check_exploits=bool(getattr(exploit, "check_exploits", True)),
        check_creds=bool(getattr(exploit, "check_creds", True)),
        threads=int(getattr(exploit, "threads", 8) or 8),
    )
