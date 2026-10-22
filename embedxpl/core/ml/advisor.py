"""Attack prioritization and timing hints via lightweight (interpretable) scoring.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Type

from embedxpl.core.exploit.exploit import Protocol

logger = logging.getLogger(__name__)


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


def _load_default_config() -> Dict[str, Any]:
    """Load bundled JSON config from package resources."""
    ml_pkg = "embedxpl.resources.ml"
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
    return sum(x * y for x, y in zip(a, b, strict=False))


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
    """Compute class logits (one per timing template)."""
    bias: Sequence[float] = timing_cfg["bias"]
    rows: Sequence[Sequence[float]] = timing_cfg["weights"]
    if len(features) != len(rows[0]):
        logger.warning("Feature length mismatch; padding or truncating.")
    width = min(len(features), len(rows[0]))
    f = [float(features[i]) for i in range(width)]

    if use_gpu:
        try:
            import torch  # type: ignore

            if torch.cuda.is_available():
                t_feat = torch.tensor(f, dtype=torch.float32, device="cuda")
                t_rows = torch.tensor(rows, dtype=torch.float32, device="cuda")
                t_bias = torch.tensor(bias, dtype=torch.float32, device="cuda")
                logits_t = (t_rows @ t_feat) + t_bias
                return [float(x) for x in logits_t.cpu().tolist()]
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("GPU timing logits fallback: %s", exc)

    out: List[float] = []
    for k, row in enumerate(rows):
        out.append(_dot(f, row[:width]) + float(bias[k]))
    return out


class AttackAdvisor:
    """Ranks exploit/credential modules and suggests a timing template."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or _load_default_config()

    def suggest_timing_template(self, ctx: AdvisorContext, use_gpu: bool) -> Tuple[str, List[Tuple[str, float]]]:
        """Return best timing key (t0..t5) and softmax probabilities for UX."""
        feats = build_feature_vector(ctx)
        timing = self._config["timing"]
        labels: List[str] = list(timing["labels"])
        logits = logits_for_timing(feats, timing, use_gpu=use_gpu)
        probs = _softmax(logits)
        ranked = sorted(zip(labels, probs, strict=False), key=lambda x: x[1], reverse=True)
        best = ranked[0][0]
        return best, ranked

    def score_exploit_class(self, exploit_class: Type[Any], ctx: AdvisorContext) -> float:
        """ Heuristic score: higher = run earlier in AutoPwn. """
        mw = self._config["module_weights"]
        path = (getattr(exploit_class, "__module__", "") or "").lower()
        score = 0.0
        vendor = str(ctx.vendor).strip().lower()
        vendor_specific = vendor not in ("", "any")

        if vendor_specific and vendor in path:
            score += float(mw["vendor_in_module_path"])
            for domain in (".creds.perimeter.", ".creds.waf.", ".creds.vpn.", ".creds.nac.", ".creds.lb."):
                if domain in path:
                    score += float(mw.get("creds_routers_when_vendor_specific", 0))
                    break
            for domain in (".exploits.perimeter.", ".exploits.waf.", ".exploits.vpn.", ".exploits.nac.", ".exploits.lb."):
                if domain in path:
                    score += float(mw.get("exploits_routers_when_vendor_specific", 0))
                    break
        else:
            if ".creds.generic." in path:
                leaf = path.rsplit(".", 1)[-1]
                if leaf.endswith("default"):
                    score += float(mw.get("creds_generic_default_when_vendor_any", 0))
            if ".exploits.perimeter.generic." in path:
                score += float(mw.get("exploits_generic_when_vendor_any", 0))

        if "cve_20" in path:
            score += 2.0

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


def advisor_context_from_autopwn(exploit: Any) -> AdvisorContext:
    """Build context from an AutoPwn instance (duck typing, avoids circular imports)."""
    return AdvisorContext(
        vendor=str(getattr(exploit, "vendor", "any")),
        target_device_class=str(getattr(exploit, "target_device_class", "multi")),
        http_use=bool(getattr(exploit, "http_use", True)),
        ssh_use=bool(getattr(exploit, "ssh_use", True)),
        ftp_use=bool(getattr(exploit, "ftp_use", True)),
        telnet_use=bool(getattr(
            exploit,
            "telnet_use",
            True,
        )),
        snmp_use=bool(getattr(exploit, "snmp_use", True)),
        sftp_use=bool(getattr(exploit, "sftp_use", True)),
        tcp_use=bool(getattr(exploit, "tcp_use", True)),
        udp_use=bool(getattr(exploit, "udp_use", True)),
        check_exploits=bool(getattr(exploit, "check_exploits", True)),
        check_creds=bool(getattr(exploit, "check_creds", True)),
        threads=int(getattr(exploit, "threads", 8) or 8),
    )
