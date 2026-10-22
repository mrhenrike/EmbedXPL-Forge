"""Functional tests for embedxpl.core.ml: advisor, anomaly, optimizer, tuner,
banner fingerprinter, credential mutator, service fingerprinter,
response classifier, and GPU bridge.

Each class is exercised beyond import/instantiate: scoring, detection,
mutation, classification and optimization paths are verified.
"""
from __future__ import annotations

from pathlib import Path

import pytest


class TestAttackAdvisor:
    """Tests for the AttackAdvisor timing and module scoring engine."""

    def test_import_and_instantiate(self) -> None:
        from embedxpl.core.ml.advisor import AttackAdvisor
        advisor = AttackAdvisor()
        assert advisor is not None

    def test_advisor_context_creation(self) -> None:
        from embedxpl.core.ml.advisor import AdvisorContext
        ctx = AdvisorContext(
            vendor="dlink",
            target_device_class="router",
            http_use=True,
            ssh_use=True,
            ftp_use=False,
            telnet_use=True,
            snmp_use=False,
            sftp_use=False,
            tcp_use=True,
            udp_use=False,
            check_exploits=True,
            check_creds=True,
            threads=16,
        )
        assert ctx.vendor == "dlink"
        assert ctx.threads == 16

    def test_build_feature_vector_length(self) -> None:
        from embedxpl.core.ml.advisor import AdvisorContext, build_feature_vector
        ctx = AdvisorContext(
            vendor="any", target_device_class="multi",
            http_use=True, ssh_use=False, ftp_use=False, telnet_use=False,
            snmp_use=False, sftp_use=False, tcp_use=True, udp_use=False,
            check_exploits=True, check_creds=True, threads=8,
        )
        feats = build_feature_vector(ctx)
        assert len(feats) == 12
        assert all(isinstance(f, float) for f in feats)

    def test_suggest_timing_template_returns_valid(self) -> None:
        from embedxpl.core.ml.advisor import AdvisorContext, AttackAdvisor
        ctx = AdvisorContext(
            vendor="any", target_device_class="multi",
            http_use=True, ssh_use=True, ftp_use=True, telnet_use=True,
            snmp_use=True, sftp_use=True, tcp_use=True, udp_use=True,
            check_exploits=True, check_creds=True, threads=8,
        )
        advisor = AttackAdvisor()
        best, ranked = advisor.suggest_timing_template(ctx, use_gpu=False)
        assert isinstance(best, str)
        assert best.startswith("t")
        assert len(ranked) >= 1
        probs = [p for _, p in ranked]
        assert abs(sum(probs) - 1.0) < 0.01

    def test_score_exploit_class_positive(self) -> None:
        from embedxpl.core.ml.advisor import AdvisorContext, AttackAdvisor

        class FakeExploit:
            __module__ = "embedxpl.modules.exploits.perimeter.dlink.rom0"
            target_protocol = None

        ctx = AdvisorContext(
            vendor="dlink", target_device_class="router",
            http_use=True, ssh_use=False, ftp_use=False, telnet_use=False,
            snmp_use=False, sftp_use=False, tcp_use=True, udp_use=False,
            check_exploits=True, check_creds=True, threads=8,
        )
        advisor = AttackAdvisor()
        score = advisor.score_exploit_class(FakeExploit, ctx)
        assert score > 0.0

    def test_prioritize_modules_ordering(self) -> None:
        from embedxpl.core.ml.advisor import AdvisorContext, AttackAdvisor

        class Exploit1:
            __module__ = "embedxpl.modules.exploits.perimeter.dlink.rom0"
            target_protocol = None

        class Exploit2:
            __module__ = "embedxpl.modules.exploits.perimeter.generic.upnp"
            target_protocol = None

        ctx = AdvisorContext(
            vendor="dlink", target_device_class="router",
            http_use=True, ssh_use=False, ftp_use=False, telnet_use=False,
            snmp_use=False, sftp_use=False, tcp_use=True, udp_use=False,
            check_exploits=True, check_creds=True, threads=8,
        )
        advisor = AttackAdvisor()
        ordered = advisor.prioritize_modules([Exploit2, Exploit1], ctx)
        assert ordered[0] is Exploit1

    def test_advisor_context_from_autopwn_duck_typing(self) -> None:
        from embedxpl.core.ml.advisor import advisor_context_from_autopwn

        class FakeAutoPwn:
            vendor = "tplink"
            target_device_class = "router"
            http_use = True
            ssh_use = False
            ftp_use = False
            telnet_use = True
            snmp_use = False
            sftp_use = False
            tcp_use = True
            udp_use = False
            check_exploits = True
            check_creds = True
            threads = 4

        ctx = advisor_context_from_autopwn(FakeAutoPwn())
        assert ctx.vendor == "tplink"
        assert ctx.threads == 4

    def test_default_config_loads(self) -> None:
        from embedxpl.core.ml.advisor import _load_default_config
        cfg = _load_default_config()
        assert "timing" in cfg
        assert "labels" in cfg["timing"]
        assert "weights" in cfg["timing"]
        assert "module_weights" in cfg

    def test_softmax_sums_to_one(self) -> None:
        from embedxpl.core.ml.advisor import _softmax
        result = _softmax([1.0, 2.0, 3.0, 4.0])
        assert abs(sum(result) - 1.0) < 1e-6
        assert all(r > 0 for r in result)

    def test_softmax_empty(self) -> None:
        from embedxpl.core.ml.advisor import _softmax
        assert _softmax([]) == []


class TestAnomalyDetector:
    """Functional tests for honeypot/WAF/IPS detection."""

    def test_normal_target_scores_low(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        result = det.analyze(
            target="10.0.0.1",
            response_times_ms=[50.0, 55.0, 48.0, 52.0, 60.0],
            response_sizes=[1024, 1100, 980, 1050],
            headers={"server": "nginx/1.18"},
        )
        assert result.label == "normal"
        assert result.score < 0.3

    def test_honeypot_detected(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        result = det.analyze(
            target="10.0.0.2",
            response_times_ms=[1.0, 1.0, 1.0, 1.0, 1.0],
            response_sizes=[200, 200, 200, 200],
            headers={"server": "cowrie-ssh"},
        )
        assert result.score >= 0.6
        assert "honeypot" in result.label.lower() or "suspicious" in result.label.lower()
        assert any("cowrie" in e.lower() for e in result.evidence)

    def test_waf_detected(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        result = det.analyze(
            target="example.com",
            response_times_ms=[100.0, 110.0, 95.0],
            response_sizes=[5000, 5100, 4900],
            headers={"server": "cloudflare"},
        )
        assert any("WAF" in e or "CDN" in e for e in result.evidence)

    def test_identical_sizes_flagged(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        result = det.analyze(
            target="10.0.0.3",
            response_times_ms=[100.0, 110.0, 105.0, 98.0],
            response_sizes=[512, 512, 512, 512],
            headers={},
        )
        assert any("identical" in e.lower() for e in result.evidence)


class TestAttackOptimizer:
    """Multi-Armed Bandit optimizer tests."""

    def test_prioritize_returns_all_modules(self) -> None:
        from embedxpl.core.ml.attack_optimizer import AttackOptimizer
        opt = AttackOptimizer()
        modules = ["mod_a", "mod_b", "mod_c"]
        result = opt.prioritize(modules)
        assert set(result) == set(modules)

    def test_update_shifts_priority(self) -> None:
        from embedxpl.core.ml.attack_optimizer import AttackOptimizer
        opt = AttackOptimizer()
        for _ in range(20):
            opt.update("mod_winner", True)
            opt.update("mod_loser", False)
        a_w, b_w, rate_w = opt.get_stats("mod_winner")
        a_l, b_l, rate_l = opt.get_stats("mod_loser")
        assert rate_w > rate_l

    def test_save_and_load_rewards(self, tmp_path: Path) -> None:
        from embedxpl.core.ml.attack_optimizer import AttackOptimizer
        path = str(tmp_path / "rewards.json")
        opt1 = AttackOptimizer()
        for _ in range(10):
            opt1.update("ssh_brute", True)
        opt1.save_rewards(path)

        opt2 = AttackOptimizer(rewards_path=path)
        a, b, rate = opt2.get_stats("ssh_brute")
        assert a > 1.0

    def test_scan_outcome_repr(self) -> None:
        from embedxpl.core.ml.attack_optimizer import ScanOutcome
        out = ScanOutcome("test_mod", True, 150.0, 3)
        assert "test_mod" in repr(out)
        assert out.success is True


class TestAutoTuner:
    """Auto-tuning parameter recommendation tests."""

    def test_defaults_without_data(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner
        tuner = AutoTuner()
        profile = tuner.recommend()
        assert "defaults" in profile.reasoning.lower()

    def test_high_latency_triggers_slow_mode(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner
        tuner = AutoTuner()
        for lat in [3000, 2500, 2800, 3200]:
            tuner.record_latency(float(lat))
        profile = tuner.recommend()
        assert profile.threads <= 4
        assert profile.timing_template in ("T1", "T2")
        assert profile.delay_s >= 0.5

    def test_low_latency_triggers_aggressive(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner
        tuner = AutoTuner()
        for lat in [10, 15, 8, 12, 20]:
            tuner.record_latency(float(lat))
        profile = tuner.recommend()
        assert profile.threads >= 16
        assert profile.timing_template in ("T4", "T5")

    def test_high_error_rate_backs_off(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner
        tuner = AutoTuner()
        for lat in [200, 250, 180]:
            tuner.record_latency(float(lat))
        for _ in range(10):
            tuner.record_result(False)
        for _ in range(2):
            tuner.record_result(True)
        profile = tuner.recommend()
        assert profile.delay_s > 0

    def test_reset_clears_state(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner
        tuner = AutoTuner()
        tuner.record_latency(5000.0)
        tuner.record_result(False)
        tuner.reset()
        profile = tuner.recommend()
        assert "defaults" in profile.reasoning.lower()

    def test_tuning_profile_dataclass(self) -> None:
        from embedxpl.core.ml.auto_tuner import TuningProfile
        p = TuningProfile(threads=16, timeout_s=10.0, timing_template="T5")
        assert p.threads == 16
        assert p.batch_size == 10


class TestBannerFingerprinter:
    """Banner fingerprinting with regex, corpus and cosine matching."""

    def test_regex_match_dlink(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        matches = fp.match("D-Link DIR-615 Wireless Router")
        assert any(m.vendor == "dlink" for m in matches)

    def test_corpus_match_goahead(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        matches = fp.match("GoAhead-Webs")
        assert any(m.vendor == "multi" for m in matches)

    def test_no_match_returns_empty(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        assert fp.match("") == []
        assert fp.match("   ") == []

    def test_corpus_size(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        assert fp.corpus_size > 30

    def test_add_custom_signature(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        before = fp.corpus_size
        fp.add_signature("CustomDevice/1.0", "custom_vendor", "custom_model")
        assert fp.corpus_size == before + 1
        matches = fp.match("CustomDevice/1.0")
        assert any(m.vendor == "custom_vendor" for m in matches)

    def test_match_batch(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        results = fp.match_batch(["micro_httpd", "dropbear sshd", "NETGEAR R7000"])
        assert len(results) == 3
        assert any(m.vendor == "dlink" for m in results[0])
        assert any(m.vendor == "netgear" for m in results[2])

    def test_cosine_match_returns_results(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
        fp = BannerFingerprinter()
        results = fp.match_cosine(["TP-LINK Archer C7", "Cisco IOS 15.1"], top_k=3)
        assert len(results) == 2
        assert isinstance(results[0], list)

    def test_fingerprint_match_dataclass(self) -> None:
        from embedxpl.core.ml.banner_fingerprint import FingerprintMatch
        m = FingerprintMatch(vendor="test", model="X1", confidence=0.95)
        assert m.vendor == "test"
        assert m.firmware == ""


class TestCredentialMutator:
    """Credential mutation and streaming tests."""

    def test_mutate_generates_variants(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mut = CredentialMutator()
        candidates = mut.mutate(["admin"])
        assert len(candidates) > 5
        assert "admin" in candidates
        assert "ADMIN" in candidates
        assert "Admin" in candidates

    def test_leet_speak_mutation(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mut = CredentialMutator()
        candidates = mut.mutate(["password"])
        assert "p455w0rd" in candidates

    def test_suffix_mutations(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mut = CredentialMutator()
        candidates = mut.mutate(["admin"])
        assert "admin123" in candidates
        assert "admin!" in candidates

    def test_reverse_mutation(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mut = CredentialMutator()
        candidates = mut.mutate(["admin"])
        assert "nimda" in candidates

    def test_max_candidates_limit(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mut = CredentialMutator()
        candidates = mut.mutate(["a", "b", "c", "d"], max_candidates=10)
        assert len(candidates) <= 10

    def test_stream_candidates_generator(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mut = CredentialMutator()
        gen = mut.stream_candidates(["root"])
        first = next(gen)
        assert first == "root"
        collected = [first]
        for cred in gen:
            collected.append(cred)
            if len(collected) >= 20:
                break
        assert len(set(collected)) == len(collected)


class TestServiceFingerprinter:
    """Service fingerprinter with ML fallback to heuristic."""

    def test_heuristic_fortinet(self) -> None:
        from embedxpl.core.ml.fingerprinter import ServiceFingerprinter
        fp = ServiceFingerprinter()
        preds = fp.predict("FortiOS Login Page - FortiGate-60E")
        assert any(p.vendor == "fortinet" for p in preds)

    def test_heuristic_cisco(self) -> None:
        from embedxpl.core.ml.fingerprinter import ServiceFingerprinter
        fp = ServiceFingerprinter()
        preds = fp.predict("Cisco Adaptive Security Appliance")
        assert any(p.vendor == "cisco" for p in preds)

    def test_unknown_banner_empty(self) -> None:
        from embedxpl.core.ml.fingerprinter import ServiceFingerprinter
        fp = ServiceFingerprinter()
        preds = fp.predict("xyzzy random unknown service")
        assert preds == [] or all(p.confidence < 0.5 for p in preds)

    def test_predict_batch(self) -> None:
        from embedxpl.core.ml.fingerprinter import ServiceFingerprinter
        fp = ServiceFingerprinter()
        results = fp.predict_batch(["FortiGate", "pfsense admin"])
        assert len(results) == 2

    def test_prediction_dataclass(self) -> None:
        from embedxpl.core.ml.fingerprinter import Prediction
        p = Prediction(vendor="test", product="fw", confidence=0.8, evidence="matched")
        assert p.vendor == "test"


class TestResponseClassifier:
    """HTTP response classification: ML pipeline and heuristic fallback."""

    def test_heuristic_vulnerable_detection(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier, ResponseLabel
        clf = ResponseClassifier()
        result = clf.classify(
            "root:x:0:0:root:/root:/bin/bash\nuid=0(root)",
            status_code=200,
        )
        assert result.label == ResponseLabel.VULNERABLE
        assert result.confidence >= 0.5

    def test_heuristic_not_vulnerable(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier, ResponseLabel
        clf = ResponseClassifier()
        result = clf.classify(
            "<title>403 Forbidden</title><p>Access denied</p>",
            status_code=403,
        )
        assert result.label == ResponseLabel.NOT_VULNERABLE

    def test_heuristic_honeypot(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier, ResponseLabel
        clf = ResponseClassifier()
        result = clf.classify(
            "Welcome to cowrie SSH honeypot system",
            status_code=200,
        )
        assert result.label == ResponseLabel.HONEYPOT

    def test_empty_body_returns_unknown(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier, ResponseLabel
        clf = ResponseClassifier()
        result = clf.classify("", status_code=200)
        assert result.label == ResponseLabel.UNKNOWN

    def test_ml_available_property(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier
        clf = ResponseClassifier()
        assert isinstance(clf.is_ml_available, bool)
        assert clf.is_trained is False

    def test_add_training_sample(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier, ResponseLabel
        clf = ResponseClassifier()
        clf.add_training_sample("test body", ResponseLabel.VULNERABLE)
        assert len(clf._training_data) == 1

    def test_train_needs_minimum_samples(self) -> None:
        from embedxpl.core.ml.response_classifier import ResponseClassifier, ResponseLabel
        clf = ResponseClassifier()
        clf.add_training_sample("test", ResponseLabel.VULNERABLE)
        assert clf.train(min_samples=20) is False

    def test_classified_response_dataclass(self) -> None:
        from embedxpl.core.ml.response_classifier import ClassifiedResponse
        cr = ClassifiedResponse(label="vulnerable", confidence=0.9, detail="test")
        assert cr.label == "vulnerable"
        assert cr.features_used == []


class TestMLGpuBridge:
    """Tests for the ML/GPU detection bridge module."""

    def test_detect_all_backends_returns_list(self) -> None:
        from embedxpl.core.ml.gpu import detect_all_backends
        backends = detect_all_backends()
        assert isinstance(backends, list)
        assert "cpu" in backends

    def test_gpu_capability_summary(self) -> None:
        from embedxpl.core.ml.gpu import gpu_capability_summary
        nvidia_ok, cuda_torch, lines = gpu_capability_summary()
        assert isinstance(nvidia_ok, bool)
        assert isinstance(cuda_torch, bool)
        assert isinstance(lines, list)
        assert len(lines) >= 1

    def test_torch_cuda_available_returns_bool(self) -> None:
        from embedxpl.core.ml.gpu import torch_cuda_available
        assert isinstance(torch_cuda_available(), bool)


class TestMLLazyImports:
    """Verify that the ML __init__.py lazy import mechanism works."""

    def test_lazy_import_advisor(self) -> None:
        from embedxpl.core.ml import AdvisorContext, AttackAdvisor
        assert AttackAdvisor is not None
        assert AdvisorContext is not None

    def test_lazy_import_anomaly(self) -> None:
        from embedxpl.core.ml import AnomalyDetector, AnomalyScore
        assert AnomalyDetector is not None
        assert AnomalyScore is not None

    def test_lazy_import_optimizer(self) -> None:
        from embedxpl.core.ml import AttackOptimizer, ScanOutcome
        assert AttackOptimizer is not None
        assert ScanOutcome is not None

    def test_lazy_import_tuner(self) -> None:
        from embedxpl.core.ml import AutoTuner, TuningProfile
        assert AutoTuner is not None
        assert TuningProfile is not None

    def test_lazy_import_banner(self) -> None:
        from embedxpl.core.ml import BannerFingerprinter, FingerprintMatch
        assert BannerFingerprinter is not None
        assert FingerprintMatch is not None

    def test_lazy_import_credential(self) -> None:
        from embedxpl.core.ml import CredentialMutator
        assert CredentialMutator is not None

    def test_lazy_import_fingerprinter(self) -> None:
        from embedxpl.core.ml import Prediction, ServiceFingerprinter
        assert ServiceFingerprinter is not None
        assert Prediction is not None

    def test_lazy_import_classifier(self) -> None:
        from embedxpl.core.ml import ClassifiedResponse, ResponseClassifier, ResponseLabel
        assert ResponseClassifier is not None
        assert ClassifiedResponse is not None
        assert ResponseLabel is not None

    def test_lazy_import_gpu_functions(self) -> None:
        from embedxpl.core.ml import detect_all_backends, gpu_capability_summary
        assert callable(detect_all_backends)
        assert callable(gpu_capability_summary)

    def test_lazy_import_invalid_raises(self) -> None:
        with pytest.raises(AttributeError):
            from embedxpl.core import ml
            ml.NonExistentClass  # noqa: B018
