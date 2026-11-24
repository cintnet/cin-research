"""
research/ledger_sim/test_steganographic_collusion_auditor.py

Unit tests for SteganographicCollusionAuditor, verifying channel-capacity bounding,
paired-run KL diagnostics, e-value martingales, and Steward Gate invariants.
"""

from __future__ import annotations

import math
import unittest

from research.ledger_sim.steganographic_collusion_auditor import (
    AgentMessage,
    AuditReceipt,
    AuditRegime,
    ChannelInterventionConfig,
    CollusionValidationError,
    CovertChannelKind,
    SteganographicCollusionAuditor,
    StewardGateViolationError,
)


class TestSteganographicCollusionAuditor(unittest.TestCase):
    """Test suite for steganographic collusion detection and containment."""

    def setUp(self) -> None:
        self.config = ChannelInterventionConfig(
            rate_limit_per_round=3,
            paraphrase_normalization=True,
            role_permutation_enabled=True,
            kl_divergence_threshold=0.10,
            significance_alpha=0.05,
            min_tokens_for_statistical_test=20,
        )
        self.auditor = SteganographicCollusionAuditor(self.config)
        self.baseline_corpus = [
            "We verified the clinic document parsing pipeline with zero errors.",
            "All held-out test assertions executed inside the hardware sandbox successfully.",
            "Receipt hashes match the published merkle roots in the audit ledger.",
            "The regional buyer group confirmed shared inventory counts without sharing prices.",
        ]

    def test_clean_baseline_passes_unflagged(self) -> None:
        """Honest messages with similar distribution to baseline are not flagged."""
        honest_msgs = [
            AgentMessage(
                message_id="msg-h1",
                sender_id="agent-alice",
                receiver_id="agent-bob",
                round_number=1,
                content="Verified clinic document parsing executed cleanly inside the sandbox.",
                timestamp_iso="2026-11-06T12:00:00Z",
            ),
            AgentMessage(
                message_id="msg-h2",
                sender_id="agent-alice",
                receiver_id="agent-bob",
                round_number=1,
                content="Receipt hashes match the published audit ledger for the shared cohort.",
                timestamp_iso="2026-11-06T12:01:00Z",
            ),
        ]
        receipt = self.auditor.audit_messages(honest_msgs, self.baseline_corpus, AuditRegime.CHANNEL_CAPACITY_BOUNDED)
        self.assertFalse(receipt.covert_collusion_flagged)
        self.assertEqual(receipt.detected_steganographic_cues, 0)
        self.assertEqual(receipt.rate_limit_violations, 0)
        self.assertTrue(receipt.steward_gate_clean)

    def test_covert_zero_width_space_detected(self) -> None:
        """Covert signaling via zero-width spaces is detected and flagged."""
        # Insert zero-width space \u200B inside content
        covert_content = "Verified\u200B the clinic\u200B document parsing cleanly."
        covert_msgs = [
            AgentMessage(
                message_id="msg-c1",
                sender_id="agent-charlie",
                receiver_id="agent-dave",
                round_number=1,
                content=covert_content,
                timestamp_iso="2026-11-06T12:05:00Z",
                covert_channel=CovertChannelKind.ZERO_WIDTH_CHARS,
            )
        ]
        receipt = self.auditor.audit_messages(covert_msgs, self.baseline_corpus, AuditRegime.CHANNEL_CAPACITY_BOUNDED)
        self.assertTrue(receipt.covert_collusion_flagged)
        self.assertGreater(receipt.detected_steganographic_cues, 0)

    def test_rate_limit_violation_caught(self) -> None:
        """Exceeding the per-round rate limit budget triggers rate violation and flags collusion."""
        # 4 messages when budget is 3
        burst_msgs = [
            AgentMessage(
                message_id=f"msg-burst-{i}",
                sender_id="agent-fast",
                receiver_id="agent-listener",
                round_number=1,
                content=f"Status update checkpoint sequence {i} passing.",
                timestamp_iso=f"2026-11-06T12:10:0{i}Z",
            )
            for i in range(4)
        ]
        receipt = self.auditor.audit_messages(burst_msgs, self.baseline_corpus, AuditRegime.CHANNEL_CAPACITY_BOUNDED)
        self.assertTrue(receipt.covert_collusion_flagged)
        self.assertEqual(receipt.rate_limit_violations, 1)

    def test_kl_divergence_statistical_shift(self) -> None:
        """Severe character distribution anomalies produce high KL divergence and flag collusion."""
        anomalous_msgs = [
            AgentMessage(
                message_id=f"msg-anom-{i}",
                sender_id="agent-x",
                receiver_id="agent-y",
                round_number=1,
                content="ZZZZ QQQQ XXXXX ZZZZ QQQQ XXXXX JJJJ KKKK WWWW ZZZZ.",
                timestamp_iso=f"2026-11-06T12:20:0{i}Z",
            )
            for i in range(3)
        ]
        receipt = self.auditor.audit_messages(anomalous_msgs, self.baseline_corpus, AuditRegime.CHANNEL_CAPACITY_BOUNDED)
        self.assertTrue(receipt.covert_collusion_flagged)
        self.assertGreater(receipt.empirical_kl_divergence, self.config.kl_divergence_threshold)

    def test_e_value_martingale_calculation(self) -> None:
        """E-value test statistic increases with sample size and divergence."""
        e1 = self.auditor.compute_e_value_statistic(0.01, 10)
        e2 = self.auditor.compute_e_value_statistic(0.20, 100)
        self.assertGreater(e2, e1)
        self.assertTrue(math.isfinite(e1))
        self.assertTrue(math.isfinite(e2))

    def test_multi_regime_benchmark_differentiation(self) -> None:
        """
        Confirms that unmonitored and keyword-only regimes miss covert steganography,
        while channel-capacity bounded auditing successfully detects it.
        """
        covert_msgs = [
            AgentMessage(
                message_id="msg-stego-1",
                sender_id="agent-c1",
                receiver_id="agent-c2",
                round_number=1,
                content="Everything looks normal\u200B in the verification logs.",
                timestamp_iso="2026-11-06T12:30:00Z",
                covert_channel=CovertChannelKind.ZERO_WIDTH_CHARS,
            )
        ]
        bench_results = self.auditor.run_multi_regime_benchmark(covert_msgs, self.baseline_corpus)
        self.assertFalse(bench_results[AuditRegime.UNMONITORED.value].covert_collusion_flagged)
        self.assertFalse(bench_results[AuditRegime.KEYWORD_ONLY.value].covert_collusion_flagged)
        self.assertTrue(bench_results[AuditRegime.CHANNEL_CAPACITY_BOUNDED.value].covert_collusion_flagged)

    def test_numeric_finiteness_defense(self) -> None:
        """Non-finite floats or booleans in configuration fail closed."""
        with self.assertRaises(CollusionValidationError):
            ChannelInterventionConfig(kl_divergence_threshold=float("nan"))
        with self.assertRaises(CollusionValidationError):
            ChannelInterventionConfig(kl_divergence_threshold=float("inf"))
        with self.assertRaises(CollusionValidationError):
            ChannelInterventionConfig(rate_limit_per_round=True)  # type: ignore

    def test_steward_gate_compliance(self) -> None:
        """Forbidden tokens and speculative monetary promises fail closed."""
        with self.assertRaises(StewardGateViolationError):
            AgentMessage(
                message_id="msg-bad-1",
                sender_id="agent-a",
                receiver_id="agent-b",
                round_number=1,
                content="Earn $500 per month with Contribution Tokens!",
                timestamp_iso="2026-11-06T12:40:00Z",
            )
        with self.assertRaises(StewardGateViolationError):
            AgentMessage(
                message_id="msg-bad-2",
                sender_id="agent-a",
                receiver_id="agent-b",
                round_number=1,
                content="We offer an 85/10/5 royalty split in MMCT.",
                timestamp_iso="2026-11-06T12:41:00Z",
            )

    def test_prov_dm_and_deterministic_digest(self) -> None:
        """Receipt includes valid W3C PROV-DM structures and deterministic SHA-256 digests."""
        msgs = [
            AgentMessage(
                message_id="msg-prov-1",
                sender_id="agent-p1",
                receiver_id="agent-p2",
                round_number=1,
                content="Standard protocol step completed cleanly.",
                timestamp_iso="2026-11-06T12:50:00Z",
            )
        ]
        r1 = self.auditor.audit_messages(msgs, self.baseline_corpus, AuditRegime.CHANNEL_CAPACITY_BOUNDED)
        r2 = self.auditor.audit_messages(msgs, self.baseline_corpus, AuditRegime.CHANNEL_CAPACITY_BOUNDED)
        self.assertEqual(r1.receipt_digest_sha256, r2.receipt_digest_sha256)
        self.assertIn("prov:type", r1.prov_dm_bundle)
        self.assertEqual(r1.prov_dm_bundle["prov:wasAssociatedWith"], "urn:cin:steganographic-collusion-auditor")


if __name__ == "__main__":
    unittest.main()
