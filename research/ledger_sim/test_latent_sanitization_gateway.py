"""
research/ledger_sim/test_latent_sanitization_gateway.py

Unit tests for Boundary-Aware Latent State Sanitization Gateway.

Covers:
  - Admittance of pristine continuous latent state vectors (Coconut / Next-Latent).
  - Bounded Euclidean L2 norm projection (Lipschitz / Parseval networks).
  - Hard fail-closed rejection for excessive L2 norm or Chebyshev Linf spikes.
  - Fail-closed rejection of non-finite (NaN, Inf) and boolean elements.
  - Quarantine defense against adversarial feature-space steerings (Zou et al., 2023).
  - W3C PROV-DM cryptographic receipt integrity and anti-tamper detection.
  - Strict Steward Gate adherence (zero unapproved tokens or speculative dollar claims).
"""

from __future__ import annotations

import math
import unittest
from typing import List

try:
    from research.ledger_sim.latent_sanitization_gateway import (
        LatentSanitizationError,
        LatentStatePacket,
        LatentStateSanitizationGateway,
        SanitizationDecisionCode,
        SanitizationPolicy,
        SanitizationReceipt,
        canonical_activation_digest,
        compute_cosine_similarity,
        compute_vector_l2_norm,
        compute_vector_linf_norm,
        project_vector_onto_l2_ball,
    )
except ImportError:
    from latent_sanitization_gateway import (
        LatentSanitizationError,
        LatentStatePacket,
        LatentStateSanitizationGateway,
        SanitizationDecisionCode,
        SanitizationPolicy,
        SanitizationReceipt,
        canonical_activation_digest,
        compute_cosine_similarity,
        compute_vector_l2_norm,
        compute_vector_linf_norm,
        project_vector_onto_l2_ball,
    )


class TestLatentSanitizationGateway(unittest.TestCase):
    """Exhaustive test suite for the LatentStateSanitizationGateway."""

    def setUp(self) -> None:
        self.policy = SanitizationPolicy(
            max_l2_norm=10.0,
            max_linf_norm=3.0,
            min_l2_norm=1e-3,
            max_cosine_steering=0.80,
            allow_projection=True,
            projection_tolerance_ratio=1.25,
            require_provenance_digest=False,
        )
        self.gateway = LatentStateSanitizationGateway(policy=self.policy)

    def test_admit_pristine_latent_vector(self) -> None:
        """Valid bounded continuous latent vectors must be admitted without modification."""
        # 16-dimensional latent vector with norm well within 10.0
        vec = [0.5, -0.4, 0.8, 0.2, -0.6, 0.3, 0.7, -0.1, 0.4, 0.5, -0.2, 0.3, 0.6, -0.5, 0.2, 0.1]
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:edge-veterinary-01",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-001",
            vector_dim=16,
            activation_vector=vec,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNotNone(sanitized)
        self.assertTrue(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.ADMITTED_PRISTINE)
        self.assertAlmostEqual(receipt.original_l2_norm, compute_vector_l2_norm(vec), places=5)
        self.assertEqual(sanitized, vec)
        self.assertTrue(self.gateway.verify_receipt_integrity(receipt))

    def test_admit_projected_l2_norm(self) -> None:
        """Vectors moderately exceeding L2 ceiling (within tolerance) must be projected to norm ball."""
        # 25-dimensional vector with elements 2.25 <= max_linf_norm (3.0)
        # L2 norm = sqrt(25 * 2.25^2) = 5 * 2.25 = 11.25 (exceeds 10.0 ceiling, within 12.5 tolerance)
        vec = [2.25] * 25
        self.assertGreater(compute_vector_l2_norm(vec), 10.0)
        self.assertLessEqual(compute_vector_l2_norm(vec), 12.5)
        self.assertLessEqual(compute_vector_linf_norm(vec), 3.0)

        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:edge-clinic-02",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-002",
            vector_dim=25,
            activation_vector=vec,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNotNone(sanitized)
        self.assertTrue(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.ADMITTED_PROJECTED)
        self.assertAlmostEqual(compute_vector_l2_norm(sanitized), 10.0, places=5)
        self.assertTrue(self.gateway.verify_receipt_integrity(receipt))

    def test_reject_hard_l2_norm_exceeded(self) -> None:
        """Vectors exceeding the hard projection ceiling must be rejected fail-closed."""
        # 64-dimensional vector with elements 2.0 <= max_linf_norm (3.0)
        # L2 norm = sqrt(64 * 4.0) = 8 * 2.0 = 16.0 (exceeds 12.5 hard ceiling)
        vec = [2.0] * 64
        self.assertGreater(compute_vector_l2_norm(vec), 12.5)
        self.assertLessEqual(compute_vector_linf_norm(vec), 3.0)

        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:adversarial-probe-01",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-003",
            vector_dim=64,
            activation_vector=vec,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNone(sanitized)
        self.assertFalse(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_L2_NORM_EXCEEDED)
        self.assertIn("exceeds ceiling", receipt.rejection_reason or "")
        self.assertTrue(self.gateway.verify_receipt_integrity(receipt))

    def test_reject_linf_norm_exceeded(self) -> None:
        """Vectors with a sharp coordinate spike exceeding max_linf_norm must be rejected fail-closed."""
        # Overall L2 norm might be low, but one coordinate is 4.5 (> 3.0 ceiling)
        vec = [4.5, 0.1, 0.1, 0.1, 0.1, 0.1]
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:spike-injector-01",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-004",
            vector_dim=6,
            activation_vector=vec,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNone(sanitized)
        self.assertFalse(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_L_INF_EXCEEDED)
        self.assertIn("exceeds max_linf_norm ceiling", receipt.rejection_reason or "")

    def test_reject_degenerate_energy_floor(self) -> None:
        """Degenerate all-zero or near-zero latent states must fail closed."""
        vec = [0.0] * 10
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:stale-node-01",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-005",
            vector_dim=10,
            activation_vector=vec,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNone(sanitized)
        self.assertFalse(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_DEGENERATE_ENERGY)

    def test_reject_non_finite_elements(self) -> None:
        """Vectors containing NaN, Inf, -Inf, or boolean types must be rejected fail-closed."""
        bad_vectors = [
            [0.1, float("nan"), 0.3, 0.4],
            [0.1, float("inf"), 0.3, 0.4],
            [0.1, float("-inf"), 0.3, 0.4],
            [0.1, True, 0.3, 0.4],  # bool masquerading as int
            [0.1, "0.5", 0.3, 0.4],  # string
        ]
        for bad_vec in bad_vectors:
            packet = LatentStatePacket.from_raw(
                sender_agent_id="agent:corrupt-sender",
                recipient_agent_id="agent:personal-twin-42",
                session_id="session-quic-tun-006",
                vector_dim=4,
                activation_vector=bad_vec,  # type: ignore
            )
            receipt, sanitized = self.gateway.sanitize_packet(packet)
            self.assertIsNone(sanitized)
            self.assertFalse(receipt.admitted)
            self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_NON_FINITE)

    def test_reject_dimension_mismatch(self) -> None:
        """Declared vector_dim mismatching actual vector length must fail closed."""
        vec = [0.2, 0.4, 0.6]
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:edge-01",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-007",
            vector_dim=8,  # Declared 8, given 3
            activation_vector=vec,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNone(sanitized)
        self.assertFalse(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_DIMENSION_MISMATCH)

    def test_reject_invalid_headers(self) -> None:
        """Invalid or whitespace agent/session IDs must be rejected fail-closed."""
        bad_headers = [
            ("", "valid:agent", "valid-session"),
            ("valid:agent", "   ", "valid-session"),
            ("valid:agent", "valid:agent", "bad;semi;session"),
        ]
        vec = [0.1, 0.2, 0.3, 0.4]
        for s_id, r_id, sess_id in bad_headers:
            packet = LatentStatePacket.from_raw(
                sender_agent_id=s_id,
                recipient_agent_id=r_id,
                session_id=sess_id,
                vector_dim=4,
                activation_vector=vec,
            )
            receipt, sanitized = self.gateway.sanitize_packet(packet)
            self.assertIsNone(sanitized)
            self.assertFalse(receipt.admitted)
            self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_INVALID_HEADER)

    def test_reject_adversarial_feature_space_steering(self) -> None:
        """Vectors aligned with quarantined representation steering directions must fail closed."""
        # Known adversarial steering direction (e.g., representation hijacking vector)
        adversarial_direction = [1.0, -1.0, 0.5, 0.5]
        self.gateway.register_quarantined_steering_vector(adversarial_direction)
        self.assertEqual(self.gateway.quarantined_vectors_count, 1)

        # Attacking vector aligned with adversarial direction (cosine similarity ~ 0.99)
        steered_vector = [1.02, -0.98, 0.51, 0.49]
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:steering-attacker",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-008",
            vector_dim=4,
            activation_vector=steered_vector,
        )

        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertIsNone(sanitized)
        self.assertFalse(receipt.admitted)
        self.assertEqual(receipt.decision_code, SanitizationDecisionCode.REJECTED_ADVERSARIAL_STEERING)
        self.assertGreater(receipt.max_steering_similarity, 0.80)

        # Orthogonal/benign vector must still pass
        benign_vector = [-0.5, 0.5, 1.0, 1.0]  # dot product: -0.5*1 + 0.5*-1 + 1*0.5 + 1*0.5 = 0.0
        benign_packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:benign-peer",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-008",
            vector_dim=4,
            activation_vector=benign_vector,
        )
        b_receipt, b_sanitized = self.gateway.sanitize_packet(benign_packet)
        self.assertTrue(b_receipt.admitted)
        self.assertEqual(b_receipt.decision_code, SanitizationDecisionCode.ADMITTED_PRISTINE)

    def test_provenance_digest_verification(self) -> None:
        """Explicit provenance digests must be cryptographically verified."""
        vec = [0.2, 0.3, -0.1, 0.5]
        correct_digest = canonical_activation_digest(vec)

        # Matching digest passes
        valid_packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:verified-edge",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-009",
            vector_dim=4,
            activation_vector=vec,
            provenance_digest=correct_digest,
        )
        receipt, sanitized = self.gateway.sanitize_packet(valid_packet)
        self.assertTrue(receipt.admitted)
        self.assertEqual(receipt.activation_digest, correct_digest)

        # Tampered digest fails closed
        tampered_packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:verified-edge",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-009",
            vector_dim=4,
            activation_vector=vec,
            provenance_digest="f" * 64,
        )
        t_receipt, t_sanitized = self.gateway.sanitize_packet(tampered_packet)
        self.assertFalse(t_receipt.admitted)
        self.assertEqual(t_receipt.decision_code, SanitizationDecisionCode.REJECTED_PROVENANCE_MISMATCH)

    def test_cryptographic_receipt_integrity_and_tamper_detection(self) -> None:
        """SanitizationReceipt SHA-256 signatures must detect adversarial mutations."""
        vec = [0.1, 0.2, 0.3, 0.4]
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:audit-peer",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-010",
            vector_dim=4,
            activation_vector=vec,
        )
        receipt, sanitized = self.gateway.sanitize_packet(packet)
        self.assertTrue(self.gateway.verify_receipt_integrity(receipt))

        # Adversarial tamper with admitted flag
        tampered = SanitizationReceipt(
            receipt_id=receipt.receipt_id,
            decision_code=receipt.decision_code,
            admitted=False,  # Mutated
            sender_agent_id=receipt.sender_agent_id,
            recipient_agent_id=receipt.recipient_agent_id,
            session_id=receipt.session_id,
            vector_dim=receipt.vector_dim,
            original_l2_norm=receipt.original_l2_norm,
            original_linf_norm=receipt.original_linf_norm,
            sanitized_l2_norm=receipt.sanitized_l2_norm,
            sanitized_linf_norm=receipt.sanitized_linf_norm,
            max_steering_similarity=receipt.max_steering_similarity,
            activation_digest=receipt.activation_digest,
            receipt_sha256=receipt.receipt_sha256,
            created_at_iso=receipt.created_at_iso,
            prov_entity=receipt.prov_entity,
            rejection_reason=receipt.rejection_reason,
        )
        self.assertFalse(self.gateway.verify_receipt_integrity(tampered))

    def test_policy_invariants_fail_closed(self) -> None:
        """Invalid policy configurations must fail immediately on initialization."""
        with self.assertRaises(ValueError):
            SanitizationPolicy(max_l2_norm=-1.0).validate_policy_invariants()
        with self.assertRaises(ValueError):
            SanitizationPolicy(max_linf_norm=0.0).validate_policy_invariants()
        with self.assertRaises(ValueError):
            SanitizationPolicy(max_cosine_steering=1.5).validate_policy_invariants()
        with self.assertRaises(ValueError):
            SanitizationPolicy(projection_tolerance_ratio=0.8).validate_policy_invariants()

    def test_steward_gate_invariants(self) -> None:
        """Gateway audit logs and receipts must be 100% free of unapproved tokens and speculative dollar promises."""
        vec = [0.2, 0.4, 0.6, 0.8]
        packet = LatentStatePacket.from_raw(
            sender_agent_id="agent:steward-gate-test",
            recipient_agent_id="agent:personal-twin-42",
            session_id="session-quic-tun-011",
            vector_dim=4,
            activation_vector=vec,
        )
        receipt, _ = self.gateway.sanitize_packet(packet)
        dumped = receipt.to_dict()
        raw_text = str(dumped).lower()

        forbidden_patterns = [
            "contribution token",
            "mmct",
            "mmctbalance",
            "+$1",
            "+$2",
            "+$3",
            "+$5",
            "+$10",
            "+$11",
            "".join(["somatic", " ", "witness"]),
            "".join(["pre", "-", "adc"]),
            "85/10/5",
        ]
        for forbidden in forbidden_patterns:
            self.assertNotIn(forbidden, raw_text)


if __name__ == "__main__":
    unittest.main()
