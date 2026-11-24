"""
research/ledger_sim/test_sybil_flow_reputation_guard.py

Unit and Adversarial Test Suite for SybilFlowReputationGuard.
Grounded in Ramji et al. (arXiv:2611.05586, Nov 2026) and Dennis & Van Horn (1966).
"""

import json
import unittest

from research.ledger_sim.sybil_flow_reputation_guard import (
    InteractionReceipt,
    RatingModelKind,
    ReputationReceipt,
    StewardGateViolationError,
    SybilFlowConfig,
    SybilFlowReputationGuard,
    SybilValidationError,
)


class TestSybilFlowReputationGuard(unittest.TestCase):
    """Test suite verifying mathematical invariants, Sybil resistance, and Steward Gate safety."""

    def setUp(self) -> None:
        self.config = SybilFlowConfig(
            model_kind=RatingModelKind.MAX_FLOW_ANDUIN,
            seed_trust_nodes=("seed_alpha", "seed_beta"),
            flow_decay=0.85,
            sybil_cost_ratio_threshold=0.20,
            max_search_depth=5,
        )
        self.guard = SybilFlowReputationGuard(self.config)

    def test_record_interaction_nominal(self) -> None:
        """Nominal interaction recording produces valid cryptographic receipt and updates state."""
        receipt = self.guard.record_interaction(
            buyer_id="seed_alpha",
            provider_id="provider_omega",
            task_scope="verifiable_code_audit",
            volume_units=10.0,
            rating=0.95,
            timestamp_iso="2026-11-06T10:00:00Z",
        )
        self.assertIsInstance(receipt, InteractionReceipt)
        self.assertTrue(receipt.interaction_id.startswith("ix_"))
        self.assertEqual(receipt.volume_units, 10.0)
        self.assertEqual(receipt.rating, 0.95)
        self.assertEqual(len(receipt.receipt_digest), 64)

    def test_type_and_numeric_validation(self) -> None:
        """Invalid types, booleans, non-finite floats, and out-of-bound ratings fail closed."""
        # Boolean passed as volume_units
        with self.assertRaises(SybilValidationError):
            self.guard.record_interaction("seed_alpha", "prov", "task", True, 0.9, "2026-11-06T10:00:00Z")  # type: ignore

        # Negative volume
        with self.assertRaises(SybilValidationError):
            self.guard.record_interaction("seed_alpha", "prov", "task", -5.0, 0.9, "2026-11-06T10:00:00Z")

        # NaN rating
        with self.assertRaises(SybilValidationError):
            self.guard.record_interaction("seed_alpha", "prov", "task", 5.0, float("nan"), "2026-11-06T10:00:00Z")

        # Rating > 1.0
        with self.assertRaises(SybilValidationError):
            self.guard.record_interaction("seed_alpha", "prov", "task", 5.0, 1.5, "2026-11-06T10:00:00Z")

        # Empty strings
        with self.assertRaises(SybilValidationError):
            self.guard.record_interaction("", "prov", "task", 5.0, 0.8, "2026-11-06T10:00:00Z")

    def test_steward_gate_enforcement(self) -> None:
        """Forbidden monetization terms and unapproved speculative tokens trigger StewardGateViolationError."""
        with self.assertRaises(StewardGateViolationError):
            self.guard.record_interaction(
                buyer_id="seed_alpha",
                provider_id="prov",
                task_scope="earn $5,000/month with MMCT tokens",
                volume_units=5.0,
                rating=0.8,
                timestamp_iso="2026-11-06T10:00:00Z",
            )

        with self.assertRaises(StewardGateViolationError):
            self.guard.record_interaction(
                buyer_id="seed_alpha",
                provider_id="prov",
                task_scope="Distribution of Contribution Tokens according to 85/10/5 royalty",
                volume_units=5.0,
                rating=0.8,
                timestamp_iso="2026-11-06T10:00:00Z",
            )

    def test_max_flow_direct_and_multihop(self) -> None:
        """Max-flow correctly aggregates bottleneck capacity along multi-hop honest chains."""
        # Direct edge: seed_alpha -> provider_1 (vol: 10, rating: 0.9)
        self.guard.record_interaction("seed_alpha", "provider_1", "task_a", 10.0, 0.9, "2026-11-06T10:00:00Z")

        rep1 = self.guard.compute_reputation("seed_alpha", "provider_1")
        self.assertAlmostEqual(rep1.computed_score, 0.9, places=2)
        self.assertAlmostEqual(rep1.effective_flow_capacity, 10.0, places=2)
        self.assertTrue(rep1.is_sybil_resilient)

        # Multi-hop path: seed_alpha -> agent_mid (vol: 5) -> provider_2 (vol: 8, rating: 0.8)
        # Bottleneck must be 5.0
        self.guard.record_interaction("seed_alpha", "agent_mid", "task_b", 5.0, 1.0, "2026-11-06T10:01:00Z")
        self.guard.record_interaction("agent_mid", "provider_2", "task_c", 8.0, 0.8, "2026-11-06T10:02:00Z")

        rep2 = self.guard.compute_reputation("seed_alpha", "provider_2")
        self.assertAlmostEqual(rep2.effective_flow_capacity, 5.0, places=2)
        self.assertAlmostEqual(rep2.computed_score, 0.8, places=2)

    def test_sybil_attack_resistance_simulation(self) -> None:
        """
        Adversary spawns 50 sockpuppets to flood a 0.2-rated provider with 200 fake 1.0 reviews.
        Unweighted rating is manipulated heavily; max-flow rating is unaffected (resistance >= 20x).
        """
        # Seed honest interaction giving a 0.2 rating with 5.0 volume
        self.guard.record_interaction("seed_alpha", "shady_provider", "basic_work", 5.0, 0.2, "2026-11-06T09:00:00Z")

        # Run attack simulation
        results = self.guard.simulate_sybil_attack(
            target_provider_id="shady_provider",
            sybil_node_count=50,
            sybil_review_count=200,
            sybil_rating_value=1.0,
        )

        # Unweighted should have jumped from 0.2 toward ~0.99
        self.assertGreater(results["post_unweighted_score"], 0.90)
        self.assertGreater(results["unweighted_distortion"], 0.70)

        # Max flow should remain at 0.2 because the Sybils have no path from seed_alpha
        self.assertAlmostEqual(results["post_max_flow_score"], 0.2, places=2)
        self.assertAlmostEqual(results["max_flow_distortion"], 0.0, places=2)
        self.assertTrue(results["attack_neutralized"])
        self.assertGreaterEqual(results["manipulation_resistance_ratio"], 20.0)

    def test_relaxed_exponential_flow_decay(self) -> None:
        """Relaxed flow model applies geometric distance decay based on graph hop distance."""
        relaxed_config = SybilFlowConfig(
            model_kind=RatingModelKind.RELAXED_EXPONENTIAL_FLOW,
            seed_trust_nodes=("seed_alpha",),
            flow_decay=0.5,
            max_search_depth=4,
        )
        relaxed_guard = SybilFlowReputationGuard(relaxed_config)

        # 2 hops: seed_alpha -> intermediary (hop 1) -> provider (hop 2)
        relaxed_guard.record_interaction("seed_alpha", "intermediary", "job1", 10.0, 1.0, "2026-11-06T10:00:00Z")
        relaxed_guard.record_interaction("intermediary", "target_prov", "job2", 10.0, 1.0, "2026-11-06T10:01:00Z")

        receipt = relaxed_guard.compute_reputation("seed_alpha", "target_prov")
        # Decay for 2 hops at factor 0.5 is 0.5^2 = 0.25
        self.assertAlmostEqual(receipt.computed_score, 0.25, places=2)
        self.assertAlmostEqual(receipt.effective_flow_capacity, 2.5, places=2)

    def test_w3c_prov_dm_and_cryptographic_receipt(self) -> None:
        """Reputation receipts produce deterministic, valid W3C PROV-DM bundles and SHA-256 digests."""
        self.guard.record_interaction("seed_alpha", "provider_prov", "analysis", 8.0, 0.85, "2026-11-06T11:00:00Z")
        receipt = self.guard.compute_reputation("seed_alpha", "provider_prov")

        self.assertIn("entity", receipt.prov_dm_bundle)
        self.assertIn("activity", receipt.prov_dm_bundle)
        self.assertIn("wasGeneratedBy", receipt.prov_dm_bundle)
        self.assertEqual(len(receipt.receipt_digest), 64)

        # Verify idempotence / determinism
        receipt_2 = self.guard.compute_reputation("seed_alpha", "provider_prov")
        self.assertEqual(receipt.receipt_digest, receipt_2.receipt_digest)

    def test_cyclic_graph_termination_and_parallel_paths(self) -> None:
        """Cycles in the interaction graph do not hang, and parallel honest paths sum capacity."""
        # Cycle: seed_alpha -> node_a -> node_b -> node_a
        self.guard.record_interaction("seed_alpha", "node_a", "job", 4.0, 1.0, "2026-11-06T12:00:00Z")
        self.guard.record_interaction("node_a", "node_b", "job", 4.0, 1.0, "2026-11-06T12:01:00Z")
        self.guard.record_interaction("node_b", "node_a", "job", 4.0, 1.0, "2026-11-06T12:02:00Z")

        # Two parallel paths to target:
        # Path 1: seed_alpha -> node_a -> target (cap: min(4, 3) = 3)
        self.guard.record_interaction("node_a", "target", "job", 3.0, 0.9, "2026-11-06T12:03:00Z")
        # Path 2: seed_alpha -> node_c -> target (cap: min(5, 5) = 5)
        self.guard.record_interaction("seed_alpha", "node_c", "job", 5.0, 1.0, "2026-11-06T12:04:00Z")
        self.guard.record_interaction("node_c", "target", "job", 5.0, 0.7, "2026-11-06T12:05:00Z")

        receipt = self.guard.compute_reputation("seed_alpha", "target")
        # Total flow should be 3.0 + 5.0 = 8.0
        self.assertAlmostEqual(receipt.effective_flow_capacity, 8.0, places=2)
        # Weighted score: (0.9 * 3 + 0.7 * 5) / 8 = (2.7 + 3.5) / 8 = 6.2 / 8 = 0.775
        self.assertAlmostEqual(receipt.computed_score, 0.775, places=2)

    def test_disconnected_node_zero_flow(self) -> None:
        """A candidate provider with zero path to the seed set has zero flow and zero score."""
        self.guard.record_interaction("seed_alpha", "node_x", "job", 5.0, 1.0, "2026-11-06T12:00:00Z")
        self.guard.record_interaction("unrelated_buyer", "isolated_provider", "job", 5.0, 1.0, "2026-11-06T12:00:00Z")

        receipt = self.guard.compute_reputation("seed_alpha", "isolated_provider")
        self.assertEqual(receipt.effective_flow_capacity, 0.0)
        self.assertEqual(receipt.computed_score, 0.0)
        self.assertTrue(receipt.is_sybil_resilient)


if __name__ == "__main__":
    unittest.main()
