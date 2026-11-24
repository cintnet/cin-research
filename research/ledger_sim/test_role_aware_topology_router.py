#!/usr/bin/env python3
"""
test_role_aware_topology_router.py: Conformance and security unit tests for
Testnet Ledger Role-Aware Topology Router (ACTS / arXiv:2610.25851).
"""

import math
import sys
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
REPO_ROOT = TEST_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

try:
    from research.ledger_sim.role_aware_topology_router import (
        RoleAwareTopologyRouter,
        RouteDecision,
        RoutingPhase,
        RoutingValidationError,
        TestnetAgentRole,
        canonical_sha256,
    )
except ImportError:
    from role_aware_topology_router import (
        RoleAwareTopologyRouter,
        RouteDecision,
        RoutingPhase,
        RoutingValidationError,
        TestnetAgentRole,
        canonical_sha256,
    )


class TestRoleAwareTopologyRouter(unittest.TestCase):
    """Unit test suite for testnet ledger role-aware topology router."""

    def setUp(self) -> None:
        self.router = RoleAwareTopologyRouter(admission_threshold=0.50)

    def test_route_decision_validations(self) -> None:
        """Verify RouteDecision dataclass fails closed on malformed values."""
        # Non-boolean deliver flag
        with self.assertRaises(RoutingValidationError):
            RouteDecision(
                should_deliver="yes",  # type: ignore
                affinity_score=0.8,
                channel_priority=1,
                rationale="Valid test",
            )
        # NaN affinity
        with self.assertRaises(RoutingValidationError):
            RouteDecision(
                should_deliver=True,
                affinity_score=float("nan"),
                channel_priority=1,
                rationale="Valid test",
            )
        # Out-of-bounds affinity
        with self.assertRaises(RoutingValidationError):
            RouteDecision(
                should_deliver=True,
                affinity_score=1.5,
                channel_priority=1,
                rationale="Valid test",
            )
        # Invalid priority
        with self.assertRaises(RoutingValidationError):
            RouteDecision(
                should_deliver=True,
                affinity_score=0.5,
                channel_priority=0,
                rationale="Valid test",
            )

    def test_self_loops_suppressed(self) -> None:
        """Verify that intra-role self-loops are automatically suppressed."""
        decision = self.router.evaluate_route(
            sender_role=TestnetAgentRole.LEDGER_COORDINATOR,
            receiver_role=TestnetAgentRole.LEDGER_COORDINATOR,
            message_category="TASK_CAMPAIGN",
            phase=RoutingPhase.SYNTHESIS,
        )
        self.assertFalse(decision.should_deliver)
        self.assertEqual(decision.affinity_score, 0.0)
        self.assertIn("Self-loop message suppressed", decision.rationale)

    def test_pipeline_edges_admitted(self) -> None:
        """Verify that high-affinity canonical pipeline links are admitted."""
        decision = self.router.evaluate_route(
            sender_role=TestnetAgentRole.ATTENTION_WATCHER,
            receiver_role=TestnetAgentRole.PRIVACY_GUARD,
            message_category="ATTENTION_SIGNAL",
            phase=RoutingPhase.EXPLORATION,
        )
        self.assertTrue(decision.should_deliver)
        self.assertGreaterEqual(decision.affinity_score, 0.80)
        self.assertEqual(decision.channel_priority, 1)
        self.assertEqual(len(decision.provenance_hash), 64)

    def test_phase_modulation(self) -> None:
        """Verify that task phase modulates role affinity appropriately."""
        # Verification runner is de-prioritized during exploration
        dec_explore = self.router.evaluate_route(
            sender_role=TestnetAgentRole.VERIFICATION_RUNNER,
            receiver_role=TestnetAgentRole.LEDGER_COORDINATOR,
            message_category="VERIFICATION_RECEIPT",
            phase=RoutingPhase.EXPLORATION,
        )
        # Verification runner is strongly prioritized during verification phase
        dec_verify = self.router.evaluate_route(
            sender_role=TestnetAgentRole.VERIFICATION_RUNNER,
            receiver_role=TestnetAgentRole.LEDGER_COORDINATOR,
            message_category="VERIFICATION_RECEIPT",
            phase=RoutingPhase.VERIFICATION,
        )
        self.assertGreater(dec_verify.affinity_score, dec_explore.affinity_score)

    def test_batch_routing_sparsity_and_token_savings(self) -> None:
        """Verify batch routing eliminates quadratic message overhead."""
        # Generate full pairwise candidate transmissions (6 roles x 6 roles = 36 messages)
        roles = list(TestnetAgentRole)
        messages = []
        for s in roles:
            for r in roles:
                messages.append({
                    "sender_role": s.value,
                    "receiver_role": r.value,
                    "category": "TESTNET_MSG",
                })
        self.assertEqual(len(messages), 36)

        batch_result = self.router.route_batch(messages, RoutingPhase.SYNTHESIS)
        self.assertEqual(batch_result["total_candidate_messages"], 36)
        # Verifies that at least 50% of unnecessary pairwise chatter is pruned
        self.assertGreaterEqual(batch_result["message_sparsity_ratio"], 0.50)
        self.assertGreaterEqual(batch_result["token_bandwidth_saved_pct"], 50.0)
        self.assertLess(batch_result["delivered_count"], 36)

    def test_invalid_parameters_fail_closed(self) -> None:
        """Verify fail-closed error handling on malformed role or phase arguments."""
        with self.assertRaises(RoutingValidationError):
            RoleAwareTopologyRouter(admission_threshold=1.5)

        with self.assertRaises(RoutingValidationError):
            self.router.evaluate_route(
                sender_role="NON_EXISTENT",  # type: ignore
                receiver_role=TestnetAgentRole.LEDGER_COORDINATOR,
                message_category="MSG",
                phase=RoutingPhase.SYNTHESIS,
            )

        with self.assertRaises(RoutingValidationError):
            self.router.evaluate_route(
                sender_role=TestnetAgentRole.LEDGER_COORDINATOR,
                receiver_role=TestnetAgentRole.PRIVACY_GUARD,
                message_category="MSG; DROP TABLE",
                phase=RoutingPhase.SYNTHESIS,
            )


if __name__ == "__main__":
    unittest.main()
