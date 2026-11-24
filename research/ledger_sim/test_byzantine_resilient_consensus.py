"""
research/ledger_sim/test_byzantine_resilient_consensus.py

Unit test suite for Decentralized Byzantine-Resilient Consensus & Self-Anchored Consensus (SAC).
Grounded in:
- Lee et al. (arXiv:2605.09076, 2026): Robust Multi-Agent LLMs under Byzantine Faults.
- LeBlanc et al. (IEEE JSAC, 2013, DOI:10.1109/JSAC.2013.130413): Resilient Asymptotic Consensus in Robust Networks.
- Dennis & Van Horn (CACM, 1966): Object-Capability Security.
- W3C PROV-DM (2013): Cryptographic Provenance Model.
"""

from __future__ import annotations

import math
import unittest
from typing import Dict, List

from research.ledger_sim.byzantine_resilient_consensus import (
    ByzantineAgentNode,
    ByzantineResilientConsensusEngine,
    ConsensusGraphTopology,
    ConsensusSecurityViolation,
    ConsensusValidationError,
    NodeRole,
    SemanticMessage,
    StewardGateViolationError,
    assert_finite_float,
    assert_steward_gate_compliance,
    canonical_sha256,
)


class TestByzantineResilientConsensus(unittest.TestCase):
    """Test suite verifying Byzantine fault isolation, topological robustness, and Steward Gate invariants."""

    def setUp(self) -> None:
        self.node_ids = ["agent_0", "agent_1", "agent_2", "agent_3", "agent_4", "agent_byz"]

    def test_topology_robustness_validation(self) -> None:
        """Graph topology must correctly verify (F+1)-robustness degree requirements."""
        # 6 nodes, F=1. Required: N > 3*F (6 > 3 is ok), in-degree >= 2*F+1 = 3.
        clique_top = ConsensusGraphTopology.build_fully_connected(self.node_ids, max_byzantine_f=1)
        ok, msg = clique_top.verify_f_plus_1_robustness()
        self.assertTrue(ok)
        self.assertIn("satisfies", msg)

        # Insufficient node count: 3 nodes with F=1 (3 <= 3*1 -> invalid)
        small_top = ConsensusGraphTopology.build_fully_connected(["a", "b", "c"], max_byzantine_f=1)
        ok_small, msg_small = small_top.verify_f_plus_1_robustness()
        self.assertFalse(ok_small)
        self.assertIn("Insufficient nodes", msg_small)

        # Insufficient in-degree
        fragile_in = {
            "agent_0": ("agent_1",),
            "agent_1": ("agent_0",),
            "agent_2": ("agent_3",),
            "agent_3": ("agent_2",),
            "agent_4": ("agent_byz",),
            "agent_byz": ("agent_4",),
        }
        fragile_top = ConsensusGraphTopology(
            nodes=tuple(self.node_ids),
            in_neighbors=fragile_in,
            max_byzantine_f=1,
        )
        ok_fragile, msg_fragile = fragile_top.verify_f_plus_1_robustness()
        self.assertFalse(ok_fragile)
        self.assertIn("less than required", msg_fragile)

    def test_honest_consensus_convergence(self) -> None:
        """All-honest agents with distinct initial observations converge to consensus."""
        honest_ids = ["node_a", "node_b", "node_c", "node_d"]
        topology = ConsensusGraphTopology.build_fully_connected(honest_ids, max_byzantine_f=0)

        engine = ByzantineResilientConsensusEngine(topology)
        initial_values = [10.0, 12.0, 9.0, 11.0]
        anchors = [10.5, 10.5, 10.5, 10.5]

        for nid, val, anch in zip(honest_ids, initial_values, anchors):
            node = ByzantineAgentNode(
                agent_id=nid,
                role=NodeRole.HONEST,
                initial_value=val,
                self_anchor_value=anch,
                max_byzantine_f=0,
                alpha_anchor=0.2,
                beta_neighbors=0.6,
            )
            engine.register_node(node)

        receipt = engine.run_consensus(max_rounds=20, convergence_threshold=0.01, ground_truth=10.5)
        self.assertTrue(receipt.converged)
        self.assertLess(receipt.final_discrepancy, 0.01)
        self.assertAlmostEqual(receipt.honest_mean_value, 10.5, delta=0.5)
        self.assertTrue(len(receipt.receipt_digest) == 64)

    def test_byzantine_extreme_isolation(self) -> None:
        """A malicious agent injecting extreme outliers is trimmed by honest nodes."""
        topology = ConsensusGraphTopology.build_fully_connected(self.node_ids, max_byzantine_f=1)
        engine = ByzantineResilientConsensusEngine(topology)

        # Honest agents cluster around 20.0
        honest_inits = [19.0, 20.0, 21.0, 19.5, 20.5]
        for i in range(5):
            nid = f"agent_{i}"
            node = ByzantineAgentNode(
                agent_id=nid,
                role=NodeRole.HONEST,
                initial_value=honest_inits[i],
                self_anchor_value=20.0,
                max_byzantine_f=1,
                alpha_anchor=0.3,
                beta_neighbors=0.5,
            )
            engine.register_node(node)

        # Byzantine node injects an extreme outlier of +5000.0
        byz_node = ByzantineAgentNode(
            agent_id="agent_byz",
            role=NodeRole.BYZANTINE_EXTREME,
            initial_value=5000.0,
            self_anchor_value=5000.0,
            max_byzantine_f=1,
            adversarial_bias=5000.0,
        )
        engine.register_node(byz_node)

        receipt = engine.run_consensus(max_rounds=25, convergence_threshold=0.05, ground_truth=20.0)

        # Honest agents must converge despite Byzantine injection
        self.assertTrue(receipt.converged)
        self.assertLess(receipt.final_discrepancy, 0.05)
        self.assertAlmostEqual(receipt.honest_mean_value, 20.0, delta=1.0)

        # Verify that all honest nodes trimmed agent_byz in their audit logs
        for i in range(5):
            nid = f"agent_{i}"
            trimmed = receipt.trimmed_audit_log[nid]
            self.assertIn("agent_byz", trimmed)

    def test_byzantine_erratic_oscillation_isolation(self) -> None:
        """An erratic oscillating agent is successfully trimmed without destabilizing honest nodes."""
        topology = ConsensusGraphTopology.build_fully_connected(self.node_ids, max_byzantine_f=1)
        engine = ByzantineResilientConsensusEngine(topology)

        for i in range(5):
            nid = f"agent_{i}"
            node = ByzantineAgentNode(
                agent_id=nid,
                role=NodeRole.HONEST,
                initial_value=50.0,
                self_anchor_value=50.0,
                max_byzantine_f=1,
                alpha_anchor=0.3,
                beta_neighbors=0.5,
            )
            engine.register_node(node)

        byz_node = ByzantineAgentNode(
            agent_id="agent_byz",
            role=NodeRole.BYZANTINE_RANDOM,
            initial_value=-1000.0,
            self_anchor_value=-1000.0,
            max_byzantine_f=1,
            adversarial_bias=2000.0,
        )
        engine.register_node(byz_node)

        receipt = engine.run_consensus(max_rounds=20, convergence_threshold=0.01, ground_truth=50.0)
        self.assertTrue(receipt.converged)
        self.assertAlmostEqual(receipt.honest_mean_value, 50.0, delta=0.1)

    def test_steward_gate_compliance(self) -> None:
        """Forbidden tokens and speculative monetary promises fail closed."""
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("Deploy Contribution Tokens across the swarm")
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance({"action": "mint MMCT for agents"})
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("guaranteed profit from multi-agent negotiation")
        with self.assertRaises(StewardGateViolationError):
            SemanticMessage.create(
                sender_id="bad_agent",
                round_number=0,
                claim_value=1.0,
                statement="Deploy MMCT now",
                confidence=0.9,
            )

    def test_numeric_finiteness_defense(self) -> None:
        """Non-finite floats (NaN/Inf) fail closed with ConsensusValidationError."""
        with self.assertRaises(ConsensusValidationError):
            assert_finite_float(float("nan"), "test_nan")
        with self.assertRaises(ConsensusValidationError):
            assert_finite_float(float("inf"), "test_inf")
        with self.assertRaises(ConsensusValidationError):
            ByzantineAgentNode(
                agent_id="node_nan",
                role=NodeRole.HONEST,
                initial_value=float("nan"),
                self_anchor_value=1.0,
                max_byzantine_f=1,
            )
        with self.assertRaises(ConsensusValidationError):
            SemanticMessage.create(
                sender_id="node_a",
                round_number=0,
                claim_value=float("inf"),
                statement="Valid statement",
                confidence=0.5,
            )

    def test_tampered_signature_detection(self) -> None:
        """Tampered messages raise ConsensusSecurityViolation."""
        msg = SemanticMessage.create(
            sender_id="agent_1",
            round_number=1,
            claim_value=25.0,
            statement="Honest claim",
            confidence=0.95,
        )
        self.assertTrue(msg.verify_digest())

        # Construct a tampered copy with modified claim_value but same signature
        tampered = SemanticMessage(
            sender_id=msg.sender_id,
            round_number=msg.round_number,
            claim_value=999.0,
            statement=msg.statement,
            confidence=msg.confidence,
            signature_digest=msg.signature_digest,
        )
        self.assertFalse(tampered.verify_digest())

        receiver = ByzantineAgentNode(
            agent_id="agent_0",
            role=NodeRole.HONEST,
            initial_value=25.0,
            self_anchor_value=25.0,
            max_byzantine_f=1,
        )
        with self.assertRaises(ConsensusSecurityViolation):
            receiver.filter_and_refine([tampered])

    def test_execution_receipt_and_determinism(self) -> None:
        """Consensus execution produces deterministic receipts and W3C PROV-DM structures."""
        honest_ids = ["n0", "n1", "n2", "n3"]
        topology = ConsensusGraphTopology.build_fully_connected(honest_ids, max_byzantine_f=0)

        def run_once() -> str:
            engine = ByzantineResilientConsensusEngine(topology)
            for nid in honest_ids:
                node = ByzantineAgentNode(
                    agent_id=nid,
                    role=NodeRole.HONEST,
                    initial_value=10.0,
                    self_anchor_value=10.0,
                    max_byzantine_f=0,
                )
                engine.register_node(node)
            rcpt = engine.run_consensus(max_rounds=5, convergence_threshold=0.001, ground_truth=10.0)
            return rcpt.receipt_digest

        digest_1 = run_once()
        digest_2 = run_once()
        self.assertEqual(digest_1, digest_2)
        self.assertEqual(len(digest_1), 64)


if __name__ == "__main__":
    unittest.main()
