"""
Unit Tests for GoAgent Communication Topology Optimization & Cryptographic Verification
(research/ledger_sim/test_goagent_dag_optimizer.py)

Validates:
  - AgentGroup and GroupEdge fail-closed argument validations.
  - Topological sorting via Kahn's algorithm and strict DAG cycle detection.
  - Information Bottleneck (IB) edge scoring and communication sparsification.
  - W3C PROV-DM cryptographic receipt generation and deterministic verification.
  - Strict Steward Gate defense against premature tokens, speculative savings, and sci-fi lore.
"""

import json
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
    from research.ledger_sim.goagent_dag_optimizer import (
        AgentGroup,
        GroupEdge,
        GoAgentDAGOptimizer,
        canonical_sha256,
        verify_goagent_prov_receipt,
    )
except ImportError:
    from goagent_dag_optimizer import (
        AgentGroup,
        GroupEdge,
        GoAgentDAGOptimizer,
        canonical_sha256,
        verify_goagent_prov_receipt,
    )


class TestGoAgentDAGOptimizer(unittest.TestCase):

    def setUp(self) -> None:
        self.optimizer = GoAgentDAGOptimizer(beta=0.25, min_retained_edges_per_node=1)

    def test_agent_group_and_edge_validation_fail_closed(self) -> None:
        """Verify fail-closed validation on malformed AgentGroup and GroupEdge arguments."""
        # Empty group_id
        with self.assertRaises(ValueError):
            AgentGroup(group_id="", role_name="Scout", agent_count=3, capability_keys=("search",)).validate()

        # Invalid characters in group_id
        with self.assertRaises(ValueError):
            AgentGroup(group_id="group@invalid!", role_name="Scout", agent_count=3, capability_keys=("search",)).validate()

        # Zero or negative agent_count
        with self.assertRaises(ValueError):
            AgentGroup(group_id="group-1", role_name="Scout", agent_count=0, capability_keys=("search",)).validate()

        # Negative mean_token_cost
        with self.assertRaises(ValueError):
            AgentGroup(group_id="group-1", role_name="Scout", agent_count=2, capability_keys=("search",), mean_token_cost=-10).validate()

        # Out-of-bounds group_accuracy
        with self.assertRaises(ValueError):
            AgentGroup(group_id="group-1", role_name="Scout", agent_count=2, capability_keys=("search",), group_accuracy=1.5).validate()

        # GroupEdge self-loop rejection
        with self.assertRaises(ValueError):
            GroupEdge(source_group_id="group-1", target_group_id="group-1", relevance_score=0.8).validate()

        # Out-of-bounds relevance score
        with self.assertRaises(ValueError):
            GroupEdge(source_group_id="group-1", target_group_id="group-2", relevance_score=-0.1).validate()

        # Negative bandwidth tokens
        with self.assertRaises(ValueError):
            GroupEdge(source_group_id="group-1", target_group_id="group-2", relevance_score=0.5, channel_bandwidth_tokens=-50).validate()

    def test_topological_sorting_and_cycle_detection(self) -> None:
        """Verify Kahn's algorithm topological sort and fail-closed cycle detection."""
        g1 = AgentGroup("scouts", "Literature Scouts", 2, ("retrieval",))
        g2 = AgentGroup("synthesizers", "Task Synthesizers", 3, ("synthesis",))
        g3 = AgentGroup("auditors", "Verification Auditors", 2, ("audit",))
        groups = [g1, g2, g3]

        edges = [
            GroupEdge("scouts", "synthesizers", 0.9),
            GroupEdge("synthesizers", "auditors", 0.85),
        ]

        order = self.optimizer.compute_topological_order(groups, edges)
        self.assertEqual(order, ["scouts", "synthesizers", "auditors"])

        # Introduce circular dependency: auditors -> scouts
        cycle_edges = edges + [GroupEdge("auditors", "scouts", 0.5)]
        with self.assertRaises(ValueError) as ctx:
            self.optimizer.compute_topological_order(groups, cycle_edges)
        self.assertIn("Cycle detected", str(ctx.exception))

    def test_information_bottleneck_edge_scoring(self) -> None:
        """Verify Information Bottleneck scoring balances relevance against normalized token cost."""
        e1 = GroupEdge("g1", "g2", relevance_score=0.9, channel_bandwidth_tokens=100)
        e2 = GroupEdge("g1", "g3", relevance_score=0.4, channel_bandwidth_tokens=500)
        edges = [e1, e2]

        scores = self.optimizer.compute_ib_scores(edges)
        score_e1 = scores[("g1", "g2")]
        score_e2 = scores[("g1", "g3")]

        # e1 has higher relevance and lower cost ratio -> higher IB score
        self.assertGreater(score_e1, score_e2)
        # e2 cost ratio is 500/500 = 1.0; IB score = 0.4 - (0.25 * 1.0) = 0.15
        self.assertAlmostEqual(score_e2, 0.15, places=2)

    def test_topology_optimization_sparsity_and_token_savings(self) -> None:
        """Verify GoAgent pruning achieves measurable token savings while preserving execution DAG."""
        g1 = AgentGroup("intake", "Intake Coordinator", 1, ("dispatch",), mean_token_cost=200)
        g2 = AgentGroup("retrievers", "Evidence Retrieval Group", 2, ("retrieval",), mean_token_cost=400)
        g3 = AgentGroup("planners", "DAG Planner Group", 2, ("planning",), mean_token_cost=300)
        g4 = AgentGroup("verifiers", "Proof Verifier Group", 1, ("verification",), mean_token_cost=250)
        groups = [g1, g2, g3, g4]

        # Dense forward edges
        edges = [
            GroupEdge("intake", "retrievers", relevance_score=0.95, channel_bandwidth_tokens=150),
            GroupEdge("intake", "planners", relevance_score=0.80, channel_bandwidth_tokens=200),
            GroupEdge("intake", "verifiers", relevance_score=0.15, channel_bandwidth_tokens=300),  # Low relevance distractor
            GroupEdge("retrievers", "planners", relevance_score=0.90, channel_bandwidth_tokens=250),
            GroupEdge("retrievers", "verifiers", relevance_score=0.20, channel_bandwidth_tokens=350),  # Redundant distractor
            GroupEdge("planners", "verifiers", relevance_score=0.88, channel_bandwidth_tokens=200),
        ]

        result = self.optimizer.optimize_topology(
            groups=groups,
            dense_edges=edges,
            task_objective="Optimize collaborative medical billing verification DAG",
            task_id="task-med-audit-01",
        )

        self.assertEqual(result.original_groups, 4)
        self.assertEqual(result.active_groups, 4)
        self.assertEqual(result.original_edges, 6)
        self.assertLess(result.retained_edges, 6)
        self.assertGreater(result.pruned_edges, 0)
        self.assertGreater(result.token_savings_pct, 0.0)
        self.assertTrue(result.steward_gate_passed)
        self.assertEqual(result.topological_execution_order[0], "intake")
        self.assertEqual(result.topological_execution_order[-1], "verifiers")

    def test_w3c_prov_receipt_generation_and_integrity(self) -> None:
        """Verify W3C PROV-DM cryptographic receipts pass deterministic validation and detect tampering."""
        g1 = AgentGroup("group-a", "Frontier Scout", 1, ("search",))
        g2 = AgentGroup("group-b", "Proof Verifier", 1, ("verify",))
        groups = [g1, g2]
        edges = [GroupEdge("group-a", "group-b", relevance_score=0.9, channel_bandwidth_tokens=100)]

        result = self.optimizer.optimize_topology(
            groups=groups,
            dense_edges=edges,
            task_objective="Verify cryptographic proof of work without monetary tokens",
            task_id="task-pcc-01",
        )

        receipt = result.prov_receipt
        valid, errors = verify_goagent_prov_receipt(receipt)
        self.assertTrue(valid, f"Receipt failed validation: {errors}")
        self.assertEqual(errors, [])

        # Verify canonical SHA-256 matches
        self.assertEqual(canonical_sha256(receipt), result.prov_envelope_sha256)

        # Tampering test: corrupt entity reference
        tampered_receipt = json.loads(json.dumps(receipt))
        tampered_receipt["relations"][0]["target_id"] = "non-existent-activity"
        valid_tampered, errors_tampered = verify_goagent_prov_receipt(tampered_receipt)
        self.assertFalse(valid_tampered)
        self.assertIn("target 'non-existent-activity' not in activities", errors_tampered[0])

    def test_steward_gate_compliance_defense(self) -> None:
        """Verify strict fail-closed defense against unapproved tokens and speculative dollar promises."""
        g1 = AgentGroup("group-a", "Frontier Scout", 1, ("search",))
        g2 = AgentGroup("group-b", "Proof Verifier", 1, ("verify",))
        groups = [g1, g2]
        edges = [GroupEdge("group-a", "group-b", relevance_score=0.9)]

        # Forbidden token name in task objective
        with self.assertRaises(ValueError) as ctx:
            self.optimizer.optimize_topology(
                groups=groups,
                dense_edges=edges,
                task_objective="Award +50 Contribution Tokens to participants",
                task_id="task-violation-01",
            )
        self.assertIn("Steward Gate violation", str(ctx.exception))

        # Forbidden speculative dollar claim
        with self.assertRaises(ValueError) as ctx:
            self.optimizer.optimize_topology(
                groups=groups,
                dense_edges=edges,
                task_objective="Deliver +$12,400/yr in guaranteed personal savings",
                task_id="task-violation-02",
            )
        self.assertIn("Steward Gate violation", str(ctx.exception))

        # Forbidden unapproved royalty split
        with self.assertRaises(ValueError) as ctx:
            self.optimizer.optimize_topology(
                groups=groups,
                dense_edges=edges,
                task_objective="Apply 85% direct + 10% Data Shapley royalty split",
                task_id="task-violation-03",
            )
        self.assertIn("Steward Gate violation", str(ctx.exception))

        # Forbidden receipt text check
        fake_receipt = {
            "standard": "W3C PROV-DM",
            "receipt_id": "TEST",
            "task_id": "T1",
            "entities": {},
            "activities": {},
            "agents": {},
            "relations": [],
            "note": "Users earn MMCT rewards",
        }
        valid, errs = verify_goagent_prov_receipt(fake_receipt)
        self.assertFalse(valid)
        self.assertIn("STEWARD_GATE_VIOLATION", errs[0])


if __name__ == "__main__":
    unittest.main()
