"""
test_tgr_evodag_evolution_router.py: Test suite for TGR-EvoDAG Multi-Agent Code Evolution Router.

Verifies:
  - Directed Acyclic Graph invariants (cycle prevention, topological sort).
  - Multi-branch concurrent exploration without linear overwriting.
  - Multi-parent topological merge with composite Pareto utility.
  - Non-dominated Pareto frontier extraction and leaf branch pruning.
  - W3C PROV-DM cryptographic provenance export.
  - Fail-closed parameter validation and strict Steward Gate enforcement.
"""

from __future__ import annotations

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

from research.ledger_sim.tgr_evodag_evolution_router import (
    EvoDAGCycleError,
    EvoDAGNode,
    EvoDAGValidationError,
    EvolutionStrategyType,
    TGREvoDAGRouter,
    VariantMetrics,
    assert_steward_gate_compliance,
    canonical_sha256,
)


class TestTGREvoDAGRouter(unittest.TestCase):
    """Unit test suite for TGREvoDAGRouter and related components."""

    def setUp(self) -> None:
        self.root_metrics = VariantMetrics(
            task_success_rate=0.80,
            token_efficiency_ratio=1.0,
            latency_ms=120.0,
            test_pass_count=10,
            test_fail_count=2,
        )
        self.root_node = EvoDAGNode(
            node_id="evo_root_001",
            parent_ids=(),
            strategy=EvolutionStrategyType.ROOT_BASELINE,
            author_role="RESEARCH_EXPLORER",
            code_artifact="def solve(query):\n    return baseline_planner(query)\n",
            metrics=self.root_metrics,
        )
        self.router = TGREvoDAGRouter(root_node=self.root_node)

    def test_node_creation_and_deterministic_digest(self) -> None:
        """Verifies that nodes compute deterministic SHA-256 digests."""
        digest1 = self.root_node.sha256_digest
        self.assertTrue(digest1)
        self.assertEqual(len(digest1), 64)

        # Recreating the exact same node yields identical digest
        duplicate_node = EvoDAGNode(
            node_id="evo_root_001",
            parent_ids=(),
            strategy=EvolutionStrategyType.ROOT_BASELINE,
            author_role="RESEARCH_EXPLORER",
            code_artifact="def solve(query):\n    return baseline_planner(query)\n",
            metrics=self.root_metrics,
        )
        self.assertEqual(duplicate_node.sha256_digest, digest1)

    def test_steward_gate_compliance(self) -> None:
        """Verifies that forbidden tokens, speculative dollars, and sci-fi lore fail closed."""
        forbidden_strings = [
            "We award 50 Contribution Tokens",
            "User balance is 120 MMCT",
            "mintedMMCT parameter set to true",
            "You will save +$11,420/yr in recurring fees",
            "85% direct + 10% pool split",
            "needs 95% Data Shapley credit",
            "Equipped with Somatic Witness ring",
            "Pre-ADC consensus layer",
        ]
        for bad_str in forbidden_strings:
            with self.subTest(bad_str=bad_str):
                with self.assertRaises(ValueError):
                    assert_steward_gate_compliance(bad_str)

                with self.assertRaises(ValueError):
                    EvoDAGNode(
                        node_id=f"node_{abs(hash(bad_str))}",
                        parent_ids=(),
                        strategy=EvolutionStrategyType.MUTATION,
                        author_role="ENGINEER",
                        code_artifact=bad_str,
                        metrics=self.root_metrics,
                    )

    def test_metrics_validation(self) -> None:
        """Verifies bounds and type validation on VariantMetrics."""
        # Success rate out of bounds
        with self.assertRaises(EvoDAGValidationError):
            VariantMetrics(task_success_rate=1.5, token_efficiency_ratio=1.0, latency_ms=10.0, test_pass_count=1, test_fail_count=0)

        with self.assertRaises(EvoDAGValidationError):
            VariantMetrics(task_success_rate=-0.1, token_efficiency_ratio=1.0, latency_ms=10.0, test_pass_count=1, test_fail_count=0)

        # Non-positive latency or efficiency
        with self.assertRaises(EvoDAGValidationError):
            VariantMetrics(task_success_rate=0.9, token_efficiency_ratio=-1.0, latency_ms=10.0, test_pass_count=1, test_fail_count=0)

        with self.assertRaises(EvoDAGValidationError):
            VariantMetrics(task_success_rate=0.9, token_efficiency_ratio=1.0, latency_ms=0.0, test_pass_count=1, test_fail_count=0)

        # Negative test counts
        with self.assertRaises(EvoDAGValidationError):
            VariantMetrics(task_success_rate=0.9, token_efficiency_ratio=1.0, latency_ms=10.0, test_pass_count=-1, test_fail_count=0)

    def test_branch_exploration(self) -> None:
        """Verifies branching creates independent sibling nodes from parent."""
        mutations = [
            (
                "token_pruning",
                "def solve(query):\n    pruned = prune_tokens(query)\n    return baseline_planner(pruned)\n",
                VariantMetrics(0.85, 1.35, 105.0, 11, 1),
                "PRUNING_SPECIALIST",
            ),
            (
                "parallel_decomposition",
                "def solve(query):\n    parts = decompose(query)\n    return merge_solutions(parts)\n",
                VariantMetrics(0.92, 1.10, 85.0, 12, 0),
                "DECOMPOSITION_SPECIALIST",
            ),
        ]

        child_ids = self.router.branch_exploration(self.root_node.node_id, mutations)
        self.assertEqual(len(child_ids), 2)
        self.assertEqual(self.router.node_count, 3)

        child1 = self.router.get_node(child_ids[0])
        child2 = self.router.get_node(child_ids[1])

        self.assertEqual(child1.parent_ids, (self.root_node.node_id,))
        self.assertEqual(child2.parent_ids, (self.root_node.node_id,))
        self.assertEqual(child1.strategy, EvolutionStrategyType.MUTATION)
        self.assertEqual(child2.strategy, EvolutionStrategyType.MUTATION)

    def test_cycle_rejection(self) -> None:
        """Verifies that attempts to add edges creating cycles fail closed."""
        m1 = VariantMetrics(0.85, 1.2, 100.0, 10, 0)
        n1 = EvoDAGNode("n1", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "ROLE_A", "code_n1", m1)
        self.router.add_node(n1)

        m2 = VariantMetrics(0.88, 1.3, 90.0, 10, 0)
        n2 = EvoDAGNode("n2", ("n1",), EvolutionStrategyType.MUTATION, "ROLE_B", "code_n2", m2)
        self.router.add_node(n2)

        # Attempt to make n1 a child of n2 (cycle n1 -> n2 -> n1)
        # By attempting to add a node with ID 'n1' that has parent 'n2', or adding an edge
        with self.assertRaises(EvoDAGValidationError):
            # Duplicate ID
            self.router.add_node(n1)

        # Self-parenting node
        with self.assertRaises(EvoDAGValidationError):
            self.router.add_node(
                EvoDAGNode("self_parent", ("self_parent",), EvolutionStrategyType.MUTATION, "ROLE_A", "code", m1)
            )

    def test_topological_sort(self) -> None:
        """Verifies topological sorting respects dependency orders."""
        m = VariantMetrics(0.85, 1.0, 100.0, 10, 0)
        n_a = EvoDAGNode("node_A", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "ROLE_A", "code_A", m)
        n_b = EvoDAGNode("node_B", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "ROLE_B", "code_B", m)
        self.router.add_node(n_a)
        self.router.add_node(n_b)

        n_c = EvoDAGNode("node_C", ("node_A", "node_B"), EvolutionStrategyType.CROSSOVER, "ROLE_C", "code_C", m)
        self.router.add_node(n_c)

        ordered = self.router.topological_sort()
        self.assertEqual(len(ordered), 4)
        self.assertEqual(ordered[0], self.root_node.node_id)
        # node_A and node_B must appear before node_C
        idx_a = ordered.index("node_A")
        idx_b = ordered.index("node_B")
        idx_c = ordered.index("node_C")
        self.assertLess(idx_a, idx_c)
        self.assertLess(idx_b, idx_c)

    def test_topological_merge(self) -> None:
        """Verifies topological multi-parent merge with composite utility derivation."""
        mutations = [
            (
                "branch_1",
                "def solve(query): return fast_solve(query)\n",
                VariantMetrics(0.88, 1.25, 95.0, 10, 0),
                "ENGINEER_1",
            ),
            (
                "branch_2",
                "def solve(query): return accurate_solve(query)\n",
                VariantMetrics(0.95, 1.10, 110.0, 10, 0),
                "ENGINEER_2",
            ),
        ]
        child_ids = self.router.branch_exploration(self.root_node.node_id, mutations)

        merged_metrics = VariantMetrics(0.96, 1.30, 92.0, 12, 0)
        merged_code = (
            "def solve(query):\n"
            "    # Synthesized from branch_1 and branch_2\n"
            "    fast_cand = fast_solve(query)\n"
            "    return accurate_verify(fast_cand)\n"
        )

        merged_node = self.router.topological_merge(
            merged_node_id="merged_branch_1_2",
            parent_ids=child_ids,
            synthesized_code=merged_code,
            author_role="LEAD_ARCHITECT",
            tested_metrics=merged_metrics,
        )

        self.assertEqual(merged_node.node_id, "merged_branch_1_2")
        self.assertEqual(len(merged_node.parent_ids), 2)
        self.assertEqual(merged_node.strategy, EvolutionStrategyType.TOPOLOGICAL_MERGE)
        self.assertGreater(merged_node.metrics.composite_utility, self.root_metrics.composite_utility)
        self.assertTrue(self.router.has_node("merged_branch_1_2"))

    def test_pareto_front_extraction(self) -> None:
        """Verifies extraction of non-dominated leaf candidates."""
        # Add 3 variants:
        # V1: high success, moderate efficiency, moderate latency
        # V2: low success, high efficiency, very low latency (tradeoff)
        # V3: dominated by V1 in all dimensions (lower success, lower efficiency, higher latency)
        v1_metrics = VariantMetrics(0.95, 1.4, 80.0, 10, 0)
        v2_metrics = VariantMetrics(0.75, 2.0, 40.0, 10, 0)
        v3_metrics = VariantMetrics(0.80, 1.1, 100.0, 8, 2)

        v1 = EvoDAGNode("v1", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "ROLE_1", "c1", v1_metrics)
        v2 = EvoDAGNode("v2", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "ROLE_2", "c2", v2_metrics)
        v3 = EvoDAGNode("v3", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "ROLE_3", "c3", v3_metrics)

        self.router.add_node(v1)
        self.router.add_node(v2)
        self.router.add_node(v3)

        front = self.router.get_pareto_front()
        front_ids = {node.node_id for node in front}

        self.assertIn("v1", front_ids)
        self.assertIn("v2", front_ids)
        self.assertNotIn("v3", front_ids)  # V3 is strictly dominated by V1

    def test_prune_suboptimal_branches(self) -> None:
        """Verifies leaf branch pruning bounds active search width."""
        m_low = VariantMetrics(0.60, 0.8, 200.0, 5, 5)
        m_mid = VariantMetrics(0.80, 1.1, 120.0, 8, 2)
        m_high = VariantMetrics(0.95, 1.5, 75.0, 12, 0)

        n_low = EvoDAGNode("leaf_low", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "R1", "c_low", m_low)
        n_mid = EvoDAGNode("leaf_mid", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "R2", "c_mid", m_mid)
        n_high = EvoDAGNode("leaf_high", (self.root_node.node_id,), EvolutionStrategyType.MUTATION, "R3", "c_high", m_high)

        self.router.add_node(n_low)
        self.router.add_node(n_mid)
        self.router.add_node(n_high)

        # We have 3 leaves; keep top 2
        to_prune = self.router.prune_suboptimal_branches(max_leaves=2)
        self.assertEqual(to_prune, ["leaf_low"])

    def test_export_w3c_prov_dm(self) -> None:
        """Verifies that export_w3c_prov_dm returns valid PROV-DM structures."""
        m_child = VariantMetrics(0.90, 1.25, 90.0, 10, 0)
        child = EvoDAGNode(
            node_id="prov_child_01",
            parent_ids=(self.root_node.node_id,),
            strategy=EvolutionStrategyType.MUTATION,
            author_role="VERIFICATION_RUNNER",
            code_artifact="def solve(query): return refined(query)\n",
            metrics=m_child,
        )
        self.router.add_node(child)

        prov = self.router.export_w3c_prov_dm("prov_child_01")

        self.assertIn("@context", prov)
        self.assertIn("entity", prov)
        self.assertIn("agent", prov)
        self.assertIn("wasGeneratedBy", prov)
        self.assertIn("wasDerivedFrom", prov)

        child_entity_key = "cin:variant/prov_child_01"
        self.assertIn(child_entity_key, prov["entity"])
        self.assertEqual(prov["entity"][child_entity_key]["cin:sha256"], child.sha256_digest)

        derivation_key = f"cin:derivation/prov_child_01_from_{self.root_node.node_id}"
        self.assertIn(derivation_key, prov["wasDerivedFrom"])
        self.assertEqual(
            prov["wasDerivedFrom"][derivation_key]["prov:usedEntity"],
            f"cin:variant/{self.root_node.node_id}",
        )


if __name__ == "__main__":
    unittest.main()
