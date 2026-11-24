"""
test_dynamic_joint_state_graph_router.py: Unit tests for Dynamic Homogeneous Joint-State Graph Router.

Verifies:
  - Agent local state initialization, validation, and content digest determinism.
  - JointStateNode task coverage bounds and cumulative cost arithmetic.
  - Dynamic-HJSG root creation, single/multi-agent state transitions, and branching.
  - Cycle detection and fail-closed prevention (HJSGCycleError).
  - Cost boundary enforcement (HJSGBudgetExceededError).
  - Pareto optimality frontier calculation across coverage and coordination cost.
  - Suboptimal leaf state pruning bounded by max_active_joint_states.
  - W3C PROV-DM cryptographic lineage receipt export and SHA-256 digest validation.
  - Strict Steward Gate fail-closed enforcement (zero unapproved tokens/royalties/claims).
"""

from __future__ import annotations

import unittest

from research.ledger_sim.dynamic_joint_state_graph_router import (
    AgentLocalState,
    DynamicHJSGRouter,
    HJSGBudgetExceededError,
    HJSGCycleError,
    HJSGValidationError,
    JointStateNode,
    assert_steward_gate_compliance,
)


class TestDynamicHJSGRouter(unittest.TestCase):
    """Test suite for DynamicHJSGRouter."""

    def setUp(self) -> None:
        self.router = DynamicHJSGRouter(max_active_joint_states=10, max_coordination_cost=50.0)
        self.a1 = AgentLocalState("agent-alpha", "init", cost_units=1.0)
        self.a2 = AgentLocalState("agent-beta", "idle", cost_units=0.5)

    def test_agent_local_state_determinism(self) -> None:
        s1 = AgentLocalState("agent-alpha", "ready", cost_units=2.0, attributes={"p": 1})
        s2 = AgentLocalState("agent-alpha", "ready", cost_units=2.0, attributes={"p": 1})
        self.assertEqual(s1.content_digest, s2.content_digest)
        self.assertTrue(len(s1.content_digest) == 64)

    def test_agent_local_state_validation(self) -> None:
        with self.assertRaises(HJSGValidationError):
            AgentLocalState("", "ready")
        with self.assertRaises(HJSGValidationError):
            AgentLocalState("a1", "")
        with self.assertRaises(HJSGValidationError):
            AgentLocalState("a1", "ready", cost_units=-1.0)

    def test_create_root_joint_state(self) -> None:
        root = self.router.create_root_joint_state([self.a1, self.a2])
        self.assertIsNotNone(root)
        self.assertEqual(root.step_index, 0)
        self.assertEqual(root.cumulative_cost, 1.5)
        self.assertEqual(root.task_coverage, 0.0)
        self.assertEqual(len(root.agent_states), 2)
        self.assertEqual(self.router.root_node_id, root.node_id)

    def test_duplicate_agent_root_rejection(self) -> None:
        dup = AgentLocalState("agent-alpha", "idle")
        with self.assertRaises(HJSGValidationError):
            self.router.create_root_joint_state([self.a1, dup])

    def test_expand_joint_state(self) -> None:
        root = self.router.create_root_joint_state([self.a1, self.a2])
        a1_next = AgentLocalState("agent-alpha", "queried", cost_units=1.5)

        child = self.router.expand_joint_state(
            parent_node_id=root.node_id,
            agent_transitions={"agent-alpha": a1_next},
            action_label="alpha_query_subtask",
            step_cost=1.0,
            coverage_gain=0.25,
        )

        self.assertEqual(child.step_index, 1)
        self.assertEqual(child.parent_ids, (root.node_id,))
        self.assertEqual(child.agent_states["agent-alpha"].state_key, "queried")
        self.assertEqual(child.agent_states["agent-beta"].state_key, "idle")  # Preserved
        self.assertAlmostEqual(child.task_coverage, 0.25)
        self.assertAlmostEqual(child.cumulative_cost, 1.5 + 1.0 + 1.5)  # 4.0

    def test_budget_exceeded_error(self) -> None:
        strict_router = DynamicHJSGRouter(max_coordination_cost=5.0)
        root = strict_router.create_root_joint_state([self.a1, self.a2])  # cost: 1.5
        a1_heavy = AgentLocalState("agent-alpha", "heavy_op", cost_units=10.0)

        with self.assertRaises(HJSGBudgetExceededError):
            strict_router.expand_joint_state(
                parent_node_id=root.node_id,
                agent_transitions={"agent-alpha": a1_heavy},
                action_label="heavy_computation",
                step_cost=2.0,
            )

    def test_cycle_rejection(self) -> None:
        root = self.router.create_root_joint_state([self.a1, self.a2])
        with self.assertRaises(HJSGCycleError):
            self.router._check_cycle(root.node_id, root.node_id)

    def test_pareto_optimal_joint_states(self) -> None:
        root = self.router.create_root_joint_state([self.a1, self.a2])
        # Branch A: high coverage (0.6), moderate cost
        child_a = self.router.expand_joint_state(
            parent_node_id=root.node_id,
            agent_transitions={"agent-alpha": AgentLocalState("agent-alpha", "high_cov", cost_units=1.0)},
            action_label="plan_a",
            step_cost=2.0,
            coverage_gain=0.6,
        )
        # Branch B: low coverage (0.2), high cost (dominated)
        child_b = self.router.expand_joint_state(
            parent_node_id=root.node_id,
            agent_transitions={"agent-beta": AgentLocalState("agent-beta", "low_cov", cost_units=5.0)},
            action_label="plan_b",
            step_cost=4.0,
            coverage_gain=0.2,
        )

        pareto = self.router.extract_pareto_optimal_joint_states()
        pareto_ids = {n.node_id for n in pareto}
        self.assertIn(root.node_id, pareto_ids)  # Cost 1.5, cov 0.0
        self.assertIn(child_a.node_id, pareto_ids)  # Cost 5.5, cov 0.6
        self.assertNotIn(child_b.node_id, pareto_ids)  # Cost 11.5, cov 0.2 (strictly dominated by child_a)

    def test_prune_suboptimal_joint_states(self) -> None:
        tiny_router = DynamicHJSGRouter(max_active_joint_states=3, max_coordination_cost=100.0)
        root = tiny_router.create_root_joint_state([self.a1])

        # Add 3 children from root -> total 4 nodes (exceeding max 3)
        for i in range(3):
            tiny_router.expand_joint_state(
                parent_node_id=root.node_id,
                agent_transitions={"agent-alpha": AgentLocalState("agent-alpha", f"s_{i}", cost_units=float(i + 1))},
                action_label=f"step_{i}",
                step_cost=1.0,
                coverage_gain=0.1 * (i + 1),
            )

        self.assertLessEqual(len(tiny_router.nodes), 3)

    def test_optimal_coordination_path(self) -> None:
        root = self.router.create_root_joint_state([self.a1, self.a2])
        step1 = self.router.expand_joint_state(
            parent_node_id=root.node_id,
            agent_transitions={"agent-alpha": AgentLocalState("agent-alpha", "s1", cost_units=1.0)},
            action_label="step1",
            step_cost=1.0,
            coverage_gain=0.5,
        )
        step2 = self.router.expand_joint_state(
            parent_node_id=step1.node_id,
            agent_transitions={"agent-beta": AgentLocalState("agent-beta", "s2", cost_units=1.0)},
            action_label="step2",
            step_cost=1.0,
            coverage_gain=0.5,
            is_terminal=True,
        )

        path = self.router.find_optimal_coordination_path(target_node_id=step2.node_id)
        self.assertEqual(len(path), 3)
        self.assertEqual(path[0].node_id, root.node_id)
        self.assertEqual(path[1].node_id, step1.node_id)
        self.assertEqual(path[2].node_id, step2.node_id)

    def test_export_w3c_prov_dm(self) -> None:
        root = self.router.create_root_joint_state([self.a1, self.a2])
        self.router.expand_joint_state(
            parent_node_id=root.node_id,
            agent_transitions={"agent-alpha": AgentLocalState("agent-alpha", "s1", cost_units=1.0)},
            action_label="step1",
            step_cost=1.0,
            coverage_gain=0.4,
        )

        receipt = self.router.export_w3c_prov_dm()
        self.assertEqual(receipt["schema_version"], "1.0.0")
        self.assertEqual(receipt["node_count"], 2)
        self.assertEqual(receipt["edge_count"], 1)
        self.assertTrue(len(receipt["prov_sha256"]) == 64)
        self.assertIn("wasDerivedFrom", receipt["prov_document"])

    def test_steward_gate_compliance(self) -> None:
        with self.assertRaises(ValueError):
            assert_steward_gate_compliance("Earn +50 Contribution Tokens now!")
        with self.assertRaises(ValueError):
            assert_steward_gate_compliance("User mmctBalance is 100")
        with self.assertRaises(ValueError):
            assert_steward_gate_compliance("Save +$14,200/yr on insurance")
        with self.assertRaises(ValueError):
            assert_steward_gate_compliance("85% direct + 10% attribution split")
        with self.assertRaises(ValueError):
            assert_steward_gate_compliance("Activate Somatic Witness Ring")

        # Compliant strings pass
        assert_steward_gate_compliance("Dynamic-HJSG joint-state coordination with GPTSwarm DAG.")


if __name__ == "__main__":
    unittest.main()
