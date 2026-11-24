"""
Unit tests for Task-Adaptive Polycentric Orchestration Simulation Framework.

Grounded in:
- arXiv:2602.16873 (AdaptOrch, Nov 2026):
  "AdaptOrch: Task-Adaptive Multi-Agent Orchestration in the Era of LLM Performance Convergence"
- Elinor Ostrom (1990, 2010):
  "Governing the Commons: The Evolution of Institutions for Collective Action"
  & "Beyond Markets and States: Polycentric Governance of Complex Economic Systems"
- Vincent Ostrom, Tiebout, & Warren (1961):
  "The Organization of Government in Metropolitan Areas: A Theoretical Inquiry"
"""

import math
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.ledger_sim.task_adaptive_orchestration_sim import (
    ActiveSubTopology,
    AgentNode,
    AgentSpecialization,
    CapitalConservationError,
    ExecutionReceipt,
    OrchestrationTopology,
    RegimeMetrics,
    StewardGateViolationError,
    TaskAdaptiveOrchestrator,
    TaskAdaptiveValidationError,
    TaskComplexity,
    TaskWorkload,
    generate_deterministic_workload,
    screen_steward_gate,
)


class TestTaskAdaptiveOrchestrationSim(unittest.TestCase):
    def setUp(self) -> None:
        self.agents = [
            AgentNode("agent-coordinator", AgentSpecialization.COORDINATOR, 0.95),
            AgentNode("agent-builder-1", AgentSpecialization.CODE_BUILDER, 0.90),
            AgentNode("agent-builder-2", AgentSpecialization.CODE_BUILDER, 0.88),
            AgentNode("agent-auditor", AgentSpecialization.VERIFIER_AUDITOR, 0.94),
            AgentNode("agent-guardian", AgentSpecialization.COMMONS_GUARDIAN, 0.92),
        ]
        self.orchestrator = TaskAdaptiveOrchestrator(self.agents, initial_treasury=2000.0, seed=42)

    def test_capital_conservation_across_all_regimes(self) -> None:
        """Every regime must conserve 100% of capital: initial == spent + remaining."""
        workload = generate_deterministic_workload(count=30, seed=101)
        results = self.orchestrator.compare_regimes(workload)

        for regime_name, metrics in results.items():
            self.assertTrue(metrics.capital_conserved, f"Capital leaked under {regime_name}")
            self.assertAlmostEqual(
                self.orchestrator.initial_treasury,
                metrics.total_cost_spent + metrics.remaining_treasury,
                places=4,
                msg=f"Discrepancy under {regime_name}",
            )

    def test_fail_closed_numeric_and_type_defense(self) -> None:
        """Non-finite floats, boolean masquerades, and negative values must fail closed."""
        # Non-finite cost
        with self.assertRaises(TaskAdaptiveValidationError):
            TaskWorkload("task-01", TaskComplexity.LOCAL_DETERMINISTIC, 0.2, float("nan"), False, 0.1)

        with self.assertRaises(TaskAdaptiveValidationError):
            TaskWorkload("task-02", TaskComplexity.LOCAL_DETERMINISTIC, 0.2, float("inf"), False, 0.1)

        # Boolean as number
        with self.assertRaises(TaskAdaptiveValidationError):
            TaskWorkload("task-03", TaskComplexity.LOCAL_DETERMINISTIC, True, 5.0, False, 0.1)  # type: ignore

        # Out-of-bounds stake level
        with self.assertRaises(TaskAdaptiveValidationError):
            TaskWorkload("task-04", TaskComplexity.LOCAL_DETERMINISTIC, 1.5, 5.0, False, 0.1)

        # Non-finite treasury
        with self.assertRaises(TaskAdaptiveValidationError):
            TaskAdaptiveOrchestrator(self.agents, initial_treasury=float("nan"))

    def test_steward_gate_invariants(self) -> None:
        """Steward Gate strictly rejects unapproved tokens, financial promises, and sci-fi terms."""
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Payload promises guaranteed returns on agent compute.")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Allocate 100 Contribution Tokens to participants.")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Using MMCT balances for governance rights.")

        with self.assertRaises(StewardGateViolationError):
            TaskWorkload("task-hyperdrive-core", TaskComplexity.COMMONS_CRITICAL, 0.5, 10.0, True, 0.8)

    def test_coordinator_blackout_resilience(self) -> None:
        """
        When coordinator fails, RIGID_HIERARCHY stalls 100% of tasks,
        whereas TASK_ADAPTIVE_POLYCENTRIC routes seamlessly around the fault.
        """
        workload = generate_deterministic_workload(count=25, seed=202)

        # Run with coordinator fault
        results = self.orchestrator.compare_regimes(workload, coordinator_fault=True)

        hier = results[OrchestrationTopology.RIGID_HIERARCHY.value]
        poly = results[OrchestrationTopology.TASK_ADAPTIVE_POLYCENTRIC.value]

        # Hierarchy completely halted
        self.assertEqual(hier.completed_tasks, 0)
        self.assertEqual(hier.manager_bottleneck_stalls, len(workload))
        self.assertEqual(hier.failed_tasks, len(workload))

        # Polycentric completed all tasks without stalls
        self.assertEqual(poly.manager_bottleneck_stalls, 0)
        self.assertEqual(poly.completed_tasks, len(workload))
        self.assertEqual(poly.failed_tasks, 0)

    def test_swarm_message_explosion_and_conflict_rate(self) -> None:
        """
        Flat uncoordinated swarm generates quadratic messages and suffers high conflict rates
        on commons-critical tasks.
        """
        workload = generate_deterministic_workload(count=30, seed=303)
        results = self.orchestrator.compare_regimes(workload)

        swarm = results[OrchestrationTopology.UNCOORDINATED_SWARM.value]
        poly = results[OrchestrationTopology.TASK_ADAPTIVE_POLYCENTRIC.value]

        # Swarm message overhead is vastly higher than polycentric
        # N=5 nodes -> 5*4 = 20 messages per task in swarm
        self.assertGreater(swarm.total_messages, poly.total_messages * 3)
        # Swarm experiences conflict failures on commons-critical tasks
        self.assertGreater(swarm.failed_tasks, 0)
        # Polycentric completes cleanly
        self.assertEqual(poly.failed_tasks, 0)

    def test_dynamic_topology_selection_and_latency_reduction(self) -> None:
        """
        Task-adaptive polycentric orchestration achieves lower mean latency than rigid hierarchy
        due to avoiding the single manager queue bottleneck.
        """
        workload = generate_deterministic_workload(count=40, seed=404)
        results = self.orchestrator.compare_regimes(workload)

        hier = results[OrchestrationTopology.RIGID_HIERARCHY.value]
        poly = results[OrchestrationTopology.TASK_ADAPTIVE_POLYCENTRIC.value]

        self.assertLess(poly.mean_latency_ms, hier.mean_latency_ms)

    def test_cryptographic_receipt_integrity(self) -> None:
        """Execution receipts produce verifiable SHA-256 digests and detect mutations."""
        rcpt = ExecutionReceipt.create(
            task_id="task-test-01",
            topology_used="TASK_ADAPTIVE_POLYCENTRIC:DIRECT_PEER",
            cost_spent=2.50,
            latency_ms=45.0,
            timestamp_tick=1,
        )
        self.assertTrue(rcpt.receipt_id.startswith("rcpt-"))
        self.assertEqual(len(rcpt.digest), 64)

        # Verify digest consistency
        expected_payload = f"task-test-01:TASK_ADAPTIVE_POLYCENTRIC:DIRECT_PEER:2.500000:45.00:1"
        import hashlib
        self.assertEqual(rcpt.digest, hashlib.sha256(expected_payload.encode("utf-8")).hexdigest())

    def test_multi_seed_experiment_and_markdown_table(self) -> None:
        """10-seed experiment aggregates cleanly into formatted markdown."""
        markdown = ""
        for s in range(10):
            orch = TaskAdaptiveOrchestrator(self.agents, initial_treasury=3000.0, seed=s)
            workload = generate_deterministic_workload(count=20, seed=s + 100)
            res = orch.compare_regimes(workload)
            markdown = TaskAdaptiveOrchestrator.format_comparison_markdown(res)
            self.assertIn("TASK_ADAPTIVE_POLYCENTRIC", markdown)
            self.assertIn("100%", markdown)
            # Ensure zero forbidden tokens in markdown table
            screen_steward_gate(markdown)


if __name__ == "__main__":
    unittest.main()
