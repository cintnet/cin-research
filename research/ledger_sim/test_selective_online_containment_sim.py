"""
research/ledger_sim/test_selective_online_containment_sim.py

Unit test suite for Selective Online Containment & Blast-Radius Simulation.
Tests capital conservation, RNG isolation, fail-closed typing, W3C PROV-DM receipts,
and multi-regime containment properties.
"""

from __future__ import annotations

import math
import random
import unittest

from research.ledger_sim.selective_online_containment_sim import (
    AIRLOCK_SELECTIVE_CONTAINMENT,
    FULL_PIPELINE_ABORT,
    STATIC_NODE_QUARANTINE,
    UNCONTAINED_CASCADE,
    CapabilityLease,
    ContainmentReceipt,
    ContainmentRegime,
    ContainmentValidationError,
    DAGTask,
    LeaseRevocationError,
    StewardGateViolationError,
    TaskKind,
    TaskStatus,
    WorkflowDAG,
    generate_workload_dag,
    run_selective_online_containment_benchmark,
    run_workflow_under_regime,
    screen_steward_gate,
)


class TestSelectiveOnlineContainmentSim(unittest.TestCase):
    """Test suite verifying containment simulation invariants and multi-regime properties."""

    def setUp(self) -> None:
        self.rng = random.Random(1337)
        self.sample_dag = generate_workload_dag(
            self.rng,
            workflow_id="test-wf-01",
            num_tasks=12,
            branch_factor=2,
            fault_node_index=2,
        )

    def test_capital_conservation_across_all_regimes(self) -> None:
        """Every regime must strictly conserve capital: total_budget == healthy + tainted + reserve."""
        for regime in ContainmentRegime:
            result = run_workflow_under_regime(self.sample_dag, regime)
            total_settled = result.spent_healthy_cents + result.spent_tainted_cents + result.salvaged_reserve_cents
            self.assertEqual(
                total_settled,
                self.sample_dag.total_budget_cents,
                f"Capital leak under {regime.value}: settled {total_settled} != budget {self.sample_dag.total_budget_cents}",
            )
            self.assertGreaterEqual(result.salvaged_reserve_cents, 0)
            self.assertGreaterEqual(result.spent_healthy_cents, 0)
            self.assertGreaterEqual(result.spent_tainted_cents, 0)

    def test_airlock_containment_superiority(self) -> None:
        """Airlock must achieve 100% downstream containment and preserve healthy parallel work."""
        airlock_res = run_workflow_under_regime(self.sample_dag, ContainmentRegime.AIRLOCK_SELECTIVE_CONTAINMENT)
        abort_res = run_workflow_under_regime(self.sample_dag, ContainmentRegime.FULL_PIPELINE_ABORT)
        uncontained_res = run_workflow_under_regime(self.sample_dag, ContainmentRegime.UNCONTAINED_CASCADE)
        static_res = run_workflow_under_regime(self.sample_dag, ContainmentRegime.STATIC_NODE_QUARANTINE)

        # Airlock containment rate = 1.0 (downstream taints prevented)
        self.assertEqual(airlock_res.taint_containment_rate, 1.0)
        self.assertEqual(abort_res.taint_containment_rate, 1.0)
        self.assertEqual(uncontained_res.taint_containment_rate, 0.0)
        self.assertEqual(static_res.taint_containment_rate, 0.0)

        # Airlock preserves strictly more healthy work than full abort
        self.assertGreater(
            airlock_res.healthy_work_preservation_rate,
            abort_res.healthy_work_preservation_rate,
        )
        self.assertEqual(airlock_res.healthy_work_preservation_rate, 1.0)

        # Airlock generates a valid signed containment receipt
        self.assertIsNotNone(airlock_res.containment_receipt)
        self.assertTrue(len(airlock_res.containment_receipt.tamper_evident_digest) == 64)
        self.assertIn("cin:containment", airlock_res.containment_receipt.prov_entity["prov:id"])

    def test_fail_closed_numeric_and_boolean_typing(self) -> None:
        """Strict validation rejects booleans as numbers, negative costs, and non-ints."""
        # Boolean passed as cost_cents in DAGTask
        with self.assertRaises(ContainmentValidationError):
            DAGTask(
                task_id="bad_task",
                kind=TaskKind.DATA_INGESTION,
                parent_ids=(),
                cost_cents=True,  # type: ignore
                is_fault_injection_point=False,
                output_payload="Clean payload",
            )

        # Negative cost_cents in DAGTask
        with self.assertRaises(ContainmentValidationError):
            DAGTask(
                task_id="bad_task_2",
                kind=TaskKind.DATA_INGESTION,
                parent_ids=(),
                cost_cents=-50,
                is_fault_injection_point=False,
                output_payload="Clean payload",
            )

        # Float passed as total_budget_cents in WorkflowDAG
        with self.assertRaises(ContainmentValidationError):
            WorkflowDAG(
                workflow_id="wf_bad",
                tasks=self.sample_dag.tasks,
                root_ids=self.sample_dag.root_ids,
                total_budget_cents=5000.5,  # type: ignore
            )

    def test_capability_lease_expiration_and_revocation(self) -> None:
        """Capability lease must fail closed on expiration or revocation."""
        lease = CapabilityLease(
            lease_id="test-lease-1",
            task_id="task_01",
            actor_id="agent-01",
            expires_at_step=10,
        )
        # Active step before expiration
        lease.verify_active(current_step=5)

        # Step at expiration
        with self.assertRaises(LeaseRevocationError):
            lease.verify_active(current_step=10)

        # Revocation
        lease.revoke()
        self.assertTrue(lease.revoked)
        with self.assertRaises(LeaseRevocationError):
            lease.verify_active(current_step=2)

    def test_steward_gate_invariants(self) -> None:
        """Payloads containing forbidden tokens or speculative claims must fail closed."""
        screen_steward_gate("Safe verified coordination pipeline.")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Contains unapproved MMCT tokens.")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Guaranteed returns for participants.")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Activating hyperdrive coordinates.")

    def test_workload_determinism_and_decoupling(self) -> None:
        """Workload generation must be deterministic and decoupled from regime execution."""
        rng1 = random.Random(999)
        rng2 = random.Random(999)
        dag1 = generate_workload_dag(rng1, "wf-det", num_tasks=8, branch_factor=2, fault_node_index=2)
        dag2 = generate_workload_dag(rng2, "wf-det", num_tasks=8, branch_factor=2, fault_node_index=2)

        self.assertEqual(dag1.total_budget_cents, dag2.total_budget_cents)
        self.assertEqual(list(dag1.tasks.keys()), list(dag2.tasks.keys()))
        for tid in dag1.tasks:
            self.assertEqual(dag1.tasks[tid].cost_cents, dag2.tasks[tid].cost_cents)
            self.assertEqual(dag1.tasks[tid].output_payload, dag2.tasks[tid].output_payload)

    def test_benchmark_runner_aggregates(self) -> None:
        """Benchmark runner produces valid aggregate statistics across multiple workflows."""
        bench = run_selective_online_containment_benchmark(seed=123, num_workflows=5)
        self.assertIn(ContainmentRegime.AIRLOCK_SELECTIVE_CONTAINMENT, bench)
        airlock_metrics = bench[ContainmentRegime.AIRLOCK_SELECTIVE_CONTAINMENT]
        self.assertEqual(airlock_metrics["mean_containment_rate"], 1.0)
        self.assertGreater(airlock_metrics["mean_healthy_preservation_rate"], 0.8)
        self.assertGreater(airlock_metrics["total_salvaged_cents"], 0)


if __name__ == "__main__":
    unittest.main()
