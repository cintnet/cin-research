"""
research/ledger_sim/test_counterfactual_cascade_audit_sim.py

Unit test suite for Counterfactual Cascade Auditing & Information Taint Preemption Simulation.
Grounded in Vivek Acharya et al. (arXiv:2610.20668, Oct 2026).
"""

from __future__ import annotations

import math
import unittest

from research.ledger_sim.counterfactual_cascade_audit_sim import (
    ActionType,
    CallBeforeReadRecord,
    CascadeAuditRegime,
    CascadeAuditSecurityViolation,
    CascadeAuditValidationError,
    CascadeStepExecutionRecord,
    CounterfactualCascadeAuditSimulator,
    LedgerTamperError,
    StewardGateViolationError,
    TerminalStatus,
    canonical_sha256,
    generate_cascade_workloads,
    run_counterfactual_cascade_sweep,
    screen_steward_gate,
)


class TestCounterfactualCascadeAuditSim(unittest.TestCase):
    """Test suite asserting mathematical, security, and Steward Gate invariants."""

    def test_capital_conservation_across_all_regimes(self) -> None:
        """Every regime must strictly conserve capital: initial == spent + unspent."""
        sweep = run_counterfactual_cascade_sweep(count=30, seed=77, taint_frequency=0.30)
        for regime, res in sweep.items():
            self.assertTrue(res.capital_conservation_verified, f"Capital not conserved in {regime}")
            self.assertEqual(
                res.total_initial_budget_cents,
                res.total_spent_cents + res.total_unspent_cents,
                f"Capital conservation math failed in {regime}",
            )
            self.assertGreaterEqual(res.total_initial_budget_cents, 0)
            self.assertGreaterEqual(res.total_spent_cents, 0)
            self.assertGreaterEqual(res.total_unspent_cents, 0)
            self.assertGreaterEqual(res.total_wasted_cents, 0)
            self.assertLessEqual(res.total_wasted_cents, res.total_spent_cents)

            # Strict integer typing assertion
            self.assertIs(type(res.total_initial_budget_cents), int)
            self.assertNotIsInstance(res.total_initial_budget_cents, bool)
            self.assertIs(type(res.total_spent_cents), int)
            self.assertNotIsInstance(res.total_spent_cents, bool)
            self.assertIs(type(res.total_unspent_cents), int)
            self.assertNotIsInstance(res.total_unspent_cents, bool)
            self.assertIs(type(res.total_wasted_cents), int)
            self.assertNotIsInstance(res.total_wasted_cents, bool)

    def test_deterministic_workload_reproducibility(self) -> None:
        """Workload generation must be 100% deterministic and decoupled from regime logic."""
        w1 = generate_cascade_workloads(count=25, seed=99, taint_frequency=0.20)
        w2 = generate_cascade_workloads(count=25, seed=99, taint_frequency=0.20)
        self.assertEqual(len(w1), len(w2))
        for item1, item2 in zip(w1, w2):
            self.assertEqual(item1.task_id, item2.task_id)
            self.assertEqual(item1.taint_present, item2.taint_present)
            self.assertEqual(item1.clean_action, item2.clean_action)
            self.assertEqual(item1.tainted_action, item2.tainted_action)
            self.assertEqual(item1.base_cost_cents, item2.base_cost_cents)
            self.assertEqual(item1.allocated_budget_cents, item2.allocated_budget_cents)
            self.assertEqual(item1.sentinel_audit_tripwire, item2.sentinel_audit_tripwire)

    def test_fail_closed_numeric_and_type_defense(self) -> None:
        """Non-finite floats, booleans as numbers, and negative inputs must fail closed."""
        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(count=-5)

        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(count=True)  # type: ignore

        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(seed=False)  # type: ignore

        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(taint_frequency=float("nan"))

        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(taint_frequency=float("inf"))

        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(taint_frequency=1.5)

        with self.assertRaises(CascadeAuditValidationError):
            generate_cascade_workloads(max_depth=0)

        sim = CounterfactualCascadeAuditSimulator()
        with self.assertRaises(CascadeAuditValidationError):
            sim.simulate_regime("INVALID_REGIME", [])  # type: ignore

    def test_call_before_read_hash_chain_and_tamper_detection(self) -> None:
        """Call-before-read log enforces tamper-evident SHA-256 hash chaining."""
        sim = CounterfactualCascadeAuditSimulator()
        r1 = sim.log_call_before_read("t1", "agent-a", "srv-1", "clean text 1", "lease-1", 100.0)
        r2 = sim.log_call_before_read("t2", "agent-b", "srv-2", "clean text 2", "lease-2", 110.0)
        self.assertTrue(sim.verify_call_before_read_integrity())

        # Verify entry hashes match payload
        self.assertEqual(r2.prev_hash, r1.entry_hash)

        # Corrupt an entry and verify tamper detection
        corrupted_record = CallBeforeReadRecord(
            read_id=r1.read_id,
            task_id=r1.task_id,
            agent_id=r1.agent_id,
            source_service_id=r1.source_service_id,
            data_digest="corrupted_digest_0000000000000000000000000000000000000000000000000",
            timestamp_ms=r1.timestamp_ms,
            capability_lease_id=r1.capability_lease_id,
            prev_hash=r1.prev_hash,
            entry_hash=r1.entry_hash,
        )
        sim.call_before_read_ledger[0] = corrupted_record
        with self.assertRaises(LedgerTamperError):
            sim.verify_call_before_read_integrity()

    def test_counterfactual_audit_detects_taint_and_preempts(self) -> None:
        """Counterfactual auditing preempts execution when causal divergence is proven."""
        workloads = generate_cascade_workloads(count=30, seed=123, taint_frequency=0.40)
        sim = CounterfactualCascadeAuditSimulator()
        res = sim.simulate_regime(CascadeAuditRegime.CASCADE_LEDGER_COUNTERFACTUAL, workloads)

        # Counterfactual regime must preempt tainted tasks
        self.assertGreater(res.preempted_by_audit, 0)
        self.assertGreaterEqual(res.audit_detection_rate_pct, 70.0)
        self.assertTrue(sim.verify_call_before_read_integrity())

        # Preempted steps must have zero wasted cents and proven divergence
        preempted_steps = [s for s in res.step_records if s.status == TerminalStatus.PREEMPTED_BY_AUDIT]
        for step in preempted_steps:
            self.assertEqual(step.wasted_cents, 0)
            self.assertTrue(step.counterfactual_divergence_proven)
            self.assertIn(
                step.executed_action,
                (ActionType.BENIGN_ANALYSIS, ActionType.BENIGN_COMPUTE, ActionType.BENIGN_DATA_AGGREGATION),
            )

    def test_compliance_theatre_in_post_hoc_summary(self) -> None:
        """Post-hoc summary audits fail to catch covert taints due to compliance theatre."""
        workloads = generate_cascade_workloads(count=30, seed=123, taint_frequency=0.40)
        sim = CounterfactualCascadeAuditSimulator()
        res_summary = sim.simulate_regime(CascadeAuditRegime.POST_HOC_SUMMARY_AUDIT, workloads)
        res_cf = sim.simulate_regime(CascadeAuditRegime.CASCADE_LEDGER_COUNTERFACTUAL, workloads)

        # Summary audit suffers far more wasted capital than counterfactual audit
        self.assertGreater(res_summary.total_wasted_cents, res_cf.total_wasted_cents)
        self.assertGreater(res_summary.tainted_completed, res_cf.tainted_completed)

    def test_steward_gate_invariants(self) -> None:
        """Steward Gate screening rejects forbidden speculative and token promises."""
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Earn Contribution Tokens by running agent workloads.")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("MMCT token distribution model ensures guaranteed returns.")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Passive income through hyperdrive agent fleets.")

        # Clean text passes without error
        screen_steward_gate("Analyze municipal sensor telemetry for water conservation.")


if __name__ == "__main__":
    unittest.main()
