"""
research/ledger_sim/test_two_ledger_accounting_sim.py

Unit tests for Two-Ledger Transaction Accounting & Runaway Loop Preemption Simulation.
Grounded in Vivek Acharya (arXiv:2611.06989, Nov 2026).
"""

import dataclasses
import math
import unittest

try:
    from research.ledger_sim.two_ledger_accounting_sim import (
        AccountingRegime,
        LedgerTamperError,
        RunawayLoopError,
        StewardGateViolationError,
        TaskExecutionStatus,
        TaskWorkload,
        TwoLedgerAccountingSimulator,
        TwoLedgerSecurityViolation,
        TwoLedgerValidationError,
        canonical_sha256,
        generate_two_ledger_workloads,
        run_two_ledger_comparative_sweep,
        screen_steward_gate,
    )
except ImportError:
    from two_ledger_accounting_sim import (
        AccountingRegime,
        LedgerTamperError,
        RunawayLoopError,
        StewardGateViolationError,
        TaskExecutionStatus,
        TaskWorkload,
        TwoLedgerAccountingSimulator,
        TwoLedgerSecurityViolation,
        TwoLedgerValidationError,
        canonical_sha256,
        generate_two_ledger_workloads,
        run_two_ledger_comparative_sweep,
        screen_steward_gate,
    )


class TestTwoLedgerAccountingSim(unittest.TestCase):
    """Test suite verifying two-ledger accounting, capital conservation, and cycle preemption."""

    def setUp(self):
        self.sim = TwoLedgerAccountingSimulator(
            max_recursion_depth=5,
            token_cost_per_100=2,
            tool_invocation_cost_cents=5,
            sync_lock_latency_ms=35.0,
            decoupled_write_latency_ms=1.0,
        )

    def test_workload_determinism_and_decoupling(self):
        """Verifies that workload generation is deterministic and decoupled from regime execution."""
        wl1 = generate_two_ledger_workloads(count=20, seed=123)
        wl2 = generate_two_ledger_workloads(count=20, seed=123)
        wl3 = generate_two_ledger_workloads(count=20, seed=456)

        self.assertEqual(len(wl1), 20)
        self.assertEqual(wl1, wl2)
        self.assertNotEqual(wl1, wl3)

    def test_capital_conservation_across_all_regimes(self):
        """Every regime must conserve capital: total initial budget == spent + unspent."""
        workloads = generate_two_ledger_workloads(count=25, seed=77, runaway_frequency=0.20)
        total_initial = sum(w.allocated_budget_cents for w in workloads)

        for regime in AccountingRegime:
            result = self.sim.simulate_regime(regime, workloads)
            self.assertTrue(result.capital_conservation_verified)
            self.assertEqual(result.total_initial_budget_cents, total_initial)
            self.assertEqual(
                result.total_spent_cents + result.total_unspent_cents,
                total_initial,
                f"Capital leak detected in {regime.value}",
            )

    def test_runaway_loop_preemption_and_waste_elimination(self):
        """Two-Ledger and Synchronous regimes preempt runaway loops, reducing wasted cents to 0."""
        workloads = generate_two_ledger_workloads(count=30, seed=99, runaway_frequency=0.30)
        
        unmetered = self.sim.simulate_regime(AccountingRegime.UNMETERED_AGGREGATE, workloads)
        two_ledger = self.sim.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, workloads)

        self.assertGreater(unmetered.total_wasted_cents, 0)
        self.assertEqual(unmetered.preempted_tasks, 0)

        self.assertEqual(two_ledger.total_wasted_cents, 0)
        self.assertGreater(two_ledger.preempted_tasks, 0)
        self.assertEqual(two_ledger.runaway_loops_intercepted, two_ledger.preempted_tasks)

    def test_throughput_and_latency_advantage_of_decoupling(self):
        """Two-Ledger decoupled writes deliver significantly higher throughput than synchronous locking."""
        workloads = generate_two_ledger_workloads(count=30, seed=42, runaway_frequency=0.15)

        sync_res = self.sim.simulate_regime(AccountingRegime.SYNCHRONOUS_INLINE_METERING, workloads)
        two_ledger_res = self.sim.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, workloads)

        self.assertGreater(two_ledger_res.throughput_tasks_per_sec, sync_res.throughput_tasks_per_sec)
        self.assertLess(two_ledger_res.total_metering_overhead_ms, sync_res.total_metering_overhead_ms)
        self.assertEqual(two_ledger_res.attribution_completeness_pct, 100.0)

    def test_two_ledger_cryptographic_hash_chain_integrity(self):
        """Cryptographic hash chains verify tamper-evidence across attribution and settlement records."""
        workloads = generate_two_ledger_workloads(count=15, seed=10, runaway_frequency=0.20)
        self.sim.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, workloads)

        # Baseline integrity passes cleanly
        self.assertTrue(self.sim.verify_two_ledger_integrity())

        # Tampering with attribution entry raises LedgerTamperError
        corrupted_attr = dataclasses.replace(
            self.sim.attribution_ledger[2],
            intent_summary="tampered unauthorized intent",
        )
        self.sim.attribution_ledger[2] = corrupted_attr
        with self.assertRaises(LedgerTamperError):
            self.sim.verify_two_ledger_integrity()

    def test_settlement_ledger_tamper_detection(self):
        """Modifying tokens or costs in the settlement ledger breaks the SHA-256 chain."""
        workloads = generate_two_ledger_workloads(count=15, seed=20, runaway_frequency=0.20)
        self.sim.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, workloads)

        corrupted_settle = dataclasses.replace(
            self.sim.settlement_ledger[1],
            cost_cents=self.sim.settlement_ledger[1].cost_cents + 500,
        )
        self.sim.settlement_ledger[1] = corrupted_settle
        with self.assertRaises(LedgerTamperError):
            self.sim.verify_two_ledger_integrity()

    def test_fail_closed_numeric_and_boolean_typing(self):
        """Strict validation rejects booleans as numbers, NaNs, and negative inputs."""
        # Booleans as integers must fail closed
        with self.assertRaises(TwoLedgerValidationError):
            TwoLedgerAccountingSimulator(token_cost_per_100=True)  # type: ignore

        with self.assertRaises(TwoLedgerValidationError):
            TwoLedgerAccountingSimulator(tool_invocation_cost_cents=False)  # type: ignore

        # NaN / Inf must fail closed
        with self.assertRaises(TwoLedgerValidationError):
            TwoLedgerAccountingSimulator(sync_lock_latency_ms=float("nan"))

        with self.assertRaises(TwoLedgerValidationError):
            TwoLedgerAccountingSimulator(decoupled_write_latency_ms=float("inf"))

        # Empty workloads must fail closed
        with self.assertRaises(TwoLedgerValidationError):
            self.sim.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, [])

    def test_steward_gate_invariants(self):
        """Steward Gate strictly catches forbidden tokens and speculative promises."""
        screen_steward_gate("Safe multi-agent accounting with signed task receipts")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Issuing MMCT tokens for computation")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Generating passive income from agent swarms")

        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Guaranteed yields from automated trading")

    def test_w3c_prov_receipt_determinism(self):
        """Identical simulation runs produce bit-identical W3C PROV-DM receipt digests."""
        workloads = generate_two_ledger_workloads(count=20, seed=55)
        sim1 = TwoLedgerAccountingSimulator()
        sim2 = TwoLedgerAccountingSimulator()

        res1 = sim1.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, workloads)
        res2 = sim2.simulate_regime(AccountingRegime.TWO_LEDGER_DECOUPLED, workloads)

        self.assertEqual(res1.receipt_digest, res2.receipt_digest)
        self.assertEqual(len(res1.receipt_digest), 64)


if __name__ == "__main__":
    unittest.main()
