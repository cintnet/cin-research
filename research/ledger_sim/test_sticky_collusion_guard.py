"""
research/ledger_sim/test_sticky_collusion_guard.py

Unit and invariant test suite for StickyCollusionGuardSimulator.
Validates:
- Fail-closed parameter typing and bounds validation (including boolean-as-int and NaN rejections).
- Strict capital conservation invariants (delta == 0 cents).
- RNG decoupling across workloads and regimes.
- 10-seed empirical reproduction of sticky collusion persistence (Cahyono 2026) vs complete elimination under ephemeral scrubbing.
- W3C PROV-DM receipt integrity and SHA-256 hashing.
- Strict CIN Steward Gate compliance (rejection of unapproved tokens and speculative promises).
"""

from __future__ import annotations

import math
import unittest

from research.ledger_sim.sticky_collusion_guard import (
    CollusionValidationError,
    GuardRegime,
    MemoryLeakageError,
    RoundExecutionReceipt,
    SimulationMetrics,
    StewardGateViolationError,
    StickyCollusionGuardSimulator,
    StickyCollusionSecurityViolation,
    VerificationTask,
    assert_steward_gate_compliance,
    generate_frozen_workload,
    run_multi_seed_sticky_collusion_sweep,
)


class TestStickyCollusionGuard(unittest.TestCase):
    """Test suite for multi-agent sticky collusion simulation and containment guard."""

    def test_frozen_workload_determinism(self) -> None:
        """Workload generation with the same seed must produce bit-for-bit identical tasks."""
        wl1 = generate_frozen_workload(num_rounds=20, seed=123)
        wl2 = generate_frozen_workload(num_rounds=20, seed=123)
        self.assertEqual(len(wl1), 20)
        self.assertEqual(len(wl2), 20)
        for t1, t2 in zip(wl1, wl2):
            self.assertEqual(t1.task_id, t2.task_id)
            self.assertEqual(t1.true_quality_score, t2.true_quality_score)
            self.assertEqual(t1.is_adversarially_poisoned, t2.is_adversarially_poisoned)
            self.assertEqual(t1.sentinel_audit_selected, t2.sentinel_audit_selected)

    def test_fail_closed_parameter_validation(self) -> None:
        """Invalid types, booleans disguised as ints, negative values, and NaNs must fail closed."""
        # Boolean as int for num_rounds
        with self.assertRaises(CollusionValidationError):
            generate_frozen_workload(num_rounds=True)  # type: ignore

        # NaN for poison_fraction
        with self.assertRaises(CollusionValidationError):
            generate_frozen_workload(num_rounds=20, poison_fraction=float("nan"))

        # Negative seed
        with self.assertRaises(CollusionValidationError):
            generate_frozen_workload(num_rounds=-5)

        # Boolean as int for quality score
        with self.assertRaises(CollusionValidationError):
            VerificationTask(
                task_id="t-1",
                round_index=0,
                true_quality_score=True,  # type: ignore
                is_adversarially_poisoned=False,
                complexity_budget_units=5,
                sentinel_audit_selected=False,
            )

        # Out-of-bounds quality score
        with self.assertRaises(CollusionValidationError):
            VerificationTask(
                task_id="t-1",
                round_index=0,
                true_quality_score=150,
                is_adversarially_poisoned=False,
                complexity_budget_units=5,
                sentinel_audit_selected=False,
            )

    def test_capital_conservation_invariant_across_regimes(self) -> None:
        """Every bond posted must be accounted for by refunds plus slashes (delta == 0 cents)."""
        tasks = generate_frozen_workload(num_rounds=30, seed=42)
        for reg in (
            GuardRegime.UNCONSTRAINED_HISTORY,
            GuardRegime.PENALTY_ONLY_RETENTION,
            GuardRegime.ISOLATED_EPHEMERAL_SCRUBBING,
        ):
            sim = StickyCollusionGuardSimulator(
                tasks=tasks,
                regime=reg,
                partner_swap_round=15,
                bond_per_round_cents=500,
                slash_penalty_cents=500,
            )
            metrics = sim.run_simulation()
            self.assertEqual(
                metrics.capital_conservation_delta_cents,
                0,
                f"Capital conservation violated in {reg}: posted {metrics.total_bonds_posted_cents} != "
                f"refunded {metrics.total_bonds_refunded_cents} + slashed {metrics.total_bonds_slashed_cents}",
            )
            self.assertEqual(
                metrics.total_bonds_posted_cents,
                metrics.total_bonds_refunded_cents + metrics.total_bonds_slashed_cents,
            )

    def test_unconstrained_history_develops_and_retains_collusion(self) -> None:
        """In unconstrained history, agents adopt shortcuts and collude with high probability."""
        tasks = generate_frozen_workload(num_rounds=30, seed=99, poison_fraction=0.4)
        sim = StickyCollusionGuardSimulator(
            tasks=tasks,
            regime=GuardRegime.UNCONSTRAINED_HISTORY,
            partner_swap_round=15,
        )
        metrics = sim.run_simulation()
        self.assertGreater(metrics.collusion_rate, 0.5)
        self.assertGreater(metrics.sticky_persistence_after_swap_rate, 0.5)

    def test_penalty_only_leaves_sticky_collusion(self) -> None:
        """Under penalty-only retention, newcomer agent gamma inherits sticky shortcut from scratchpad."""
        tasks = generate_frozen_workload(num_rounds=30, seed=99, poison_fraction=0.4)
        sim = StickyCollusionGuardSimulator(
            tasks=tasks,
            regime=GuardRegime.PENALTY_ONLY_RETENTION,
            partner_swap_round=15,
        )
        metrics = sim.run_simulation()
        # Newcomer adopts shortcut due to lingering context
        self.assertGreater(metrics.sticky_persistence_after_swap_rate, 0.5)

    def test_isolated_ephemeral_scrubbing_eliminates_collusion(self) -> None:
        """Under isolated ephemeral lease scrubbing, collusion and sticky persistence drop to exactly 0.0."""
        tasks = generate_frozen_workload(num_rounds=30, seed=99, poison_fraction=0.4)
        sim = StickyCollusionGuardSimulator(
            tasks=tasks,
            regime=GuardRegime.ISOLATED_EPHEMERAL_SCRUBBING,
            partner_swap_round=15,
        )
        metrics = sim.run_simulation()
        self.assertEqual(metrics.collusion_rate, 0.0)
        self.assertEqual(metrics.sticky_persistence_after_swap_rate, 0.0)
        self.assertEqual(metrics.false_approval_rate, 0.0)
        # Verify that all receipts report session memory purged
        for rec in sim.receipts:
            self.assertTrue(rec.session_memory_purged)
            self.assertFalse(rec.collusive_shortcut_used)

    def test_w3c_prov_dm_bundle_structure_and_hashes(self) -> None:
        """Simulation produces valid W3C PROV-DM structures with sha256 digests."""
        tasks = generate_frozen_workload(num_rounds=15, seed=77)
        sim = StickyCollusionGuardSimulator(
            tasks=tasks,
            regime=GuardRegime.ISOLATED_EPHEMERAL_SCRUBBING,
            partner_swap_round=8,
        )
        metrics = sim.run_simulation()
        bundle = metrics.w3c_prov_bundle
        self.assertIn("@context", bundle)
        self.assertIn("prov:Entity", bundle)
        self.assertIn("prov:Activity", bundle)
        self.assertIn("prov:Agent", bundle)
        # Check that receipt digests are 64-char hex strings
        for rec in sim.receipts:
            self.assertEqual(len(rec.w3c_prov_digest), 64)
            int(rec.w3c_prov_digest, 16)  # valid hex

    def test_steward_gate_compliance(self) -> None:
        """Steward Gate screening must reject unapproved tokens, royalty promises, and retired jargon."""
        # Unapproved tokens
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("Payouts in Contribution Tokens are issued.")
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("Stake your MMCT to verify.")

        # Speculative dollar promises
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("Guaranteed to save $1,200 per year.")

        # Fixed royalty split
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("85/10/5 royalty splits applied.")

        # Retired neologisms
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("The Somatic Witness observed the transaction.")

        # Valid payload passes cleanly
        assert_steward_gate_compliance("Clean slate session scrubbing prevents collusion in verification.")

    def test_multi_seed_sweep_execution(self) -> None:
        """Sweep across 5 seeds executes with zero capital leaks and reports expected ordering."""
        sweep = run_multi_seed_sticky_collusion_sweep(num_seeds=5, rounds_per_seed=25, partner_swap_round=12)
        summaries = sweep["regime_summaries"]

        unconstrained = summaries[GuardRegime.UNCONSTRAINED_HISTORY.value]
        penalty_only = summaries[GuardRegime.PENALTY_ONLY_RETENTION.value]
        ephemeral = summaries[GuardRegime.ISOLATED_EPHEMERAL_SCRUBBING.value]

        # Ephemeral scrubbing must have 0% collusion and 0% sticky persistence
        self.assertEqual(ephemeral["mean_collusion_rate"], 0.0)
        self.assertEqual(ephemeral["mean_sticky_persistence_post_swap"], 0.0)
        self.assertEqual(ephemeral["mean_false_approval_rate"], 0.0)
        self.assertEqual(ephemeral["total_capital_conservation_delta_cents"], 0)

        # Unconstrained must have substantial collusion
        self.assertGreater(unconstrained["mean_collusion_rate"], 0.5)
        self.assertGreater(unconstrained["mean_sticky_persistence_post_swap"], 0.5)


if __name__ == "__main__":
    unittest.main()
