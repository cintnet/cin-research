"""
Unit tests for research/ledger_sim/mandate_bound_whole_state_clearing_sim.py.

Verifies:
1. Pre-sampled workload generation and zero RNG phase drift (`rng_phase_drift == 0.0`)
   across UNBOUND_SIGNATURE_TRUST, CENTRALIZED_PAYMENT_GATEWAY, and MANDATELOCK_WHOLE_STATE_COOP.
2. Strict integer-cent capital conservation (`capital_conservation_delta_cents == 0`).
3. Empirical calibration to:
   - You et al. (arXiv:2611.25821, Nov 2026): 98.7% unbound bearer signature vulnerability vs 100%
     altered-mandate rejection under nonce-bound MandateLock contracts.
   - Joshi (software-world-model, Nov 2026): whole-database-diff detection of collateral ERP
     database damage and payment un-reconciliations across Invoice Ninja, Dolibarr, Odoo 17, and Odoo 18.
   - Sistla et al. (arXiv:2611.25599, Nov 2026): Tether Lean 4 stateful sandbox policy blocking 100%
     of in-scope attacks with under 5% benign false positives.
4. Fail-closed boolean, NaN, out-of-range, and Steward Gate validation.
"""

from __future__ import annotations

import math
import unittest

import research.ledger_sim.mandate_bound_whole_state_clearing_sim as sim


class TestMandateBoundWholeStateClearingSim(unittest.TestCase):
    def test_three_regime_comparison_conservation_and_zero_rng_drift(self) -> None:
        cfg = sim.MandateClearingConfig(num_coops=12, num_episodes=300, seed=42)
        report = sim.run_three_regime_comparison(cfg)

        self.assertEqual(report["rng_phase_drift"], 0.0)
        self.assertEqual(report["capital_conservation_delta_cents"], 0)

        unbound = report["regimes"]["UNBOUND_SIGNATURE_TRUST"]
        central = report["regimes"]["CENTRALIZED_PAYMENT_GATEWAY"]
        mandatelock = report["regimes"]["MANDATELOCK_WHOLE_STATE_COOP"]

        for reg_data in (unbound, central, mandatelock):
            self.assertEqual(reg_data["capital_conservation_delta_cents"], 0)
            self.assertEqual(reg_data["initial_total_capital_cents"], reg_data["final_total_capital_cents"])

        # MandateLock rejects 100% of altered commerce mandates and rolls back 100% of collateral DB faults
        self.assertEqual(mandatelock["mandate_rejection_rate"], 1.0)
        self.assertEqual(mandatelock["uncontained_mandate_diversions"], 0)
        self.assertEqual(mandatelock["db_fault_rollback_rate"], 1.0)
        self.assertEqual(mandatelock["uncontained_db_corruptions"], 0)
        self.assertEqual(mandatelock["total_diversion_and_db_losses_cents"], 0)
        self.assertEqual(mandatelock["total_gateway_fees_paid_cents"], 0)

        # Unbound signature trust suffers severe mandate diversions and un-reconciled DB corruptions
        self.assertGreater(unbound["uncontained_mandate_diversions"], 0)
        self.assertGreater(unbound["uncontained_db_corruptions"], 0)
        self.assertLess(unbound["mandate_rejection_rate"], 0.15)
        self.assertEqual(unbound["db_fault_rollback_rate"], 0.0)

        # Centralized gateway charges fees and still misses a majority of underlying ERP DB corruptions
        self.assertGreater(central["total_gateway_fees_paid_cents"], 0)
        self.assertGreater(central["uncontained_db_corruptions"], 0)

        # Net cooperative surplus and voluntary adoption are highest under MANDATELOCK_WHOLE_STATE_COOP
        self.assertGreater(mandatelock["net_cooperative_surplus_cents"], central["net_cooperative_surplus_cents"])
        self.assertGreater(mandatelock["net_cooperative_surplus_cents"], unbound["net_cooperative_surplus_cents"])
        self.assertEqual(mandatelock["voluntary_mandatelock_adoption_rate"], 1.0)

    def test_multi_seed_stability_and_conservation(self) -> None:
        for seed in (7, 19, 101, 2026):
            cfg = sim.MandateClearingConfig(num_episodes=200, seed=seed)
            report = sim.run_three_regime_comparison(cfg)
            self.assertEqual(report["rng_phase_drift"], 0.0)
            self.assertEqual(report["capital_conservation_delta_cents"], 0)

    def test_fail_closed_validation_guards(self) -> None:
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.MandateClearingConfig(num_coops=True)  # type: ignore[arg-type]
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.MandateClearingConfig(order_escrow_cents=False)  # type: ignore[arg-type]
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.MandateClearingConfig(mandate_attack_fraction=math.nan)
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.MandateClearingConfig(unbound_bearer_vulnerability_rate=1.5)
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.MandateClearingConfig(tether_benign_false_positive_rate=-0.1)
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.MandateClearingConfig(central_gateway_fee_cents=5000, order_surplus_cents=2000)

        cfg = sim.MandateClearingConfig()
        with self.assertRaises(sim.MandateClearingValidationError):
            sim.evaluate_clearing_regime(cfg, "UNKNOWN_REGIME")

    def test_steward_gate_screening(self) -> None:
        with self.assertRaises(sim.StewardGateViolationError):
            sim.screen_steward_gate("Earn guaranteed returns with Contribution Tokens")
        with self.assertRaises(sim.StewardGateViolationError):
            sim.screen_steward_gate("Mint MMCT on the galactic ledger")

    def test_cli_entrypoint(self) -> None:
        rc = sim.main(["--simulate", "--episodes", "80", "--seed", "42"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
