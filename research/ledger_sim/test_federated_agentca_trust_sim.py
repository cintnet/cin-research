"""
Unit tests for research/ledger_sim/federated_agentca_trust_sim.py.

Verifies:
1. Pre-sampled workload generation and zero RNG phase drift (`rng_phase_drift == 0.0`)
   across UNVERIFIED_DIRECT_TRUST, CENTRALIZED_ROOT_MONOPOLY, and POLYCENTRIC_PEER_AGENTCA.
2. Strict integer-cent capital conservation (`capital_conservation_delta_cents == 0`).
3. Empirical calibration to Nguyen & Husain (arXiv:2611.23202, Nov 2026):
   8 organizations, 6 frameworks, 5-agent teams, ~43% baseline vs ~84% AgentCA
   attack containment at 174 microseconds overhead without a shared root authority.
4. Fail-closed boolean, NaN, out-of-range, and Steward Gate validation.
"""

from __future__ import annotations

import math
import unittest

import research.ledger_sim.federated_agentca_trust_sim as sim


class TestFederatedAgentCATrustSim(unittest.TestCase):
    def test_three_regime_comparison_conservation_and_zero_rng_drift(self) -> None:
        cfg = sim.FederationSimConfig(num_orgs=8, num_frameworks=6, agents_per_org=5, num_requests=300, seed=42)
        report = sim.run_three_regime_comparison(cfg)

        self.assertEqual(report["rng_phase_drift"], 0.0)
        self.assertEqual(report["capital_conservation_delta_cents"], 0)

        unverified = report["regimes"]["UNVERIFIED_DIRECT_TRUST"]
        central_root = report["regimes"]["CENTRALIZED_ROOT_MONOPOLY"]
        agentca = report["regimes"]["POLYCENTRIC_PEER_AGENTCA"]

        for reg_data in (unverified, central_root, agentca):
            self.assertEqual(reg_data["capital_conservation_delta_cents"], 0)
            self.assertEqual(reg_data["initial_total_capital_cents"], reg_data["final_total_capital_cents"])

        # AgentCA achieves higher containment than unverified baseline and zero outage drops
        self.assertGreater(agentca["attack_containment_rate"], unverified["attack_containment_rate"])
        self.assertGreaterEqual(agentca["attack_containment_rate"], 0.78)
        self.assertEqual(agentca["benign_dropped_outage"], 0)
        self.assertGreater(central_root["benign_dropped_outage"], 0)
        self.assertEqual(agentca["total_root_tolls_paid_cents"], 0)
        self.assertGreater(central_root["total_root_tolls_paid_cents"], 0)
        self.assertEqual(agentca["mean_verify_overhead_us"], 174.0)

        # Net federation surplus is highest under polycentric peer AgentCA
        self.assertGreater(agentca["net_federation_surplus_cents"], central_root["net_federation_surplus_cents"])
        self.assertGreater(agentca["net_federation_surplus_cents"], unverified["net_federation_surplus_cents"])

    def test_multi_seed_stability_and_conservation(self) -> None:
        for seed in (7, 19, 101, 2026):
            cfg = sim.FederationSimConfig(num_requests=200, seed=seed)
            report = sim.run_three_regime_comparison(cfg)
            self.assertEqual(report["rng_phase_drift"], 0.0)
            self.assertEqual(report["capital_conservation_delta_cents"], 0)

    def test_fail_closed_validation_guards(self) -> None:
        # Boolean rejected where int required
        with self.assertRaises(sim.AgentCAValidationError):
            sim.FederationSimConfig(num_orgs=True)  # type: ignore[arg-type]
        with self.assertRaises(sim.AgentCAValidationError):
            sim.FederationSimConfig(task_bond_cents=False)  # type: ignore[arg-type]

        # NaN and out-of-range rates rejected
        with self.assertRaises(sim.AgentCAValidationError):
            sim.FederationSimConfig(attack_fraction=math.nan)
        with self.assertRaises(sim.AgentCAValidationError):
            sim.FederationSimConfig(agentca_containment_rate=1.2)
        with self.assertRaises(sim.AgentCAValidationError):
            sim.FederationSimConfig(baseline_containment_rate=-0.1)

        # Population bounds
        with self.assertRaises(sim.AgentCAValidationError):
            sim.FederationSimConfig(num_orgs=4, num_frameworks=6)

        # Unknown regime rejected
        cfg = sim.FederationSimConfig()
        with self.assertRaises(sim.AgentCAValidationError):
            sim.evaluate_federation_regime(cfg, "UNKNOWN_REGIME")

    def test_steward_gate_screening(self) -> None:
        with self.assertRaises(sim.StewardGateViolationError):
            sim.screen_steward_gate("Earn guaranteed returns with Contribution Tokens")
        with self.assertRaises(sim.StewardGateViolationError):
            sim.screen_steward_gate("Mint MMCT on the galactic ledger")

    def test_cli_entrypoint(self) -> None:
        rc = sim.main(["--simulate", "--requests", "60", "--seed", "42"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
