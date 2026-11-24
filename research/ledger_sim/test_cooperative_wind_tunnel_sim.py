"""
research/ledger_sim/test_cooperative_wind_tunnel_sim.py

Comprehensive unit test suite for the Multi-Agent Cooperative Wind-Tunnel
Stress-Testing Simulation Suite (`cooperative_wind_tunnel_sim.py`).
"""

from __future__ import annotations

import dataclasses
import math
import unittest

from research.ledger_sim.cooperative_wind_tunnel_sim import (
    CooperativeWindTunnelRegime,
    ExecutionReceipt,
    FailureBoundaryBreachedError,
    MICRO_SCALE,
    RegimeConfig,
    StewardGateViolationError,
    WindTunnelValidationError,
    default_config_for_regime,
    generate_wind_tunnel_workload,
    run_cooperative_wind_tunnel_benchmark,
    screen_steward_gate,
    simulate_wind_tunnel_regime,
    verify_kill_criteria,
)


class TestCooperativeWindTunnelSim(unittest.TestCase):
    """Verify invariants, fail-closed validation, capital conservation, and specification bounds."""

    def test_01_capital_conservation_across_all_regimes(self) -> None:
        """Every regime must conserve capital: total fines == bounties + commons reserve."""
        workload = generate_wind_tunnel_workload(ticks=100, agent_count=60, seed=123)
        for regime in CooperativeWindTunnelRegime:
            res = simulate_wind_tunnel_regime(regime, workload)
            self.assertTrue(res.capital_conserved, f"Capital leak in regime {regime.value}")
            self.assertEqual(
                res.total_fines_confiscated_micro,
                res.total_bounties_paid_micro + res.commons_reserve_addition_micro,
                f"Financial flow mismatch in {regime.value}",
            )

    def test_02_strict_rng_decoupling_and_workload_determinism(self) -> None:
        """Workload generation must be bit-identical across runs with identical seed."""
        w1 = generate_wind_tunnel_workload(ticks=50, agent_count=60, seed=42)
        w2 = generate_wind_tunnel_workload(ticks=50, agent_count=60, seed=42)
        w3 = generate_wind_tunnel_workload(ticks=50, agent_count=60, seed=99)

        self.assertEqual(len(w1.ticks), 50)
        for t1, t2 in zip(w1.ticks, w2.ticks):
            self.assertEqual(t1.demand_intercept, t2.demand_intercept)
            self.assertEqual(t1.marginal_cost, t2.marginal_cost)
            self.assertEqual(t1.cartel_formation_draw, t2.cartel_formation_draw)

        # Different seed produces different shocks
        self.assertNotEqual(w1.ticks[0].demand_intercept, w3.ticks[0].demand_intercept)

    def test_03_fail_closed_numeric_and_type_validation(self) -> None:
        """Booleans as numbers, NaN, Inf, and negative inputs must fail closed."""
        workload = generate_wind_tunnel_workload(ticks=20, agent_count=60, seed=10)

        # Booleans rejected for agent_count
        with self.assertRaises(WindTunnelValidationError):
            generate_wind_tunnel_workload(ticks=20, agent_count=True, seed=10)  # type: ignore

        # Negative ticks rejected
        with self.assertRaises(WindTunnelValidationError):
            generate_wind_tunnel_workload(ticks=-10, agent_count=60, seed=10)

        # NaN/Inf rejected
        cfg = default_config_for_regime(CooperativeWindTunnelRegime.FULL_DEFENSE)
        with self.assertRaises(WindTunnelValidationError):
            RegimeConfig(
                regime=CooperativeWindTunnelRegime.FULL_DEFENSE,
                agent_count=60,
                channel=cfg.channel,
                border_opacity_tau=float("nan"),
                whistleblower_bounty_credits=6,
                whistleblower_bounty_micro=6 * MICRO_SCALE,
                has_governance_graph=True,
                has_whistleblower_leniency=True,
                has_physical_energy_audit=True,
            )

        with self.assertRaises(WindTunnelValidationError):
            RegimeConfig(
                regime=CooperativeWindTunnelRegime.FULL_DEFENSE,
                agent_count=60,
                channel=cfg.channel,
                border_opacity_tau=1.5,  # Rate > 1.0
                whistleblower_bounty_credits=6,
                whistleblower_bounty_micro=6 * MICRO_SCALE,
                has_governance_graph=True,
                has_whistleblower_leniency=True,
                has_physical_energy_audit=True,
            )

    def test_04_steward_gate_invariants(self) -> None:
        """Forbidden tokens, speculative promises, and sci-fi lore must raise StewardGateViolationError."""
        clean_text = "Standard cooperative market clearing with 6 credits bounty."
        screen_steward_gate(clean_text)  # Should not raise

        forbidden_samples = [
            "Users receive 100 Contribution Tokens upon entry",
            "Holders receive MMCT reward distribution",
            "Guaranteed returns on automated factory capacity",
            "This mechanism generates passive income for buyers",
            "Achieve 95% savings on all trades",
        ]
        for sample in forbidden_samples:
            with self.assertRaises(StewardGateViolationError):
                screen_steward_gate(sample)

    def test_05_four_regimes_benchmark_satisfies_specification_matrix(self) -> None:
        """The four regimes must satisfy the expected collusion and efficiency ranges from the spec."""
        results = run_cooperative_wind_tunnel_benchmark(seed=42, ticks=100, agent_count=60)

        # Regime 1: UNCONSTRAINED
        r1 = results[CooperativeWindTunnelRegime.UNCONSTRAINED]
        self.assertGreaterEqual(r1.mean_collusion_rate, 0.65)
        self.assertLessEqual(r1.mean_collusion_rate, 0.85)
        self.assertLess(r1.mean_welfare_efficiency, 0.40)
        self.assertGreater(r1.mean_welfare_regret, 0.60)

        # Regime 2: PROMPT_GOVERNED
        r2 = results[CooperativeWindTunnelRegime.PROMPT_GOVERNED]
        self.assertGreaterEqual(r2.mean_collusion_rate, 0.45)
        self.assertLessEqual(r2.mean_collusion_rate, 0.55)
        self.assertGreaterEqual(r2.mean_welfare_efficiency, 0.55)
        self.assertLessEqual(r2.mean_welfare_efficiency, 0.67)

        # Regime 3: GOVERNANCE_GRAPH
        r3 = results[CooperativeWindTunnelRegime.GOVERNANCE_GRAPH]
        self.assertGreaterEqual(r3.mean_collusion_rate, 0.05)
        self.assertLessEqual(r3.mean_collusion_rate, 0.10)
        self.assertGreaterEqual(r3.mean_welfare_efficiency, 0.88)
        self.assertLessEqual(r3.mean_welfare_efficiency, 0.95)

        # Regime 4: FULL_DEFENSE
        r4 = results[CooperativeWindTunnelRegime.FULL_DEFENSE]
        self.assertLess(r4.mean_collusion_rate, 0.01)
        self.assertGreater(r4.mean_welfare_efficiency, 0.95)
        self.assertLess(r4.mean_false_accusation_frequency, 0.02)
        self.assertLessEqual(r4.mean_whistleblower_latency, 2.0)

    def test_06_kill_criteria_and_failure_boundaries(self) -> None:
        """Breaching any kill criterion must raise FailureBoundaryBreachedError."""
        results = run_cooperative_wind_tunnel_benchmark(seed=42, ticks=100, agent_count=60)
        # Compliant results must pass verification
        verify_kill_criteria(results)

        # Tamper results to simulate kill criterion breach (false accusation > 2%)
        tampered_r4 = results[CooperativeWindTunnelRegime.FULL_DEFENSE]
        breached_r4 = dataclasses.replace(tampered_r4, mean_false_accusation_frequency=0.035)
        bad_results = dict(results)
        bad_results[CooperativeWindTunnelRegime.FULL_DEFENSE] = breached_r4

        with self.assertRaises(FailureBoundaryBreachedError):
            verify_kill_criteria(bad_results)

    def test_07_cryptographic_receipt_integrity(self) -> None:
        """Execution receipts produce deterministic SHA-256 digests and detect tampered quotes."""
        r1 = ExecutionReceipt.create(
            tick_id=1,
            seller_id="agent-01",
            buyer_id="agent-02",
            price_quoted=10.5,
            reservation_cap=11.0,
            units_transacted=5.0,
            state_valid=True,
        )
        r2 = ExecutionReceipt.create(
            tick_id=1,
            seller_id="agent-01",
            buyer_id="agent-02",
            price_quoted=10.5,
            reservation_cap=11.0,
            units_transacted=5.0,
            state_valid=True,
        )
        self.assertEqual(r1.receipt_id, r2.receipt_id)
        self.assertEqual(r1.payload_digest, r2.payload_digest)

        # Different price produces different digest
        r3 = ExecutionReceipt.create(
            tick_id=1,
            seller_id="agent-01",
            buyer_id="agent-02",
            price_quoted=12.0,
            reservation_cap=11.0,
            units_transacted=5.0,
            state_valid=False,
        )
        self.assertNotEqual(r1.payload_digest, r3.payload_digest)


if __name__ == "__main__":
    unittest.main()
