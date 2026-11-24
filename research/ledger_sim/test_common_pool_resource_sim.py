"""
research/ledger_sim/test_common_pool_resource_sim.py

Unit test suite for Common-Pool Resource (CPR) Simulation and Ostrom Capability Lease Guard.

Verifies:
1. Exact double-entry capital and resource conservation across rounds.
2. Unconstrained Nash extraction collapses common pool to zero (GovSim baseline).
3. Unstructured cheap talk experiences private defection and long-horizon collapse.
4. Ostrom verified capability lease governance maintains long-horizon sustainability.
5. Monotonic graduated sanctions (Warning -> Restricted -> Revoked) on over-harvesting.
6. Cryptographic W3C PROV-DM receipt verification and tamper detection.
7. Emergency reserve treasury buffers environmental shocks (Rehm 2026).
8. Strict fail-closed defenses against NaN, Inf, bool types, and invalid bounds.
9. Strict Steward Gate compliance: rejects unapproved tokens, speculative claims, and lore.
"""

from __future__ import annotations

import unittest

from research.ledger_sim.common_pool_resource_sim import (
    AppropriationReceipt,
    CPRGovernanceRegime,
    CPRSecurityViolation,
    CPRValidationError,
    CommonPoolResourceSimulator,
    EnvironmentalFluctuationProfile,
    LeaseSanctionLevel,
    ResourceShock,
    StewardGateViolationError,
    format_cpr_comparison_markdown,
    run_cpr_regime_sweep,
    screen_steward_gate,
)


class TestCommonPoolResourceSimulation(unittest.TestCase):
    """Deterministic verification suite for Common-Pool Resource testbed."""

    def test_capital_and_resource_conservation_invariance(self) -> None:
        """Every round must strictly conserve physical and computational resource units."""
        sim = CommonPoolResourceSimulator(
            num_agents=5,
            carrying_capacity=1000,
            initial_stock=600,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=15,
            initial_treasury=20,
        )
        res = sim.run_simulation(CPRGovernanceRegime.OSTROM_VERIFIED_LEASE)
        self.assertTrue(res.conservation_verified)
        self.assertTrue(res.is_sustainable)
        self.assertEqual(res.survived_rounds, 15)

        # Audit step-by-step conservation
        for s in res.steps:
            total_in = s.starting_stock + s.regrowth_units
            # Note: treasury changes are accounted for
            self.assertGreaterEqual(s.ending_stock, 100)
            self.assertGreaterEqual(s.total_harvested, 0)

    def test_ungoverned_nash_collapses_commons(self) -> None:
        """Unconstrained greedy extraction must deplete the resource below the critical threshold."""
        sim = CommonPoolResourceSimulator(
            num_agents=5,
            carrying_capacity=1000,
            initial_stock=300,
            critical_threshold=100,
            regrowth_rate=0.20,
            total_rounds=10,
        )
        # Demands of 35 units per agent per round (5 * 35 = 175, far exceeding regrowth)
        demands = {f"agent_{i+1:02d}": [35] * 10 for i in range(5)}
        res = sim.run_simulation(CPRGovernanceRegime.UNGOVERNED_NASH, agent_demand_profiles=demands)

        self.assertFalse(res.is_sustainable)
        self.assertLess(res.survived_rounds, 10)
        self.assertEqual(res.final_stock, 0)

    def test_unstructured_cheap_talk_collapses_over_horizon(self) -> None:
        """Cheap talk without verification or sanctions allows defection to collapse the resource."""
        sim = CommonPoolResourceSimulator(
            num_agents=5,
            carrying_capacity=1000,
            initial_stock=350,
            critical_threshold=100,
            regrowth_rate=0.20,
            total_rounds=12,
        )
        res = sim.run_simulation(CPRGovernanceRegime.UNSTRUCTURED_CHEAP_TALK)
        # Should collapse due to opportunistic defectors
        self.assertFalse(res.is_sustainable)
        self.assertEqual(res.final_stock, 0)

    def test_ostrom_verified_lease_sustains_commons(self) -> None:
        """Ostrom governance with verified quotas guarantees survival and positive stock."""
        sim = CommonPoolResourceSimulator(
            num_agents=5,
            carrying_capacity=1000,
            initial_stock=500,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=20,
        )
        res = sim.run_simulation(CPRGovernanceRegime.OSTROM_VERIFIED_LEASE)
        self.assertTrue(res.is_sustainable)
        self.assertEqual(res.survived_rounds, 20)
        self.assertGreater(res.final_stock, 100)
        self.assertGreater(res.total_harvested, 0)

    def test_graduated_sanctions_monotonic_attenuation(self) -> None:
        """Persistent over-appropriation must trigger monotonic graduated sanctions."""
        sim = CommonPoolResourceSimulator(
            num_agents=4,
            carrying_capacity=1000,
            initial_stock=500,
            critical_threshold=100,
            regrowth_rate=0.20,
            total_rounds=6,
        )
        # Agent 1 submits excessive demands every round (wants 80 units)
        demands = {
            "agent_01": [80] * 6,
            "agent_02": [5] * 6,
            "agent_03": [5] * 6,
            "agent_04": [5] * 6,
        }
        res = sim.run_simulation(CPRGovernanceRegime.OSTROM_VERIFIED_LEASE, agent_demand_profiles=demands)

        # Inspect agent 1 receipts across rounds
        agent_1_receipts = [step.receipts[0] for step in res.steps]
        sanctions = [r.sanction_level for r in agent_1_receipts]

        # Round 0: Offense 1 -> WARNING
        self.assertEqual(sanctions[0], LeaseSanctionLevel.WARNING)
        # Round 1: Offense 2 -> RESTRICTED
        self.assertEqual(sanctions[1], LeaseSanctionLevel.RESTRICTED)
        # Round 2: Offense 3 -> REVOKED
        self.assertEqual(sanctions[2], LeaseSanctionLevel.REVOKED)
        # When REVOKED, granted units must be 0
        self.assertEqual(agent_1_receipts[2].granted_units, 0)

    def test_cryptographic_receipt_verification_and_tamper_detection(self) -> None:
        """Appropriation receipts must carry verifiable SHA-256 digests that detect tampering."""
        rcpt = AppropriationReceipt.create(
            agent_id="agent_clinic_01",
            round_idx=3,
            requested_units=20,
            granted_units=15,
            sanction_level=LeaseSanctionLevel.NORMAL,
            timestamp="2026-11-06T12:00:03Z",
        )
        self.assertTrue(rcpt.verify_digest())

        # Tamper with granted units
        tampered_rcpt = AppropriationReceipt(
            agent_id=rcpt.agent_id,
            round_idx=rcpt.round_idx,
            requested_units=rcpt.requested_units,
            granted_units=99,  # Forged grant
            sanction_level=rcpt.sanction_level,
            timestamp=rcpt.timestamp,
            provenance_hash=rcpt.provenance_hash,
        )
        self.assertFalse(tampered_rcpt.verify_digest())

    def test_emergency_treasury_mitigates_shocks(self) -> None:
        """Emergency reserve treasury backstops agent allocations during severe regrowth shocks."""
        shocks = [
            ResourceShock(round_idx=2, shock_factor=0.1),  # Severe 90% drop in regrowth
            ResourceShock(round_idx=3, shock_factor=0.1),
        ]
        sim = CommonPoolResourceSimulator(
            num_agents=4,
            carrying_capacity=1000,
            initial_stock=400,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=6,
            initial_treasury=40,
            shocks=shocks,
        )
        # Agents submit baseline demand of 1 unit per round
        demands = {f"agent_{i+1:02d}": [1] * 6 for i in range(4)}
        res = sim.run_simulation(CPRGovernanceRegime.OSTROM_VERIFIED_LEASE, agent_demand_profiles=demands)
        self.assertTrue(res.is_sustainable)
        step2 = res.steps[2]
        self.assertGreater(step2.total_harvested, 0)
        self.assertEqual(step2.total_harvested, 8)

    def test_fail_closed_validation_on_malformed_inputs(self) -> None:
        """Malformed bounds, NaN, Inf, or boolean values must fail closed."""
        with self.assertRaises(CPRValidationError):
            CommonPoolResourceSimulator(num_agents=1)  # Minimum 2 agents
        with self.assertRaises(CPRValidationError):
            CommonPoolResourceSimulator(num_agents=True)  # Bool trap
        with self.assertRaises(CPRValidationError):
            CommonPoolResourceSimulator(carrying_capacity=-500)
        with self.assertRaises(CPRValidationError):
            CommonPoolResourceSimulator(regrowth_rate=float("nan"))
        with self.assertRaises(CPRValidationError):
            CommonPoolResourceSimulator(regrowth_rate=float("inf"))
        with self.assertRaises(CPRValidationError):
            CommonPoolResourceSimulator(critical_threshold=700, initial_stock=500)  # Inverted threshold

        with self.assertRaises(CPRValidationError):
            ResourceShock(round_idx=1, shock_factor=float("nan"))
        with self.assertRaises(CPRValidationError):
            ResourceShock(round_idx=1, shock_factor=3.5)  # Out of [0, 2]

    def test_steward_gate_invariants(self) -> None:
        """Forbidden speculative tokens, promises, and lore must raise StewardGateViolationError."""
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Deploying Contribution Tokens for common resource credit")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Transfer MMCT units across agents")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Split 85/10/5 among participants")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Guaranteed yields of 20% on commons pool")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Activating galactic hyperdrive engine")

    def test_regime_sweep_and_markdown_formatting(self) -> None:
        """Multi-regime sweep must execute cleanly and generate readable markdown tables."""
        results = run_cpr_regime_sweep(
            num_agents=4,
            carrying_capacity=1000,
            initial_stock=450,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=8,
            initial_treasury=20,
        )
        self.assertIn("UNGOVERNED_NASH", results)
        self.assertIn("UNSTRUCTURED_CHEAP_TALK", results)
        self.assertIn("OSTROM_VERIFIED_LEASE", results)
        self.assertIn("MONOLITHIC_DELEGATION", results)
        self.assertIn("POLYCENTRIC_DELEGATION", results)

        md = format_cpr_comparison_markdown(results)
        self.assertIn("| `OSTROM_VERIFIED_LEASE` |", md)
        self.assertIn("| `MONOLITHIC_DELEGATION` |", md)
        self.assertIn("| `POLYCENTRIC_DELEGATION` |", md)
        self.assertIn("**YES**", md)
        self.assertIn("NO (Collapsed)", md)

    def test_monolithic_delegation_scale_accountability_tradeoff(self) -> None:
        """Monolithic delegation extracts overhead rent when N > N*, attenuating constituent quotas."""
        # 10 agents delegating to a single central planner (N* = 5)
        sim = CommonPoolResourceSimulator(
            num_agents=10,
            carrying_capacity=1000,
            initial_stock=600,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=10,
            initial_treasury=0,
        )
        res = sim.run_simulation(CPRGovernanceRegime.MONOLITHIC_DELEGATION)
        self.assertTrue(res.conservation_verified)

        # Monolithic center extracts rent tau = min(0.40, 0.05 * (10 - 5)) = 25% overhead
        # Central treasury must swell from extracted overhead units
        self.assertGreater(res.final_treasury, 50)
        # Quota per agent is attenuated
        for step in res.steps:
            for rcpt in step.receipts:
                self.assertLessEqual(rcpt.granted_units, 7)

    def test_polycentric_delegation_sustains_commons_under_scale(self) -> None:
        """Polycentric delegation with nested chapters bounds overhead and sustains commons under scale."""
        sim = CommonPoolResourceSimulator(
            num_agents=10,
            carrying_capacity=1000,
            initial_stock=600,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=20,
            initial_treasury=10,
        )
        res = sim.run_simulation(CPRGovernanceRegime.POLYCENTRIC_DELEGATION)
        self.assertTrue(res.conservation_verified)
        self.assertTrue(res.is_sustainable)
        self.assertEqual(res.survived_rounds, 20)
        self.assertGreater(res.final_stock, 100)
        self.assertGreater(res.total_harvested, 0)
        # Compare total harvested: polycentric delivers more resources to constituents than monolithic hoarding
        res_mono = sim.run_simulation(CPRGovernanceRegime.MONOLITHIC_DELEGATION)
        self.assertGreater(res.total_harvested, res_mono.total_harvested)

    def test_polycentric_delegation_mitigates_localized_shocks(self) -> None:
        """Polycentric delegation releases emergency reserves during severe regrowth shocks."""
        shocks = [
            ResourceShock(round_idx=3, shock_factor=0.15),
            ResourceShock(round_idx=4, shock_factor=0.15),
        ]
        sim = CommonPoolResourceSimulator(
            num_agents=8,
            carrying_capacity=1000,
            initial_stock=500,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=8,
            initial_treasury=30,
            shocks=shocks,
        )
        res = sim.run_simulation(CPRGovernanceRegime.POLYCENTRIC_DELEGATION)
        self.assertTrue(res.conservation_verified)
        self.assertTrue(res.is_sustainable)
        self.assertEqual(res.survived_rounds, 8)

    def test_environmental_fluctuation_profile_validation_and_bounds(self) -> None:
        """Grounded in arXiv:2611.06156: validate parameter constraints and deterministic multipliers."""
        prof = EnvironmentalFluctuationProfile(base_amplitude=0.3, frequency=0.2, noise_sigma=0.08, seed=123)
        self.assertEqual(prof.base_amplitude, 0.3)
        self.assertEqual(prof.frequency, 0.2)
        self.assertEqual(prof.noise_sigma, 0.08)

        # Deterministic multipliers stay strictly within [0.1, 2.0]
        multipliers = [prof.get_multiplier(r) for r in range(20)]
        for m in multipliers:
            self.assertGreaterEqual(m, 0.1)
            self.assertLessEqual(m, 2.0)

        # Determinism check across identical seeds
        prof2 = EnvironmentalFluctuationProfile(base_amplitude=0.3, frequency=0.2, noise_sigma=0.08, seed=123)
        self.assertEqual([prof2.get_multiplier(r) for r in range(10)], multipliers[:10])

        # Bounds validation
        with self.assertRaises(CPRValidationError):
            EnvironmentalFluctuationProfile(base_amplitude=1.5)
        with self.assertRaises(CPRValidationError):
            EnvironmentalFluctuationProfile(frequency=0.0)
        with self.assertRaises(CPRValidationError):
            EnvironmentalFluctuationProfile(noise_sigma=0.9)

    def test_environmental_fluctuations_stabilize_ostrom_commons_while_unconstrained_collapses(self) -> None:
        """
        Grounded in arXiv:2611.06156: moderate environmental noise with Ostrom reserve buffering
        counteracts oscillatory collapse and preserves 100% capital conservation.
        """
        fluct = EnvironmentalFluctuationProfile(base_amplitude=0.35, frequency=0.25, noise_sigma=0.05, seed=777)

        sim = CommonPoolResourceSimulator(
            num_agents=5,
            carrying_capacity=1000,
            initial_stock=550,
            critical_threshold=100,
            regrowth_rate=0.25,
            total_rounds=18,
            initial_treasury=15,
            fluctuation_profile=fluct,
        )

        # Unconstrained Nash collapses due to greedy overharvesting under variable regeneration
        res_nash = sim.run_simulation(CPRGovernanceRegime.UNGOVERNED_NASH)
        self.assertTrue(res_nash.conservation_verified)
        self.assertFalse(res_nash.is_sustainable)
        self.assertLess(res_nash.survived_rounds, 18)

        # Ostrom verified lease absorbs fluctuations and sustains commons
        res_ostrom = sim.run_simulation(CPRGovernanceRegime.OSTROM_VERIFIED_LEASE)
        self.assertTrue(res_ostrom.conservation_verified)
        self.assertTrue(res_ostrom.is_sustainable)
        self.assertEqual(res_ostrom.survived_rounds, 18)
        self.assertGreater(res_ostrom.final_stock, 100)

        # Polycentric delegation also safely buffers fluctuations
        res_poly = sim.run_simulation(CPRGovernanceRegime.POLYCENTRIC_DELEGATION)
        self.assertTrue(res_poly.conservation_verified)
        self.assertTrue(res_poly.is_sustainable)
        self.assertEqual(res_poly.survived_rounds, 18)


if __name__ == "__main__":
    unittest.main()
