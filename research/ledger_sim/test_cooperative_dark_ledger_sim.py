"""
research/ledger_sim/test_cooperative_dark_ledger_sim.py

Comprehensive unit test suite for Cooperative Economy Transition & Dark-Ledger
Cartel Containment Simulation Engine (`cooperative_dark_ledger_sim.py`).
"""

from __future__ import annotations

import math
import unittest

from research.ledger_sim.cooperative_dark_ledger_sim import (
    CooperativeSimValidationError,
    FulfillmentAttestation,
    StewardGateViolationError,
    TransitionPolicyConfig,
    TransitionRegime,
    VerificationModality,
    aggregate_sybil_resistant_fulfillment_signals,
    apply_zero_sum_credit_decay_and_clearing,
    compare_cooperative_transition_regimes,
    compute_human_root_modality_weight,
    compute_myerson_club_value,
    compute_nash_cartel_threshold,
    compute_physical_conservation_detection_prob,
    default_policy_for_regime,
    generate_dark_ledger_workloads,
    generate_transition_workloads,
    screen_steward_gate,
    simulate_cooperative_transition,
    simulate_dark_ledger_containment,
)


class TestCooperativeDarkLedgerSim(unittest.TestCase):
    """Verify conservation laws, monotonicity, Sybil invariance, and Nash thresholds."""

    def test_01_zero_sum_mutual_credit_conservation_every_step(self) -> None:
        """Mutual credit balances must sum to 0 (< 1e-9) at every step, including under decay."""
        res = simulate_cooperative_transition(
            TransitionRegime.COOPERATIVE_TRANSITION,
            steps=40,
            automation_start=0.25,
            automation_end=0.98,
            seed=101,
        )
        self.assertTrue(res.credit_zero_sum_verified)
        self.assertLess(res.max_abs_credit_sum_error, 1e-9)
        self.assertLess(abs(sum(res.final_balances)), 1e-9)
        self.assertGreater(res.cumulative_mutual_credit_volume, 0.0)
        for rec in res.step_records:
            self.assertLess(abs(rec.net_credit_balance_sum), 1e-9)

        # Direct stress test on asymmetric integer micro-credit balances under decay
        asymmetric = [450_123, 319_877, -100_000, -250_000, -420_000]
        self.assertEqual(sum(asymmetric), 0)
        after = apply_zero_sum_credit_decay_and_clearing(
            balances_micro=asymmetric,
            clearing_volume=17.345678,
            decay_rate=0.13,
            num_households=3,
            rotation_offset=2,
        )
        self.assertEqual(sum(after), 0)

    def test_02_equity_and_physical_capacity_conservation(self) -> None:
        """Private + cooperative equity shares == 1.0 and capacity == durable + waste + idle."""
        compared = compare_cooperative_transition_regimes(steps=35, seed=77)
        for regime, res in compared.items():
            self.assertTrue(res.capacity_conservation_verified, msg=f"Failed for {regime}")
            for rec in res.step_records:
                self.assertAlmostEqual(
                    rec.private_equity_share + rec.cooperative_equity_share,
                    1.0,
                    places=12,
                )
                self.assertAlmostEqual(
                    rec.total_capacity,
                    rec.fulfilled_durable_output
                    + rec.obsolescence_waste_output
                    + rec.idle_unpurchased_capacity,
                    places=9,
                )

    def test_03_monotonicity_of_meidner_cooperative_convergence(self) -> None:
        """Meidner share dilution must increase cooperative equity monotonically and scale with delta."""
        res_coop = simulate_cooperative_transition(
            TransitionRegime.COOPERATIVE_TRANSITION,
            steps=35,
            automation_start=0.25,
            automation_end=0.98,
            seed=42,
        )
        shares = [r.cooperative_equity_share for r in res_coop.step_records]
        for prev_s, next_s in zip(shares, shares[1:]):
            self.assertGreater(next_s, prev_s)
        self.assertGreater(res_coop.final_cooperative_share, 0.80)

        # Higher dilution rate delta strictly accelerates cooperative convergence at identical step
        finals_by_delta = []
        for delta in (0.0, 0.05, 0.12, 0.25):
            pol = TransitionPolicyConfig(
                regime=TransitionRegime.COOPERATIVE_TRANSITION,
                meidner_dilution_rate=delta,
                automation_dilution_threshold=0.30,
                blinded_commissioning_rate=0.0,
                baseline_provisioning_share=0.10,
                zk_durability_steering=True,
                mutual_credit_limit_share=0.50,
                expiring_balance_decay_rate=0.05,
            )
            r = simulate_cooperative_transition(
                TransitionRegime.COOPERATIVE_TRANSITION,
                policy=pol,
                steps=30,
                seed=42,
            )
            finals_by_delta.append(r.final_cooperative_share)
        for d_low, d_high in zip(finals_by_delta, finals_by_delta[1:]):
            self.assertGreater(d_high, d_low)

    def test_04_demand_collapse_under_enclosure_vs_stability_under_cooperative_95pct_automation(self) -> None:
        """At >=95% automation, Concentrated Enclosure suffers severe demand collapse while Cooperative Transition maintains high utilization and durable household well-being."""
        compared = compare_cooperative_transition_regimes(
            steps=30,
            automation_start=0.25,
            automation_end=0.98,
            seed=42,
        )
        enc = compared[TransitionRegime.CONCENTRATED_ENCLOSURE]
        coop = compared[TransitionRegime.COOPERATIVE_TRANSITION]

        # Find step closest to >= 95% automation
        enc_95 = next(r for r in enc.step_records if r.automation_level >= 0.95)
        coop_95 = next(r for r in coop.step_records if r.automation_level >= 0.95)

        self.assertLessEqual(enc_95.wage_share, 0.05)
        # Under concentrated enclosure, productive capacity is high (>250) yet utilization collapses (<25%)
        self.assertGreater(enc_95.total_capacity, 250.0)
        self.assertLess(enc_95.capacity_utilization, 0.25)
        self.assertGreater(enc_95.idle_unpurchased_capacity, 180.0)

        # Under cooperative transition, capacity utilization remains high (>90%) and durable output is >4x higher
        self.assertGreater(coop_95.capacity_utilization, 0.90)
        self.assertGreater(coop_95.fulfilled_durable_output, 4.0 * enc_95.fulfilled_durable_output)
        self.assertGreater(coop_95.household_median_wellbeing, 5.0 * enc_95.household_median_wellbeing)

    def test_05_counter_cyclical_mutual_credit_stabilization(self) -> None:
        """Mutual credit clearing must strictly raise capacity utilization during liquidity shocks."""
        workloads = generate_transition_workloads(steps=25, num_accounts=120, seed=99)
        pol_no_mc = TransitionPolicyConfig(
            regime=TransitionRegime.COOPERATIVE_TRANSITION,
            meidner_dilution_rate=0.10,
            automation_dilution_threshold=0.30,
            blinded_commissioning_rate=0.03,
            baseline_provisioning_share=0.12,
            zk_durability_steering=True,
            mutual_credit_limit_share=0.0,
            expiring_balance_decay_rate=0.05,
        )
        pol_with_mc = TransitionPolicyConfig(
            regime=TransitionRegime.COOPERATIVE_TRANSITION,
            meidner_dilution_rate=0.10,
            automation_dilution_threshold=0.30,
            blinded_commissioning_rate=0.03,
            baseline_provisioning_share=0.12,
            zk_durability_steering=True,
            mutual_credit_limit_share=0.85,
            expiring_balance_decay_rate=0.05,
        )
        res_no_mc = simulate_cooperative_transition(
            TransitionRegime.COOPERATIVE_TRANSITION, policy=pol_no_mc, steps=25, workloads=workloads
        )
        res_with_mc = simulate_cooperative_transition(
            TransitionRegime.COOPERATIVE_TRANSITION, policy=pol_with_mc, steps=25, workloads=workloads
        )
        self.assertEqual(res_no_mc.cumulative_mutual_credit_volume, 0.0)
        self.assertGreater(res_with_mc.cumulative_mutual_credit_volume, 100.0)
        for r0, r1 in zip(res_no_mc.step_records, res_with_mc.step_records):
            self.assertGreater(r1.capacity_utilization, r0.capacity_utilization)

    def test_06_sybil_resistant_one_human_root_invariance(self) -> None:
        """Spawning 500 Sybil agents under 1 human root yields exact zero additional weight; unanchored Sybils get 0."""
        single_honest = [
            FulfillmentAttestation(
                attestation_id="att-h1-1",
                agent_id="agent-honest-1",
                human_root_id="human-root-alice",
                human_root_verified=True,
                modality=VerificationModality.THIRTY_DAY_DURABILITY,
                durable_fulfilled=True,
            )
        ]
        # Same human root spawns 500 Sybil agents trying to flood ratings + 200 unanchored bots
        sybil_flood = list(single_honest)
        for i in range(500):
            sybil_flood.append(
                FulfillmentAttestation(
                    attestation_id=f"att-sybil-{i}",
                    agent_id=f"sybil-bot-{i}",
                    human_root_id="human-root-alice",
                    human_root_verified=True,
                    modality=VerificationModality.THIRTY_DAY_DURABILITY,
                    durable_fulfilled=True,
                )
            )
        for j in range(200):
            sybil_flood.append(
                FulfillmentAttestation(
                    attestation_id=f"att-unanchored-{j}",
                    agent_id=f"anon-bot-{j}",
                    human_root_id=None,
                    human_root_verified=False,
                    modality=VerificationModality.THIRTY_DAY_DURABILITY,
                    durable_fulfilled=False,
                )
            )

        agg_single = aggregate_sybil_resistant_fulfillment_signals(single_honest)
        agg_flood = aggregate_sybil_resistant_fulfillment_signals(sybil_flood)

        self.assertEqual(agg_flood.verified_human_roots, 1)
        self.assertEqual(agg_flood.rejected_unanchored_attestations, 200)
        self.assertEqual(agg_flood.collapsed_duplicate_agent_attestations, 500)
        self.assertAlmostEqual(agg_single.total_effective_weight, agg_flood.total_effective_weight, places=12)
        self.assertAlmostEqual(agg_single.weighted_durability_score, 1.0, places=12)
        self.assertAlmostEqual(agg_flood.weighted_durability_score, 1.0, places=12)

    def test_07_submodular_diminishing_marginal_returns_across_modalities(self) -> None:
        """Modality set function f(M) must satisfy strict submodularity f(A U {x}) - f(A) > f(B U {x}) - f(B) for A subset B."""
        set_a = frozenset({VerificationModality.DELIVERY_RECEIPT})
        set_b = frozenset(
            {VerificationModality.DELIVERY_RECEIPT, VerificationModality.THIRTY_DAY_DURABILITY}
        )
        added = VerificationModality.REPAIRABILITY_CHECK

        gain_from_a = (
            compute_human_root_modality_weight(set_a | {added})
            - compute_human_root_modality_weight(set_a)
        )
        gain_from_b = (
            compute_human_root_modality_weight(set_b | {added})
            - compute_human_root_modality_weight(set_b)
        )
        self.assertGreater(gain_from_a, 0.0)
        self.assertGreater(gain_from_b, 0.0)
        self.assertGreater(gain_from_a, gain_from_b)
        self.assertAlmostEqual(
            compute_human_root_modality_weight(frozenset(VerificationModality)),
            1.0,
            places=12,
        )

    def test_08_myerson_club_good_superadditivity(self) -> None:
        """Disjoint open cooperative coalitions must satisfy Myerson superadditivity V(S U T) > V(S) + V(T)."""
        v_s, _ = compute_myerson_club_value(18, 60)
        v_t, _ = compute_myerson_club_value(24, 60)
        v_union, _ = compute_myerson_club_value(18 + 24, 60)
        self.assertGreater(v_union, v_s + v_t)

    def test_09_physical_energy_compute_conservation_boundary(self) -> None:
        """Physical boundary metering satisfies E_in == E_accounted + E_shadow + epsilon and monotonic detection."""
        e_in_clean, resid_clean, p_clean = compute_physical_conservation_detection_prob(
            accounted_open_mw=50.0,
            shadow_unaccounted_mw=0.0,
            metering_noise_epsilon_mw=0.4,
            noise_tolerance_mw=1.5,
        )
        self.assertAlmostEqual(e_in_clean, 50.4, places=12)
        self.assertAlmostEqual(resid_clean, 0.4, places=12)
        self.assertEqual(p_clean, 0.0)

        probs = []
        for shadow_mw in (5.0, 15.0, 40.0, 100.0):
            e_in, resid, p_det = compute_physical_conservation_detection_prob(
                accounted_open_mw=50.0,
                shadow_unaccounted_mw=shadow_mw,
                metering_noise_epsilon_mw=-0.3,
                noise_tolerance_mw=1.5,
            )
            self.assertAlmostEqual(e_in, 50.0 + shadow_mw - 0.3, places=12)
            self.assertAlmostEqual(resid, shadow_mw - 0.3, places=12)
            probs.append(p_det)

        for p_lo, p_hi in zip(probs, probs[1:]):
            self.assertGreater(p_hi, p_lo)

    def test_10_exact_nash_cartel_collapse_threshold_harrington_and_tau(self) -> None:
        """Verify exact closed-form B* and tau* thresholds separate cartel persistence from 100% round-0 collapse."""
        # High collusive rent, zero physical audit, moderate tau -> positive critical bounty B* > 0
        base_thresh = compute_nash_cartel_threshold(
            total_agents=60,
            active_cartel_size=20,
            opacity_margin_tau=0.10,
            whistleblower_bounty=0.0,
            physical_detection_prob=0.0,
            sanction_fine=18.0,
            discount_factor=0.80,
            collusive_rent_scale=16.0,
            border_trade_exposure=14.0,
        )
        b_star = base_thresh.critical_whistleblower_bounty
        self.assertGreater(b_star, 1.0)
        self.assertFalse(base_thresh.defection_strictly_dominant)

        # Just below B* (with physical_audit_enabled=False so only Nash leniency acts): cartel persists (0% defection)
        below_res = simulate_dark_ledger_containment(
            total_agents=60,
            initial_cartel_size=20,
            rounds=10,
            opacity_margin_tau=0.10,
            whistleblower_bounty=b_star - 0.25,
            physical_audit_enabled=False,
            sanction_fine=18.0,
            discount_factor=0.80,
            collusive_rent_scale=16.0,
            border_trade_exposure=14.0,
            seed=42,
        )
        self.assertFalse(below_res.cartel_collapsed)
        self.assertEqual(below_res.final_cartel_size, 20)
        self.assertEqual(below_res.cartel_defection_rate, 0.0)

        # Just above B*: dominant-strategy whistleblower cascade collapses cartel 100% in round 0
        above_res = simulate_dark_ledger_containment(
            total_agents=60,
            initial_cartel_size=20,
            rounds=10,
            opacity_margin_tau=0.10,
            whistleblower_bounty=b_star + 0.25,
            physical_audit_enabled=False,
            sanction_fine=18.0,
            discount_factor=0.80,
            collusive_rent_scale=16.0,
            border_trade_exposure=14.0,
            seed=42,
        )
        self.assertTrue(above_res.cartel_collapsed)
        self.assertEqual(above_res.collapse_round, 0)
        self.assertEqual(above_res.final_cartel_size, 0)
        self.assertAlmostEqual(above_res.cartel_defection_rate, 1.0, places=12)

        # Verify exact opacity quarantine margin threshold tau* at zero bounty
        tau_star = base_thresh.critical_opacity_margin_tau
        self.assertGreater(tau_star, 0.10)
        self.assertLess(tau_star, 1.0)
        above_tau = compute_nash_cartel_threshold(
            total_agents=60,
            active_cartel_size=20,
            opacity_margin_tau=min(1.0, tau_star + 0.02),
            whistleblower_bounty=0.0,
            physical_detection_prob=0.0,
            sanction_fine=18.0,
            discount_factor=0.80,
            collusive_rent_scale=16.0,
            border_trade_exposure=14.0,
        )
        self.assertTrue(above_tau.defection_strictly_dominant)

    def test_11_dark_ledger_capital_and_energy_conservation_invariants(self) -> None:
        """All slashed bonds, whistleblower bounties, and opacity margins must be strictly conserved in integer cents."""
        for tau, bounty, phys in ((0.05, 0.0, False), (0.20, 4.0, True), (0.35, 15.0, True)):
            res = simulate_dark_ledger_containment(
                total_agents=60,
                initial_cartel_size=16,
                rounds=18,
                opacity_margin_tau=tau,
                whistleblower_bounty=bounty,
                physical_audit_enabled=phys,
                seed=55,
            )
            self.assertTrue(res.capital_conservation_verified)
            self.assertTrue(res.physical_energy_conservation_verified)
            self.assertEqual(
                res.final_commons_reserve_cents,
                res.total_opacity_margin_collected_cents
                + res.total_slashed_collateral_cents
                - res.total_whistleblower_bounty_paid_cents,
            )
            self.assertLessEqual(
                res.total_whistleblower_bounty_paid_cents,
                res.total_slashed_collateral_cents,
            )

    def test_12_deterministic_reproducibility_and_zero_rng_drift(self) -> None:
        """Identical seeds produce bit-identical digests and shared shock sequences across regimes."""
        wl_a = generate_transition_workloads(steps=20, num_accounts=120, seed=1234)
        wl_b = generate_transition_workloads(steps=20, num_accounts=120, seed=1234)
        self.assertEqual(wl_a, wl_b)

        r1 = simulate_cooperative_transition(TransitionRegime.COOPERATIVE_TRANSITION, steps=20, seed=1234)
        r2 = simulate_cooperative_transition(TransitionRegime.COOPERATIVE_TRANSITION, steps=20, seed=1234)
        self.assertEqual(r1.receipt_digest, r2.receipt_digest)
        self.assertEqual(r1.step_records, r2.step_records)

        dl_wls = generate_dark_ledger_workloads(rounds=15, seed=9876)
        d1 = simulate_dark_ledger_containment(rounds=15, seed=9876)
        d2 = simulate_dark_ledger_containment(rounds=15, workloads=dl_wls)
        self.assertEqual(d1.receipt_digest, d2.receipt_digest)
        self.assertEqual(d1.round_records, d2.round_records)

    def test_13_fail_closed_validation_rejects_bool_nan_inf_and_bad_bounds(self) -> None:
        """Fail-closed validation must reject bool-as-int/float, NaN, Inf, and inverted automation bounds."""
        with self.assertRaises(CooperativeSimValidationError):
            simulate_cooperative_transition(steps=True)  # type: ignore[arg-type]
        with self.assertRaises(CooperativeSimValidationError):
            simulate_cooperative_transition(automation_start=math.nan)
        with self.assertRaises(CooperativeSimValidationError):
            simulate_cooperative_transition(automation_end=math.inf)
        with self.assertRaises(CooperativeSimValidationError):
            simulate_cooperative_transition(automation_start=0.80, automation_end=0.50)
        with self.assertRaises(CooperativeSimValidationError):
            compute_nash_cartel_threshold(opacity_margin_tau=-0.1)
        with self.assertRaises(CooperativeSimValidationError):
            compute_nash_cartel_threshold(discount_factor=1.0)
        with self.assertRaises(CooperativeSimValidationError):
            default_policy_for_regime("INVALID")  # type: ignore[arg-type]

    def test_14_steward_gate_rejects_forbidden_terms(self) -> None:
        """Steward Gate must reject unapproved tokens, royalty splits, and retired neologisms."""
        for forbidden in ("Earn Contribution Tokens", "MMCT staking", "85/10/5 split", "royalties forever"):
            with self.assertRaises(StewardGateViolationError):
                screen_steward_gate(forbidden)
        with self.assertRaises(StewardGateViolationError):
            FulfillmentAttestation(
                attestation_id="MMCT-claim-1",
                agent_id="agent-1",
                human_root_id="root-1",
                human_root_verified=True,
                modality=VerificationModality.DELIVERY_RECEIPT,
                durable_fulfilled=True,
            )


if __name__ == "__main__":
    unittest.main()
