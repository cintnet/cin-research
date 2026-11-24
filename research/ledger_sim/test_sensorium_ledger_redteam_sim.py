#!/usr/bin/env python3
"""
Unit tests for `research/ledger_sim/sensorium_ledger_redteam_sim.py`.

Verifies:
  1. Bit-for-bit determinism and per-scenario/per-trial SHA-256 RNG isolation (zero phase drift).
  2. Zero raw Private Autobiographical Ledger leakage across the 1:1 Markov Blanket.
  3. Strict integer-cent capital conservation and fail-closed numeric/bool/NaN/Steward validation.
  4. Strictly superior attack-blocking and false-penalty elimination of `CIN_DEFENSE_IN_DEPTH`
     over `NAIVE_SIGNED_IS_TRUE` across all 8 hardware & bifurcated-ledger red-team vectors.
"""

from __future__ import annotations

import dataclasses
import json
import math
from pathlib import Path
import sys
import time
import unittest

_DIR = Path(__file__).resolve().parent
_ROOT = _DIR.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

try:
    from research.ledger_sim import sensorium_ledger_redteam_sim as sim
except ModuleNotFoundError:
    import sensorium_ledger_redteam_sim as sim  # type: ignore[no-redef]


class SensoriumLedgerRedTeamSimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        t0 = time.perf_counter()
        cls.suite_200 = sim.run_all_scenarios(seed=20261115, trials=200)
        cls.elapsed_200 = time.perf_counter() - t0

    def test_01_bit_for_bit_determinism_across_repeated_runs(self) -> None:
        r1 = sim.run_all_scenarios(seed=20261115, trials=40)
        r2 = sim.run_all_scenarios(seed=20261115, trials=40)
        self.assertEqual(r1["results_sha256"], r2["results_sha256"])
        self.assertEqual(
            json.dumps(r1, sort_keys=True),
            json.dumps(r2, sort_keys=True),
        )

    def test_02_distinct_seeds_produce_distinct_trajectories(self) -> None:
        r_a = sim.run_all_scenarios(seed=20261115, trials=40)
        r_b = sim.run_all_scenarios(seed=20261116, trials=40)
        self.assertNotEqual(r_a["results_sha256"], r_b["results_sha256"])

    def test_03_per_scenario_and_per_trial_rng_isolation_no_phase_drift(self) -> None:
        # Running RT5 standalone must match RT5 inside run_all_scenarios identically
        standalone_rt5 = sim.run_single_scenario(
            sim.ScenarioId.RT5_CALIBRATION_AND_COVERAGE_BIAS,
            seed=20261115,
            trials=200,
        )
        suite_rt5 = self.suite_200["scenarios"]["RT5_CALIBRATION_AND_COVERAGE_BIAS"]
        self.assertEqual(standalone_rt5, suite_rt5)

        # Prefix trials 0..29 of trials=30 must match prefix 0..29 of trials=60
        zk_key = b"prefix-isolation-key-32bytes-pad"
        b30 = sim.generate_scenario_workloads(
            sim.ScenarioId.RT2_OBSERVATION_AWARE_DEFEAT_GAMING,
            master_seed=99,
            trials=30,
            zk_shared_key=zk_key,
        )
        b60 = sim.generate_scenario_workloads(
            sim.ScenarioId.RT2_OBSERVATION_AWARE_DEFEAT_GAMING,
            master_seed=99,
            trials=60,
            zk_shared_key=zk_key,
        )
        self.assertEqual(b30, b60[:30])

    def test_04_execution_speed_under_two_point_five_seconds(self) -> None:
        self.assertLess(self.elapsed_200, 2.5)

    def test_05_zero_private_autobiographical_bytes_exposed_all_scenarios(self) -> None:
        agg = self.suite_200["aggregate_summary"]
        self.assertEqual(agg["total_private_bytes_exposed"], 0)
        self.assertGreater(agg["total_private_bytes_vaulted"], 500_000)
        for sc_name, sc_data in self.suite_200["scenarios"].items():
            for reg_name, reg_metrics in sc_data["regimes"].items():
                self.assertEqual(
                    reg_metrics["private_bytes_exposed"],
                    0,
                    msg=f"Leak detected in {sc_name} / {reg_name}",
                )
                self.assertGreater(reg_metrics["private_bytes_vaulted"], 0)

    def test_06_markov_blanket_fails_closed_on_ownership_mismatch_or_raw_leak(self) -> None:
        vault = sim.EpisodicMemoryVault("person:alice", "agent:alice-1to1", b"vkey")
        vault.append_event(
            window_id=1,
            device_time_ticks=100,
            raw_private_bytes=b"private-medical-diary-entry",
            polarity_tag="FAVORABLE",
            hw_signing_key=b"hwkey",
        )
        wrong_blanket = sim.MonogamousMarkovBlanket("person:mallory", "agent:mallory", b"zk")
        obs = sim.build_transducer_observation(
            modality=sim.Modality.VISUAL,
            measured_displacement_m=12.0,
            self_confidence=0.95,
            device_time_ticks=105,
            dice_secret=b"hwkey",
            spdm_session_id="s1",
            challenger_nonce="n1",
        )
        sensorium = sim.fuse_multimodal_sensorium(
            [obs],
            calibration_stratum_supported=True,
            active_spdm_session_id="s1",
            expected_challenger_nonce="n1",
            vault_last_committed_ticks=100,
        )
        with self.assertRaises(sim.MarkovBlanketLeakError):
            wrong_blanket.project_to_public_ledger(
                vault=vault,
                included_indices=[0],
                claim_id="c-bad",
                scenario_id=sim.ScenarioId.RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION,
                is_adversarial_attack=True,
                is_honest_participant=False,
                is_under_calibrated_stratum=False,
                requester_escrow_cents=1000,
                participant_stake_cents=500,
                attester_bond_cents=0,
                sensorium=sensorium,
                dice_verify_key=b"hwkey",
                scheduled_checkpoint_clean=True,
                spot_check_violations_found=0,
                duress_canary_active=False,
                velocity_ratio=1.0,
                unbonded_new_recipient=False,
                observer_attestations=(),
                observer_graph_edges=(),
            )

        # Also verify WideNetworkEscrowVerifier rejects any tampered claim carrying raw bytes
        good_blanket = sim.MonogamousMarkovBlanket("person:alice", "agent:alice-1to1", b"zk")
        clean_claim = good_blanket.project_to_public_ledger(
            vault=vault,
            included_indices=[0],
            claim_id="c-ok",
            scenario_id=sim.ScenarioId.RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION,
            is_adversarial_attack=False,
            is_honest_participant=True,
            is_under_calibrated_stratum=False,
            requester_escrow_cents=1000,
            participant_stake_cents=500,
            attester_bond_cents=0,
            sensorium=sensorium,
            dice_verify_key=b"hwkey",
            scheduled_checkpoint_clean=True,
            spot_check_violations_found=0,
            duress_canary_active=False,
            velocity_ratio=1.0,
            unbonded_new_recipient=False,
            observer_attestations=(),
            observer_graph_edges=(),
        )
        leaking_claim = dataclasses.replace(clean_claim, raw_private_leak_bytes=b"secret")
        verifier = sim.WideNetworkEscrowVerifier(sim.CIN_HARDENED_POLICY, b"zk")
        with self.assertRaises(sim.MarkovBlanketLeakError):
            verifier.evaluate(leaking_claim)

    def test_07_strict_capital_conservation_and_tamper_detection(self) -> None:
        self.assertTrue(self.suite_200["aggregate_summary"]["all_scenarios_capital_conserved"])
        bundles = sim.generate_scenario_workloads(
            sim.ScenarioId.RT8_SYBIL_ESCROW_COLLUSION_RING,
            master_seed=20261115,
            trials=25,
            zk_shared_key=b"zk-cap-test",
        )
        c = bundles[0].claim
        with self.assertRaises(sim.CapitalConservationError):
            sim.WideNetworkEscrowVerifier._finalize(
                claim=c,
                initial_total_cents=c.requester_escrow_cents + c.participant_stake_cents + c.attester_bond_cents,
                decision=sim.SettlementDecision.APPROVED_PAYOUT,
                requester_refunded_cents=1,  # extra unbacked cent
                claimant_payout_cents=c.requester_escrow_cents,
                recovery_vault_frozen_cents=0,
                participant_retained_cents=c.participant_stake_cents,
                audit_treasury_cents=0,
                attester_bond_returned_cents=c.attester_bond_cents,
            )

    def test_08_fail_closed_bool_nan_inf_and_cents_validation(self) -> None:
        with self.assertRaises(sim.SensoriumSimValidationError):
            sim.validate_strict_int("seed", True)
        with self.assertRaises(sim.SensoriumSimValidationError):
            sim.validate_strict_int("cents", 12.5)
        with self.assertRaises(sim.SensoriumSimValidationError):
            sim.validate_finite_float("conf", False)
        with self.assertRaises(sim.SensoriumSimValidationError):
            sim.validate_finite_float("conf", math.nan, 0.0, 1.0)
        with self.assertRaises(sim.SensoriumSimValidationError):
            sim.validate_finite_float("conf", math.inf, 0.0, 1.0)

    def test_09_steward_gate_blocks_forbidden_tokens_and_lore(self) -> None:
        for bad in (
            "Mint 50 MMCT rewards",
            "Issue Contribution Tokens to verifiers",
            "Split 85/10/5 across pools",
            "Guaranteed 95% savings",
            "Verified by Somatic Witness sensor",
        ):
            with self.assertRaises(sim.StewardGateViolationError):
                sim.screen_steward_gate(bad)

    def test_10_all_eight_scenarios_cin_strictly_superior_to_naive(self) -> None:
        self.assertEqual(len(self.suite_200["scenarios"]), 8)
        self.assertTrue(self.suite_200["aggregate_summary"]["all_scenarios_cin_strictly_superior"])
        for sc_id in sim.ScenarioId:
            sc = self.suite_200["scenarios"][sc_id.value]
            naive = sc["regimes"][sim.Regime.NAIVE_SIGNED_IS_TRUE.value]
            cin = sc["regimes"][sim.Regime.CIN_DEFENSE_IN_DEPTH.value]
            self.assertLess(
                cin["system_failure_rate"],
                naive["system_failure_rate"],
                msg=f"CIN did not outperform NAIVE in {sc_id.value}",
            )
            self.assertGreater(sc["comparative_delta"]["system_failure_rate_reduction"], 0.70)

    def test_11_rt1_analog_hole_transduction_spoof_blocked_by_kinematics(self) -> None:
        sc = self.suite_200["scenarios"]["RT1_ANALOG_HOLE_TRANSDUCTION_SPOOF"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertGreater(naive["attack_success_rate"], 0.95)
        self.assertEqual(cin["attack_success_rate"], 0.0)
        self.assertEqual(cin["honest_false_rejection_rate"], 0.0)

    def test_12_rt2_observation_aware_defeat_gaming_caught_by_spot_escrow(self) -> None:
        sc = self.suite_200["scenarios"]["RT2_OBSERVATION_AWARE_DEFEAT_GAMING"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertEqual(naive["attack_success_rate"], 1.0)
        self.assertLess(cin["attack_success_rate"], 0.05)
        self.assertGreater(cin["attack_block_rate"], 0.95)

    def test_13_rt3_channel_replay_interception_blocked_by_spdm_and_clock(self) -> None:
        sc = self.suite_200["scenarios"]["RT3_CHANNEL_REPLAY_INTERCEPTION"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertEqual(naive["attack_success_rate"], 1.0)
        self.assertEqual(cin["attack_success_rate"], 0.0)
        self.assertEqual(cin["honest_false_rejection_rate"], 0.0)

    def test_14_rt4_monoculture_common_mode_fault_collapsed_by_lineage_independence(self) -> None:
        sc = self.suite_200["scenarios"]["RT4_MONOCULTURE_COMMON_MODE_FAULT"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertEqual(naive["attack_success_rate"], 1.0)
        self.assertEqual(cin["attack_success_rate"], 0.0)

        # Direct unit check on Union-Find lineage collapsing
        correlated = [
            sim.ObserverAttestation("o1", "org-a", "SameChip", "fw-1", "c1", True, True, True),
            sim.ObserverAttestation("o2", "org-b", "SameChip", "fw-2", "c2", True, True, True),
            sim.ObserverAttestation("o3", "org-c", "OtherChip", "fw-2", "c3", True, True, True),
        ]
        # o1 shares vendor with o2, and o2 shares firmware with o3 -> transitive single class!
        self.assertEqual(sim.count_independent_observer_classes(correlated), 1)

    def test_15_rt5_calibration_bias_uncertainty_falls_on_system_zero_false_penalty(self) -> None:
        sc = self.suite_200["scenarios"]["RT5_CALIBRATION_AND_COVERAGE_BIAS"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertGreater(naive["false_penalty_rate"], 0.70)
        self.assertGreater(naive["total_unfair_honest_penalty_cents"], 0)
        self.assertEqual(cin["false_penalty_rate"], 0.0)
        self.assertEqual(cin["total_unfair_honest_penalty_cents"], 0)
        self.assertEqual(
            cin["contestable_human_review_routed"],
            cin["under_calibrated_honest_trials"],
        )

    def test_16_rt6_coerced_signing_and_key_extraction_frozen_in_recovery_escrow(self) -> None:
        sc = self.suite_200["scenarios"]["RT6_COERCED_SIGNING_AND_KEY_EXTRACTION"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertEqual(naive["attack_success_rate"], 1.0)
        self.assertEqual(cin["attack_success_rate"], 0.0)
        self.assertGreater(cin["total_protected_or_recovered_cents"], 0)

    def test_17_rt7_markov_selective_omission_detected_with_zero_private_leak(self) -> None:
        sc = self.suite_200["scenarios"]["RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertEqual(naive["attack_success_rate"], 1.0)
        self.assertEqual(cin["attack_success_rate"], 0.0)
        self.assertEqual(cin["private_bytes_exposed"], 0)
        self.assertEqual(cin["honest_false_rejection_rate"], 0.0)

    def test_18_rt8_sybil_collusion_ring_quarantined_and_slashed_by_ktruss(self) -> None:
        sc = self.suite_200["scenarios"]["RT8_SYBIL_ESCROW_COLLUSION_RING"]
        naive = sc["regimes"]["NAIVE_SIGNED_IS_TRUE"]
        cin = sc["regimes"]["CIN_DEFENSE_IN_DEPTH"]
        self.assertEqual(naive["attack_success_rate"], 1.0)
        self.assertEqual(cin["attack_success_rate"], 0.0)
        self.assertGreater(cin["total_slashed_to_audit_treasury_cents"], 0)

    def test_19_ktruss_decomposition_exact_on_clique_versus_tree(self) -> None:
        clique_k5 = [(f"c{i}", f"c{j}") for i in range(5) for j in range(i + 1, 5)]
        tree_edges = [("t0", "t1"), ("t1", "t2"), ("t2", "t3")]
        truss = sim.compute_edge_truss_numbers(clique_k5 + tree_edges + [("c0", "t0")])
        self.assertEqual(truss[("c0", "c1")], 5)
        self.assertEqual(truss[("t0", "t1")], 2)
        self.assertAlmostEqual(sim.induced_triangle_density(["c0", "c1", "c2", "c3"], clique_k5), 1.0)
        self.assertAlmostEqual(sim.induced_triangle_density(["t0", "t1", "t2"], tree_edges), 0.0)

    def test_20_results_json_artifact_matches_canonical_default_run(self) -> None:
        self.assertTrue(sim.RESULTS_JSON_PATH.exists(), "sensorium_ledger_redteam_results.json missing")
        disk_data = json.loads(sim.RESULTS_JSON_PATH.read_text(encoding="utf-8"))
        fresh_250 = sim.run_all_scenarios(seed=20261115, trials=250)
        self.assertEqual(disk_data["results_sha256"], fresh_250["results_sha256"])
        self.assertEqual(disk_data["trials_per_scenario"], 250)


if __name__ == "__main__":
    unittest.main()
