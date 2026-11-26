#!/usr/bin/env python3
"""Unit tests for supplier_swap_idempotent_memory_sim.py."""

from __future__ import annotations

import json
import math
from pathlib import Path
import unittest

from research.ledger_sim.supplier_swap_idempotent_memory_sim import (
    DISCRETE_ORDER_CENTS_SUPPORT,
    REGIME_CONFIGS,
    SupplierSwapEpisode,
    assert_steward_gate_text,
    evaluate_regime,
    generate_supplier_swap_workload,
    run_multi_seed_simulation,
)


RESULTS_PATH = Path(__file__).resolve().parent / "supplier_swap_idempotent_memory_results.json"


class TestSupplierSwapIdempotentMemorySim(unittest.TestCase):
    def test_ten_seed_ablation_conservation_and_zero_drift(self) -> None:
        summary = run_multi_seed_simulation()
        self.assertEqual(summary["rng_phase_drift"], 0.0)
        self.assertEqual(summary["capital_conservation_delta_cents"], 0)
        self.assertEqual(summary["total_episodes_per_regime"], 3000)

        retry_all = summary["regimes"]["RETRY_ALL_BEARER_MERGED_MEMORY"]
        state_only = summary["regimes"]["PERSISTENT_STATE_WITHOUT_SUPPLIER_IDEMPOTENCY"]
        merged_mem = summary["regimes"]["IDEMPOTENT_MANDATELOCK_MERGED_MEMORY"]
        cin = summary["regimes"]["CIN_OPCP_IDEMPOTENT_MANDATELOCK_DISCERN"]

        # Baseline suffers cross-supplier and same-supplier duplicates, redirections, and memory collisions
        self.assertGreater(retry_all["cross_supplier_duplicate_commits"], 0)
        self.assertGreater(retry_all["same_supplier_duplicate_commits"], 0)
        self.assertGreater(retry_all["bearer_mandate_redirections"], 0)
        self.assertGreater(retry_all["entity_collision_misroutes"], 0)
        self.assertGreater(retry_all["unanswerable_false_commits"], 0)
        self.assertGreater(retry_all["member_identifier_bytes_leaked"], 0)

        # OPCP persistent state blocks cross-supplier replay yet leaves same-supplier non-idempotent retries open
        self.assertEqual(state_only["cross_supplier_duplicate_commits"], 0)
        self.assertGreater(state_only["same_supplier_duplicate_commits"], 0)

        # Adding supplier idempotency + MandateLock stops all duplicates & redirections yet leaves merged-memory errors
        self.assertEqual(merged_mem["cross_supplier_duplicate_commits"], 0)
        self.assertEqual(merged_mem["same_supplier_duplicate_commits"], 0)
        self.assertEqual(merged_mem["bearer_mandate_redirections"], 0)
        self.assertGreater(merged_mem["entity_collision_misroutes"], 0)
        self.assertGreater(merged_mem["unanswerable_false_commits"], 0)

        # Full five-primitive regime eliminates duplicates, redirections, entity collisions, false commits, & ID leaks
        self.assertEqual(cin["cross_supplier_duplicate_commits"], 0)
        self.assertEqual(cin["same_supplier_duplicate_commits"], 0)
        self.assertEqual(cin["bearer_mandate_redirections"], 0)
        self.assertEqual(cin["entity_collision_misroutes"], 0)
        self.assertEqual(cin["unanswerable_false_commits"], 0)
        self.assertEqual(cin["member_identifier_bytes_leaked"], 0)
        self.assertEqual(cin["extracted_duplicate_and_diversion_cents"], 0)
        self.assertEqual(cin["safe_or_clean_rate"], 1.0)
        self.assertGreater(cin["iec61508_deadman_trips"], 0)
        self.assertGreater(
            cin["endogenous_coop_adoption_rate"],
            retry_all["endogenous_coop_adoption_rate"],
        )

    def test_checked_in_results_json_matches_live_run(self) -> None:
        self.assertTrue(RESULTS_PATH.exists(), f"Missing {RESULTS_PATH}")
        stored = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        live = run_multi_seed_simulation()
        self.assertEqual(stored, live)

    def test_fail_closed_bool_nan_population_and_discrete_support_guards(self) -> None:
        with self.assertRaises(ValueError):
            generate_supplier_swap_workload(0, num_episodes=10, num_members=2, num_domains=4)
        with self.assertRaises(ValueError):
            generate_supplier_swap_workload(True, num_episodes=10)  # type: ignore[arg-type]

        episodes, _ = generate_supplier_swap_workload(0, num_episodes=4)
        base = episodes[0]

        # Reject bool passed as int
        with self.assertRaises(ValueError):
            SupplierSwapEpisode(
                episode_id=True,  # type: ignore[arg-type]
                member_id=base.member_id,
                domain_id=base.domain_id,
                primary_supplier_id=0,
                fallback_supplier_id=1,
                device_time_ns=base.device_time_ns,
                spdm_rats_quote_valid=True,
                transduction_cross_modal_ok=True,
                witness_classes_verified=4,
                supplier_fault_kind="none",
                retry_targets_fallback_supplier=False,
                mandate_redirection_attempted=False,
                confusable_entity_collision=False,
                evidence_sufficient=True,
                permission_legitimately_blocked=False,
                delegated_identifier_bytes=128,
                order_amount_cents=DISCRETE_ORDER_CENTS_SUPPORT[0],
                challenger_bond_cents=300,
                audit_spot_draw=0.5,
            )

        # Reject NaN in rate check
        with self.assertRaises(ValueError):
            SupplierSwapEpisode(
                episode_id=0,
                member_id=base.member_id,
                domain_id=base.domain_id,
                primary_supplier_id=0,
                fallback_supplier_id=1,
                device_time_ns=base.device_time_ns,
                spdm_rats_quote_valid=True,
                transduction_cross_modal_ok=True,
                witness_classes_verified=4,
                supplier_fault_kind="none",
                retry_targets_fallback_supplier=False,
                mandate_redirection_attempted=False,
                confusable_entity_collision=False,
                evidence_sufficient=True,
                permission_legitimately_blocked=False,
                delegated_identifier_bytes=128,
                order_amount_cents=DISCRETE_ORDER_CENTS_SUPPORT[0],
                challenger_bond_cents=300,
                audit_spot_draw=math.nan,
            )

        # Reject out-of-support order valuation
        with self.assertRaises(ValueError):
            SupplierSwapEpisode(
                episode_id=0,
                member_id=base.member_id,
                domain_id=base.domain_id,
                primary_supplier_id=0,
                fallback_supplier_id=1,
                device_time_ns=base.device_time_ns,
                spdm_rats_quote_valid=True,
                transduction_cross_modal_ok=True,
                witness_classes_verified=4,
                supplier_fault_kind="none",
                retry_targets_fallback_supplier=False,
                mandate_redirection_attempted=False,
                confusable_entity_collision=False,
                evidence_sufficient=True,
                permission_legitimately_blocked=False,
                delegated_identifier_bytes=128,
                order_amount_cents=1_234,
                challenger_bond_cents=300,
                audit_spot_draw=0.5,
            )

    def test_indivisible_clearing_under_zero_cash_exhaustion(self) -> None:
        episodes, _ = generate_supplier_swap_workload(3, num_episodes=40)
        for cfg in REGIME_CONFIGS:
            m = evaluate_regime(episodes, cfg, budget_multiplier=0)
            self.assertEqual(m.capital_conservation_delta_cents, 0)
            self.assertEqual(m.clean_settlements, 0)
            self.assertEqual(m.supplier_settlement_cents, 0)
            self.assertEqual(m.extracted_duplicate_and_diversion_cents, 0)
            self.assertGreater(m.cash_exhaustion_skips, 0)

    def test_out_of_sample_seeds_and_steward_gate(self) -> None:
        oos = run_multi_seed_simulation(seeds=(401, 502, 603, 704), episodes_per_seed=90)
        self.assertEqual(oos["rng_phase_drift"], 0.0)
        self.assertEqual(oos["capital_conservation_delta_cents"], 0)
        cin = oos["regimes"]["CIN_OPCP_IDEMPOTENT_MANDATELOCK_DISCERN"]
        self.assertEqual(cin["total_duplicate_commits"], 0)
        self.assertEqual(cin["extracted_duplicate_and_diversion_cents"], 0)
        self.assertEqual(cin["member_identifier_bytes_leaked"], 0)
        with self.assertRaises(ValueError):
            assert_steward_gate_text("Earn guaranteed returns with MMCT tokens")


if __name__ == "__main__":
    unittest.main()
