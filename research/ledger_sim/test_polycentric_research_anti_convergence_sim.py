"""
Unit tests for `research/ledger_sim/polycentric_research_anti_convergence_sim.py`.

Verifies:
1. Zero RNG phase drift (`rng_phase_drift == 0.0`) across all three regimes and multiple seeds.
2. Strict integer-cent capital conservation (`capital_conservation_delta_cents == 0`) including under cash exhaustion.
3. Polycentric claim-registry + human-dyad taste + SCITT execution evidence strictly outperforms both
   top-down agenda bureaucracy and uncoordinated synthetic-hivemind swarms on effective project diversity,
   unique viable discoveries, spoofed-run rejection, and net collective surplus (`0` private diary bytes leaked).
4. Fail-closed validation on booleans, NaN/Inf, out-of-range rates, population bounds, and Steward Gate invariants.
"""

from __future__ import annotations

import math
from pathlib import Path
import sys
import unittest

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent.parent
for _p in (str(SIM_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from research.ledger_sim.polycentric_research_anti_convergence_sim import (
    AntiConvergenceConfig,
    AntiConvergenceValidationError,
    ResearchCoordinationRegime,
    ResearchEpisodeItem,
    StewardGateViolationError,
    evaluate_research_regime,
    generate_research_workload,
    main,
    run_three_regime_comparison,
    screen_steward_gate,
)


class TestPolycentricResearchAntiConvergenceSim(unittest.TestCase):
    def test_zero_rng_phase_drift_and_exact_conservation_across_seeds(self) -> None:
        for seed in (7, 42, 2026):
            cfg = AntiConvergenceConfig(seed=seed, num_episodes=360)
            summary = run_three_regime_comparison(cfg)
            self.assertEqual(summary["rng_phase_drift"], 0.0)
            self.assertEqual(summary["capital_conservation_delta_cents"], 0)

            for reg_name, metrics in summary["regimes"].items():
                self.assertEqual(
                    metrics["capital_conservation_delta_cents"],
                    0,
                    f"Conservation leak in {reg_name} for seed {seed}",
                )
                self.assertEqual(metrics["private_diary_bytes_leaked"], 0)

    def test_polycentric_commons_breaks_hivemind_crowding_and_beats_bureaucracy(self) -> None:
        summary = run_three_regime_comparison(AntiConvergenceConfig(seed=42, num_episodes=360))
        top_down = summary["regimes"][ResearchCoordinationRegime.TOP_DOWN_AGENDA_BUREAUCRACY.value]
        hivemind = summary["regimes"][ResearchCoordinationRegime.UNCOORDINATED_SYNTHETIC_HIVEMIND.value]
        poly = summary["regimes"][ResearchCoordinationRegime.POLYCENTRIC_SCITT_DIVERSITY_COMMONS.value]

        # Polycentric claim registry spreads research across many times more effective projects
        self.assertGreater(poly["effective_project_diversity"], hivemind["effective_project_diversity"] * 5.0)
        self.assertGreater(poly["effective_project_diversity"], top_down["effective_project_diversity"] * 4.0)

        # Unintended crowding collisions collapse under shared claim registry
        self.assertLess(poly["duplicate_crowding_rate"], 0.05)
        self.assertGreater(hivemind["duplicate_crowding_rate"], 0.50)

        # Human-dyad problem taste + registry deduplication yields far more unique viable discoveries
        self.assertGreater(poly["viable_unique_discoveries"], hivemind["viable_unique_discoveries"] * 4)
        self.assertGreater(poly["viable_unique_discoveries"], top_down["viable_unique_discoveries"] * 3)

        # Offline SCITT execution-evidence catches 100% of spoofed runs without raw diary leaks
        self.assertEqual(poly["spoof_catch_rate"], 1.0)
        self.assertEqual(poly["uncontained_spoofed_acceptances"], 0)
        self.assertGreater(hivemind["uncontained_spoofed_acceptances"], 0)

        # Net collective surplus and voluntary adoption strictly favor polycentric commons
        self.assertGreater(poly["net_collective_surplus_cents"], top_down["net_collective_surplus_cents"])
        self.assertGreater(poly["net_collective_surplus_cents"], hivemind["net_collective_surplus_cents"])
        self.assertGreaterEqual(poly["voluntary_polycentric_adoption_rate"], 0.90)

    def test_cash_exhaustion_preserves_indivisible_clearing_and_conservation(self) -> None:
        tight_cfg = AntiConvergenceConfig(
            num_orgs=8,
            num_domains=8,
            num_episodes=160,
            initial_org_treasury_cents=10_000,
            compute_escrow_cents=4_500,
            discovery_grant_cents=5_000,
            spoof_collateral_loss_cents=3_000,
            seed=99,
        )
        summary = run_three_regime_comparison(tight_cfg)
        self.assertEqual(summary["capital_conservation_delta_cents"], 0)
        hivemind = summary["regimes"][ResearchCoordinationRegime.UNCOORDINATED_SYNTHETIC_HIVEMIND.value]
        self.assertLess(hivemind["executed_episodes"], tight_cfg.num_episodes)

    def test_deterministic_replay_equivalence(self) -> None:
        cfg = AntiConvergenceConfig(seed=1234, num_episodes=180)
        s1 = run_three_regime_comparison(cfg)
        s2 = run_three_regime_comparison(cfg)
        self.assertEqual(s1, s2)

    def test_fail_closed_config_and_episode_validation(self) -> None:
        with self.assertRaises(AntiConvergenceValidationError):
            AntiConvergenceConfig(num_orgs=True)  # type: ignore[arg-type]
        with self.assertRaises(AntiConvergenceValidationError):
            AntiConvergenceConfig(hivemind_crowded_share=math.nan)
        with self.assertRaises(AntiConvergenceValidationError):
            AntiConvergenceConfig(synthetic_idea_viability_rate=math.inf)
        with self.assertRaises(AntiConvergenceValidationError):
            AntiConvergenceConfig(human_dyad_idea_viability_rate=1.2)
        with self.assertRaises(AntiConvergenceValidationError):
            AntiConvergenceConfig(num_orgs=4, num_domains=8)
        with self.assertRaises(AntiConvergenceValidationError):
            AntiConvergenceConfig(central_bureaucracy_fee_cents=3_000, discovery_grant_cents=2_400)
        with self.assertRaises(AntiConvergenceValidationError):
            evaluate_research_regime(AntiConvergenceConfig(), "INVALID_REGIME")

        wl, _ = generate_research_workload(AntiConvergenceConfig(num_episodes=12))
        base = wl[0]
        with self.assertRaises(AntiConvergenceValidationError):
            ResearchEpisodeItem(
                **{**base.__dict__, "is_spoofed_execution": True}  # type: ignore[arg-type]
            )
        with self.assertRaises(AntiConvergenceValidationError):
            ResearchEpisodeItem(
                **{**base.__dict__, "proposer_org_id": base.verifier_org_id}
            )

    def test_steward_gate_blocks_forbidden_tickers_and_promises(self) -> None:
        for bad in (
            "Mint Contribution Tokens for reviewers",
            "Stake MMCT for research yield",
            "Apply 85/10/5 split",
            "Earn passive income with guaranteed returns",
            "Launch galactic hyperdrive",
        ):
            with self.assertRaises(StewardGateViolationError):
                screen_steward_gate(bad)

    def test_cli_entrypoint_succeeds(self) -> None:
        rc = main(["--simulate", "--episodes", "60", "--seed", "11"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
