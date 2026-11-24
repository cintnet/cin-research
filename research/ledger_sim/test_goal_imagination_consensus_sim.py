#!/usr/bin/env python3
"""
Unit Tests for Goal Imagination Consensus Simulation & DAG Topology Alignment
(research/ledger_sim/test_goal_imagination_consensus_sim.py)

Validates:
  - Fail-closed validations on GoalVector and AgentIntent data models.
  - Mathematical correctness of L2 dispersion and consensus score computations.
  - Multi-agent goal consensus selection under MAGI (arXiv:2403.03172).
  - Multi-agent DAG execution pipeline alignment and drift localization.
  - W3C PROV-DM cryptographic provenance receipt generation.
  - Multi-regime benchmark across 10 deterministic seeds.
  - Strict Steward Gate defense against premature tokens, royalties, and speculative claims.
"""

import math
import sys
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
REPO_ROOT = TEST_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

try:
    from research.ledger_sim.goal_imagination_consensus_sim import (
        AgentIntent,
        CoordinationRegime,
        GoalEvaluation,
        GoalImaginationConsensusEngine,
        GoalVector,
        StewardGateViolationError,
        assert_steward_gate_compliance,
        canonical_sha256,
        run_coordination_benchmark,
    )
except ImportError:
    from goal_imagination_consensus_sim import (
        AgentIntent,
        CoordinationRegime,
        GoalEvaluation,
        GoalImaginationConsensusEngine,
        GoalVector,
        StewardGateViolationError,
        assert_steward_gate_compliance,
        canonical_sha256,
        run_coordination_benchmark,
    )


class TestGoalImaginationConsensusSim(unittest.TestCase):
    """Test suite for Goal Imagination Consensus and DAG alignment."""

    def setUp(self) -> None:
        self.engine = GoalImaginationConsensusEngine(
            dispersion_penalty_lambda=1000.0,
            max_consensus_dispersion=2.0,
            consensus_threshold_bps=4000,
        )

    # -----------------------------------------------------------------------
    # Data Model Fail-Closed Validations
    # -----------------------------------------------------------------------

    def test_goal_vector_validation_fail_closed(self) -> None:
        """Verify GoalVector strictly validates types, bounds, and finite floats."""
        # Empty goal_id
        with self.assertRaises(ValueError):
            GoalVector(goal_id="", features=(1.0, 2.0), target_horizon_steps=3, expected_utility_bps=5000)

        # Invalid characters in goal_id
        with self.assertRaises(ValueError):
            GoalVector(goal_id="goal@bad!", features=(1.0, 2.0), target_horizon_steps=3, expected_utility_bps=5000)

        # Non-numeric or boolean features
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, True), target_horizon_steps=3, expected_utility_bps=5000)  # type: ignore

        # NaN or Inf in features
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, float("nan")), target_horizon_steps=3, expected_utility_bps=5000)
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, float("inf")), target_horizon_steps=3, expected_utility_bps=5000)

        # Horizon < 1 or boolean
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, 2.0), target_horizon_steps=0, expected_utility_bps=5000)
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, 2.0), target_horizon_steps=True, expected_utility_bps=5000)  # type: ignore

        # Utility out of range [0, 10000] or boolean
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, 2.0), target_horizon_steps=3, expected_utility_bps=-1)
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, 2.0), target_horizon_steps=3, expected_utility_bps=10001)
        with self.assertRaises(ValueError):
            GoalVector(goal_id="g1", features=(1.0, 2.0), target_horizon_steps=3, expected_utility_bps=False)  # type: ignore

        # Valid goal vector generates deterministic digest
        valid_goal = GoalVector(goal_id="g-alpha", features=(1.0, 2.5), target_horizon_steps=4, expected_utility_bps=7500)
        self.assertEqual(len(valid_goal.digest), 64)
        self.assertEqual(valid_goal.digest, valid_goal.digest)

    def test_agent_intent_validation_fail_closed(self) -> None:
        """Verify AgentIntent validates states, preference dimensions, and tolerances."""
        # Empty agent_id or role_name
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0, 1.0))
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="", current_state=(0.0, 0.0), preference_weights=(1.0, 1.0))

        # Dimension mismatch between state and preference weights
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0,))

        # Negative or NaN preference weights
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0, -0.5))
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0, float("nan")))

        # Dispersion threshold <= 0, NaN, or boolean
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0, 1.0), max_acceptable_dispersion=0.0)
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0, 1.0), max_acceptable_dispersion=float("nan"))
        with self.assertRaises(ValueError):
            AgentIntent(agent_id="a1", role_name="analyst", current_state=(0.0, 0.0), preference_weights=(1.0, 1.0), max_acceptable_dispersion=True)  # type: ignore

    # -----------------------------------------------------------------------
    # Consensus Engine & Evaluation
    # -----------------------------------------------------------------------

    def test_evaluate_candidate_goal_and_consensus_selection(self) -> None:
        """Verify candidate goal evaluation, dispersion computation, and consensus selection."""
        agents = [
            AgentIntent(
                agent_id="agent-1",
                role_name="verifier",
                current_state=(0.5, 0.5),
                preference_weights=(1.0, 0.5),
                max_acceptable_dispersion=3.0,
            ),
            AgentIntent(
                agent_id="agent-2",
                role_name="composer",
                current_state=(0.6, 0.4),
                preference_weights=(0.5, 1.0),
                max_acceptable_dispersion=3.0,
            ),
        ]

        # Candidate 1: Close achievable state with high utility
        goal_a = GoalVector(goal_id="goal-a", features=(1.2, 1.0), target_horizon_steps=3, expected_utility_bps=8000)
        # Candidate 2: Far state with extreme utility but high dispersion
        goal_b = GoalVector(goal_id="goal-b", features=(5.0, 5.0), target_horizon_steps=3, expected_utility_bps=9500)

        eval_a = self.engine.evaluate_candidate_goal(goal_a, agents)
        eval_b = self.engine.evaluate_candidate_goal(goal_b, agents)

        # Goal A has lower dispersion than Goal B
        self.assertLess(eval_a.mean_dispersion, eval_b.mean_dispersion)
        self.assertTrue(eval_a.is_acceptable)
        # Goal B should violate dispersion threshold or agent tolerance
        self.assertFalse(eval_b.is_acceptable)

        # Selection should pick Goal A
        selected, best_eval, all_evals = self.engine.select_consensus_goal([goal_a, goal_b], agents)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.goal_id, "goal-a")
        self.assertEqual(best_eval.goal_id, "goal-a")
        self.assertEqual(len(all_evals), 2)

    def test_dag_execution_alignment_and_drift_detection(self) -> None:
        """Verify DAG intermediate node checks identify trajectory drift and suggest corrections."""
        consensus_goal = GoalVector(
            goal_id="goal-consensus",
            features=(2.0, 4.0),
            target_horizon_steps=4,
            expected_utility_bps=8500,
        )

        dag_nodes = [
            {"node_id": "step-1", "step_index": 1},
            {"node_id": "step-2", "step_index": 2},
            {"node_id": "step-3", "step_index": 3},
        ]

        # Perfectly aligned intermediate states
        # step 1: (0.5, 1.0), step 2: (1.0, 2.0), step 3: (1.5, 3.0)
        aligned_states = {
            "step-1": (0.5, 1.0),
            "step-2": (1.0, 2.0),
            "step-3": (1.5, 3.0),
        }

        report_aligned = self.engine.align_dag_execution(
            consensus_goal, dag_nodes, aligned_states, max_allowed_drift=0.5
        )
        self.assertTrue(report_aligned["pipeline_aligned"])
        self.assertEqual(report_aligned["drift_detected_count"], 0)

        # Drifting intermediate state at step-2
        drifting_states = {
            "step-1": (0.5, 1.0),
            "step-2": (3.5, -1.0),  # Severe drift away from expected (1.0, 2.0)
            "step-3": (1.5, 3.0),
        }
        report_drifting = self.engine.align_dag_execution(
            consensus_goal, dag_nodes, drifting_states, max_allowed_drift=0.5
        )
        self.assertFalse(report_drifting["pipeline_aligned"])
        self.assertGreater(report_drifting["drift_detected_count"], 0)
        # Check that an adjustment vector was generated for step-2
        step_2_check = next(c for c in report_drifting["node_checks"] if c["node_id"] == "step-2")
        self.assertTrue(step_2_check["drift_exceeded"])
        self.assertIsNotNone(step_2_check["adjustment_vector"])

    def test_w3c_prov_receipt_generation(self) -> None:
        """Verify W3C PROV-DM cryptographic receipts compute deterministic digests."""
        agents = [
            AgentIntent(
                agent_id="agent-1",
                role_name="coordinator",
                current_state=(1.0, 1.0),
                preference_weights=(1.0, 1.0),
            )
        ]
        goal = GoalVector(
            goal_id="g-prov",
            features=(2.0, 2.0),
            target_horizon_steps=2,
            expected_utility_bps=7000,
        )
        evaluation = self.engine.evaluate_candidate_goal(goal, agents)
        receipt = self.engine.create_prov_receipt(agents, goal, evaluation)

        self.assertIn("prov_statement", receipt)
        self.assertIn("statement_digest", receipt)
        self.assertEqual(len(receipt["statement_digest"]), 64)
        self.assertEqual(receipt["prov_statement"]["magi:primary_source"], "arXiv:2403.03172")
        self.assertEqual(receipt["prov_statement"]["magi:consensus_goal_id"], "g-prov")

    # -----------------------------------------------------------------------
    # Multi-Regime Benchmark & Invariants
    # -----------------------------------------------------------------------

    def test_multi_regime_benchmark_10_seeds(self) -> None:
        """Verify multi-regime simulation executes across 10 deterministic seeds."""
        seeds = list(range(1, 11))
        results = run_coordination_benchmark(seeds, num_agents=4, num_candidate_goals=6, feature_dim=3)

        summary = results["summary"]
        self.assertIn(CoordinationRegime.UNCOORDINATED_LOCAL, summary)
        self.assertIn(CoordinationRegime.AUTOREGRESSIVE_TOKEN_DEBATE, summary)
        self.assertIn(CoordinationRegime.MAGI_GOAL_IMAGINATION, summary)

        magi_stats = summary[CoordinationRegime.MAGI_GOAL_IMAGINATION]
        uncoord_stats = summary[CoordinationRegime.UNCOORDINATED_LOCAL]
        debate_stats = summary[CoordinationRegime.AUTOREGRESSIVE_TOKEN_DEBATE]

        # MAGI achieves higher completion rate and lower dispersion than uncoordinated
        self.assertGreaterEqual(magi_stats["completion_rate_pct"], uncoord_stats["completion_rate_pct"])
        self.assertLess(magi_stats["mean_dispersion"], uncoord_stats["mean_dispersion"])

        # MAGI uses dramatically fewer tokens than multi-turn autoregressive debate
        self.assertLess(magi_stats["mean_token_cost"], debate_stats["mean_token_cost"])

        # Decoupled RNG determinism check: re-running with the same seeds produces identical summary
        results_repeat = run_coordination_benchmark(seeds, num_agents=4, num_candidate_goals=6, feature_dim=3)
        self.assertEqual(results["summary"], results_repeat["summary"])

    # -----------------------------------------------------------------------
    # Strict Steward Gate Compliance
    # -----------------------------------------------------------------------

    def test_steward_gate_compliance_invariants(self) -> None:
        """Verify Steward Gate rejects forbidden tokens, speculative dollars, and retired neologisms."""
        forbidden_phrases = [
            "We award 500 Contribution Tokens to participants.",
            "Balances are tracked via MMCT tokens on ledger.",
            "Save +$4,200/yr by adopting this DAG consensus.",
            "Creators receive 85% direct + 10% pool royalty split.",
            "Our model needs 95% Data Shapley threshold.",
            "The Somatic Witness observes the agent execution.",
            "Pre-ADC consensus was established.",
            "Upcoding Reversal was triggered.",
            "The Algebraic Coalition resolves the drift.",
            "Fractured Alignment was detected.",
        ]
        for phrase in forbidden_phrases:
            with self.assertRaises(StewardGateViolationError):
                assert_steward_gate_compliance(phrase)

        # GoalVector with forbidden pattern in goal_id or metadata fails closed
        with self.assertRaises(StewardGateViolationError):
            GoalVector(
                goal_id="goal-MMCT-token",
                features=(1.0, 1.0),
                target_horizon_steps=2,
                expected_utility_bps=5000,
            )

        with self.assertRaises(StewardGateViolationError):
            GoalVector(
                goal_id="goal-good",
                features=(1.0, 1.0),
                target_horizon_steps=2,
                expected_utility_bps=5000,
                metadata={"note": "Includes Contribution Tokens"},
            )


if __name__ == "__main__":
    unittest.main()
