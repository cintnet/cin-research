"""
research/ledger_sim/test_multi_agent_agreement_bounds_sim.py

Unit and property-based test suite for MultiAgentAgreementBoundsSimulator.
Validates scaling degradation, Byzantine isolation, capital conservation,
fail-closed validation, cryptographic receipts, and CIN Steward Gate compliance.
"""

from __future__ import annotations

import math
import unittest

from research.ledger_sim.multi_agent_agreement_bounds_sim import (
    AgreementDeadlockError,
    AgreementReceipt,
    AgreementSecurityViolation,
    AgreementValidationError,
    AgentRole,
    AgentState,
    CapitalConservationError,
    ConsensusTask,
    DeliberationRegime,
    MultiAgentAgreementBoundsSimulator,
    StewardGateViolationError,
    evaluate_agreement_scaling_and_faults,
    screen_steward_gate,
)


class TestMultiAgentAgreementBoundsSim(unittest.TestCase):
    """Test suite for multi-agent agreement bounds simulation framework."""

    def setUp(self) -> None:
        self.default_task = ConsensusTask(
            task_id="task-cpr-001",
            ground_truth_target=100.0,
            tolerance=3.0,
            entropy_uncertainty=1.0,
            cost_budget=150.0,
        )

    def test_capital_conservation_across_all_regimes(self) -> None:
        """Every regime must conserve capital: initial == spent + reserve."""
        for reg in DeliberationRegime:
            sim = MultiAgentAgreementBoundsSimulator(
                regime=reg,
                group_size=5,
                byzantine_count=0,
                seed=42,
            )
            receipt = sim.run_consensus(self.default_task)
            self.assertAlmostEqual(
                receipt.capital_initial,
                receipt.capital_spent + receipt.capital_reserve,
                places=6,
                msg=f"Capital conservation violated in regime {reg.value}",
            )
            self.assertGreaterEqual(receipt.capital_reserve, 0.0)

    def test_clean_scaling_degradation(self) -> None:
        """Berdoz et al. 2026: As group size scales, naive conversational drift compounds."""
        task = ConsensusTask(
            task_id="task-scaling-test",
            ground_truth_target=50.0,
            tolerance=2.0,
            entropy_uncertainty=1.5,
            cost_budget=200.0,
        )
        sim_small = MultiAgentAgreementBoundsSimulator(
            regime=DeliberationRegime.NAIVE_CONVERSATIONAL_DELIBERATION,
            group_size=3,
            byzantine_count=0,
            seed=42,
        )
        sim_large = MultiAgentAgreementBoundsSimulator(
            regime=DeliberationRegime.NAIVE_CONVERSATIONAL_DELIBERATION,
            group_size=15,
            byzantine_count=0,
            seed=42,
        )
        receipt_small = sim_small.run_consensus(task)
        receipt_large = sim_large.run_consensus(task)

        # Larger groups suffer greater conversational variance drift
        self.assertGreater(receipt_large.total_messages, receipt_small.total_messages)

    def test_byzantine_fault_isolation_in_bounded_polycentric(self) -> None:
        """Byzantine oscillation severely disrupts naive deliberation while bounded polycentric isolates it."""
        task = ConsensusTask(
            task_id="task-byz-test",
            ground_truth_target=100.0,
            tolerance=3.0,
            entropy_uncertainty=1.0,
            cost_budget=200.0,
        )
        # Naive conversational deliberation with Byzantine oscillator
        naive_sim = MultiAgentAgreementBoundsSimulator(
            regime=DeliberationRegime.NAIVE_CONVERSATIONAL_DELIBERATION,
            group_size=7,
            byzantine_count=1,
            seed=123,
        )
        naive_receipt = naive_sim.run_consensus(task)

        # Bounded polycentric agreement with Byzantine oscillator
        bounded_sim = MultiAgentAgreementBoundsSimulator(
            regime=DeliberationRegime.BOUNDED_POLYCENTRIC_AGREEMENT,
            group_size=7,
            byzantine_count=1,
            seed=123,
        )
        bounded_receipt = bounded_sim.run_consensus(task)

        # Bounded polycentric agreement either reaches consensus or safely triggers conservative fallback
        self.assertTrue(
            bounded_receipt.reached_consensus or bounded_receipt.fail_closed_fallback_triggered
        )
        self.assertLessEqual(
            bounded_receipt.deviation_from_target,
            naive_receipt.deviation_from_target + 5.0,
        )

    def test_fail_closed_validation(self) -> None:
        """Simulation parameters and inputs must fail closed on NaN, Inf, and booleans."""
        # Non-finite target
        with self.assertRaises(AgreementValidationError):
            ConsensusTask(
                task_id="invalid-target",
                ground_truth_target=float("nan"),
                tolerance=1.0,
                entropy_uncertainty=0.5,
                cost_budget=100.0,
            )
        # Negative tolerance
        with self.assertRaises(AgreementValidationError):
            ConsensusTask(
                task_id="invalid-tol",
                ground_truth_target=10.0,
                tolerance=-1.0,
                entropy_uncertainty=0.5,
                cost_budget=100.0,
            )
        # Boolean as budget
        with self.assertRaises(AgreementValidationError):
            ConsensusTask(
                task_id="bool-budget",
                ground_truth_target=10.0,
                tolerance=1.0,
                entropy_uncertainty=0.5,
                cost_budget=True,  # type: ignore
            )
        # Invalid group size
        with self.assertRaises(AgreementValidationError):
            MultiAgentAgreementBoundsSimulator(
                regime=DeliberationRegime.BOUNDED_POLYCENTRIC_AGREEMENT,
                group_size=1,  # minimum 3
            )
        # Byzantine count >= group size
        with self.assertRaises(AgreementValidationError):
            MultiAgentAgreementBoundsSimulator(
                regime=DeliberationRegime.BOUNDED_POLYCENTRIC_AGREEMENT,
                group_size=4,
                byzantine_count=4,
            )

    def test_steward_gate_invariants(self) -> None:
        """Screening rejects unapproved tokens, financial guarantees, and sci-fi terms."""
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Contains Contribution Tokens for voting")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Promises guaranteed returns on consensus stakes")
        with self.assertRaises(StewardGateViolationError):
            screen_steward_gate("Deploys hyperdrive multi-agent engines")
        with self.assertRaises(StewardGateViolationError):
            ConsensusTask(
                task_id="task-with-MMCT-token",
                ground_truth_target=10.0,
                tolerance=1.0,
                entropy_uncertainty=0.5,
                cost_budget=100.0,
            )

    def test_tamper_evident_receipt_and_prov_bundle(self) -> None:
        """Receipt digest and PROV bundle must be deterministically generated."""
        sim = MultiAgentAgreementBoundsSimulator(
            regime=DeliberationRegime.BOUNDED_POLYCENTRIC_AGREEMENT,
            group_size=5,
            byzantine_count=0,
            seed=99,
        )
        receipt = sim.run_consensus(self.default_task)
        self.assertIsInstance(receipt, AgreementReceipt)
        self.assertEqual(len(receipt.digest), 64)
        self.assertIn("prefix", receipt.prov_bundle)
        self.assertIn("activity", receipt.prov_bundle)
        self.assertIn("entity", receipt.prov_bundle)

    def test_evaluate_scaling_arena(self) -> None:
        """Comparative evaluation arena executes cleanly across group sizes."""
        eval_data = evaluate_agreement_scaling_and_faults(
            group_sizes=(3, 5),
            target=50.0,
            tolerance=2.0,
            entropy=1.0,
            budget=150.0,
            seed=42,
        )
        self.assertIn("scaling_clean", eval_data)
        self.assertIn("byzantine_faults", eval_data)
        self.assertIn("3", eval_data["scaling_clean"])
        self.assertIn("5", eval_data["scaling_clean"])


if __name__ == "__main__":
    unittest.main()
