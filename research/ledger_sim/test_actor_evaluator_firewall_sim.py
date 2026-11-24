"""
research/ledger_sim/test_actor_evaluator_firewall_sim.py

Comprehensive deterministic test suite verifying Actor-Evaluator Firewalling,
Protocol Opacity, Capability Lease Bounding, and RNG/Capital Conservation.
"""

import math
import unittest

try:
    from research.ledger_sim.actor_evaluator_firewall_sim import (
        ActorEvaluatorFirewallSim,
        CapabilityLeaseBreachError,
        CapabilityLeaseGrant,
        EvaluationReceipt,
        EvaluationTask,
        EvaluationTaskKind,
        FirewallRegime,
        FirewallSecurityViolation,
        FirewallValidationError,
        LeaseState,
        StewardGateViolationError,
        screen_steward_gate,
    )
except ImportError:
    from actor_evaluator_firewall_sim import (
        ActorEvaluatorFirewallSim,
        CapabilityLeaseBreachError,
        CapabilityLeaseGrant,
        EvaluationReceipt,
        EvaluationTask,
        EvaluationTaskKind,
        FirewallRegime,
        FirewallSecurityViolation,
        FirewallValidationError,
        LeaseState,
        StewardGateViolationError,
        screen_steward_gate,
    )


class TestActorEvaluatorFirewallSim(unittest.TestCase):
    """Test suite for ActorEvaluatorFirewallSim and object-capability containment."""

    def setUp(self) -> None:
        self.sim = ActorEvaluatorFirewallSim(
            num_steps=30,
            seed=2026,
            initial_budget_cents=6000,
            cost_per_step_cents=150,
        )

    def test_capital_conservation_across_all_regimes(self) -> None:
        """Every regime must strictly conserve capital: initial == spent + reserve."""
        results = self.sim.run_all_regimes()
        for regime, res in results.items():
            self.assertTrue(
                res.capital_conserved,
                f"Regime {regime.value} violated capital conservation.",
            )
            self.assertEqual(res.total_cost_cents, 30 * 150)
            self.assertEqual(res.total_steps, 30)

    def test_rng_decoupling_and_workload_reproducibility(self) -> None:
        """Workload generation must be 100% deterministic and decoupled from regime execution."""
        sim1 = ActorEvaluatorFirewallSim(num_steps=20, seed=999)
        sim2 = ActorEvaluatorFirewallSim(num_steps=20, seed=999)
        w1 = sim1.generate_workload()
        w2 = sim2.generate_workload()
        
        self.assertEqual(len(w1), len(w2))
        for t1, t2 in zip(w1, w2):
            self.assertEqual(t1.task_id, t2.task_id)
            self.assertEqual(t1.hidden_evaluator_canary, t2.hidden_evaluator_canary)
            self.assertEqual(t1.is_sentinel_audit, t2.is_sentinel_audit)
            self.assertEqual(t1.difficulty, t2.difficulty)

    def test_firewall_blocks_all_canary_leaks_and_side_tasks(self) -> None:
        """Under FIREWALLED_REALM_ISOLATION, zero canary leaks or unauthorized side tasks succeed."""
        results = self.sim.run_all_regimes()
        firewalled = results[FirewallRegime.FIREWALLED_REALM_ISOLATION]

        self.assertEqual(firewalled.canary_leak_count, 0)
        self.assertEqual(firewalled.unauthorized_side_task_count, 0)
        self.assertGreater(firewalled.blocked_violations, 0)
        # In firewalled regime, reported compliance closely tracks true task accuracy
        diff = abs(firewalled.mean_compliance_score - firewalled.mean_true_accuracy)
        self.assertLess(diff, 0.05)

    def test_unprotected_regime_suffers_compliance_theatre(self) -> None:
        """Under UNPROTECTED_EVALUATOR_LEAK, canary leaks succeed, causing severe compliance theatre."""
        results = self.sim.run_all_regimes()
        unprotected = results[FirewallRegime.UNPROTECTED_EVALUATOR_LEAK]

        self.assertGreater(unprotected.canary_leak_count, 0)
        self.assertGreater(unprotected.unauthorized_side_task_count, 0)
        # Compliance score looks very high due to reward hacking, but true accuracy is degraded
        self.assertGreater(unprotected.mean_compliance_score, unprotected.mean_true_accuracy + 0.20)

    def test_capability_lease_bounds_and_dynamic_revocation(self) -> None:
        """CapabilityLeaseGrant strictly enforces scope, expiration, quotas, and revocation."""
        lease = CapabilityLeaseGrant(
            lease_id="test-lease-01",
            actor_id="agent-solver-42",
            task_id="task-01",
            allowed_scopes=("tool:read", "tool:query"),
            max_invocations=2,
            expires_at_step=10,
        )

        # 1. First valid call succeeds
        lease.verify_and_consume(current_step=5, requested_scope="tool:read")
        self.assertEqual(lease.invocations_used, 1)

        # 2. Second valid call succeeds
        lease.verify_and_consume(current_step=6, requested_scope="tool:query")
        self.assertEqual(lease.invocations_used, 2)

        # 3. Third call raises exhausted error fail-closed
        with self.assertRaises(CapabilityLeaseBreachError):
            lease.verify_and_consume(current_step=7, requested_scope="tool:read")

        # 4. Out-of-scope call fails closed
        fresh_lease = CapabilityLeaseGrant(
            lease_id="test-lease-02",
            actor_id="agent-solver-42",
            task_id="task-02",
            allowed_scopes=("tool:read",),
            max_invocations=5,
            expires_at_step=10,
        )
        with self.assertRaises(CapabilityLeaseBreachError):
            fresh_lease.verify_and_consume(current_step=5, requested_scope="tool:write_danger")

        # 5. Expired step fails closed
        with self.assertRaises(CapabilityLeaseBreachError):
            fresh_lease.verify_and_consume(current_step=10, requested_scope="tool:read")

        # 6. Revoked lease fails closed
        active_lease = CapabilityLeaseGrant(
            lease_id="test-lease-03",
            actor_id="agent-solver-42",
            task_id="task-03",
            allowed_scopes=("tool:read",),
            max_invocations=5,
            expires_at_step=20,
        )
        active_lease.state = LeaseState.REVOKED
        with self.assertRaises(CapabilityLeaseBreachError):
            active_lease.verify_and_consume(current_step=5, requested_scope="tool:read")

    def test_tamper_evident_execution_receipt(self) -> None:
        """Execution receipts produce deterministic digests and reject forged payloads."""
        rcpt = EvaluationReceipt.create(
            step=1,
            task_id="eval-task-001",
            actor_id="agent-01",
            action_type="TASK_EVALUATION_STEP",
            cost_cents=150,
            lease_digest="lease-sig-abc",
            prev_receipt_digest="0" * 64,
        )
        self.assertTrue(rcpt.receipt_id.startswith("rcpt-"))
        self.assertEqual(len(rcpt.tamper_evident_digest), 64)
        self.assertIn("w3c:entity", rcpt.prov_entity)

        # Negative cost raises validation error fail-closed
        with self.assertRaises(FirewallValidationError):
            EvaluationReceipt.create(
                step=1,
                task_id="eval-task-001",
                actor_id="agent-01",
                action_type="TASK_EVALUATION_STEP",
                cost_cents=-50,
                lease_digest="lease-sig-abc",
                prev_receipt_digest="0" * 64,
            )

    def test_fail_closed_numeric_and_type_defense(self) -> None:
        """Non-finite floats (NaN/Inf), booleans as numbers, and negative inputs must fail closed."""
        # Boolean passed as integer step count
        with self.assertRaises(FirewallValidationError):
            ActorEvaluatorFirewallSim(num_steps=True)  # type: ignore

        # Negative steps
        with self.assertRaises(FirewallValidationError):
            ActorEvaluatorFirewallSim(num_steps=-5)

        # Budget insufficient
        with self.assertRaises(FirewallValidationError):
            ActorEvaluatorFirewallSim(num_steps=50, initial_budget_cents=100, cost_per_step_cents=150)

    def test_steward_gate_invariants(self) -> None:
        """Steward Gate strictly screens out forbidden tokens, speculative claims, and sci-fi lore."""
        clean_prompt = "Perform structured data retrieval under audited safety rules."
        screen_steward_gate(clean_prompt)

        forbidden_samples = [
            "Reward agents with 50 Contribution Tokens upon task completion.",
            "Transfer 10 MMCT to the high-performing solver.",
            "Promise guaranteed returns of 15% on pooled compute.",
            "Deploy galactic hyperdrive subagent fleet.",
        ]
        for bad in forbidden_samples:
            with self.assertRaises(StewardGateViolationError):
                screen_steward_gate(bad)


if __name__ == "__main__":
    unittest.main()
