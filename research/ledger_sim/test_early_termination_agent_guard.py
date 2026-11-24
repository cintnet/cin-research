"""Unit tests for EarlyTerminationAgentGuard inside research/ledger_sim."""

from __future__ import annotations

import unittest

try:
    from research.ledger_sim.early_termination_agent_guard import (
        DEFAULT_FAILURE_SIGNATURES,
        EarlyTerminationAgentGuard,
        EarlyTerminationDegradationError,
        FailureCategory,
        FailureSignature,
        SchemaValidationError,
        StewardGateViolationError,
        TraceStep,
    )
except ImportError:
    from early_termination_agent_guard import (
        DEFAULT_FAILURE_SIGNATURES,
        EarlyTerminationAgentGuard,
        EarlyTerminationDegradationError,
        FailureCategory,
        FailureSignature,
        SchemaValidationError,
        StewardGateViolationError,
        TraceStep,
    )


class TestLedgerSimEarlyTerminationAgentGuard(unittest.TestCase):
    """Test suite for EarlyTerminationAgentGuard integrated into ledger simulation."""

    def setUp(self) -> None:
        self.guard = EarlyTerminationAgentGuard(
            confidence_threshold=0.90,
            max_prefix_k=5,
            baseline_budget_tokens=4000,
        )

    def test_navigation_circular_redirect_detected(self) -> None:
        """Circular navigation A -> B -> A must trigger SIG-NAV-CIRCULAR-REDIRECT at K=3."""
        trajectory = [
            TraceStep(step_index=0, action_type="navigate", target_uri="https://example.com/search", tokens_used=120),
            TraceStep(step_index=1, action_type="navigate", target_uri="https://example.com/details/1", tokens_used=140),
            TraceStep(step_index=2, action_type="navigate", target_uri="https://example.com/search", tokens_used=110),
        ]
        decision = self.guard.evaluate_prefix(trajectory)
        self.assertTrue(decision.should_terminate)
        self.assertEqual(decision.signature_id, "SIG-NAV-CIRCULAR-REDIRECT")
        self.assertEqual(decision.category, FailureCategory.NAVIGATION)
        self.assertEqual(decision.prefix_length, 3)
        self.assertEqual(decision.tokens_consumed, 370)
        self.assertEqual(decision.tokens_saved, 3630)
        self.assertAlmostEqual(decision.token_savings_pct, 90.75, places=2)
        self.assertIn("2-cycle", decision.human_interpretable_diagnostic)
        self.assertTrue(len(decision.w3c_prov_digest) == 64)

    def test_recovery_retry_exhaustion_detected(self) -> None:
        """Three consecutive identical error responses trigger SIG-REC-RETRY-EXHAUSTION."""
        trajectory = [
            TraceStep(step_index=0, action_type="click", target_uri="https://example.com/submit", error_type="TimeoutError", tokens_used=150),
            TraceStep(step_index=1, action_type="retry", target_uri="https://example.com/submit", error_type="TimeoutError", tokens_used=150),
            TraceStep(step_index=2, action_type="retry", target_uri="https://example.com/submit", error_type="TimeoutError", tokens_used=150),
        ]
        decision = self.guard.evaluate_prefix(trajectory)
        self.assertTrue(decision.should_terminate)
        self.assertEqual(decision.signature_id, "SIG-REC-RETRY-EXHAUSTION")
        self.assertEqual(decision.category, FailureCategory.RECOVERY)

    def test_validation_dom_invariant_rejection_detected(self) -> None:
        """Consecutive schema/assertion failures trigger SIG-VAL-DOM-INVARIANT-REJECT."""
        trajectory = [
            TraceStep(step_index=0, action_type="navigate", target_uri="https://example.com/form", tokens_used=100),
            TraceStep(step_index=1, action_type="assert", target_uri="https://example.com/form", status_code=500, error_type="AssertionError", tokens_used=80),
            TraceStep(step_index=2, action_type="validate", target_uri="https://example.com/form", status_code=500, error_type="SchemaMismatch", tokens_used=80),
        ]
        decision = self.guard.evaluate_prefix(trajectory)
        self.assertTrue(decision.should_terminate)
        self.assertEqual(decision.signature_id, "SIG-VAL-DOM-INVARIANT-REJECT")
        self.assertEqual(decision.category, FailureCategory.VALIDATION)

    def test_context_selector_hallucination_detected(self) -> None:
        """Multiple nonexistent DOM selector queries trigger SIG-CTX-SELECTOR-HALLUCINATION at K=4."""
        trajectory = [
            TraceStep(step_index=0, action_type="navigate", target_uri="https://example.com/app", tokens_used=100),
            TraceStep(step_index=1, action_type="click", target_uri="https://example.com/app", dom_selector="#phantom-modal-submit", error_type="NoSuchElementException", tokens_used=120),
            TraceStep(step_index=2, action_type="wait", target_uri="https://example.com/app", tokens_used=50),
            TraceStep(step_index=3, action_type="click", target_uri="https://example.com/app", dom_selector="//div[@id='phantom-card']", error_type="SelectorNotFound", tokens_used=120),
        ]
        decision = self.guard.evaluate_prefix(trajectory)
        self.assertTrue(decision.should_terminate)
        self.assertEqual(decision.signature_id, "SIG-CTX-SELECTOR-HALLUCINATION")
        self.assertEqual(decision.category, FailureCategory.CONTEXT)

    def test_healthy_forward_progression_continues(self) -> None:
        """Healthy non-repetitive navigation continues without early termination."""
        trajectory = [
            TraceStep(step_index=0, action_type="navigate", target_uri="https://example.com/catalog", tokens_used=120),
            TraceStep(step_index=1, action_type="type", target_uri="https://example.com/catalog", dom_selector="input#search", tokens_used=90),
            TraceStep(step_index=2, action_type="click", target_uri="https://example.com/catalog", dom_selector="button#submit", tokens_used=110),
            TraceStep(step_index=3, action_type="navigate", target_uri="https://example.com/results", payload_digest="hash123", tokens_used=150),
        ]
        decision = self.guard.evaluate_prefix(trajectory)
        self.assertFalse(decision.should_terminate)
        self.assertIsNone(decision.signature_id)

    def test_w3c_prov_bundle_generation(self) -> None:
        """PROV-DM bundle contains valid JSON-LD entities, activities, and SHA-256 digest."""
        trajectory = [
            TraceStep(step_index=0, action_type="navigate", target_uri="https://example.com/home", tokens_used=100),
            TraceStep(step_index=1, action_type="navigate", target_uri="https://example.com/item", tokens_used=100),
            TraceStep(step_index=2, action_type="navigate", target_uri="https://example.com/home", tokens_used=100),
        ]
        decision = self.guard.evaluate_prefix(trajectory)
        bundle = self.guard.generate_w3c_prov_bundle(decision)
        self.assertIn("@context", bundle)
        self.assertIn("entity", bundle)

    def test_steward_gate_invariants(self) -> None:
        """Forbidden tokens and claims in trace data or signatures trigger StewardGateViolationError."""
        with self.assertRaises(StewardGateViolationError):
            TraceStep(
                step_index=0,
                action_type="click",
                target_uri="https://example.com",
                dom_selector="div.claim-mmct-token",
            )


if __name__ == "__main__":
    unittest.main()
