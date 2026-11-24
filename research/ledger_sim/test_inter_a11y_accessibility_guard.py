"""Unit tests for InterA11y Interactive Web Accessibility Guard.

Validates structured WCAG 2.2 rubrics, deterministic DOM inspection heuristics,
safe DOM construction, Steward Gate invariants, and cryptographic receipt verification.
Grounded on arXiv:2610.39488 (InterA11y, University of Washington, Oct 2026).
"""

import sys
import unittest
from pathlib import Path

# Ensure research/ledger_sim is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from research.ledger_sim.inter_a11y_accessibility_guard import (
    InterA11yAccessibilityGuard,
    InterA11yAuditReport,
    InterA11yViolation,
    verify_inter_a11y_receipt,
)


class TestInterA11yAccessibilityGuard(unittest.TestCase):
    """Test suite validating deterministic accessibility & composition checking."""

    def setUp(self) -> None:
        self.guard = InterA11yAccessibilityGuard()

    def test_clean_accessible_snippet_passes(self) -> None:
        """Valid accessible HTML with proper labels, buttons, and safe DOM passes with 100% score."""
        clean_html = """
        <header role="banner">
          <h1>Collective Intelligence Network</h1>
          <nav aria-label="Main Navigation">
            <button type="button" aria-label="Toggle Navigation Menu">Menu</button>
          </nav>
        </header>
        <main role="main">
          <section aria-labelledby="overview-heading">
            <h2 id="overview-heading">Overview</h2>
            <p>A minimalist blank-slate sanctuary for human agency.</p>
            <img src="diagram.svg" alt="Topology DAG Architecture" width="400" height="200">
            <button type="button" class="whoami-btn-primary">Enter Sanctuary</button>
          </section>
        </main>
        """
        report = self.guard.audit_snippet(clean_html)
        self.assertTrue(report.is_compliant)
        self.assertEqual(report.total_violations, 0)
        self.assertEqual(report.wcag_conformance_score, 1.0)
        self.assertEqual(report.empirical_recall_benchmark, 0.790)
        self.assertEqual(report.baseline_llm_recall, 0.444)
        self.assertTrue(verify_inter_a11y_receipt(report))

    def test_detects_unsafe_dom_construction(self) -> None:
        """Flags .innerHTML, outerHTML, and eval() as CRITICAL security violations."""
        unsafe_js = """
        function renderCard(data) {
          const el = document.getElementById("target");
          el.innerHTML = "<div>" + data.text + "</div>";
          eval("console.log(data)");
        }
        """
        report = self.guard.audit_snippet(unsafe_js)
        self.assertFalse(report.is_compliant)
        self.assertGreaterEqual(report.critical_count, 2)
        rules = [v.rule_id for v in report.violations]
        self.assertIn("SAFE_DOM", rules)
        self.assertLess(report.wcag_conformance_score, 0.5)
        self.assertTrue(verify_inter_a11y_receipt(report))

    def test_detects_steward_gate_invariants(self) -> None:
        """Flags unapproved MMCT tokens, speculative dollar promises, and sci-fi lore."""
        violating_copy = """
        <div class="card">
          <h3>Stage 2 Rewards</h3>
          <p>Earn +50 Contribution Tokens (MMCT) upon completion!</p>
          <p>Identifies +$11,420/yr in recoverable household savings.</p>
          <p>Pairs with Somatic Witness Ring hardware.</p>
        </div>
        """
        report = self.guard.audit_snippet(violating_copy)
        self.assertFalse(report.is_compliant)
        self.assertGreaterEqual(report.critical_count, 3)
        rules = [v.rule_id for v in report.violations]
        self.assertIn("STEWARD_GATE", rules)
        self.assertTrue(verify_inter_a11y_receipt(report))

    def test_detects_missing_button_accessible_names(self) -> None:
        """Flags buttons with no text and no aria-label under WCAG 4.1.2."""
        bad_buttons = """
        <div>
          <button type="button" class="icon-btn"><svg></svg></button>
          <button type="button" class="whoami-btn-ghost"></button>
        </div>
        """
        report = self.guard.audit_snippet(bad_buttons)
        self.assertFalse(report.is_compliant)
        self.assertGreaterEqual(report.high_count, 1)
        rules = [v.rule_id for v in report.violations]
        self.assertIn("4.1.2", rules)

    def test_detects_unlabelled_images(self) -> None:
        """Flags images missing alt attributes or aria-hidden under WCAG 1.1.1."""
        bad_img = """
        <div>
          <img src="/assets/hero.png">
          <img src="/assets/chart.png" aria-label="Bar chart">
          <img src="/assets/spacer.png" alt="">
        </div>
        """
        report = self.guard.audit_snippet(bad_img)
        self.assertFalse(report.is_compliant)
        self.assertEqual(report.high_count, 1)
        self.assertEqual(report.violations[0].rule_id, "1.1.1")

    def test_detects_non_interactive_click_listeners(self) -> None:
        """Flags divs or spans with click handlers without role='button' and tabindex='0'."""
        bad_div = """
        <div class="card" onclick="openModal()">Click here</div>
        """
        report = self.guard.audit_snippet(bad_div)
        self.assertFalse(report.is_compliant)
        self.assertGreaterEqual(report.high_count, 1)
        self.assertEqual(report.violations[0].rule_id, "2.1.1")

    def test_detects_unlabelled_dialogs(self) -> None:
        """Flags dialogs missing aria-label or aria-labelledby under WCAG 4.1.2."""
        bad_dialog = """
        <div role="dialog" class="whoami-system-window">
          <div>Dialog content</div>
        </div>
        """
        report = self.guard.audit_snippet(bad_dialog)
        self.assertFalse(report.is_compliant)
        self.assertGreaterEqual(report.medium_count, 1)
        self.assertEqual(report.violations[0].rule_id, "4.1.2")

    def test_receipt_tamper_detection(self) -> None:
        """Verifies that tampering with report score or violations invalidates SHA-256 digest."""
        clean_html = "<button type='button'>Save Settings</button>"
        report = self.guard.audit_snippet(clean_html)
        self.assertTrue(verify_inter_a11y_receipt(report))

        # Tampered report with forged score
        tampered_report = InterA11yAuditReport(
            is_compliant=report.is_compliant,
            total_violations=report.total_violations,
            critical_count=report.critical_count,
            high_count=report.high_count,
            medium_count=report.medium_count,
            wcag_conformance_score=0.999,  # altered
            empirical_recall_benchmark=report.empirical_recall_benchmark,
            baseline_llm_recall=report.baseline_llm_recall,
            violations=report.violations,
            tamper_resistant_receipt=report.tamper_resistant_receipt,
        )
        self.assertFalse(verify_inter_a11y_receipt(tampered_report))

    def test_empirical_recall_benchmark_provenance(self) -> None:
        """Verifies InterA11y 79.0% empirical recall vs 44.4% LLM baseline grounding (arXiv:2610.39488)."""
        report = self.guard.audit_snippet("<p>Test</p>")
        self.assertAlmostEqual(report.empirical_recall_benchmark, 0.790, places=3)
        self.assertAlmostEqual(report.baseline_llm_recall, 0.444, places=3)
        self.assertIn("arXiv:2610.39488", report.provenance_source)


if __name__ == "__main__":
    unittest.main()
