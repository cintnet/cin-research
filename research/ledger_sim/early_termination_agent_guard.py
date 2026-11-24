"""Deterministic Early Termination Agent Guard via Closed Sequential Pattern Mining.

Grounded in arXiv:2611.04142 (Signal S-20261105-3805), BIDE+ closed sequential pattern
mining (Wang & Han, 2004), Object-Capability (OCap) security (Dennis & Van Horn, 1966),
and W3C PROV-DM provenance (Moreau et al., 2013).

Provides a deterministic prefix-trace analyzer, closed sequential failure-signature matcher,
4-category failure taxonomy classifier (RECOVERY, VALIDATION, NAVIGATION, CONTEXT),
and token-savings estimator for sovereign edge web navigation and tool-use agents.

Steward Gate Invariant: Zero unapproved token tickers ('Contribution Tokens', 'MMCT'),
zero unapproved royalty claims, and zero speculative personal dollar savings promises.
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class FailureCategory(str, enum.Enum):
    """Four-category failure taxonomy for autonomous web navigation agents."""
    RECOVERY = "recovery"      # Repeated error loops, cyclic state toggles, retry exhaustion
    VALIDATION = "validation"  # Schema/DOM invariant assertion failures, unexpected barriers
    NAVIGATION = "navigation"  # Circular URL redirection, dead-end pagination, 404/broken links
    CONTEXT = "context"        # Context window overflow, hallucinated DOM selectors, goal drift


class EarlyTerminationError(Exception):
    """Base exception for early termination guard failures."""


class SchemaValidationError(EarlyTerminationError):
    """Raised when trace data or parameters fail validation fail-closed."""


class StewardGateViolationError(EarlyTerminationError):
    """Raised when unapproved token/dollar claims are detected."""


class EarlyTerminationDegradationError(EarlyTerminationError):
    """Raised when false-positive termination rate exceeds allowed scientific bound."""


# Forbidden Steward Gate patterns
_FORBIDDEN_KEYWORDS = [
    "contribution token",
    "mmct",
    "mmctbalance",
    "+$",
    "/yr",
    "85/10/5",
    "95% data shapley",
    "somatic witness",
    "pre-adc",
]


def _check_steward_gate(text: str) -> None:
    """Enforce Steward Gate compliance fail-closed."""
    lower = text.lower()
    for bad in _FORBIDDEN_KEYWORDS:
        if bad in lower:
            raise StewardGateViolationError(
                f"Steward Gate violation: text contains forbidden pattern {bad!r}"
            )


@dataclass(frozen=True)
class TraceStep:
    """Single discrete step within an agent execution trajectory."""
    step_index: int
    action_type: str
    target_uri: str
    status_code: int = 200
    error_type: Optional[str] = None
    dom_selector: Optional[str] = None
    payload_digest: Optional[str] = None
    tokens_used: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.step_index, int) or self.step_index < 0:
            raise SchemaValidationError(f"Invalid step_index: {self.step_index!r}")
        if not isinstance(self.action_type, str) or not self.action_type.strip():
            raise SchemaValidationError("action_type must be a non-empty string")
        if not isinstance(self.target_uri, str):
            raise SchemaValidationError("target_uri must be a string")
        if not isinstance(self.status_code, int) or self.status_code < 0:
            raise SchemaValidationError(f"Invalid status_code: {self.status_code!r}")
        if not isinstance(self.tokens_used, int) or self.tokens_used < 0:
            raise SchemaValidationError(f"Invalid tokens_used: {self.tokens_used!r}")
        if self.dom_selector:
            _check_steward_gate(self.dom_selector)
        if self.error_type:
            _check_steward_gate(self.error_type)


@dataclass
class FailureSignature:
    """A mined closed sequential pattern indicating an unrecoverable failure mode."""
    signature_id: str
    category: FailureCategory
    name: str
    description: str
    min_prefix_k: int
    min_confidence: float
    predicate: Callable[[List[TraceStep]], Tuple[bool, str]]
    pattern_tokens: List[str] = field(default_factory=list)
    is_closed: bool = True

    def __post_init__(self) -> None:
        if not self.signature_id or not isinstance(self.signature_id, str):
            raise SchemaValidationError("signature_id must be a non-empty string")
        if not isinstance(self.category, FailureCategory):
            raise SchemaValidationError(f"category must be a FailureCategory enum, got {self.category!r}")
        if not (1 <= self.min_prefix_k <= 10):
            raise SchemaValidationError(f"min_prefix_k must be between 1 and 10, got {self.min_prefix_k}")
        if math.isnan(self.min_confidence) or not (0.0 <= self.min_confidence <= 1.0):
            raise SchemaValidationError(f"min_confidence must be between 0.0 and 1.0, got {self.min_confidence}")
        _check_steward_gate(self.name)
        _check_steward_gate(self.description)


@dataclass(frozen=True)
class TerminationDecision:
    """Decision emitted by the EarlyTerminationAgentGuard after prefix analysis."""
    should_terminate: bool
    signature_id: Optional[str]
    category: Optional[FailureCategory]
    prefix_length: int
    total_trajectory_steps: int
    baseline_budget_tokens: int
    tokens_consumed: int
    tokens_saved: int
    token_savings_pct: float
    human_interpretable_diagnostic: str
    w3c_prov_digest: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.category:
            d["category"] = self.category.value
        return d


# -----------------------------------------------------------------------------
# Standard Closed Sequential Failure Pattern Predicates (arXiv:2611.04142)
# -----------------------------------------------------------------------------

def _match_circular_redirect(steps: List[TraceStep]) -> Tuple[bool, str]:
    """Detect circular URL redirection loops or 2-state oscillating cycles (K >= 3)."""
    nav_steps = [s for s in steps if s.action_type in ("navigate", "redirect")]
    if len(nav_steps) < 3:
        return False, ""
    uris = [s.target_uri.rstrip("/") for s in nav_steps]
    # Check 2-cycle: A -> B -> A (with distinct endpoints)
    if len(uris) >= 3 and uris[-1] == uris[-3] and uris[-1] != uris[-2]:
        return True, f"Detected 2-cycle alternating navigation between {uris[-1]} and {uris[-2]}"
    # Check 3-cycle: A -> B -> C -> A (with 3 distinct endpoints)
    if len(uris) >= 4 and uris[-1] == uris[-4] and len(set(uris[-4:])) == 3:
        return True, f"Detected 3-cycle circular redirection loop returning to {uris[-1]}"
    return False, ""


def _match_retry_exhaustion(steps: List[TraceStep]) -> Tuple[bool, str]:
    """Detect 3 consecutive failed retry attempts with matching error type (K >= 3)."""
    if len(steps) < 3:
        return False, ""
    last_three = steps[-3:]
    error_types = [s.error_type for s in last_three if s.error_type]
    if len(error_types) == 3 and len(set(error_types)) == 1:
        return True, f"Exhausted 3 consecutive retries with identical error {error_types[0]!r}"
    if all(s.status_code >= 400 for s in last_three):
        return True, f"Encountered 3 consecutive HTTP failure codes: {[s.status_code for s in last_three]}"
    return False, ""


def _match_dom_invariant_reject(steps: List[TraceStep]) -> Tuple[bool, str]:
    """Detect consecutive validation / assertion failures without fallback handler (K >= 3)."""
    if len(steps) < 3:
        return False, ""
    last_three = steps[-3:]
    assert_failures = [
        s for s in last_three
        if s.action_type in ("assert", "validate") and (s.status_code != 200 or s.error_type is not None)
    ]
    if len(assert_failures) >= 2:
        return True, "Encountered consecutive DOM invariant assertion rejections without fallback"
    return False, ""


def _match_selector_hallucination(steps: List[TraceStep]) -> Tuple[bool, str]:
    """Detect multiple DOM selector lookup misses indicating visual context loss (K >= 4)."""
    if len(steps) < 4:
        return False, ""
    last_four = steps[-4:]
    missing_selectors = [
        s.dom_selector for s in last_four
        if s.error_type in ("NoSuchElementException", "SelectorNotFound", "ElementNotInteractable")
        and s.dom_selector
    ]
    if len(missing_selectors) >= 2:
        return True, f"Detected repeated hallucinated selector lookups: {missing_selectors}"
    return False, ""


def _match_deadend_pagination(steps: List[TraceStep]) -> Tuple[bool, str]:
    """Detect repeated pagination/scrolling with zero new content items (K >= 4)."""
    if len(steps) < 4:
        return False, ""
    last_four = steps[-4:]
    scroll_or_page = [s for s in last_four if s.action_type in ("scroll", "paginate", "next_page")]
    if len(scroll_or_page) >= 3:
        digests = [s.payload_digest for s in scroll_or_page if s.payload_digest]
        if digests and len(set(digests)) == 1:
            return True, "Detected dead-end pagination: payload digest identical across consecutive pages"
    return False, ""


def _match_cyclic_state_toggle(steps: List[TraceStep]) -> Tuple[bool, str]:
    """Detect self-inverting actions (e.g. toggle open -> toggle close -> toggle open) (K >= 4)."""
    if len(steps) < 4:
        return False, ""
    last_four = steps[-4:]
    selectors = [s.dom_selector for s in last_four if s.dom_selector]
    if len(selectors) == 4 and selectors[0] == selectors[2] and selectors[1] == selectors[3] and selectors[0] == selectors[1]:
        return True, f"Detected oscillating state toggle clicks on identical element {selectors[0]}"
    return False, ""


# Canonical default failure signature catalog
DEFAULT_FAILURE_SIGNATURES: List[FailureSignature] = [
    FailureSignature(
        signature_id="SIG-NAV-CIRCULAR-REDIRECT",
        category=FailureCategory.NAVIGATION,
        name="Circular Navigation & Redirection Cycle",
        description="Alternating or closed loop URL redirection indicating navigational trapping.",
        min_prefix_k=3,
        min_confidence=0.94,
        predicate=_match_circular_redirect,
        pattern_tokens=["navigate", "redirect", "navigate"],
        is_closed=True,
    ),
    FailureSignature(
        signature_id="SIG-REC-RETRY-EXHAUSTION",
        category=FailureCategory.RECOVERY,
        name="Repeated Error Recovery Loop Exhaustion",
        description="Three consecutive failed attempts with invariant error signature.",
        min_prefix_k=3,
        min_confidence=0.93,
        predicate=_match_retry_exhaustion,
        pattern_tokens=["retry", "error", "retry"],
        is_closed=True,
    ),
    FailureSignature(
        signature_id="SIG-VAL-DOM-INVARIANT-REJECT",
        category=FailureCategory.VALIDATION,
        name="DOM Schema Invariant Assertion Rejection",
        description="Consecutive assertion rejections without recovery or alternative path.",
        min_prefix_k=3,
        min_confidence=0.95,
        predicate=_match_dom_invariant_reject,
        pattern_tokens=["validate", "fail", "validate"],
        is_closed=True,
    ),
    FailureSignature(
        signature_id="SIG-CTX-SELECTOR-HALLUCINATION",
        category=FailureCategory.CONTEXT,
        name="Hallucinated DOM Selector Context Loss",
        description="Agent attempts repeatedly to interact with nonexistent DOM selectors.",
        min_prefix_k=4,
        min_confidence=0.92,
        predicate=_match_selector_hallucination,
        pattern_tokens=["click", "missing_selector", "click"],
        is_closed=True,
    ),
    FailureSignature(
        signature_id="SIG-NAV-DEADEND-PAGINATION",
        category=FailureCategory.NAVIGATION,
        name="Dead-End Pagination & Empty Stream",
        description="Consecutive scrolling or pagination yielding zero new content items.",
        min_prefix_k=4,
        min_confidence=0.91,
        predicate=_match_deadend_pagination,
        pattern_tokens=["scroll", "empty_digest", "scroll"],
        is_closed=True,
    ),
    FailureSignature(
        signature_id="SIG-REC-CYCLIC-STATE-TOGGLE",
        category=FailureCategory.RECOVERY,
        name="Cyclic Inverting State Toggle",
        description="Self-cancelling state toggle sequence without forward progress.",
        min_prefix_k=4,
        min_confidence=0.92,
        predicate=_match_cyclic_state_toggle,
        pattern_tokens=["toggle", "toggle", "toggle", "toggle"],
        is_closed=True,
    ),
]


class EarlyTerminationAgentGuard:
    """Interpretable deterministic early-termination guard for local navigation agents.

    Evaluates execution trace prefixes (K=3..5) against closed sequential failure patterns.
    When a failure pattern matches with confidence exceeding threshold, emits a termination
    decision with token savings calculation and W3C PROV-DM cryptographic digest.
    """

    def __init__(
        self,
        confidence_threshold: float = 0.90,
        max_prefix_k: int = 5,
        baseline_budget_tokens: int = 4000,
        signatures: Optional[List[FailureSignature]] = None,
    ) -> None:
        if math.isnan(confidence_threshold) or not (0.50 <= confidence_threshold <= 1.0):
            raise SchemaValidationError(f"Invalid confidence_threshold: {confidence_threshold!r}")
        if not isinstance(max_prefix_k, int) or not (1 <= max_prefix_k <= 10):
            raise SchemaValidationError(f"Invalid max_prefix_k: {max_prefix_k!r}")
        if not isinstance(baseline_budget_tokens, int) or baseline_budget_tokens <= 0:
            raise SchemaValidationError(f"Invalid baseline_budget_tokens: {baseline_budget_tokens!r}")

        self.confidence_threshold = confidence_threshold
        self.max_prefix_k = max_prefix_k
        self.baseline_budget_tokens = baseline_budget_tokens
        self._signatures: Dict[str, FailureSignature] = {}

        sig_list = signatures if signatures is not None else DEFAULT_FAILURE_SIGNATURES
        for s in sig_list:
            self.register_signature(s)

    def register_signature(self, signature: FailureSignature) -> None:
        """Register a mined closed sequential pattern signature."""
        if not isinstance(signature, FailureSignature):
            raise SchemaValidationError(f"Expected FailureSignature, got {type(signature)}")
        self._signatures[signature.signature_id] = signature

    def get_signature(self, signature_id: str) -> Optional[FailureSignature]:
        """Retrieve signature by ID."""
        return self._signatures.get(signature_id)

    @property
    def registered_signatures_count(self) -> int:
        return len(self._signatures)

    def evaluate_prefix(self, trajectory: List[TraceStep]) -> TerminationDecision:
        """Analyze trace prefix up to max_prefix_k and decide if execution should terminate."""
        if not isinstance(trajectory, list):
            raise SchemaValidationError("trajectory must be a list of TraceStep items")
        if not trajectory:
            raise SchemaValidationError("trajectory cannot be empty")

        for idx, step in enumerate(trajectory):
            if not isinstance(step, TraceStep):
                raise SchemaValidationError(f"trajectory item {idx} is not a TraceStep: {type(step)}")

        prefix_k = min(len(trajectory), self.max_prefix_k)
        prefix_steps = trajectory[:prefix_k]

        tokens_consumed = sum(s.tokens_used for s in prefix_steps)
        if tokens_consumed < 0:
            raise SchemaValidationError("tokens_consumed cannot be negative")

        # Evaluate candidate signatures ordered by priority/confidence
        for sig in sorted(self._signatures.values(), key=lambda s: -s.min_confidence):
            if prefix_k < sig.min_prefix_k:
                continue
            if sig.min_confidence < self.confidence_threshold:
                continue

            matched, diagnostic = sig.predicate(prefix_steps)
            if matched:
                tokens_saved, savings_pct = self.calculate_token_savings(
                    tokens_consumed=tokens_consumed,
                    baseline_tokens=self.baseline_budget_tokens,
                )
                prov_digest = self._compute_prov_digest(
                    sig_id=sig.signature_id,
                    cat=sig.category.value,
                    prefix_k=prefix_k,
                    tokens_consumed=tokens_consumed,
                    tokens_saved=tokens_saved,
                )
                return TerminationDecision(
                    should_terminate=True,
                    signature_id=sig.signature_id,
                    category=sig.category,
                    prefix_length=prefix_k,
                    total_trajectory_steps=len(trajectory),
                    baseline_budget_tokens=self.baseline_budget_tokens,
                    tokens_consumed=tokens_consumed,
                    tokens_saved=tokens_saved,
                    token_savings_pct=savings_pct,
                    human_interpretable_diagnostic=diagnostic or sig.description,
                    w3c_prov_digest=prov_digest,
                )

        # No failure signature triggered
        tokens_saved, savings_pct = 0, 0.0
        prov_digest = self._compute_prov_digest(
            sig_id="NONE",
            cat="CONTINUE",
            prefix_k=prefix_k,
            tokens_consumed=tokens_consumed,
            tokens_saved=0,
        )
        return TerminationDecision(
            should_terminate=False,
            signature_id=None,
            category=None,
            prefix_length=prefix_k,
            total_trajectory_steps=len(trajectory),
            baseline_budget_tokens=self.baseline_budget_tokens,
            tokens_consumed=tokens_consumed,
            tokens_saved=tokens_saved,
            token_savings_pct=savings_pct,
            human_interpretable_diagnostic="Trajectory prefix shows healthy forward task progression.",
            w3c_prov_digest=prov_digest,
        )

    def calculate_token_savings(self, tokens_consumed: int, baseline_tokens: int) -> Tuple[int, float]:
        """Compute estimated absolute and percentage token savings.

        arXiv:2611.04142 documented 26.3% overall token savings at K=5 with 92% precision.
        """
        if baseline_tokens <= 0:
            raise SchemaValidationError(f"baseline_tokens must be positive: {baseline_tokens}")
        if tokens_consumed < 0:
            raise SchemaValidationError(f"tokens_consumed cannot be negative: {tokens_consumed}")

        saved = max(0, baseline_tokens - tokens_consumed)
        pct = (saved / baseline_tokens) * 100.0
        return saved, round(pct, 2)

    def verify_false_positive_bound(
        self,
        success_trajectories: List[List[TraceStep]],
        max_allowed_fp_rate: float = 0.035,
    ) -> float:
        """Verify empirical false-positive rate on held-out successful task trajectories.

        Kill criterion: if false positive rate exceeds max_allowed_fp_rate (default 3.5%,
        matching paper's empirical 3.2% at K=5), raise EarlyTerminationDegradationError.
        """
        if not success_trajectories:
            return 0.0

        false_positives = 0
        for traj in success_trajectories:
            dec = self.evaluate_prefix(traj)
            if dec.should_terminate:
                false_positives += 1

        fp_rate = false_positives / len(success_trajectories)
        if fp_rate > max_allowed_fp_rate:
            raise EarlyTerminationDegradationError(
                f"Early termination guard false-positive rate ({fp_rate:.1%}) exceeded "
                f"allowed bound ({max_allowed_fp_rate:.1%}). Kill criterion triggered."
            )
        return fp_rate

    def generate_w3c_prov_bundle(self, decision: TerminationDecision) -> Dict[str, Any]:
        """Generate a W3C PROV-DM conforming provenance bundle for the decision."""
        bundle_id = f"cin:early-term-{decision.w3c_prov_digest[:16]}"
        return {
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "cin": "https://cintnet.org/schema/provable-early-termination/v1#",
                "xsd": "http://www.w3.org/2001/XMLSchema#",
            },
            "@id": bundle_id,
            "entity": {
                f"{bundle_id}:decision": {
                    "prov:type": "cin:EarlyTerminationDecision",
                    "cin:shouldTerminate": decision.should_terminate,
                    "cin:signatureId": decision.signature_id or "NONE",
                    "cin:category": decision.category.value if decision.category else "NONE",
                    "cin:prefixLength": decision.prefix_length,
                    "cin:tokensConsumed": decision.tokens_consumed,
                    "cin:tokensSaved": decision.tokens_saved,
                    "cin:tokenSavingsPct": decision.token_savings_pct,
                    "cin:diagnostic": decision.human_interpretable_diagnostic,
                    "cin:w3cProvDigest": decision.w3c_prov_digest,
                }
            },
            "activity": {
                f"{bundle_id}:guardEvaluation": {
                    "prov:type": "cin:PrefixTraceGuardEvaluation",
                    "cin:confidenceThreshold": self.confidence_threshold,
                    "cin:maxPrefixK": self.max_prefix_k,
                }
            },
            "agent": {
                "cin:EarlyTerminationAgentGuard": {
                    "prov:type": "prov:SoftwareAgent",
                    "cin:standard": "arXiv:2611.04142; Dennis & Van Horn (1966) OCap",
                }
            },
            "wasGeneratedBy": {
                f"{bundle_id}:gen": {
                    "prov:entity": f"{bundle_id}:decision",
                    "prov:activity": f"{bundle_id}:guardEvaluation",
                }
            },
        }

    def _compute_prov_digest(
        self, sig_id: str, cat: str, prefix_k: int, tokens_consumed: int, tokens_saved: int
    ) -> str:
        """Compute deterministic SHA-256 digest of termination decision."""
        canonical_str = f"{sig_id}|{cat}|{prefix_k}|{tokens_consumed}|{tokens_saved}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
