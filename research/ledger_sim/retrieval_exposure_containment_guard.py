"""
research/ledger_sim/retrieval_exposure_containment_guard.py

Pre-Context Retrieval Exposure Control and Carrier Quarantine Guard for Search-Augmented Agents.

Scientific Provenance:
- Jack B. Dennis & Earl C. Van Horn (1966): Programming Semantics for Multiprogrammed Computations (CACM)
  [Object-Capability Security, Zero Ambient Authority, and Confinement Boundaries].
- Mark S. Miller, Chip Morningstar, Bill Frantz (2003): Capability Myths Demolished
  [Dynamic Revocation via Caretaker / Revocable Forwarder Pattern & Monotonic Attenuation].
- SearchInject: Retrieval Exposure Control for Indirect Prompt Injection in Language-Model Search
  (arXiv:2611.02643, Nov 2026):
  Pre-context admission control evaluating retrieval relevance, search-abuse cues, instruction likelihood,
  and quarantine thresholds before candidate carrier pages reach model context.
- Kristina Nikolić, Egor Zverev, Javier Rando, Matthew Jagielski, Edoardo Debenedetti, Florian Tramèr
  (ETH Zurich & Anthropic, arXiv:2607.05277, July 2026):
  Untrusted Content Masking for Web Agents with Security Guarantees.
- David Lindner, Charlie Griffin, Tomek Korbak et al.
  (UK AI Security Institute & Google DeepMind, arXiv:2512.22154, Dec 2025):
  Control Monitoring and Synchronous Pre-Execution Barriers.

Key Architectural Guarantees:
1. Pre-Context Admission Filtering: Untrusted retrieved web pages are intercepted and evaluated before
   they can ever enter the reasoning context window of the primary planning agent.
2. Tripartite Exposure Scoring: Computes a calibrated exposure risk score combining query relevance,
   search-abuse signals, and instruction likelihood.
3. Isolated Quarantine Envelopes: Candidates exceeding the calibrated quarantine threshold are held in
   isolated quarantine structures stripped of execution authority.
4. Cryptographic Admission Receipts: Only carrier documents passing the exposure gate receive unforgeable
   admission receipts signed under the active Capability Lease.
5. Fail-Closed Adaptive Revocation: If an active prompt injection attack or carrier poisoning pattern is
   detected, the system dynamically revokes the caller's capability lease via the Caretaker manager.
6. Strict CIN Steward Gate screening across all documents, queries, scores, and receipts.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

try:
    from .capability_lease_containment_guard import (
        ActionScope,
        CapabilityLease,
        DynamicRevocationManager,
        LeaseExpiredError,
        LeaseRevokedError,
        LeaseSecurityViolation,
        LeaseValidationError,
        StewardGateViolationError,
        assert_steward_gate_compliance,
        canonical_sha256,
    )
except ImportError:
    from capability_lease_containment_guard import (  # type: ignore
        ActionScope,
        CapabilityLease,
        DynamicRevocationManager,
        LeaseExpiredError,
        LeaseRevokedError,
        LeaseSecurityViolation,
        LeaseValidationError,
        StewardGateViolationError,
        assert_steward_gate_compliance,
        canonical_sha256,
    )


# =====================================================================
# Error Hierarchy
# =====================================================================

class ExposureControlViolation(LeaseSecurityViolation):
    """Base exception for retrieval exposure control violations."""


class CarrierQuarantineRejection(ExposureControlViolation):
    """Raised when a retrieved carrier document exceeds exposure risk thresholds and is quarantined."""


class AdmissionReceiptVerificationError(ExposureControlViolation):
    """Raised when an admission receipt has an invalid or forged signature."""


# =====================================================================
# Detection Patterns for Search Abuse & Prompt Injection
# =====================================================================

_PROMPT_INJECTION_DIRECTIVES: Tuple[Tuple[re.Pattern, float, str], ...] = (
    (re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)\b", re.I), 0.95, "Instruction override attempt"),
    (re.compile(r"\b(?:system\s*prompt|system\s*directive|system\s*message)\s*:\b", re.I), 0.90, "System prompt delimiter spoofing"),
    (re.compile(r"\b(?:you\s+are\s+now|act\s+as)\s+(?:an?\s+unrestricted|a\s+rogue|a\s+root|an\s+override)\b", re.I), 0.85, "Role hijacking pattern"),
    (re.compile(r"<\s*\|?im_start\|?\s*>|<\s*\|?im_end\|?\s*>", re.I), 0.95, "ChatML control token injection"),
    (re.compile(r"\[\s*INST\s*\]|\[\s*/\s*INST\s*\]", re.I), 0.90, "Llama instruction tag injection"),
    (re.compile(r"\b(?:curl|wget|bash|sh|powershell|cmd\.exe)\s+-[a-zA-Z0-9]", re.I), 0.80, "Raw shell payload command"),
    (re.compile(r"\b(?:format\s+c:|rm\s+-rf\s+/|drop\s+database)\b", re.I), 0.95, "Destructive system payload"),
    (re.compile(r"\b(?:exfiltrate|leak|steal|send\s+to\s+https?://)\b", re.I), 0.75, "Data exfiltration indicator"),
    (re.compile(r"\b(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_-]{16,}['\"])\b", re.I), 0.85, "Secret/Key extraction cue"),
)

_SEARCH_ABUSE_PATTERNS: Tuple[Tuple[re.Pattern, float, str], ...] = (
    (re.compile(r"(?:style\s*=\s*['\"][^'\"]*display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0)", re.I), 0.75, "Hidden text search manipulation"),
    (re.compile(r"(?:<!--.*?--\>)", re.DOTALL), 0.30, "HTML comment container"),
    (re.compile(r"(\b\w+\b)(?:\s+\1){4,}", re.I), 0.70, "Repeated keyword stuffing"),
    (re.compile(r"\b(?:seo\s+spam|meta\s+keywords|hidden\s+payload)\b", re.I), 0.60, "SEO spam cue"),
)


def _validate_safe_string(val: Any, field_name: str, max_length: int = 256) -> str:
    """Validates an identifier string."""
    if not isinstance(val, str):
        raise LeaseValidationError(f"{field_name} must be a str, got {type(val).__name__}")
    s = val.strip()
    if not s:
        raise LeaseValidationError(f"{field_name} cannot be empty")
    if len(s) > max_length:
        raise LeaseValidationError(f"{field_name} exceeds max length {max_length}")
    assert_steward_gate_compliance(s)
    return s


# =====================================================================
# Carrier Document & Exposure Risk Metrics
# =====================================================================

@dataclasses.dataclass(frozen=True)
class CarrierDocument:
    """
    Representation of an untrusted retrieved candidate document from external search.
    Grounded in SearchInject (arXiv:2611.02643).
    """
    document_id: str
    source_uri: str
    raw_content: str
    retrieval_rank: int = 1
    query_relevance: float = 0.5
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_id", _validate_safe_string(self.document_id, "document_id", 128))
        object.__setattr__(self, "source_uri", _validate_safe_string(self.source_uri, "source_uri", 512))
        if not isinstance(self.raw_content, str):
            raise LeaseValidationError("raw_content must be a string")
        if self.retrieval_rank < 1:
            raise LeaseValidationError("retrieval_rank must be >= 1")
        if not (0.0 <= self.query_relevance <= 1.0):
            raise LeaseValidationError(f"query_relevance must be in [0.0, 1.0], got {self.query_relevance}")
        assert_steward_gate_compliance(self.raw_content)

    @property
    def content_digest(self) -> str:
        """Computes deterministic digest of the raw content payload."""
        return hashlib.sha256(self.raw_content.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "source_uri": self.source_uri,
            "content_digest": self.content_digest,
            "retrieval_rank": self.retrieval_rank,
            "query_relevance": round(self.query_relevance, 4),
            "content_length": len(self.raw_content),
        }


@dataclasses.dataclass(frozen=True)
class ExposureRiskMetrics:
    """
    Quantitative risk metrics evaluating document carrier exposure prior to context entry.
    """
    document_id: str
    query_relevance: float
    search_abuse_score: float
    instruction_likelihood: float
    composite_exposure_score: float
    detected_signals: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "query_relevance": round(self.query_relevance, 4),
            "search_abuse_score": round(self.search_abuse_score, 4),
            "instruction_likelihood": round(self.instruction_likelihood, 4),
            "composite_exposure_score": round(self.composite_exposure_score, 4),
            "detected_signals": list(self.detected_signals),
        }


@dataclasses.dataclass(frozen=True)
class QuarantineEnvelope:
    """
    Isolated containment structure holding untrusted carrier documents that exceeded exposure thresholds.
    Ensures zero ambient authority and zero exposure to the primary reasoning context.
    """
    envelope_id: str
    document_id: str
    source_uri: str
    content_digest: str
    exposure_score: float
    quarantine_threshold: float
    reasons: List[str]
    quarantined_at: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "document_id": self.document_id,
            "source_uri": self.source_uri,
            "content_digest": self.content_digest,
            "exposure_score": round(self.exposure_score, 4),
            "quarantine_threshold": round(self.quarantine_threshold, 4),
            "reasons": list(self.reasons),
            "quarantined_at": round(self.quarantined_at, 4),
        }


@dataclasses.dataclass(frozen=True)
class AdmissionReceipt:
    """
    Tamper-evident, cryptographically signed receipt verifying that a candidate carrier document
    successfully passed pre-context retrieval exposure control.
    """
    receipt_id: str
    document_id: str
    source_uri: str
    content_digest: str
    lease_id: str
    exposure_score: float
    quarantine_threshold: float
    admitted_at: float
    signature: str

    def canonical_digest(self) -> str:
        payload = {
            "receipt_id": self.receipt_id,
            "document_id": self.document_id,
            "source_uri": self.source_uri,
            "content_digest": self.content_digest,
            "lease_id": self.lease_id,
            "exposure_score": round(self.exposure_score, 4),
            "quarantine_threshold": round(self.quarantine_threshold, 4),
            "admitted_at": round(self.admitted_at, 4),
        }
        return canonical_sha256(payload)

    def verify_signature(self, secret_key: bytes) -> bool:
        if not self.signature or not secret_key:
            return False
        digest = self.canonical_digest()
        expected = hmac.new(secret_key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "document_id": self.document_id,
            "source_uri": self.source_uri,
            "content_digest": self.content_digest,
            "lease_id": self.lease_id,
            "exposure_score": round(self.exposure_score, 4),
            "quarantine_threshold": round(self.quarantine_threshold, 4),
            "admitted_at": round(self.admitted_at, 4),
            "signature": self.signature,
        }


# =====================================================================
# Retrieval Exposure Containment Guard
# =====================================================================

class RetrievalExposureContainmentGuard:
    """
    Enforces deterministic retrieval exposure control and pre-context carrier quarantine.
    
    Grounded in:
    - SearchInject (arXiv:2611.02643)
    - Dennis & Van Horn Object-Capability security (CACM 1966)
    - Untrusted Content Masking (arXiv:2607.05277)
    """

    def __init__(
        self,
        revocation_manager: DynamicRevocationManager,
        signing_key: bytes,
        quarantine_threshold: float = 0.45,
        relevance_weight: float = 0.30,
        abuse_weight: float = 0.35,
        instruction_weight: float = 0.35,
    ) -> None:
        if not signing_key:
            raise LeaseValidationError("signing_key cannot be empty")
        if not (0.0 < quarantine_threshold < 1.0):
            raise LeaseValidationError("quarantine_threshold must be in (0.0, 1.0)")
        total_weight = relevance_weight + abuse_weight + instruction_weight
        if abs(total_weight - 1.0) > 1e-4:
            raise LeaseValidationError(f"Weights must sum to 1.0, got {total_weight}")

        self._revocation_mgr = revocation_manager
        self._signing_key = signing_key
        self.quarantine_threshold = float(quarantine_threshold)
        self.relevance_weight = float(relevance_weight)
        self.abuse_weight = float(abuse_weight)
        self.instruction_weight = float(instruction_weight)

        self._quarantined_envelopes: Dict[str, QuarantineEnvelope] = {}
        self._admission_receipts: Dict[str, AdmissionReceipt] = {}

    def score_document(self, doc: CarrierDocument, query: str) -> ExposureRiskMetrics:
        """
        Computes tripartite exposure risk score for a retrieved carrier document.
        """
        assert_steward_gate_compliance(query)
        assert_steward_gate_compliance(doc.raw_content)

        detected_signals: List[str] = []

        # 1. Search abuse signals
        abuse_score = 0.0
        for pattern, weight, label in _SEARCH_ABUSE_PATTERNS:
            if pattern.search(doc.raw_content):
                abuse_score = max(abuse_score, weight)
                detected_signals.append(f"abuse:{label}")

        # 2. Instruction likelihood / prompt injection cues
        instruction_score = 0.0
        for pattern, weight, label in _PROMPT_INJECTION_DIRECTIVES:
            if pattern.search(doc.raw_content):
                instruction_score = max(instruction_score, weight)
                detected_signals.append(f"injection:{label}")

        # 3. Composite exposure score:
        # Non-compensatory risk principle (arXiv:2609.39717, arXiv:2611.02643):
        # High query relevance must never compensate for active prompt injection or search abuse signals.
        relevance_risk = max(0.0, 1.0 - doc.query_relevance)
        weighted_risk = (
            self.relevance_weight * relevance_risk
            + self.abuse_weight * abuse_score
            + self.instruction_weight * instruction_score
        )
        composite = max(weighted_risk, instruction_score, abuse_score)
        composite = min(1.0, max(0.0, composite))

        return ExposureRiskMetrics(
            document_id=doc.document_id,
            query_relevance=doc.query_relevance,
            search_abuse_score=abuse_score,
            instruction_likelihood=instruction_score,
            composite_exposure_score=composite,
            detected_signals=detected_signals,
        )

    def evaluate_and_filter_candidates(
        self,
        lease: CapabilityLease,
        query: str,
        candidates: Sequence[CarrierDocument],
        current_time: Optional[float] = None,
    ) -> Tuple[List[AdmissionReceipt], List[QuarantineEnvelope]]:
        """
        Synchronously evaluates candidate carrier pages against exposure control thresholds.
        Admitted documents receive signed receipts; quarantined documents are isolated in envelopes.
        If an explicit prompt injection attempt is detected, cascades fail-closed lease revocation.
        """
        now = time.time() if current_time is None else float(current_time)

        # 1. Verify lease validity
        if not self._revocation_mgr.is_active(lease.lease_id):
            raise LeaseRevokedError(f"Capability lease '{lease.lease_id}' has been revoked")
        if lease.is_expired(now):
            raise LeaseExpiredError(f"Capability lease '{lease.lease_id}' is expired")
        if not lease.verify_signature(self._signing_key):
            raise LeaseSecurityViolation(f"Capability lease '{lease.lease_id}' signature invalid")

        admitted: List[AdmissionReceipt] = []
        quarantined: List[QuarantineEnvelope] = []

        for doc in candidates:
            metrics = self.score_document(doc, query)

            # Check if document exceeds quarantine threshold
            if metrics.composite_exposure_score >= self.quarantine_threshold:
                envelope_id = f"env-{doc.document_id}-{hashlib.sha256(str(now).encode()).hexdigest()[:8]}"
                envelope = QuarantineEnvelope(
                    envelope_id=envelope_id,
                    document_id=doc.document_id,
                    source_uri=doc.source_uri,
                    content_digest=doc.content_digest,
                    exposure_score=metrics.composite_exposure_score,
                    quarantine_threshold=self.quarantine_threshold,
                    reasons=metrics.detected_signals or ["composite_exposure_threshold_exceeded"],
                    quarantined_at=now,
                )
                self._quarantined_envelopes[envelope_id] = envelope
                quarantined.append(envelope)

                # If explicit prompt injection attack detected, trigger fail-closed dynamic revocation
                if metrics.instruction_likelihood >= 0.85:
                    self._revocation_mgr.revoke(
                        lease.lease_id,
                        reason=f"Severe prompt injection carrier detected in document '{doc.document_id}': {metrics.detected_signals}",
                        revoked_by="retrieval_exposure_containment_guard",
                        current_time=now,
                    )
                    raise CarrierQuarantineRejection(
                        f"Document '{doc.document_id}' contains active prompt injection attack (score={metrics.instruction_likelihood}); lease revoked."
                    )
            else:
                receipt_id = f"adm-{doc.document_id}-{hashlib.sha256(str(now).encode()).hexdigest()[:8]}"
                payload = {
                    "receipt_id": receipt_id,
                    "document_id": doc.document_id,
                    "source_uri": doc.source_uri,
                    "content_digest": doc.content_digest,
                    "lease_id": lease.lease_id,
                    "exposure_score": round(metrics.composite_exposure_score, 4),
                    "quarantine_threshold": round(self.quarantine_threshold, 4),
                    "admitted_at": round(now, 4),
                }
                digest = canonical_sha256(payload)
                sig = hmac.new(self._signing_key, digest.encode("utf-8"), hashlib.sha256).hexdigest()

                receipt = AdmissionReceipt(
                    receipt_id=receipt_id,
                    document_id=doc.document_id,
                    source_uri=doc.source_uri,
                    content_digest=doc.content_digest,
                    lease_id=lease.lease_id,
                    exposure_score=metrics.composite_exposure_score,
                    quarantine_threshold=self.quarantine_threshold,
                    admitted_at=now,
                    signature=sig,
                )
                self._admission_receipts[receipt_id] = receipt
                admitted.append(receipt)

        return admitted, quarantined

    def verify_admission_receipt(self, receipt: AdmissionReceipt) -> bool:
        """Verifies cryptographic validity of an admission receipt."""
        return receipt.verify_signature(self._signing_key)

    def get_quarantined_envelope(self, envelope_id: str) -> Optional[QuarantineEnvelope]:
        """Retrieves quarantine envelope metadata."""
        return self._quarantined_envelopes.get(envelope_id)
