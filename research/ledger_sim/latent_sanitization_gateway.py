"""
research/ledger_sim/latent_sanitization_gateway.py

Boundary-Aware Latent State Sanitization Gateway for Peer-to-Peer Agent Memory Sharing.

Theoretical and Provenance Foundations:
  1. Continuous Latent-Space Reasoning & Next-Latent Prediction:
     Coconut (Hao et al., Meta FAIR, arXiv:2412.06769, 2024); Teoh et al. (2025).
     Edge agents exchange compact continuous hidden state vectors across QUIC tunnels
     (IETF RFC 9000 / RFC 9221) instead of verbose discrete token transcriptions.
  2. Representation Engineering & Feature-Space Adversarial Steerings:
     Zou et al. (arXiv:2310.01405, 2023); Madry et al. (ICLR 2018).
     Unvalidated latent state injections can steer downstream model activations along
     adversarial feature-space manifolds without triggering discrete token regexes.
  3. Lipschitz / Spectral Norm Constrained Projection:
     Miyato et al. (ICLR 2018); Cisse et al. (ICML 2017, Parseval Networks).
     Enforces strict L2 and L_infinity norm boundaries and Euclidean norm ball projections.
  4. W3C PROV-DM Cryptographic Lineage:
     Moreau & Missier (2013); PROV-AGENT (Souza et al., arXiv:2508.02866, 2025).
  5. Strict Steward Gate Compliance:
     Deterministic memory sanitization and capability gating only.
     Zero unapproved tokens, arbitrary royalty percentages, or speculative financial promises.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


class SanitizationDecisionCode(str, Enum):
    """Deterministic verdict codes emitted by the Latent State Sanitization Gateway."""

    ADMITTED_PRISTINE = "ADMITTED_PRISTINE"
    ADMITTED_PROJECTED = "ADMITTED_PROJECTED"
    REJECTED_NON_FINITE = "REJECTED_NON_FINITE"
    REJECTED_DIMENSION_MISMATCH = "REJECTED_DIMENSION_MISMATCH"
    REJECTED_L2_NORM_EXCEEDED = "REJECTED_L2_NORM_EXCEEDED"
    REJECTED_L_INF_EXCEEDED = "REJECTED_L_INF_EXCEEDED"
    REJECTED_DEGENERATE_ENERGY = "REJECTED_DEGENERATE_ENERGY"
    REJECTED_ADVERSARIAL_STEERING = "REJECTED_ADVERSARIAL_STEERING"
    REJECTED_PROVENANCE_MISMATCH = "REJECTED_PROVENANCE_MISMATCH"
    REJECTED_INVALID_HEADER = "REJECTED_INVALID_HEADER"
    REJECTED_UNAUTHORIZED_CHANNEL = "REJECTED_UNAUTHORIZED_CHANNEL"


class LatentSanitizationError(Exception):
    """Raised when latent state packet fails fundamental structural or type invariants."""


def _validate_safe_agent_id(val: Any, field_name: str) -> str:
    if not isinstance(val, str):
        raise LatentSanitizationError(f"{field_name} must be a str, got {type(val).__name__}")
    s = val.strip()
    if not s:
        raise LatentSanitizationError(f"{field_name} must not be empty or whitespace")
    if len(s) > 128:
        raise LatentSanitizationError(f"{field_name} exceeds maximum length of 128 characters")
    if not re.match(r"^[A-Za-z0-9_.:@/-]+$", s):
        raise LatentSanitizationError(f"{field_name} contains invalid characters: '{s}'")
    return s


def compute_vector_l2_norm(vec: Sequence[float]) -> float:
    """Computes Euclidean L2 norm ||z||_2 = sqrt(sum(z_i^2))."""
    sum_sq = 0.0
    for x in vec:
        sum_sq += x * x
    return math.sqrt(sum_sq)


def compute_vector_linf_norm(vec: Sequence[float]) -> float:
    """Computes Chebyshev L_infinity norm ||z||_inf = max(|z_i|)."""
    max_val = 0.0
    for x in vec:
        ax = abs(x)
        if ax > max_val:
            max_val = ax
    return max_val


def compute_cosine_similarity(v1: Sequence[float], v2: Sequence[float]) -> float:
    """Computes cosine similarity cos(v1, v2) = (v1 . v2) / (||v1||_2 * ||v2||_2)."""
    if len(v1) != len(v2):
        raise LatentSanitizationError(f"Vector dimensions must match for cosine similarity: {len(v1)} != {len(v2)}")
    dot = 0.0
    norm1_sq = 0.0
    norm2_sq = 0.0
    for x, y in zip(v1, v2):
        dot += x * y
        norm1_sq += x * x
        norm2_sq += y * y
    if norm1_sq <= 1e-12 or norm2_sq <= 1e-12:
        return 0.0
    denom = math.sqrt(norm1_sq) * math.sqrt(norm2_sq)
    sim = dot / denom
    # Clamp numerical precision artifacts
    return max(-1.0, min(1.0, sim))


def project_vector_onto_l2_ball(vec: Sequence[float], max_norm: float) -> List[float]:
    """Projects a vector onto the closed Euclidean L2 ball of radius max_norm."""
    if max_norm <= 0.0:
        raise ValueError("max_norm must be strictly positive")
    current_norm = compute_vector_l2_norm(vec)
    if current_norm <= max_norm:
        return list(vec)
    scale = max_norm / current_norm
    return [x * scale for x in vec]


def canonical_activation_digest(activation_vector: Sequence[float], precision: int = 6) -> str:
    """Deterministic 64-char SHA-256 digest of normalized floating point activation sequence."""
    formatted = ",".join(f"{round(x, precision):.{precision}f}" for x in activation_vector)
    return hashlib.sha256(formatted.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LatentStatePacket:
    """
    Continuous latent memory state packet exchanged over peer-to-peer agent QUIC tunnels.
    Transports intermediate continuous reasoning state vectors (Coconut / Next-Latent).
    """

    sender_agent_id: str
    recipient_agent_id: str
    session_id: str
    vector_dim: int
    activation_vector: Tuple[float, ...]
    stated_norm: Optional[float] = None
    provenance_digest: Optional[str] = None
    capability_token_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(
        cls,
        sender_agent_id: str,
        recipient_agent_id: str,
        session_id: str,
        vector_dim: int,
        activation_vector: Sequence[float],
        stated_norm: Optional[float] = None,
        provenance_digest: Optional[str] = None,
        capability_token_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LatentStatePacket:
        return cls(
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            session_id=session_id,
            vector_dim=vector_dim,
            activation_vector=tuple(activation_vector),
            stated_norm=stated_norm,
            provenance_digest=provenance_digest,
            capability_token_id=capability_token_id,
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True)
class SanitizationPolicy:
    """
    Bounded norm and representation engineering defense configuration.
    Defines fail-closed security invariants for latent state admission.
    """

    max_l2_norm: float = 12.0
    max_linf_norm: float = 3.5
    min_l2_norm: float = 1e-4
    max_cosine_steering: float = 0.82
    quarantined_steering_vectors: Tuple[Tuple[float, ...], ...] = field(default_factory=tuple)
    allow_projection: bool = True
    projection_tolerance_ratio: float = 1.30
    require_provenance_digest: bool = False
    enforce_finite_elements: bool = True

    def validate_policy_invariants(self) -> None:
        if self.max_l2_norm <= 0.0 or math.isnan(self.max_l2_norm) or math.isinf(self.max_l2_norm):
            raise ValueError("max_l2_norm must be a finite positive float")
        if self.max_linf_norm <= 0.0 or math.isnan(self.max_linf_norm) or math.isinf(self.max_linf_norm):
            raise ValueError("max_linf_norm must be a finite positive float")
        if self.min_l2_norm < 0.0 or math.isnan(self.min_l2_norm) or math.isinf(self.min_l2_norm):
            raise ValueError("min_l2_norm must be a finite non-negative float")
        if not (0.0 < self.max_cosine_steering <= 1.0):
            raise ValueError("max_cosine_steering must be in (0.0, 1.0]")
        if self.projection_tolerance_ratio < 1.0:
            raise ValueError("projection_tolerance_ratio must be >= 1.0")


@dataclass(frozen=True)
class SanitizationReceipt:
    """
    Cryptographic verification receipt for an inspected latent state packet.
    Formatted for W3C PROV-DM cryptographic lineage tracking.
    """

    receipt_id: str
    decision_code: SanitizationDecisionCode
    admitted: bool
    sender_agent_id: str
    recipient_agent_id: str
    session_id: str
    vector_dim: int
    original_l2_norm: float
    original_linf_norm: float
    sanitized_l2_norm: Optional[float]
    sanitized_linf_norm: Optional[float]
    max_steering_similarity: float
    activation_digest: str
    receipt_sha256: str
    created_at_iso: str
    prov_entity: Dict[str, Any]
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "decision_code": self.decision_code.value,
            "admitted": self.admitted,
            "sender_agent_id": self.sender_agent_id,
            "recipient_agent_id": self.recipient_agent_id,
            "session_id": self.session_id,
            "vector_dim": self.vector_dim,
            "original_l2_norm": round(self.original_l2_norm, 6),
            "original_linf_norm": round(self.original_linf_norm, 6),
            "sanitized_l2_norm": round(self.sanitized_l2_norm, 6) if self.sanitized_l2_norm is not None else None,
            "sanitized_linf_norm": round(self.sanitized_linf_norm, 6) if self.sanitized_linf_norm is not None else None,
            "max_steering_similarity": round(self.max_steering_similarity, 6),
            "activation_digest": self.activation_digest,
            "receipt_sha256": self.receipt_sha256,
            "created_at_iso": self.created_at_iso,
            "prov_entity": self.prov_entity,
            "rejection_reason": self.rejection_reason,
        }


class LatentStateSanitizationGateway:
    """
    Boundary-Aware Latent State Sanitization Gateway (`LatentStateSanitizationGateway`).

    Performs deterministic, fail-closed inspection, norm-bounding, and adversarial steering
    defense for continuous latent state activations shared between personal and specialist agents.
    """

    def __init__(
        self,
        policy: Optional[SanitizationPolicy] = None,
        quarantined_subspaces: Optional[Sequence[Sequence[float]]] = None,
    ) -> None:
        self.policy = policy or SanitizationPolicy()
        self.policy.validate_policy_invariants()

        self._quarantined_vectors: List[Tuple[float, ...]] = []
        if quarantined_subspaces:
            for qv in quarantined_subspaces:
                self.register_quarantined_steering_vector(qv)
        elif self.policy.quarantined_steering_vectors:
            for qv in self.policy.quarantined_steering_vectors:
                self.register_quarantined_steering_vector(qv)

        self._audit_log: List[SanitizationReceipt] = []

    def register_quarantined_steering_vector(self, vector: Sequence[float]) -> None:
        """Registers a known adversarial activation steering direction in representation space."""
        if not vector:
            raise ValueError("Quarantined steering vector cannot be empty")
        for x in vector:
            if isinstance(x, bool) or not isinstance(x, (int, float)) or math.isnan(x) or math.isinf(x):
                raise ValueError("All elements of quarantined steering vector must be finite floats")
        norm = compute_vector_l2_norm(vector)
        if norm <= 1e-9:
            raise ValueError("Quarantined steering vector must have non-zero energy")
        # Normalize vector to unit length
        unit_vec = tuple(x / norm for x in vector)
        self._quarantined_vectors.append(unit_vec)

    @property
    def quarantined_vectors_count(self) -> int:
        return len(self._quarantined_vectors)

    @property
    def audit_log(self) -> List[SanitizationReceipt]:
        return list(self._audit_log)

    def sanitize_packet(
        self, packet: LatentStatePacket
    ) -> Tuple[SanitizationReceipt, Optional[List[float]]]:
        """
        Executes fail-closed boundary sanitization on an incoming latent memory packet.

        Returns:
            Tuple of (SanitizationReceipt, sanitized_vector_or_None).
        """
        created_at_iso = datetime.now(timezone.utc).isoformat()

        # 1. Header and Identifier Invariant Validation
        try:
            sender_id = _validate_safe_agent_id(packet.sender_agent_id, "sender_agent_id")
            recipient_id = _validate_safe_agent_id(packet.recipient_agent_id, "recipient_agent_id")
            session_id = _validate_safe_agent_id(packet.session_id, "session_id")
        except LatentSanitizationError as e:
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_INVALID_HEADER,
                packet=packet,
                reason=str(e),
                created_at_iso=created_at_iso,
            )

        # 2. Vector Type & Finite Verification
        vec = packet.activation_vector
        if not isinstance(vec, (tuple, list)):
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_NON_FINITE,
                packet=packet,
                reason=f"activation_vector must be a sequence, got {type(vec).__name__}",
                created_at_iso=created_at_iso,
            )

        # Check dimension consistency
        if not isinstance(packet.vector_dim, int) or isinstance(packet.vector_dim, bool) or packet.vector_dim <= 0:
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_DIMENSION_MISMATCH,
                packet=packet,
                reason=f"vector_dim must be a positive integer, got {packet.vector_dim}",
                created_at_iso=created_at_iso,
            )

        if len(vec) != packet.vector_dim:
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_DIMENSION_MISMATCH,
                packet=packet,
                reason=f"Length of activation_vector ({len(vec)}) does not match declared vector_dim ({packet.vector_dim})",
                created_at_iso=created_at_iso,
            )

        # Strict finite element check (reject NaNs, Infinities, booleans, non-numbers)
        clean_floats: List[float] = []
        for i, val in enumerate(vec):
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                return self._emit_rejection(
                    decision=SanitizationDecisionCode.REJECTED_NON_FINITE,
                    packet=packet,
                    reason=f"Element at index {i} is not a valid float: {type(val).__name__}",
                    created_at_iso=created_at_iso,
                )
            fval = float(val)
            if math.isnan(fval) or math.isinf(fval):
                return self._emit_rejection(
                    decision=SanitizationDecisionCode.REJECTED_NON_FINITE,
                    packet=packet,
                    reason=f"Element at index {i} is non-finite (NaN or Inf)",
                    created_at_iso=created_at_iso,
                )
            clean_floats.append(fval)

        # 3. Energy Floor and Norm Bounds
        orig_l2 = compute_vector_l2_norm(clean_floats)
        orig_linf = compute_vector_linf_norm(clean_floats)
        digest = canonical_activation_digest(clean_floats)

        # Provenance verification if digest is provided or required
        if packet.provenance_digest is not None:
            if not isinstance(packet.provenance_digest, str) or len(packet.provenance_digest) != 64:
                return self._emit_rejection(
                    decision=SanitizationDecisionCode.REJECTED_PROVENANCE_MISMATCH,
                    packet=packet,
                    reason="provenance_digest must be a 64-character SHA-256 hex string",
                    created_at_iso=created_at_iso,
                    orig_l2=orig_l2,
                    orig_linf=orig_linf,
                    digest=digest,
                )
            if packet.provenance_digest.lower() != digest.lower():
                return self._emit_rejection(
                    decision=SanitizationDecisionCode.REJECTED_PROVENANCE_MISMATCH,
                    packet=packet,
                    reason=f"Computed digest {digest} does not match declared {packet.provenance_digest}",
                    created_at_iso=created_at_iso,
                    orig_l2=orig_l2,
                    orig_linf=orig_linf,
                    digest=digest,
                )
        elif self.policy.require_provenance_digest:
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_PROVENANCE_MISMATCH,
                packet=packet,
                reason="SanitizationPolicy requires mandatory provenance_digest but none was provided",
                created_at_iso=created_at_iso,
                orig_l2=orig_l2,
                orig_linf=orig_linf,
                digest=digest,
            )

        # Floor check (degenerate all-zero activation)
        if orig_l2 < self.policy.min_l2_norm:
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_DEGENERATE_ENERGY,
                packet=packet,
                reason=f"L2 norm {orig_l2:.6e} is below minimum energy floor {self.policy.min_l2_norm}",
                created_at_iso=created_at_iso,
                orig_l2=orig_l2,
                orig_linf=orig_linf,
                digest=digest,
            )

        # Coordinate-wise Chebyshev Linf check
        if orig_linf > self.policy.max_linf_norm:
            return self._emit_rejection(
                decision=SanitizationDecisionCode.REJECTED_L_INF_EXCEEDED,
                packet=packet,
                reason=f"Maximum coordinate magnitude {orig_linf:.4f} exceeds max_linf_norm ceiling {self.policy.max_linf_norm:.4f}",
                created_at_iso=created_at_iso,
                orig_l2=orig_l2,
                orig_linf=orig_linf,
                digest=digest,
            )

        # 4. Adversarial Feature-Space Steering Quarantine
        max_steering = 0.0
        for qv in self._quarantined_vectors:
            if len(qv) == len(clean_floats):
                sim = abs(compute_cosine_similarity(clean_floats, qv))
                if sim > max_steering:
                    max_steering = sim
                if sim >= self.policy.max_cosine_steering:
                    return self._emit_rejection(
                        decision=SanitizationDecisionCode.REJECTED_ADVERSARIAL_STEERING,
                        packet=packet,
                        reason=f"Absolute cosine similarity {sim:.4f} against quarantined steering vector exceeds threshold {self.policy.max_cosine_steering:.4f}",
                        created_at_iso=created_at_iso,
                        orig_l2=orig_l2,
                        orig_linf=orig_linf,
                        digest=digest,
                        max_steering=max_steering,
                    )

        # 5. L2 Norm Bounds and Euclidean Projection
        sanitized_vec: List[float]
        decision: SanitizationDecisionCode

        if orig_l2 <= self.policy.max_l2_norm:
            sanitized_vec = list(clean_floats)
            decision = SanitizationDecisionCode.ADMITTED_PRISTINE
        else:
            # Exceeds max L2 norm
            hard_ceiling = self.policy.max_l2_norm * self.policy.projection_tolerance_ratio
            if not self.policy.allow_projection or orig_l2 > hard_ceiling:
                return self._emit_rejection(
                    decision=SanitizationDecisionCode.REJECTED_L2_NORM_EXCEEDED,
                    packet=packet,
                    reason=f"L2 norm {orig_l2:.4f} exceeds ceiling {self.policy.max_l2_norm:.4f} (hard reject threshold {hard_ceiling:.4f})",
                    created_at_iso=created_at_iso,
                    orig_l2=orig_l2,
                    orig_linf=orig_linf,
                    digest=digest,
                    max_steering=max_steering,
                )
            # Project onto Euclidean norm ball
            sanitized_vec = project_vector_onto_l2_ball(clean_floats, self.policy.max_l2_norm)
            decision = SanitizationDecisionCode.ADMITTED_PROJECTED

        sanitized_l2 = compute_vector_l2_norm(sanitized_vec)
        sanitized_linf = compute_vector_linf_norm(sanitized_vec)

        # Generate cryptographic receipt
        receipt = self._build_receipt(
            decision_code=decision,
            admitted=True,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            dim=packet.vector_dim,
            orig_l2=orig_l2,
            orig_linf=orig_linf,
            sanitized_l2=sanitized_l2,
            sanitized_linf=sanitized_linf,
            max_steering=max_steering,
            digest=digest,
            created_at_iso=created_at_iso,
            reason=None,
        )
        self._audit_log.append(receipt)
        return receipt, sanitized_vec

    def _emit_rejection(
        self,
        decision: SanitizationDecisionCode,
        packet: LatentStatePacket,
        reason: str,
        created_at_iso: str,
        orig_l2: float = 0.0,
        orig_linf: float = 0.0,
        digest: str = "0" * 64,
        max_steering: float = 0.0,
    ) -> Tuple[SanitizationReceipt, None]:
        sender_id = str(packet.sender_agent_id or "unknown")
        recipient_id = str(packet.recipient_agent_id or "unknown")
        session_id = str(packet.session_id or "unknown")
        dim = int(packet.vector_dim) if isinstance(packet.vector_dim, int) and not isinstance(packet.vector_dim, bool) else 0

        receipt = self._build_receipt(
            decision_code=decision,
            admitted=False,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            dim=dim,
            orig_l2=orig_l2,
            orig_linf=orig_linf,
            sanitized_l2=None,
            sanitized_linf=None,
            max_steering=max_steering,
            digest=digest,
            created_at_iso=created_at_iso,
            reason=reason,
        )
        self._audit_log.append(receipt)
        return receipt, None

    def _build_receipt(
        self,
        decision_code: SanitizationDecisionCode,
        admitted: bool,
        sender_id: str,
        recipient_id: str,
        session_id: str,
        dim: int,
        orig_l2: float,
        orig_linf: float,
        sanitized_l2: Optional[float],
        sanitized_linf: Optional[float],
        max_steering: float,
        digest: str,
        created_at_iso: str,
        reason: Optional[str],
    ) -> SanitizationReceipt:
        raw_receipt_id = f"LSSG-{sender_id}-{session_id}-{created_at_iso}"
        receipt_id = f"LSSG-REC-{hashlib.sha256(raw_receipt_id.encode('utf-8')).hexdigest()[:16]}"

        prov_entity = {
            "standard": "W3C PROV-DM (Moreau & Missier, 2013)",
            "entity_id": f"urn:cin:latent-state:{digest[:16]}",
            "entity_type": "cin:ContinuousLatentStateActivation",
            "wasAttributedTo": f"urn:cin:agent:{sender_id}",
            "generatedAtTime": created_at_iso,
            "decision": decision_code.value,
            "admitted": admitted,
        }

        receipt_payload = {
            "receipt_id": receipt_id,
            "decision_code": decision_code.value,
            "admitted": admitted,
            "sender_agent_id": sender_id,
            "recipient_agent_id": recipient_id,
            "session_id": session_id,
            "vector_dim": dim,
            "orig_l2": round(orig_l2, 6),
            "orig_linf": round(orig_linf, 6),
            "sanitized_l2": round(sanitized_l2, 6) if sanitized_l2 is not None else None,
            "sanitized_linf": round(sanitized_linf, 6) if sanitized_linf is not None else None,
            "max_steering": round(max_steering, 6),
            "digest": digest,
            "created_at_iso": created_at_iso,
            "reason": reason,
        }
        receipt_sha256 = hashlib.sha256(
            json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return SanitizationReceipt(
            receipt_id=receipt_id,
            decision_code=decision_code,
            admitted=admitted,
            sender_agent_id=sender_id,
            recipient_agent_id=recipient_id,
            session_id=session_id,
            vector_dim=dim,
            original_l2_norm=orig_l2,
            original_linf_norm=orig_linf,
            sanitized_l2_norm=sanitized_l2,
            sanitized_linf_norm=sanitized_linf,
            max_steering_similarity=max_steering,
            activation_digest=digest,
            receipt_sha256=receipt_sha256,
            created_at_iso=created_at_iso,
            prov_entity=prov_entity,
            rejection_reason=reason,
        )

    def verify_receipt_integrity(self, receipt: SanitizationReceipt) -> bool:
        """Deterministically validates the cryptographic signature of an emitted receipt."""
        if not receipt or not isinstance(receipt, SanitizationReceipt):
            return False
        receipt_payload = {
            "receipt_id": receipt.receipt_id,
            "decision_code": receipt.decision_code.value,
            "admitted": receipt.admitted,
            "sender_agent_id": receipt.sender_agent_id,
            "recipient_agent_id": receipt.recipient_agent_id,
            "session_id": receipt.session_id,
            "vector_dim": receipt.vector_dim,
            "orig_l2": round(receipt.original_l2_norm, 6),
            "orig_linf": round(receipt.original_linf_norm, 6),
            "sanitized_l2": round(receipt.sanitized_l2_norm, 6) if receipt.sanitized_l2_norm is not None else None,
            "sanitized_linf": round(receipt.sanitized_linf_norm, 6) if receipt.sanitized_linf_norm is not None else None,
            "max_steering": round(receipt.max_steering_similarity, 6),
            "digest": receipt.activation_digest,
            "created_at_iso": receipt.created_at_iso,
            "reason": receipt.rejection_reason,
        }
        recomputed = hashlib.sha256(
            json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return hmac.compare_digest(recomputed, receipt.receipt_sha256)
