"""
research/ledger_sim/contextual_integrity_guard.py

Contextual Integrity Transmission Guard and Information-Sharing Confinement for Multi-Agent Systems.

Grounded in:
- Sahra Ghalebikesabi, Eugene Bagdasaryan, Ren Yi, Itay Yona, Ilia Shumailov, Aneesh Pappu,
  Chongyang Shi, Laura Weidinger, Robert Stanforth, Leonard Berrada, Pushmeet Kohli,
  Po-Sen Huang, Borja Balle (arXiv:2408.02373, August 2024; Transactions on Machine Learning Research, 2025):
  "Operationalizing Contextual Integrity in Privacy-Conscious Assistants."
- Helen Nissenbaum (2004, 2010):
  "Privacy as Contextual Integrity" / "Privacy in Context: Technology, Policy, and the Integrity of Social Life."
- Jack B. Dennis & Earl C. Van Horn (CACM 1966):
  "Programming Semantics for Multiprogrammed Computations" [Object-Capability Zero Ambient Authority].
- Luc Moreau & Paolo Missier (W3C Recommendation, 2013):
  "PROV-DM: The PROV Data Model."

Core Finding & Architectural Solution:
When autonomous AI agents act as personal or institutional assistants, unconstrained natural language
prompting and form-filling readily leak private attributes (e.g., medical, financial, or organizational records)
to third-party recipients. Contextual Integrity establishes that privacy is preserved not by absolute secrecy,
but by adherence to contextual informational norms.

This guard operationalizes Contextual Integrity as an explicit reference monitor enforcing a 5-tuple norm:
    Norm = (data_subject, sender_role, recipient_role, information_type, transmission_principle)
Every inter-agent message or tool invocation must verify that its payload respects registered transmission
principles (e.g., EXPLICIT_USER_CONSENT, MINIMAL_AGGREGATED_DISCLOSURE, OCAP_RESTRICTED_DISCLOSURE).
Non-conforming attributes are automatically redacted, and verified transmissions generate deterministic,
tamper-evident W3C PROV-DM execution receipts.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


# =====================================================================
# Error Hierarchy
# =====================================================================

class ContextualIntegritySecurityViolation(Exception):
    """Base exception for Contextual Integrity security violations."""


class TransmissionNormViolationError(ContextualIntegritySecurityViolation):
    """Raised when an information transmission violates registered contextual norms."""


class AttributeLeakageError(ContextualIntegritySecurityViolation):
    """Raised when an unconsented sensitive attribute leaks past the redaction monitor."""


class ParameterValidationError(ContextualIntegritySecurityViolation):
    """Raised when configuration, parameter bounds, or inputs are invalid or out of support."""


class StewardGateViolationError(ContextualIntegritySecurityViolation):
    """Raised when forbidden speculative promises, unapproved tokens, or sci-fi lore are detected."""


# =====================================================================
# Steward Gate Screening
# =====================================================================

FORBIDDEN_STEWARD_TERMS: Tuple[re.Pattern, ...] = (
    re.compile(r"\bcontribution\s+tokens?\b", re.IGNORECASE),
    re.compile(r"\bmmct\b", re.IGNORECASE),
    re.compile(r"\b85/10/5\b", re.IGNORECASE),
    re.compile(r"\b95%\s+(?:cut|royalty|split|payout)\b", re.IGNORECASE),
    re.compile(r"\bguaranteed\s+(?:savings|roi|payouts?|returns?|profits?)\b", re.IGNORECASE),
    re.compile(r"\bpassive\s+income\b", re.IGNORECASE),
    re.compile(r"\btokenomic\b", re.IGNORECASE),
    re.compile(r"\byield\s+farming\b", re.IGNORECASE),
    re.compile(r"\bchronicles?\s+of\b", re.IGNORECASE),
    re.compile(r"\bgalactic\b", re.IGNORECASE),
)


def screen_steward_gate(text: str) -> None:
    """Validate that text is 100% free of unapproved tokens, money claims, or sci-fi lore."""
    if not isinstance(text, str):
        return
    for pattern in FORBIDDEN_STEWARD_TERMS:
        match = pattern.search(text)
        if match:
            raise StewardGateViolationError(
                f"Steward Gate violation: detected forbidden term '{match.group(0)}'."
            )


# =====================================================================
# Domain Enums & Data Contracts
# =====================================================================

class TransmissionPrinciple(str, enum.Enum):
    """Formal transmission principles governing Contextual Integrity flows (Nissenbaum 2004)."""
    EXPLICIT_USER_CONSENT = "EXPLICIT_USER_CONSENT"
    CONFIDENTIAL_AUDIT_ONLY = "CONFIDENTIAL_AUDIT_ONLY"
    STATUTORY_CPT_UPCODING_AUDIT = "STATUTORY_CPT_UPCODING_AUDIT"
    MINIMAL_AGGREGATED_DISCLOSURE = "MINIMAL_AGGREGATED_DISCLOSURE"
    OCAP_RESTRICTED_DISCLOSURE = "OCAP_RESTRICTED_DISCLOSURE"


class InformationSensitivityTier(int, enum.Enum):
    """Classification tiers for user and organizational attributes."""
    TIER_0_PUBLIC = 0
    TIER_1_OPERATIONAL = 1
    TIER_2_CONFIDENTIAL = 2
    TIER_3_HIGHLY_RESTRICTED = 3


@dataclasses.dataclass(frozen=True)
class ContextualNorm:
    """Registered 5-tuple informational norm defining legitimate transmission.
    
    Norm = (data_subject_role, sender_role, recipient_role, information_type, principle)
    """
    norm_id: str
    data_subject_role: str
    sender_role: str
    recipient_role: str
    information_type: str
    principle: TransmissionPrinciple
    sensitivity_tier: InformationSensitivityTier

    def __post_init__(self) -> None:
        if not self.norm_id or not isinstance(self.norm_id, str):
            raise ParameterValidationError("norm_id must be a non-empty string.")
        if not self.data_subject_role or not isinstance(self.data_subject_role, str):
            raise ParameterValidationError("data_subject_role must be a non-empty string.")
        if not self.sender_role or not isinstance(self.sender_role, str):
            raise ParameterValidationError("sender_role must be a non-empty string.")
        if not self.recipient_role or not isinstance(self.recipient_role, str):
            raise ParameterValidationError("recipient_role must be a non-empty string.")
        if not self.information_type or not isinstance(self.information_type, str):
            raise ParameterValidationError("information_type must be a non-empty string.")
        if isinstance(self.principle, bool) or not isinstance(self.principle, TransmissionPrinciple):
            raise ParameterValidationError("principle must be an instance of TransmissionPrinciple.")
        if isinstance(self.sensitivity_tier, bool) or not isinstance(self.sensitivity_tier, InformationSensitivityTier):
            raise ParameterValidationError("sensitivity_tier must be an instance of InformationSensitivityTier.")
        screen_steward_gate(self.norm_id)
        screen_steward_gate(self.information_type)


@dataclasses.dataclass(frozen=True)
class TransmissionReceipt:
    """Deterministic, tamper-evident cryptographic receipt for a verified transmission."""
    receipt_id: str
    transmission_timestamp_sec: int
    sender_agent_id: str
    recipient_agent_id: str
    norm_id: str
    payload_digest_sha256: str
    redacted_attribute_count: int
    status: str
    prov_dm_entity_id: str

    def compute_digest(self) -> str:
        serialized = (
            f"{self.receipt_id}:{self.transmission_timestamp_sec}:{self.sender_agent_id}:"
            f"{self.recipient_agent_id}:{self.norm_id}:{self.payload_digest_sha256}:"
            f"{self.redacted_attribute_count}:{self.status}"
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# =====================================================================
# Contextual Integrity Transmission Guard
# =====================================================================

class ContextualIntegrityGuard:
    """Reference monitor verifying informational norms across multi-agent interactions."""

    def __init__(self, guard_id: str) -> None:
        if not guard_id or not isinstance(guard_id, str):
            raise ParameterValidationError("guard_id must be a non-empty string.")
        screen_steward_gate(guard_id)
        self.guard_id: str = guard_id
        self._norms: Dict[str, ContextualNorm] = {}
        self._receipts: List[TransmissionReceipt] = []
        self._transmission_counter: int = 0

    def register_norm(self, norm: ContextualNorm) -> None:
        """Register a valid Contextual Integrity norm in the monitor's policy store."""
        if not isinstance(norm, ContextualNorm):
            raise ParameterValidationError("norm must be an instance of ContextualNorm.")
        if norm.norm_id in self._norms:
            raise ParameterValidationError(f"Norm '{norm.norm_id}' is already registered.")
        self._norms[norm.norm_id] = norm

    def list_norms(self) -> List[ContextualNorm]:
        """Return all registered norms in deterministic registration order."""
        return list(self._norms.values())

    def verify_and_transmit(
        self,
        sender_agent_id: str,
        sender_role: str,
        recipient_agent_id: str,
        recipient_role: str,
        data_subject_role: str,
        payload_attributes: Dict[str, Any],
        consented_principles: Set[TransmissionPrinciple],
        timestamp_sec: int,
    ) -> Tuple[Dict[str, Any], TransmissionReceipt]:
        """Inspect proposed attributes against contextual norms, redacting non-compliant fields.
        
        Fail-closed rules:
        1. Timestamps must be non-negative integers (reject floats, booleans, NaNs).
        2. Agent IDs and roles must be non-empty strings without whitespace-only entries.
        3. Attributes with sensitivity TIER_2 or higher require matching principle with explicit consent.
        4. Unknown attributes without matching norms are automatically redacted fail-closed.
        """
        # Strict fail-closed type and parameter validations
        if isinstance(timestamp_sec, bool) or not isinstance(timestamp_sec, int) or timestamp_sec < 0:
            raise ParameterValidationError("timestamp_sec must be a non-negative integer.")

        for name, val in [
            ("sender_agent_id", sender_agent_id),
            ("sender_role", sender_role),
            ("recipient_agent_id", recipient_agent_id),
            ("recipient_role", recipient_role),
            ("data_subject_role", data_subject_role),
        ]:
            if not val or not isinstance(val, str) or not val.strip():
                raise ParameterValidationError(f"{name} must be a non-empty string.")
            screen_steward_gate(val)

        if not isinstance(payload_attributes, dict):
            raise ParameterValidationError("payload_attributes must be a dictionary.")

        # Screen attribute keys and values for Steward Gate compliance
        for k, v in payload_attributes.items():
            screen_steward_gate(str(k))
            if isinstance(v, str):
                screen_steward_gate(v)
            elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                raise ParameterValidationError(f"Float attribute '{k}' contains NaN or Inf.")

        # Check consented principles
        if not isinstance(consented_principles, set):
            raise ParameterValidationError("consented_principles must be a set.")
        for p in consented_principles:
            if isinstance(p, bool) or not isinstance(p, TransmissionPrinciple):
                raise ParameterValidationError("All consented principles must be TransmissionPrinciple enums.")

        redacted_payload: Dict[str, Any] = {}
        redacted_count = 0
        matching_norm_ids: List[str] = []

        for attr_key, attr_val in sorted(payload_attributes.items()):
            # Look for an established norm for this attribute
            matched_norm = self._find_matching_norm(
                data_subject_role=data_subject_role,
                sender_role=sender_role,
                recipient_role=recipient_role,
                information_type=attr_key,
            )

            if matched_norm is None:
                # No norm authorizes transmission of this attribute to recipient: redact fail-closed
                digest = hashlib.sha256(str(attr_val).encode("utf-8")).hexdigest()[:12]
                redacted_payload[attr_key] = f"[REDACTED:UNREGISTERED_NORM:{digest}]"
                redacted_count += 1
                continue

            matching_norm_ids.append(matched_norm.norm_id)

            # Check if required transmission principle is satisfied
            if matched_norm.sensitivity_tier >= InformationSensitivityTier.TIER_2_CONFIDENTIAL:
                if matched_norm.principle not in consented_principles:
                    digest = hashlib.sha256(str(attr_val).encode("utf-8")).hexdigest()[:12]
                    redacted_payload[attr_key] = f"[REDACTED:PRINCIPLE_UNSATISFIED:{matched_norm.principle.value}:{digest}]"
                    redacted_count += 1
                    continue

            # Transmission is authorized under contextual norm
            redacted_payload[attr_key] = attr_val

        # Compute payload digest
        payload_json = json.dumps(redacted_payload, sort_keys=True)
        payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        self._transmission_counter += 1
        primary_norm_id = matching_norm_ids[0] if matching_norm_ids else "NO_MATCHING_NORM"
        receipt_id = f"rcpt-ci-{self.guard_id}-{self._transmission_counter:06d}"
        prov_entity_id = f"entity:ci:transmission:{receipt_id}"

        receipt = TransmissionReceipt(
            receipt_id=receipt_id,
            transmission_timestamp_sec=timestamp_sec,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            norm_id=primary_norm_id,
            payload_digest_sha256=payload_digest,
            redacted_attribute_count=redacted_count,
            status="VERIFIED_TRANSMISSION",
            prov_dm_entity_id=prov_entity_id,
        )
        self._receipts.append(receipt)

        return redacted_payload, receipt

    def _find_matching_norm(
        self,
        data_subject_role: str,
        sender_role: str,
        recipient_role: str,
        information_type: str,
    ) -> Optional[ContextualNorm]:
        """Find registered contextual norm matching the transmission context."""
        for norm in self._norms.values():
            if (
                norm.data_subject_role == data_subject_role
                and norm.sender_role == sender_role
                and norm.recipient_role == recipient_role
                and norm.information_type == information_type
            ):
                return norm
        return None

    def export_w3c_prov_dm(self) -> Dict[str, Any]:
        """Export audit receipts as a valid W3C PROV-DM bundle."""
        entities: Dict[str, Any] = {}
        activities: Dict[str, Any] = {}
        was_generated_by: Dict[str, Any] = {}

        for r in self._receipts:
            entities[r.prov_dm_entity_id] = {
                "prov:type": "ContextualIntegrityTransmissionReceipt",
                "receiptId": r.receipt_id,
                "payloadDigest": r.payload_digest_sha256,
                "redactedCount": r.redacted_attribute_count,
                "normId": r.norm_id,
            }
            activity_id = f"activity:ci:transmit:{r.receipt_id}"
            activities[activity_id] = {
                "prov:type": "ContextualTransmissionValidation",
                "senderAgent": r.sender_agent_id,
                "recipientAgent": r.recipient_agent_id,
                "timestampSec": r.transmission_timestamp_sec,
            }
            was_generated_by[f"wgb:{r.receipt_id}"] = {
                "prov:entity": r.prov_dm_entity_id,
                "prov:activity": activity_id,
            }

        return {
            "prefix": {
                "prov": "http://www.w3.org/ns/prov#",
                "ci": "https://cintnet.org/schema/contextual-integrity#",
            },
            "entity": entities,
            "activity": activities,
            "wasGeneratedBy": was_generated_by,
        }
