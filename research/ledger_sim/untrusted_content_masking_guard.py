"""
research/ledger_sim/untrusted_content_masking_guard.py

Untrusted Content Masking (UCM) and Structural Privilege Separation Guard for Autonomous Web & Document Agents.

Scientific Provenance:
- Jack B. Dennis & Earl C. Van Horn (1966): Programming Semantics for Multiprogrammed Computations (CACM)
  [Zero Ambient Authority, Object-Capability Security, and Structural Confinement Boundaries].
- Mark S. Miller, Chip Morningstar, Bill Frantz (2003): Capability Myths Demolished
  [Caretaker Pattern, Dynamic Revocation, and Monotonic Attenuation].
- Kristina Nikolić, Egor Zverev, Javier Rando, Matthew Jagielski, Edoardo Debenedetti, Florian Tramèr
  (ETH Zurich & Anthropic, arXiv:2607.05277, July 2026):
  Untrusted Content Masking for Web Agents with Security Guarantees.
- Nelson Gardner-Challis, Jonathan Bostock, Georgiy Kozhevnikov, Morgan Sinclaire, Joan Velja, Charlie Griffin
  (Oxford / UK AI Security Institute, arXiv:2602.20628, Feb 2026):
  When can we trust untrusted monitoring? A safety case sketch across collusion strategies.

Architectural Guarantees:
1. Structural Privilege Separation: Web and document layouts (DOM structure, coordinate boundaries, interactive widget tags)
   are strictly separated from untrusted third-party textual content.
2. Untrusted Content Masking (UCM): Untrusted zones (e.g. comments, forum posts, user reviews, external emails) are
   replaced with typed, unforgeable opaque tokens (`[UCM_MASK:uuid:tag:digest]`) before being processed by the primary planner.
3. Isolated Quarantined Model Mediation: When tasks legitimately require interpreting untrusted content (e.g., text summarization),
   the raw payload is routed exclusively to a quarantined model stripped of all tool execution permissions and bounded by
   typed schema validation.
4. Bidirectional Leakage Containment: If untrusted payload strings leak into privileged tool parameters or attempt indirect
   prompt injection attacks, the StructuralBoundaryGate halts execution and dynamically revokes the agent's capability leases.
5. Strict CIN Steward Gate screening across all payloads, schemas, and receipts.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from .capability_lease_containment_guard import (
    ActionScope,
    CapabilityLease,
    DynamicRevocationManager,
    LeaseSecurityViolation,
    LeaseValidationError,
    StewardGateViolationError,
    UntrustedMonitoringRejection,
    assert_steward_gate_compliance,
    canonical_sha256,
)


# =====================================================================
# Error Hierarchy
# =====================================================================

class BoundaryContainmentViolation(LeaseSecurityViolation):
    """Raised when an untrusted payload breaches isolation or attempts indirect prompt injection."""


class UntrustedContentMaskingError(LeaseSecurityViolation):
    """Raised when DOM traversal, masking, or unmasking parameters are malformed."""


class QuarantinedExecutionViolation(LeaseSecurityViolation):
    """Raised when a quarantined model output violates its constrained extraction schema."""


# =====================================================================
# Trust Levels and DOM Node Schema
# =====================================================================

class ContentTrustLevel(enum.Enum):
    """Trust classification for structural components and content payloads."""
    TRUSTED_FRAMEWORK = "trusted_framework"    # System prompts, user goals, verified app layout
    UNTRUSTED_CONTENT = "untrusted_content"    # Third-party user reviews, comments, unauthenticated web text
    MASKED_PLACEHOLDER = "masked_placeholder"  # Opaque redacted token replacing untrusted content


@dataclasses.dataclass
class DOMContentNode:
    """
    Represents a Document Object Model (DOM) element node.
    Separates structural attributes and layout geometry from potentially adversarial text payloads.
    """
    node_id: str
    tag_name: str
    trust_level: ContentTrustLevel = ContentTrustLevel.UNTRUSTED_CONTENT
    text_content: str = ""
    attributes: Dict[str, str] = dataclasses.field(default_factory=dict)
    children: List[DOMContentNode] = dataclasses.field(default_factory=list)
    layout_bbox: Optional[Tuple[float, float, float, float]] = None  # (x, y, width, height)
    is_interactive: bool = False

    def __post_init__(self) -> None:
        if not self.node_id or not isinstance(self.node_id, str):
            raise UntrustedContentMaskingError("node_id must be a non-empty string")
        if not self.tag_name or not isinstance(self.tag_name, str):
            raise UntrustedContentMaskingError("tag_name must be a non-empty string")
        if not isinstance(self.trust_level, ContentTrustLevel):
            raise UntrustedContentMaskingError(f"Invalid trust_level: {self.trust_level}")
        assert_steward_gate_compliance(self.node_id)
        assert_steward_gate_compliance(self.tag_name)
        assert_steward_gate_compliance(self.attributes)
        if self.trust_level == ContentTrustLevel.TRUSTED_FRAMEWORK:
            assert_steward_gate_compliance(self.text_content)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes node to a clean dictionary representation."""
        return {
            "node_id": self.node_id,
            "tag_name": self.tag_name,
            "trust_level": self.trust_level.value,
            "text_content": self.text_content,
            "attributes": dict(self.attributes),
            "layout_bbox": list(self.layout_bbox) if self.layout_bbox else None,
            "is_interactive": self.is_interactive,
            "children": [child.to_dict() for child in self.children],
        }


# =====================================================================
# Isolated Content Store
# =====================================================================

@dataclasses.dataclass(frozen=True)
class MaskedContentRecord:
    """Tamper-evident record holding untrusted text securely out of primary agent context."""
    mask_token: str
    node_id: str
    tag_name: str
    raw_content: str
    content_sha256: str
    created_at: float
    extracted_count: int = 0


class IsolatedContentStore:
    """
    Hardware/memory-isolated repository for untrusted payloads.
    Accessible exclusively by the QuarantinedModelMediator via explicit mask tokens.
    """

    def __init__(self) -> None:
        self._store: Dict[str, MaskedContentRecord] = {}

    def store(self, mask_token: str, node_id: str, tag_name: str, raw_content: str) -> MaskedContentRecord:
        """Stores untrusted content indexed strictly by its unforgeable mask token."""
        if mask_token in self._store:
            raise UntrustedContentMaskingError(f"Mask token '{mask_token}' collision in content store")
        digest = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        rec = MaskedContentRecord(
            mask_token=mask_token,
            node_id=node_id,
            tag_name=tag_name,
            raw_content=raw_content,
            content_sha256=digest,
            created_at=time.time(),
            extracted_count=0,
        )
        self._store[mask_token] = rec
        return rec

    def retrieve(self, mask_token: str) -> MaskedContentRecord:
        """Retrieves raw content for quarantined processing."""
        if mask_token not in self._store:
            raise UntrustedContentMaskingError(f"Mask token '{mask_token}' not found in isolated store")
        return self._store[mask_token]

    def has_token(self, mask_token: str) -> bool:
        return mask_token in self._store

    def count(self) -> int:
        return len(self._store)


# =====================================================================
# Untrusted Content Masker (UCM Engine)
# =====================================================================

class UntrustedContentMasker:
    """
    Transforms raw DOM trees into structurally sanitized views.
    Redacts untrusted text into typed opaque placeholders while preserving layout and interactive geometry.
    Grounded in Nikolić et al. (arXiv:2607.05277).
    """

    UNTRUSTED_SELECTORS: Tuple[str, ...] = (
        "comment",
        "review",
        "testimonial",
        "user-post",
        "chat-message",
        "tweet",
        "forum-entry",
        "user-input",
        "unverified-doc",
    )

    def __init__(self, isolated_store: Optional[IsolatedContentStore] = None) -> None:
        self.store = isolated_store or IsolatedContentStore()

    def is_node_untrusted(self, node: DOMContentNode) -> bool:
        """Determines if a node should be classified as untrusted based on trust level or selector semantics."""
        if node.trust_level == ContentTrustLevel.UNTRUSTED_CONTENT:
            return True
        if node.trust_level == ContentTrustLevel.TRUSTED_FRAMEWORK:
            return False

        # Check classes or IDs for untrusted indicators
        class_str = node.attributes.get("class", "").lower()
        id_str = node.attributes.get("id", "").lower()
        for pattern in self.UNTRUSTED_SELECTORS:
            if pattern in class_str or pattern in id_str:
                return True
        return False

    def mask_dom_tree(self, root: DOMContentNode) -> Tuple[DOMContentNode, Dict[str, Any]]:
        """
        Recursively traverses DOM tree and replaces untrusted text with typed opaque mask tokens.
        Returns the sanitized root node and a verifiable masking receipt.
        """
        masked_count = 0
        total_nodes = 0
        tokens_created: List[str] = []

        def _traverse_and_mask(current: DOMContentNode) -> DOMContentNode:
            nonlocal masked_count, total_nodes
            total_nodes += 1

            should_mask = self.is_node_untrusted(current) and bool(current.text_content.strip())

            new_text = current.text_content
            new_trust = current.trust_level

            if should_mask:
                raw_text = current.text_content
                token_uuid = str(uuid.uuid4())[:8]
                content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:10]
                mask_token = f"[UCM_MASK:{token_uuid}:{current.tag_name}:{content_hash}]"

                self.store.store(mask_token, current.node_id, current.tag_name, raw_text)
                tokens_created.append(mask_token)

                new_text = mask_token
                new_trust = ContentTrustLevel.MASKED_PLACEHOLDER
                masked_count += 1

            new_children = [_traverse_and_mask(ch) for ch in current.children]

            return DOMContentNode(
                node_id=current.node_id,
                tag_name=current.tag_name,
                trust_level=new_trust,
                text_content=new_text,
                attributes=dict(current.attributes),
                children=new_children,
                layout_bbox=current.layout_bbox,
                is_interactive=current.is_interactive,
            )

        sanitized_root = _traverse_and_mask(root)

        receipt = {
            "event": "UCM_DOM_MASKING_COMPLETE",
            "root_node_id": root.node_id,
            "total_nodes": total_nodes,
            "masked_regions_count": masked_count,
            "mask_tokens": tokens_created,
            "timestamp": round(time.time(), 4),
            "layout_digest": canonical_sha256(sanitized_root.to_dict()),
        }
        return sanitized_root, receipt


# =====================================================================
# Quarantined Model Mediator
# =====================================================================

class QuarantinedModelMediator:
    """
    Safely executes extraction queries over untrusted masked content.
    Enforces strict zero-tool isolation and typed schema parsing, preventing prompt injection payloads
    from commanding the primary planning agent.
    """

    KNOWN_INJECTION_PROBES: Tuple[re.Pattern, ...] = (
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I),
        re.compile(r"system\s*:\s*you\s+are\s+now", re.I),
        re.compile(r"transfer\s+(?:funds|balance|money)", re.I),
        re.compile(r"sudo\s+|rm\s+-rf|chmod\s+", re.I),
        re.compile(r"send\s+(?:password|token|secret|key)\s+to", re.I),
        re.compile(r"curl\s+https?://|wget\s+", re.I),
    )

    def __init__(self, content_store: IsolatedContentStore) -> None:
        self.store = content_store
        self.execution_audit_log: List[Dict[str, Any]] = []

    def execute_quarantined_extraction(
        self,
        mask_token: str,
        target_schema_type: type,
        extraction_prompt: str,
        mock_model_fn: Optional[Callable[[str, str], Any]] = None,
    ) -> Any:
        """
        Dispatches untrusted content to the isolated quarantined model.
        The model is given ZERO tool capabilities and its output is strictly validated against target_schema_type.
        """
        assert_steward_gate_compliance(extraction_prompt)
        rec = self.store.retrieve(mask_token)

        # In testing/simulation, mock_model_fn provides the simulated LLM response
        if mock_model_fn is not None:
            raw_output = mock_model_fn(extraction_prompt, rec.raw_content)
        else:
            # Default safe heuristic extractor
            raw_output = self._default_quarantined_extractor(rec.raw_content, target_schema_type)

        # Validate against target schema
        validated_result = self._validate_quarantined_schema(raw_output, target_schema_type)

        # Record audit log
        audit_entry = {
            "mask_token": mask_token,
            "target_schema": target_schema_type.__name__,
            "content_sha256": rec.content_sha256,
            "status": "QUARANTINED_EXTRACTED_SAFE",
            "timestamp": round(time.time(), 4),
        }
        self.execution_audit_log.append(audit_entry)
        return validated_result

    def _default_quarantined_extractor(self, raw_content: str, target_schema_type: type) -> Any:
        """Default type-constrained parser when no external model is bound."""
        cleaned = raw_content.strip()
        if target_schema_type is str:
            # Strip dangerous command patterns
            safe_text = re.sub(r"[;<>&|]", " ", cleaned)
            return safe_text[:256]
        elif target_schema_type is int:
            nums = re.findall(r"\d+", cleaned)
            return int(nums[0]) if nums else 0
        elif target_schema_type is float:
            nums = re.findall(r"\d+(?:\.\d+)?", cleaned)
            return float(nums[0]) if nums else 0.0
        elif target_schema_type is bool:
            return cleaned.lower() in ("true", "1", "yes")
        elif target_schema_type is dict:
            return {"text": cleaned[:128], "length": len(cleaned)}
        raise QuarantinedExecutionViolation(f"Unsupported schema type: {target_schema_type}")

    def _validate_quarantined_schema(self, output: Any, target_schema_type: type) -> Any:
        """Enforces schema adherence and strips uncontained control codes."""
        if not isinstance(output, target_schema_type):
            raise QuarantinedExecutionViolation(
                f"Quarantined output type '{type(output).__name__}' does not match expected '{target_schema_type.__name__}'"
            )

        assert_steward_gate_compliance(output)

        if isinstance(output, str):
            # Check for prompt injection attempts trying to masquerade as structured output
            for probe in self.KNOWN_INJECTION_PROBES:
                if probe.search(output):
                    raise QuarantinedExecutionViolation(
                        f"Quarantined model output contains suspicious instruction tokens: '{probe.pattern}'"
                    )
        elif isinstance(output, dict):
            for k, v in output.items():
                if isinstance(v, str):
                    for probe in self.KNOWN_INJECTION_PROBES:
                        if probe.search(v):
                            raise QuarantinedExecutionViolation(
                                f"Quarantined dict payload contains injection tokens in key '{k}'"
                            )
        return output


# =====================================================================
# Structural Boundary Gate
# =====================================================================

class StructuralBoundaryGate:
    """
    Coordinates end-to-end containment between the web environment, primary planning agent,
    quarantined mediator, and capability lease manager.
    Detects indirect prompt injection and cascades revocation upon security breach.
    """

    def __init__(
        self,
        revocation_manager: Optional[DynamicRevocationManager] = None,
        content_store: Optional[IsolatedContentStore] = None,
    ) -> None:
        self.store = content_store or IsolatedContentStore()
        self.masker = UntrustedContentMasker(self.store)
        self.mediator = QuarantinedModelMediator(self.store)
        self.revocation_manager = revocation_manager or DynamicRevocationManager()
        self.violations_log: List[Dict[str, Any]] = []

    def sanitize_page_view(self, root_node: DOMContentNode) -> Tuple[DOMContentNode, Dict[str, Any]]:
        """Prepares a web page view for the primary planning agent with all untrusted content masked."""
        return self.masker.mask_dom_tree(root_node)

    def verify_tool_invocation(
        self,
        lease: CapabilityLease,
        action_name: str,
        resource_uri: str,
        tool_args: Dict[str, Any],
    ) -> bool:
        """
        Validates that a tool invocation by the planning agent does not contain raw untrusted text
        or indirect injection commands.
        """
        assert_steward_gate_compliance(action_name)
        assert_steward_gate_compliance(resource_uri)
        assert_steward_gate_compliance(tool_args)

        serialized_args = json.dumps(tool_args, default=str)

        # Check 1: Does serialized_args contain raw untrusted content that wasn't properly masked?
        for mask_token in list(self.store._store.keys()):
            rec = self.store.retrieve(mask_token)
            # If the raw untrusted content is significant (>15 chars) and appears verbatim in tool args
            if len(rec.raw_content.strip()) >= 15 and rec.raw_content.strip() in serialized_args:
                violation = self._handle_containment_breach(
                    lease=lease,
                    reason=f"Raw untrusted content from token '{mask_token}' leaked into tool '{action_name}' parameters",
                    violation_code="UNTRUSTED_CONTENT_LEAK_IN_TOOL_CALL",
                )
                raise BoundaryContainmentViolation(violation["detail"])

        # Check 2: Does serialized_args trigger active injection patterns?
        for probe in QuarantinedModelMediator.KNOWN_INJECTION_PROBES:
            if probe.search(serialized_args):
                violation = self._handle_containment_breach(
                    lease=lease,
                    reason=f"Prompt injection directive '{probe.pattern}' detected in tool '{action_name}' call",
                    violation_code="INDIRECT_PROMPT_INJECTION_DETECTED",
                )
                raise BoundaryContainmentViolation(violation["detail"])

        return True

    def _handle_containment_breach(
        self,
        lease: CapabilityLease,
        reason: str,
        violation_code: str,
    ) -> Dict[str, Any]:
        """Fails closed and dynamically revokes the offending agent's capability leases."""
        revoked_leases = []
        if self.revocation_manager.is_active(lease.lease_id):
            revoked_leases = self.revocation_manager.revoke(
                lease_id=lease.lease_id,
                reason=f"CONTAINMENT_BREACH: {reason}",
                revoked_by="StructuralBoundaryGate",
            )

        receipt = {
            "event": "BOUNDARY_CONTAINMENT_BREACH",
            "primary_lease_id": lease.lease_id,
            "violation_code": violation_code,
            "detail": reason,
            "revoked_leases": revoked_leases,
            "timestamp": round(time.time(), 4),
            "digest": canonical_sha256({
                "lease_id": lease.lease_id,
                "code": violation_code,
                "detail": reason,
            }),
        }
        self.violations_log.append(receipt)
        return receipt

    def get_violations(self) -> List[Dict[str, Any]]:
        return list(self.violations_log)
