"""
research/ledger_sim/dual_view_environment_guard.py

DualView Environment Quarantine Guard: Defending Against Stored Indirect Prompt Injection.

Scientific Provenance:
  - Kim, Choi, Kang, Kim, & Lee (July 2026), "DualView: Preventing Indirect Prompt
    Injection in Personal AI Agents", arXiv:2607.03821.
  - Dennis & Van Horn (1966), "Programming Semantics for Multiprogrammed Computations",
    Communications of the ACM, 9(3), 143-155 (Object-Capability Security).
  - NIST AI 100-2e2025, "Adversarial Machine Learning: A Taxonomy and Terminology of
    Attacks and Mitigations", Section 3.2 (Prompt Injection & Taint Containment).
  - CIN THESIS-01, THESIS-04, VOL-01 & VOL-04: Capability-Isolated Personal Agent Runtimes.

Architectural Purpose:
  Standard in-context defenses (Dual-LLM, StruQ, CaMeL) isolate untrusted data inside
  the active model prompt. However, when an autonomous agent writes untrusted data or
  intermediate summaries to local files, scratchpads, or memory caches and reads them
  back later, traditional architectures lose the taint tag, enabling Stored Indirect
  Prompt Injection (Stored IPI).
  
  DualView maintains two strictly segregated views of the local execution environment:
  1. HumanView: Stores original, human-readable text and files so human operators and
     standard operating system utilities inspect files without friction.
  2. AgentView: Replaces untrusted content and derived files with unforgeable, symbolic
     OpaqueCapabilityHandles. The reasoning model references data symbolically without
     ingesting raw injection payloads as executable instructions.
  3. Action Gate: Side-effecting actions (network egress, shell execution, external dispatch)
     dereferencing tainted handles require explicit cryptographic approval or typed schema unwrapping.
  4. Steward Gate: Enforces fail-closed rejection of forbidden tokens, speculative claims,
     and non-finite floating point numbers.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import math
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


class StoredIPIError(Exception):
    """Base exception for Stored Indirect Prompt Injection guard violations."""


class UntrustedHandleEgressViolation(StoredIPIError):
    """Raised when an untrusted handle attempts unauthorized egress or side-effect."""


class TaintTrackingViolation(StoredIPIError):
    """Raised when taint propagation is corrupted or missing."""


class StewardGateViolation(StoredIPIError):
    """Raised when forbidden speculative monetary tokens or sci-fi lore are encountered."""


class ParameterValidationError(StoredIPIError):
    """Raised when numeric inputs are non-finite (NaN/Inf) or schemas are invalid."""


class TaintOrigin(str, enum.Enum):
    """Origin classification for environment data and artifacts."""
    TRUSTED_USER = "TRUSTED_USER"
    UNTRUSTED_WEB = "UNTRUSTED_WEB"
    UNTRUSTED_EMAIL = "UNTRUSTED_EMAIL"
    UNTRUSTED_TOOL = "UNTRUSTED_TOOL"
    DERIVED_TAINT = "DERIVED_TAINT"


# Known indirect prompt injection delimiters and escape sequences
IPI_PAYLOAD_PATTERNS: Sequence[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are\s+now", re.IGNORECASE),
    re.compile(r"<\s*\|?\s*im_start\s*\|?\s*>", re.IGNORECASE),
    re.compile(r"<\s*\|?\s*im_end\s*\|?\s*>", re.IGNORECASE),
    re.compile(r"\[\s*SYSTEM\s*TASK\s*OVERRIDE\s*\]", re.IGNORECASE),
    re.compile(r"exfiltrate\s+to\s+https?://", re.IGNORECASE),
    re.compile(r"export\s+AWS_SECRET|export\s+OPENAI_API_KEY", re.IGNORECASE),
]

# Steward Gate forbidden patterns (R4 & R5)
FORBIDDEN_STEWARD_PATTERNS: Sequence[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE), "Contribution Token forbidden"),
    (re.compile(r"\bMMCT\b"), "MMCT token ticker forbidden"),
    (re.compile(r"\btokens?\s+(reward|payout|airdrop)", re.IGNORECASE), "Token payout/reward forbidden"),
    (re.compile(r"\b(earn|save)\s+\$\s?[0-9]", re.IGNORECASE), "Monetary earn/save claim forbidden"),
    (re.compile(r"\broyalt(y|ies)\b", re.IGNORECASE), "Royalty promise forbidden"),
    (re.compile(r"\b(Somatic Witness|Pre-ADC|Upcoding Reversal|Algebraic Coalition|Fractured Alignment)\b", re.IGNORECASE), "Retired buzzword forbidden"),
]


@dataclasses.dataclass(frozen=True)
class OpaqueCapabilityHandle:
    """Unforgeable capability handle presented to the AgentView instead of raw untrusted text."""
    handle_id: str
    content_hash: str
    taint_origin: TaintOrigin
    byte_length: int
    mime_type: str
    virtual_path: str
    created_at: float
    derivation_parents: Tuple[str, ...] = ()

    def is_tainted(self) -> bool:
        return self.taint_origin != TaintOrigin.TRUSTED_USER


def _validate_safe_path(path: Any) -> str:
    if not isinstance(path, str):
        raise ParameterValidationError(f"Path must be a string, got {type(path).__name__}")
    p = path.strip()
    if not p:
        raise ParameterValidationError("Path must not be empty or whitespace only")
    if len(p) > 512:
        raise ParameterValidationError("Path exceeds maximum length of 512 characters")
    if ".." in p.split("/") or ".." in p.split("\\"):
        raise ParameterValidationError(f"Path traversal detected in '{path}'")
    if not re.match(r"^[A-Za-z0-9_./@-]+$", p):
        raise ParameterValidationError(f"Path contains invalid characters: '{path}'")
    return p


def _validate_finite_number(val: Any, field_name: str) -> float:
    if isinstance(val, bool):
        raise ParameterValidationError(f"{field_name} must be numeric, got bool")
    if not isinstance(val, (int, float)):
        raise ParameterValidationError(f"{field_name} must be a number, got {type(val).__name__}")
    f = float(val)
    if math.isnan(f) or math.isinf(f):
        raise ParameterValidationError(f"{field_name} must be finite, got {f}")
    return f


def _check_steward_gate(text: str) -> None:
    for pat, desc in FORBIDDEN_STEWARD_PATTERNS:
        if pat.search(text):
            raise StewardGateViolation(f"Steward Gate violation: {desc}")


class DualViewEnvironmentGuard:
    """
    DualView Environment Quarantine Reference Monitor.
    
    Synchronizes HumanView and AgentView representations of storage,
    intercepting Stored Indirect Prompt Injection before execution.
    """

    def __init__(self, master_secret_key: bytes) -> None:
        if not isinstance(master_secret_key, bytes) or len(master_secret_key) < 16:
            raise ParameterValidationError("master_secret_key must be at least 16 bytes")
        self._secret = master_secret_key
        # HumanView: path -> raw string content
        self._human_view: Dict[str, str] = {}
        # AgentView: path -> OpaqueCapabilityHandle or raw string (if trusted)
        self._agent_view: Dict[str, Any] = {}
        # Handle registry: handle_id -> OpaqueCapabilityHandle
        self._handles: Dict[str, OpaqueCapabilityHandle] = {}
        # Audit log of intercepted injection payloads
        self._intercepted_threats: List[Dict[str, Any]] = []

    @property
    def intercepted_threat_count(self) -> int:
        return len(self._intercepted_threats)

    def write_file(
        self,
        path: str,
        content: str,
        origin: TaintOrigin,
        mime_type: str = "text/plain",
        timestamp: Optional[float] = None,
        parent_handles: Sequence[str] = (),
    ) -> Optional[OpaqueCapabilityHandle]:
        """
        Write a file into the dual-view environment.
        
        If origin is untrusted or parent handles are tainted, the content is stored
        in HumanView as raw text, but in AgentView as an OpaqueCapabilityHandle.
        """
        clean_path = _validate_safe_path(path)
        if not isinstance(content, str):
            raise ParameterValidationError(f"Content must be str, got {type(content).__name__}")
        if not isinstance(origin, TaintOrigin):
            raise ParameterValidationError(f"Origin must be TaintOrigin enum, got {origin}")
        
        now = time.time() if timestamp is None else _validate_finite_number(timestamp, "timestamp")
        
        # Enforce Steward Gate invariants across all written content
        _check_steward_gate(content)

        # Detect any embedded prompt injection threats
        is_injection = any(pat.search(content) for pat in IPI_PAYLOAD_PATTERNS)
        if is_injection:
            self._intercepted_threats.append({
                "path": clean_path,
                "origin": origin.value,
                "timestamp": now,
                "threat": "IPI_PAYLOAD_DETECTED",
            })

        # Calculate cryptographic commitment
        payload_bytes = content.encode("utf-8")
        content_hash = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)

        # Always record in HumanView for human inspection and conventional OS tools
        self._human_view[clean_path] = content

        # Validate and check parent handles
        for h in parent_handles:
            if h not in self._handles:
                raise TaintTrackingViolation(f"Unknown parent handle ID '{h}' in derivation chain")
        inherited_taint = any(self._handles[h].is_tainted() for h in parent_handles)
        
        if is_injection and origin == TaintOrigin.TRUSTED_USER:
            effective_origin = TaintOrigin.DERIVED_TAINT
        elif inherited_taint and origin == TaintOrigin.TRUSTED_USER:
            effective_origin = TaintOrigin.DERIVED_TAINT
        else:
            effective_origin = origin

        if effective_origin == TaintOrigin.TRUSTED_USER and not is_injection:
            # Clean trusted user input: AgentView can receive the raw content safely
            self._agent_view[clean_path] = content
            return None
        else:
            # Untrusted or tainted content: Quarantine in AgentView as an OpaqueCapabilityHandle
            handle_digest = hmac.new(
                self._secret,
                f"{clean_path}:{content_hash}:{now}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()[:24]
            handle_id = f"ref://{handle_digest}"

            handle = OpaqueCapabilityHandle(
                handle_id=handle_id,
                content_hash=content_hash,
                taint_origin=effective_origin,
                byte_length=byte_len,
                mime_type=mime_type,
                virtual_path=clean_path,
                created_at=now,
                derivation_parents=tuple(parent_handles),
            )
            self._handles[handle_id] = handle
            self._agent_view[clean_path] = handle
            return handle

    def read_for_agent(self, path: str) -> Any:
        """
        Read the file representation for the AI Agent (AgentView).
        
        Returns an OpaqueCapabilityHandle if tainted/untrusted, preventing
        stored indirect prompt injection payloads from entering the prompt.
        """
        clean_path = _validate_safe_path(path)
        if clean_path not in self._agent_view:
            raise KeyError(f"File not found in AgentView: {clean_path}")
        return self._agent_view[clean_path]

    def read_for_human(self, path: str) -> str:
        """
        Read the file representation for the Human / OS utility (HumanView).
        
        Returns the raw, transparent text.
        """
        clean_path = _validate_safe_path(path)
        if clean_path not in self._human_view:
            raise KeyError(f"File not found in HumanView: {clean_path}")
        return self._human_view[clean_path]

    def generate_human_approval_token(self, handle_id: str, permitted_action: str) -> str:
        """
        Generate an unforgeable cryptographic authorization token after human review.
        """
        if handle_id not in self._handles:
            raise KeyError(f"Handle not registered: {handle_id}")
        action = _validate_safe_path(permitted_action)
        handle = self._handles[handle_id]
        msg = f"APPROVE:{handle.handle_id}:{handle.content_hash}:{action}"
        sig = hmac.new(self._secret, msg.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"tok_{sig}"

    def verify_and_dereference_handle(
        self,
        handle_id: str,
        action_name: str,
        approval_token: Optional[str] = None,
    ) -> str:
        """
        Dereference an OpaqueCapabilityHandle for tool execution.
        
        Enforces least-privilege egress gates:
        Untrusted or tainted handles require a valid human approval token.
        Deliberate prompt injection payloads are blocked fail-closed.
        """
        if handle_id not in self._handles:
            raise KeyError(f"Handle not registered: {handle_id}")
        handle = self._handles[handle_id]
        clean_action = _validate_safe_path(action_name)

        if handle.is_tainted():
            if not approval_token or not isinstance(approval_token, str):
                raise UntrustedHandleEgressViolation(
                    f"Untrusted handle {handle_id} from {handle.taint_origin.value} "
                    f"requires human approval token for action '{clean_action}'."
                )
            expected_tok = self.generate_human_approval_token(handle_id, clean_action)
            if not hmac.compare_digest(approval_token, expected_tok):
                raise UntrustedHandleEgressViolation(
                    f"Invalid approval token for handle {handle_id} on action '{clean_action}'."
                )

        raw_content = self._human_view.get(handle.virtual_path, "")
        
        # Verify content hash has not been tampered in storage
        actual_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        if actual_hash != handle.content_hash:
            raise StoredIPIError(
                f"Integrity check failed for handle {handle_id}: hash mismatch."
            )

        # Check for prompt injection delimiters attempting to break execution context
        for pat in IPI_PAYLOAD_PATTERNS:
            if pat.search(raw_content):
                raise UntrustedHandleEgressViolation(
                    f"Payload inside handle {handle_id} contains active prompt injection attack; execution refused."
                )

        return raw_content
