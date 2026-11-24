"""
research/ledger_sim/skill_supply_chain_security_guard.py

Object-Capability Bounded Sandboxing and Formal Supply Chain Security Guard for Agentic AI Skills.

Scientific Provenance:
- Jack B. Dennis & Earl C. Van Horn (1966): Programming Semantics for Multiprogrammed Computations (CACM)
  [Object-Capability Model, Fine-grained Access Control, Zero Ambient Authority].
- Mark S. Miller (2006): Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control
  [Object Capabilities, Monotonic Attenuation, Caretaker Revocation].
- Formal Analysis and Supply Chain Security for Agentic AI Skills (arXiv:2603.00195, 2026, SkillFortify):
  Formal framework for agent skill supply chains, verifying declarative capability manifests and
  enforcing runtime object-capability mediation (OCapResourceBroker).
- Exploiting LLM Agent Supply Chains via Payload-less Skills (arXiv:2605.14460, 2026):
  Addresses deceptive natural language instructions disguised as operational prerequisites.
- Supply-Chain Poisoning Attacks Against LLM Coding Agent Skill Ecosystems (arXiv:2604.03081, 2026):
  Mitigates implicit payload drops and tool manipulation in third-party skill documentation.

Core Architectural Guarantees:
1. Zero Ambient Authority: Tools, file paths, and network endpoints cannot be accessed without presenting
   an unforgeable, cryptographically signed CapabilityHandle.
2. Formal Manifest Attestation: Every skill package must declare static tool permissions, path scopes,
   and instruction hash before registration.
3. Monotonic Capability Attenuation: Subagents and delegated skills can only receive a subset of
   the delegating parent's permissions; rights amplification fails closed.
4. Payload-less Supply Chain Injection Scanning: Pre-execution inspection identifies prompt-level
   evasion patterns, confirmation overrides, and credential harvester directives.
5. Dynamic Revocation Cascades: Revoking a parent handle immediately invalidates all child handles.
6. W3C PROV-DM Cryptographic Receipts: Every verification and brokered action emits an immutable
   audit receipt with SHA-256 digests.
7. Strict CIN Steward Gate Compliance: Clean plain-language interface without token or money promises.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union


# =====================================================================
# Error Hierarchy
# =====================================================================

class SkillSecurityViolation(Exception):
    """Base exception for skill supply chain security violations."""


class SkillManifestValidationError(SkillSecurityViolation):
    """Raised when a skill manifest is malformed or its integrity hash fails."""


class MonotonicAttenuationViolation(SkillSecurityViolation):
    """Raised when a child skill attempts to amplify or exceed parent permissions."""


class AmbientAuthorityViolation(SkillSecurityViolation):
    """Raised when an action is attempted without a valid capability handle."""


class CapabilityRevokedError(SkillSecurityViolation):
    """Raised when an action is attempted using a revoked capability handle."""


class CapabilityExpiredError(SkillSecurityViolation):
    """Raised when an action is attempted using an expired capability handle."""


class PayloadlessSkillInjectionDetected(SkillSecurityViolation):
    """Raised when a skill's instructions contain deceptive supply-chain injection patterns."""


class StewardGateViolation(SkillSecurityViolation):
    """Raised when prohibited token, money, or internal ticket terms are detected."""


# =====================================================================
# Steward Gate Compliance Helpers
# =====================================================================

_PROHIBITED_TERMS = re.compile(
    r"(?:\b|_)(?:Contribution[-_ ]Tokens?|MMCT|\$\d+|royalt(?:y|ies))(?:\b|_)",
    re.I,
)
_PROHIBITED_TICKETS = re.compile(r"\b[DLP]-\d{3,4}\b")


def assert_steward_gate_compliance(text: str) -> None:
    """Ensure text strictly adheres to the CIN Steward Gate rules."""
    m_terms = _PROHIBITED_TERMS.search(text)
    if m_terms:
        raise StewardGateViolation(f"Steward Gate violation: prohibited term '{m_terms.group()}'")
    m_tick = _PROHIBITED_TICKETS.search(text)
    if m_tick:
        raise StewardGateViolation(f"Steward Gate violation: internal ticket ID '{m_tick.group()}'")


def canonical_sha256(data: Any) -> str:
    """Compute canonical SHA-256 digest of arbitrary structured data."""
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# =====================================================================
# Deceptive Skill & Supply Chain Injection Signatures
# =====================================================================

_SUPPLY_CHAIN_INJECTION_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (
        re.compile(r"\b(?:auto[- ]?confirm|skip[- ]?confirmation|bypass[- ]?approval|waive[- ]?gate)\b", re.I),
        "Confirmation bypass directive",
    ),
    (
        re.compile(r"\b(?:export|exfiltrate|leak|transmit|upload)\s+(?:api[- ]?key|secret|token|credential|env|password)\b", re.I),
        "Credential exfiltration directive",
    ),
    (
        re.compile(r"\b(?:curl|wget|nc|bash -i)\b.*?(?:\|\s*(?:sh|bash))\b", re.I),
        "Piped remote execution pattern",
    ),
    (
        re.compile(r"[\u200B\u200C\u200D\uFEFF]", re.UNICODE),
        "Zero-width steganographic concealment",
    ),
    (
        re.compile(r"\b(?:pretend\s+you\s+are\s+system|override\s+runtime\s+policy|disable\s+safety\s+filter)\b", re.I),
        "Policy override simulation",
    ),
)


# =====================================================================
# Data Classes: Manifest, Capability Handle, and Audit Receipt
# =====================================================================

@dataclasses.dataclass(frozen=True)
class SkillManifest:
    """Declarative capability contract for a reusable agent skill."""
    skill_id: str
    version: str
    author: str
    description: str
    allowed_tools: Tuple[str, ...]
    file_path_scopes: Tuple[str, ...]
    network_endpoints: Tuple[str, ...]
    memory_scopes: Tuple[str, ...]
    instruction_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "allowed_tools": list(self.allowed_tools),
            "file_path_scopes": list(self.file_path_scopes),
            "network_endpoints": list(self.network_endpoints),
            "memory_scopes": list(self.memory_scopes),
            "instruction_hash": self.instruction_hash,
        }


@dataclasses.dataclass(frozen=True)
class CapabilityHandle:
    """An unforgeable object-capability handle granting restricted tool access."""
    handle_id: str
    holder_agent: str
    allowed_tools: Tuple[str, ...]
    file_path_scopes: Tuple[str, ...]
    network_endpoints: Tuple[str, ...]
    parent_handle_id: Optional[str]
    created_at: float
    expires_at: float
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle_id": self.handle_id,
            "holder_agent": self.holder_agent,
            "allowed_tools": list(self.allowed_tools),
            "file_path_scopes": list(self.file_path_scopes),
            "network_endpoints": list(self.network_endpoints),
            "parent_handle_id": self.parent_handle_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }


@dataclasses.dataclass(frozen=True)
class ProvReceipt:
    """W3C PROV-DM compliant cryptographic execution receipt."""
    receipt_id: str
    action_type: str
    principal: str
    target_resource: str
    timestamp: float
    handle_id: Optional[str]
    manifest_hash: Optional[str]
    status: str
    details: Dict[str, Any]
    receipt_hash: str


# =====================================================================
# Object-Capability Broker: OCapResourceBroker
# =====================================================================

class OCapResourceBroker:
    """
    Object-Capability Resource Broker enforcing zero ambient authority,
    monotonic attenuation, and dynamic revocation.
    """

    def __init__(self, signing_secret: bytes = b"cin-ocap-broker-secret-2026"):
        self._secret = signing_secret
        self._active_handles: Dict[str, CapabilityHandle] = {}
        self._revoked_handles: Dict[str, Tuple[float, str]] = {}  # handle_id -> (timestamp, reason)
        self._children: Dict[str, Set[str]] = {}  # parent_id -> set of child_ids
        self._receipts: List[ProvReceipt] = []

    def _sign(self, payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._secret, serialized.encode("utf-8"), hashlib.sha256).hexdigest()

    def mint_root_handle(
        self,
        holder_agent: str,
        allowed_tools: Sequence[str],
        file_path_scopes: Sequence[str],
        network_endpoints: Sequence[str],
        lifetime_seconds: float = 3600.0,
    ) -> CapabilityHandle:
        """Mint a root capability handle for an authorized agent."""
        assert_steward_gate_compliance(holder_agent)
        now = time.time()
        handle_id = f"cap-root-{hashlib.sha256(f'{holder_agent}-{now}'.encode()).hexdigest()[:12]}"
        expires_at = now + lifetime_seconds

        payload = {
            "handle_id": handle_id,
            "holder_agent": holder_agent,
            "allowed_tools": sorted(set(allowed_tools)),
            "file_path_scopes": sorted(set(file_path_scopes)),
            "network_endpoints": sorted(set(network_endpoints)),
            "parent_handle_id": None,
            "created_at": now,
            "expires_at": expires_at,
        }
        sig = self._sign(payload)

        handle = CapabilityHandle(
            handle_id=handle_id,
            holder_agent=holder_agent,
            allowed_tools=tuple(sorted(set(allowed_tools))),
            file_path_scopes=tuple(sorted(set(file_path_scopes))),
            network_endpoints=tuple(sorted(set(network_endpoints))),
            parent_handle_id=None,
            created_at=now,
            expires_at=expires_at,
            signature=sig,
        )
        self._active_handles[handle_id] = handle
        self._children[handle_id] = set()
        return handle

    def attenuate_handle(
        self,
        parent_handle: CapabilityHandle,
        child_agent: str,
        allowed_tools: Sequence[str],
        file_path_scopes: Sequence[str],
        network_endpoints: Sequence[str],
        lifetime_seconds: float = 1800.0,
    ) -> CapabilityHandle:
        """
        Derive an attenuated child capability handle from an existing parent.
        Enforces monotonic attenuation (Miller et al., 2003): rights cannot be amplified.
        """
        self.verify_handle(parent_handle)
        assert_steward_gate_compliance(child_agent)

        # Monotonicity check 1: Tools must be subset of parent tools
        parent_tools = set(parent_handle.allowed_tools)
        child_tools = set(allowed_tools)
        if not child_tools.issubset(parent_tools):
            amplified = child_tools - parent_tools
            raise MonotonicAttenuationViolation(
                f"Tool amplification detected: requested {sorted(amplified)} not present in parent handle"
            )

        # Monotonicity check 2: File scopes must be subsumed by parent scopes
        parent_scopes = parent_handle.file_path_scopes
        for child_scope in file_path_scopes:
            subsumed = any(child_scope.startswith(ps) or ps == "*" for ps in parent_scopes)
            if not subsumed:
                raise MonotonicAttenuationViolation(
                    f"Path amplification: child scope '{child_scope}' not covered by parent scopes {parent_scopes}"
                )

        # Monotonicity check 3: Network endpoints must be subset of parent endpoints
        parent_endpoints = set(parent_handle.network_endpoints)
        child_endpoints = set(network_endpoints)
        if not child_endpoints.issubset(parent_endpoints) and "*" not in parent_endpoints:
            amplified_net = child_endpoints - parent_endpoints
            raise MonotonicAttenuationViolation(
                f"Network amplification: requested endpoints {sorted(amplified_net)} not allowed by parent"
            )

        now = time.time()
        child_expiry = min(now + lifetime_seconds, parent_handle.expires_at)
        child_id = f"cap-child-{hashlib.sha256(f'{child_agent}-{now}-{parent_handle.handle_id}'.encode()).hexdigest()[:12]}"

        payload = {
            "handle_id": child_id,
            "holder_agent": child_agent,
            "allowed_tools": sorted(child_tools),
            "file_path_scopes": sorted(set(file_path_scopes)),
            "network_endpoints": sorted(child_endpoints),
            "parent_handle_id": parent_handle.handle_id,
            "created_at": now,
            "expires_at": child_expiry,
        }
        sig = self._sign(payload)

        child_handle = CapabilityHandle(
            handle_id=child_id,
            holder_agent=child_agent,
            allowed_tools=tuple(sorted(child_tools)),
            file_path_scopes=tuple(sorted(set(file_path_scopes))),
            network_endpoints=tuple(sorted(child_endpoints)),
            parent_handle_id=parent_handle.handle_id,
            created_at=now,
            expires_at=child_expiry,
            signature=sig,
        )

        self._active_handles[child_id] = child_handle
        self._children[child_id] = set()
        self._children[parent_handle.handle_id].add(child_id)
        return child_handle

    def verify_handle(self, handle: CapabilityHandle) -> None:
        """Verify unforgeability, validity, expiration, and revocation status."""
        if handle.handle_id in self._revoked_handles:
            ts, reason = self._revoked_handles[handle.handle_id]
            raise CapabilityRevokedError(f"Handle {handle.handle_id} was revoked at {ts}: {reason}")

        if handle.handle_id not in self._active_handles:
            raise AmbientAuthorityViolation(f"Unregistered or forged handle: {handle.handle_id}")

        # Check signature integrity
        payload = {
            "handle_id": handle.handle_id,
            "holder_agent": handle.holder_agent,
            "allowed_tools": sorted(handle.allowed_tools),
            "file_path_scopes": sorted(handle.file_path_scopes),
            "network_endpoints": sorted(handle.network_endpoints),
            "parent_handle_id": handle.parent_handle_id,
            "created_at": handle.created_at,
            "expires_at": handle.expires_at,
        }
        expected_sig = self._sign(payload)
        if not hmac.compare_digest(handle.signature, expected_sig):
            raise AmbientAuthorityViolation("Cryptographic signature mismatch on capability handle")

        # Expiry check
        if time.time() > handle.expires_at:
            raise CapabilityExpiredError(f"Handle {handle.handle_id} expired at {handle.expires_at}")

    def revoke(self, handle_id: str, reason: str) -> List[str]:
        """Revoke a capability handle and trigger a cascading revocation of all descendants."""
        now = time.time()
        revoked: List[str] = []

        def _cascade(hid: str):
            if hid in self._active_handles:
                del self._active_handles[hid]
            self._revoked_handles[hid] = (now, reason)
            revoked.append(hid)
            for child in self._children.get(hid, set()):
                if child not in self._revoked_handles:
                    _cascade(child)

        _cascade(handle_id)
        return revoked

    def authorize_tool_invocation(
        self,
        handle: CapabilityHandle,
        tool_name: str,
        target_resource: str,
    ) -> bool:
        """Check whether a presented capability handle authorizes the given tool and target resource."""
        self.verify_handle(handle)

        if tool_name not in handle.allowed_tools:
            return False

        # If it's a file operation, check path scoping
        if "file" in tool_name or target_resource.startswith(("/", "\\", "C:", "E:", ".")):
            allowed = any(
                target_resource.startswith(ps) or ps == "*"
                for ps in handle.file_path_scopes
            )
            if not allowed:
                return False

        # If it's a network operation, check endpoint scoping
        if "net" in tool_name or target_resource.startswith(("http://", "https://")):
            allowed = any(
                target_resource.startswith(ne) or ne == "*"
                for ne in handle.network_endpoints
            )
            if not allowed:
                return False

        return True


# =====================================================================
# Skill Supply Chain Security Guard
# =====================================================================

class SkillSupplyChainSecurityGuard:
    """
    Formal analysis and sandboxing guard for agent skill supply chains.
    Enforces manifest validation, payload-less instruction auditing,
    OCap mediation, and W3C PROV-DM cryptographic certification.
    """

    def __init__(self, broker: Optional[OCapResourceBroker] = None):
        self.broker = broker or OCapResourceBroker()
        self._verified_skills: Dict[str, SkillManifest] = {}
        self._audit_log: List[ProvReceipt] = []

    def verify_skill_package(
        self,
        manifest: SkillManifest,
        skill_text: str,
        parent_handle: Optional[CapabilityHandle] = None,
    ) -> ProvReceipt:
        """
        Verify a skill package's integrity, check for deceptive injection patterns,
        validate monotonic attenuation against an optional parent handle, and certify.
        """
        assert_steward_gate_compliance(manifest.skill_id)
        assert_steward_gate_compliance(manifest.description)
        assert_steward_gate_compliance(skill_text)

        # 1. Integrity check: SHA-256 of skill text must match manifest declaration
        actual_hash = hashlib.sha256(skill_text.encode("utf-8")).hexdigest()
        if actual_hash != manifest.instruction_hash:
            raise SkillManifestValidationError(
                f"Instruction hash mismatch: manifest declared {manifest.instruction_hash[:10]}, "
                f"computed {actual_hash[:10]}"
            )

        # 2. Payload-less supply chain injection scan
        for pattern, desc in _SUPPLY_CHAIN_INJECTION_PATTERNS:
            if pattern.search(skill_text):
                raise PayloadlessSkillInjectionDetected(
                    f"Malicious skill injection directive detected: {desc}"
                )

        # 3. Monotonic attenuation against parent handle if provided
        if parent_handle is not None:
            self.broker.verify_handle(parent_handle)
            parent_tools = set(parent_handle.allowed_tools)
            requested_tools = set(manifest.allowed_tools)
            if not requested_tools.issubset(parent_tools):
                amplified = requested_tools - parent_tools
                raise MonotonicAttenuationViolation(
                    f"Skill manifest requests tools outside parent capability handle: {sorted(amplified)}"
                )

        # 4. Record verified skill
        self._verified_skills[manifest.skill_id] = manifest

        # 5. Emit W3C PROV-DM certification receipt
        now = time.time()
        receipt_id = f"prov-cert-{hashlib.sha256(f'{manifest.skill_id}-{now}'.encode()).hexdigest()[:12]}"
        details = {
            "skill_id": manifest.skill_id,
            "version": manifest.version,
            "allowed_tools": list(manifest.allowed_tools),
            "file_path_scopes": list(manifest.file_path_scopes),
            "network_endpoints": list(manifest.network_endpoints),
            "instruction_hash": actual_hash,
        }
        receipt_hash = canonical_sha256(details)

        receipt = ProvReceipt(
            receipt_id=receipt_id,
            action_type="SKILL_CERTIFICATION",
            principal=manifest.author,
            target_resource=manifest.skill_id,
            timestamp=now,
            handle_id=parent_handle.handle_id if parent_handle else None,
            manifest_hash=actual_hash,
            status="CERTIFIED",
            details=details,
            receipt_hash=receipt_hash,
        )
        self._audit_log.append(receipt)
        return receipt

    def execute_brokered_action(
        self,
        handle: CapabilityHandle,
        skill_id: str,
        tool_name: str,
        target_resource: str,
        action_fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Tuple[Any, ProvReceipt]:
        """
        Mediate execution of an authorized tool call via OCapResourceBroker,
        issuing a verified execution receipt.
        """
        assert_steward_gate_compliance(skill_id)
        assert_steward_gate_compliance(tool_name)
        assert_steward_gate_compliance(target_resource)

        # Verify skill was certified
        if skill_id not in self._verified_skills:
            raise SkillSecurityViolation(f"Uncertified skill '{skill_id}' attempted tool execution")

        manifest = self._verified_skills[skill_id]
        if tool_name not in manifest.allowed_tools:
            raise SkillSecurityViolation(
                f"Skill '{skill_id}' attempted undeclared tool '{tool_name}' (manifest allowed: {manifest.allowed_tools})"
            )

        # Authorize via OCap broker
        authorized = self.broker.authorize_tool_invocation(handle, tool_name, target_resource)
        if not authorized:
            raise AmbientAuthorityViolation(
                f"Capability handle {handle.handle_id} does not authorize tool '{tool_name}' on '{target_resource}'"
            )

        # Execute
        result = action_fn(*args, **kwargs)

        # Log receipt
        now = time.time()
        receipt_id = f"prov-exec-{hashlib.sha256(f'{skill_id}-{tool_name}-{now}'.encode()).hexdigest()[:12]}"
        details = {
            "skill_id": skill_id,
            "tool_name": tool_name,
            "target_resource": target_resource,
            "handle_id": handle.handle_id,
        }
        receipt = ProvReceipt(
            receipt_id=receipt_id,
            action_type="BROKERED_EXECUTION",
            principal=handle.holder_agent,
            target_resource=target_resource,
            timestamp=now,
            handle_id=handle.handle_id,
            manifest_hash=manifest.instruction_hash,
            status="SUCCESS",
            details=details,
            receipt_hash=canonical_sha256(details),
        )
        self._audit_log.append(receipt)
        return result, receipt

    def get_audit_trail(self) -> List[ProvReceipt]:
        """Retrieve copy of verified cryptographic audit receipts."""
        return list(self._audit_log)
