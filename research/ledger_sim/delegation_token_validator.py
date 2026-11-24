"""
research/ledger_sim/delegation_token_validator.py

Cryptographic Delegation Token Validator for Multi-Agent Task Chains.

Grounded in:
- IETF WIMSE Internet-Draft: draft-asor-wimse-agent-delegation-chain-03 (Oct 2026).
- RFC 9396: Rich Authorization Requests (RAR).
- RFC 9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens.
- CIN THESIS-01, THESIS-04 & VOL-04: Capability-Bounded Personal Agent Runtimes.

Enforces deterministic, offline verification of monotonic authority attenuation,
cryptographic parent byte-commitments, bounded delegation depth, and monotonic lifetime
expiry across autonomous multi-agent task chains without live authorization server calls.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple


class DelegationValidationError(Exception):
    """Raised when delegation token schema, types, or bounds are violated."""


class DelegationSecurityViolation(Exception):
    """Raised when delegation chain security invariants or signatures fail."""


def _validate_str(val: Any, field_name: str, max_len: int = 256) -> str:
    if not isinstance(val, str):
        raise DelegationValidationError(f"{field_name} must be a str, got {type(val).__name__}")
    s = val.strip()
    if not s:
        raise DelegationValidationError(f"{field_name} must not be empty or whitespace only")
    if len(s) > max_len:
        raise DelegationValidationError(f"{field_name} exceeds max length {max_len}")
    return s


def _validate_safe_id(val: Any, field_name: str = "id") -> str:
    s = _validate_str(val, field_name, max_len=128)
    if not re.match(r"^[A-Za-z0-9_.:@/-]+$", s):
        raise DelegationValidationError(f"{field_name} contains invalid characters: '{s}'")
    return s


def _validate_non_neg_int(val: Any, field_name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise DelegationValidationError(f"{field_name} must be an integer, got {type(val).__name__}")
    if val < 0:
        raise DelegationValidationError(f"{field_name} must be non-negative, got {val}")
    return val


@dataclasses.dataclass(frozen=True)
class DelegationScope:
    """Rich Authorization Request (RAR, RFC 9396) scope item."""
    action: str
    resource: str
    max_budget: int = 0
    constraints: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _validate_safe_id(self.action, "action")
        _validate_safe_id(self.resource, "resource")
        _validate_non_neg_int(self.max_budget, "max_budget")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "resource": self.resource,
            "max_budget": self.max_budget,
            "constraints": dict(self.constraints),
        }

    def allows(self, child_scope: DelegationScope) -> bool:
        """Check if this parent scope subsumes (allows) the child scope monotonically."""
        if self.action != "*" and self.action != child_scope.action:
            return False
        if self.resource != "*" and self.resource != child_scope.resource:
            return False
        if self.max_budget > 0:
            if child_scope.max_budget == 0 or child_scope.max_budget > self.max_budget:
                return False
        return True


@dataclasses.dataclass(frozen=True)
class DelegationToken:
    """Immutable delegation token carrying verifiable authority grants."""
    token_id: str
    principal: str
    issuer_actor: str
    audience_actor: str
    parent_token_hash: Optional[str]
    depth: int
    max_depth: int
    issued_at: int
    expires_at: int
    scopes: Tuple[DelegationScope, ...]
    token_status_list_uri: str = "https://example.com/status/revocation-list"
    signature: str = ""

    def __post_init__(self) -> None:
        _validate_safe_id(self.token_id, "token_id")
        _validate_safe_id(self.principal, "principal")
        _validate_safe_id(self.issuer_actor, "issuer_actor")
        _validate_safe_id(self.audience_actor, "audience_actor")
        if self.parent_token_hash is not None:
            _validate_safe_id(self.parent_token_hash, "parent_token_hash")
        _validate_non_neg_int(self.depth, "depth")
        _validate_non_neg_int(self.max_depth, "max_depth")
        if self.depth > self.max_depth:
            raise DelegationValidationError(f"depth ({self.depth}) cannot exceed max_depth ({self.max_depth})")
        _validate_non_neg_int(self.issued_at, "issued_at")
        _validate_non_neg_int(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise DelegationValidationError(f"expires_at ({self.expires_at}) must be > issued_at ({self.issued_at})")
        if not self.scopes:
            raise DelegationValidationError("scopes must not be empty")
        for s in self.scopes:
            if not isinstance(s, DelegationScope):
                raise DelegationValidationError(f"Scope must be DelegationScope, got {type(s).__name__}")
        _validate_str(self.token_status_list_uri, "token_status_list_uri")

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical byte serialization for cryptographic signing."""
        scopes_payload = [
            {"action": s.action, "resource": s.resource, "max_budget": s.max_budget, "constraints": sorted(s.constraints)}
            for s in sorted(self.scopes, key=lambda sc: (sc.action, sc.resource, sc.max_budget))
        ]
        payload = {
            "token_id": self.token_id,
            "principal": self.principal,
            "issuer_actor": self.issuer_actor,
            "audience_actor": self.audience_actor,
            "parent_token_hash": self.parent_token_hash,
            "depth": self.depth,
            "max_depth": self.max_depth,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scopes": scopes_payload,
            "token_status_list_uri": self.token_status_list_uri,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_digest(self) -> str:
        """SHA-256 hex digest representing the parent byte-commitment."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def sign(self, secret_key: bytes) -> DelegationToken:
        """Return a copy of the token with a valid HMAC-SHA256 signature."""
        sig = hmac.new(secret_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return dataclasses.replace(self, signature=sig)

    def verify_signature(self, secret_key: bytes) -> bool:
        """Verify HMAC-SHA256 cryptographic signature against issuer secret key."""
        if not self.signature:
            return False
        expected = hmac.new(secret_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class DelegationTokenValidator:
    """Deterministic reference monitor enforcing IETF WIMSE delegation chain invariants."""

    @staticmethod
    def verify_attenuation(parent_token: DelegationToken, child_token: DelegationToken) -> Tuple[bool, str]:
        """Verify monotonic authority attenuation between parent and child tokens."""
        # 1. Principal invariance
        if parent_token.principal != child_token.principal:
            return False, f"Principal mismatch: {parent_token.principal} != {child_token.principal}"

        # 2. Cryptographic byte-commitment
        expected_parent_hash = parent_token.compute_digest()
        if child_token.parent_token_hash != expected_parent_hash:
            return False, f"Parent token hash mismatch: expected {expected_parent_hash}, got {child_token.parent_token_hash}"

        # 3. Chain continuity (issuer of child must be audience of parent)
        if child_token.issuer_actor != parent_token.audience_actor:
            return False, f"Chain continuity violation: child issuer {child_token.issuer_actor} != parent audience {parent_token.audience_actor}"

        # 4. Monotonic depth bounds
        if child_token.depth != parent_token.depth + 1:
            return False, f"Depth violation: expected {parent_token.depth + 1}, got {child_token.depth}"
        if child_token.depth > parent_token.max_depth or child_token.max_depth > parent_token.max_depth:
            return False, f"Max depth expansion: parent max {parent_token.max_depth}, child {child_token.depth}/{child_token.max_depth}"

        # 5. Monotonic lifetime attenuation
        if child_token.expires_at > parent_token.expires_at:
            return False, f"Lifetime expansion: child expiry {child_token.expires_at} > parent expiry {parent_token.expires_at}"
        if child_token.issued_at < parent_token.issued_at:
            return False, f"Backdated issuance: child issued {child_token.issued_at} < parent issued {parent_token.issued_at}"

        # 6. Monotonic scope attenuation (every child scope must be subsumed by at least one parent scope)
        for c_scope in child_token.scopes:
            subsumed = any(p_scope.allows(c_scope) for p_scope in parent_token.scopes)
            if not subsumed:
                return False, f"Scope escalation detected: child scope {c_scope} not allowed by parent scopes"

        return True, "Valid attenuation"

    @classmethod
    def verify_chain(
        cls,
        chain: Sequence[DelegationToken],
        actor_key_resolver: Callable[[str], bytes],
        current_time_sec: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Verify an entire multi-hop delegation chain offline back to trusted root anchor."""
        if not chain:
            return False, "Empty delegation chain"

        # 1. Verify root token
        root = chain[0]
        if root.depth != 0:
            return False, f"Root token depth must be 0, got {root.depth}"
        if root.parent_token_hash is not None:
            return False, f"Root token parent_token_hash must be None, got {root.parent_token_hash}"

        root_key = actor_key_resolver(root.issuer_actor)
        if not root.verify_signature(root_key):
            return False, f"Invalid signature on root token {root.token_id}"

        if current_time_sec is not None:
            if current_time_sec >= root.expires_at:
                return False, f"Root token {root.token_id} expired at {root.expires_at}"

        # 2. Verify each sequential hop
        for i in range(1, len(chain)):
            parent = chain[i - 1]
            child = chain[i]

            # Signature verification on child
            child_key = actor_key_resolver(child.issuer_actor)
            if not child.verify_signature(child_key):
                return False, f"Invalid signature on token {child.token_id} at hop {i}"

            if current_time_sec is not None:
                if current_time_sec >= child.expires_at:
                    return False, f"Token {child.token_id} expired at {child.expires_at}"

            # Attenuation and invariant checks
            valid_att, reason = cls.verify_attenuation(parent, child)
            if not valid_att:
                return False, f"Chain invalid at hop {i}: {reason}"

        return True, f"Delegation chain valid ({len(chain)} hops verified offline)"


# =============================================================================
# VERA: Authority-Preserving Edge Revocation for Federated AI-Agent Workflows
# Grounded in arXiv:2608.30091 (2026-08-30).
# =============================================================================


@dataclasses.dataclass(frozen=True)
class DelegationEdge:
    """Verifiable directed delegation edge within an agentic coordination DAG.

    Grounded in:
    - VERA: Authority-Preserving Edge Revocation for Federated AI-Agent Workflows (arXiv:2608.30091).
    - IEEE Std 7012-2025: Machine-Readable Privacy and Delegation Terms.
    - W3C PROV-DM (Moreau & Missier, 2013).
    """

    edge_id: str
    workflow_id: str
    source_actor: str
    target_actor: str
    token: DelegationToken
    parent_edge_ids: Tuple[str, ...] = ()
    created_at: int = 0
    signature: str = ""

    def __post_init__(self) -> None:
        _validate_safe_id(self.edge_id, "edge_id")
        _validate_safe_id(self.workflow_id, "workflow_id")
        _validate_safe_id(self.source_actor, "source_actor")
        _validate_safe_id(self.target_actor, "target_actor")
        if not isinstance(self.token, DelegationToken):
            raise DelegationValidationError(f"token must be DelegationToken, got {type(self.token).__name__}")
        if self.token.issuer_actor != self.source_actor:
            raise DelegationValidationError(
                f"Edge source_actor '{self.source_actor}' must match token issuer '{self.token.issuer_actor}'"
            )
        if self.token.audience_actor != self.target_actor:
            raise DelegationValidationError(
                f"Edge target_actor '{self.target_actor}' must match token audience '{self.token.audience_actor}'"
            )
        for p in self.parent_edge_ids:
            _validate_safe_id(p, "parent_edge_id")
        _validate_non_neg_int(self.created_at, "created_at")

    def canonical_bytes(self) -> bytes:
        payload = {
            "edge_id": self.edge_id,
            "workflow_id": self.workflow_id,
            "source_actor": self.source_actor,
            "target_actor": self.target_actor,
            "token_digest": self.token.compute_digest(),
            "parent_edge_ids": sorted(self.parent_edge_ids),
            "created_at": self.created_at,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def sign(self, secret_key: bytes) -> DelegationEdge:
        sig = hmac.new(secret_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return dataclasses.replace(self, signature=sig)

    def verify_signature(self, secret_key: bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(secret_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclasses.dataclass(frozen=True)
class EdgeRevocationRecord:
    """Verifier-checkable edge revocation record (VERA, arXiv:2608.30091)."""

    revocation_id: str
    workflow_id: str
    edge_id: str
    revoker_actor: str
    revoked_at: int
    cascading: bool = True
    reason: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        _validate_safe_id(self.revocation_id, "revocation_id")
        _validate_safe_id(self.workflow_id, "workflow_id")
        _validate_safe_id(self.edge_id, "edge_id")
        _validate_safe_id(self.revoker_actor, "revoker_actor")
        _validate_non_neg_int(self.revoked_at, "revoked_at")
        if not isinstance(self.cascading, bool):
            raise DelegationValidationError("cascading must be a bool")
        _validate_str(self.reason, "reason", max_len=512)

    def canonical_bytes(self) -> bytes:
        payload = {
            "revocation_id": self.revocation_id,
            "workflow_id": self.workflow_id,
            "edge_id": self.edge_id,
            "revoker_actor": self.revoker_actor,
            "revoked_at": self.revoked_at,
            "cascading": self.cascading,
            "reason": self.reason,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def sign(self, secret_key: bytes) -> EdgeRevocationRecord:
        sig = hmac.new(secret_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return dataclasses.replace(self, signature=sig)

    def verify_signature(self, secret_key: bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(secret_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class VeraEdgeRevocationManager:
    """Deterministic, verifier-checkable Edge Revocation Manager.

    Implements VERA (Authority-Preserving Edge Revocation for Federated AI-Agent Workflows, arXiv:2608.30091).
    Ensures precise edge-level revocation of downstream sub-tasks in a multi-agent DAG
    without over-revoking independent shared agent nodes or collateral peer workflows.
    """

    def __init__(self) -> None:
        self._edges: Dict[str, Dict[str, DelegationEdge]] = {}  # workflow_id -> {edge_id: edge}
        self._revocations: Dict[str, Dict[str, EdgeRevocationRecord]] = {}  # workflow_id -> {edge_id: record}
        self._revocation_by_id: Dict[str, EdgeRevocationRecord] = {}

    def register_edge(
        self,
        edge: DelegationEdge,
        actor_key_resolver: Callable[[str], bytes],
    ) -> None:
        """Register a new verified edge in the workflow coordination DAG."""
        if not isinstance(edge, DelegationEdge):
            raise DelegationValidationError(f"Expected DelegationEdge, got {type(edge).__name__}")

        # Verify edge source signature
        source_key = actor_key_resolver(edge.source_actor)
        if not edge.verify_signature(source_key):
            raise DelegationSecurityViolation(f"Invalid signature on edge {edge.edge_id} from {edge.source_actor}")

        # Verify token signature
        issuer_key = actor_key_resolver(edge.token.issuer_actor)
        if not edge.token.verify_signature(issuer_key):
            raise DelegationSecurityViolation(f"Invalid signature on token {edge.token.token_id}")

        w_id = edge.workflow_id
        if w_id not in self._edges:
            self._edges[w_id] = {}
            self._revocations[w_id] = {}

        w_edges = self._edges[w_id]
        if edge.edge_id in w_edges:
            raise DelegationValidationError(f"Edge '{edge.edge_id}' already registered in workflow '{w_id}'")

        # Validate parent edge existence within this workflow
        for p_id in edge.parent_edge_ids:
            if p_id not in w_edges:
                raise DelegationValidationError(
                    f"Parent edge '{p_id}' does not exist in workflow '{w_id}'"
                )

        # Validate DAG acyclicity
        temp_adj: Dict[str, List[str]] = {eid: list(e.parent_edge_ids) for eid, e in w_edges.items()}
        temp_adj[edge.edge_id] = list(edge.parent_edge_ids)

        visited: Dict[str, int] = {}  # 0: unvisited, 1: visiting, 2: visited

        def has_cycle(u: str) -> bool:
            visited[u] = 1
            for v in temp_adj.get(u, []):
                state = visited.get(v, 0)
                if state == 1:
                    return True
                if state == 0 and has_cycle(v):
                    return True
            visited[u] = 2
            return False

        for node in temp_adj:
            if visited.get(node, 0) == 0:
                if has_cycle(node):
                    raise DelegationSecurityViolation(
                        f"Cycle detected in delegation DAG when adding edge '{edge.edge_id}'"
                    )

        w_edges[edge.edge_id] = edge

    def revoke_edge(
        self,
        record: EdgeRevocationRecord,
        revoker_secret_key: bytes,
    ) -> Dict[str, Any]:
        """Revoke a specific delegation edge, optionally cascading to downstream dependent edges."""
        if not isinstance(record, EdgeRevocationRecord):
            raise DelegationValidationError(f"Expected EdgeRevocationRecord, got {type(record).__name__}")

        # Verify cryptographic signature of the revocation record
        if not record.verify_signature(revoker_secret_key):
            raise DelegationSecurityViolation(
                f"Invalid signature on revocation record '{record.revocation_id}' from revoker '{record.revoker_actor}'"
            )

        w_id = record.workflow_id
        w_edges = self._edges.get(w_id, {})
        if record.edge_id not in w_edges:
            raise DelegationValidationError(f"Cannot revoke non-existent edge '{record.edge_id}' in workflow '{w_id}'")

        target_edge = w_edges[record.edge_id]

        # Authorization check: only the workflow principal OR the edge source_actor may revoke the edge
        allowed_revokers = {target_edge.source_actor, target_edge.token.principal}
        # Also allow root issuer if principal matches
        if record.revoker_actor not in allowed_revokers:
            raise DelegationSecurityViolation(
                f"Unauthorized revoker '{record.revoker_actor}': only edge source '{target_edge.source_actor}' "
                f"or principal '{target_edge.token.principal}' may revoke this delegation edge."
            )

        w_revs = self._revocations[w_id]
        if record.edge_id in w_revs:
            # Already revoked
            return {
                "revoked": False,
                "reason": "Edge already revoked",
                "revocation_id": w_revs[record.edge_id].revocation_id,
            }

        w_revs[record.edge_id] = record
        self._revocation_by_id[record.revocation_id] = record

        # Determine downstream cascaded edges
        cascaded_edges: List[str] = []
        if record.cascading:
            descendants = self._find_downstream_edges(w_id, record.edge_id)
            cascaded_edges = sorted(descendants)

        return {
            "revoked": True,
            "revocation_id": record.revocation_id,
            "workflow_id": w_id,
            "edge_id": record.edge_id,
            "revoker_actor": record.revoker_actor,
            "cascading": record.cascading,
            "cascaded_downstream_edges": cascaded_edges,
            "digest": record.compute_digest(),
        }

    def _find_downstream_edges(self, workflow_id: str, root_edge_id: str) -> Set[str]:
        """Find all downstream edges that depend directly or transitively on root_edge_id."""
        w_edges = self._edges.get(workflow_id, {})
        children_map: Dict[str, List[str]] = {}
        for eid, edge in w_edges.items():
            for pid in edge.parent_edge_ids:
                children_map.setdefault(pid, []).append(eid)

        descendants: Set[str] = set()
        stack = list(children_map.get(root_edge_id, []))
        while stack:
            curr = stack.pop()
            if curr not in descendants:
                descendants.add(curr)
                stack.extend(children_map.get(curr, []))
        return descendants

    def is_edge_active(
        self,
        workflow_id: str,
        edge_id: str,
        current_time_sec: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Check whether an edge is currently active and authorized, or revoked/expired."""
        w_edges = self._edges.get(workflow_id, {})
        if edge_id not in w_edges:
            return False, f"Edge '{edge_id}' not found in workflow '{workflow_id}'"

        edge = w_edges[edge_id]

        # 1. Lifetime expiration
        if current_time_sec is not None and current_time_sec >= edge.token.expires_at:
            return False, f"Token for edge '{edge_id}' expired at {edge.token.expires_at}"

        w_revs = self._revocations.get(workflow_id, {})

        # 2. Direct edge revocation
        if edge_id in w_revs:
            rec = w_revs[edge_id]
            return False, f"Edge '{edge_id}' directly revoked by '{rec.revoker_actor}' (reason: {rec.reason})"

        # 3. Cascading ancestor edge revocation
        ancestors = self._find_ancestor_edges(workflow_id, edge_id)
        for a_id in ancestors:
            if a_id in w_revs:
                rec = w_revs[a_id]
                if rec.cascading:
                    return False, f"Edge '{edge_id}' disabled by cascading revocation of ancestor edge '{a_id}' by '{rec.revoker_actor}'"

        return True, "Edge active and verifiable"

    def _find_ancestor_edges(self, workflow_id: str, edge_id: str) -> Set[str]:
        """Find all upstream parent and ancestor edges leading to edge_id."""
        w_edges = self._edges.get(workflow_id, {})
        if edge_id not in w_edges:
            return set()
        ancestors: Set[str] = set()
        stack = list(w_edges[edge_id].parent_edge_ids)
        while stack:
            curr = stack.pop()
            if curr not in ancestors and curr in w_edges:
                ancestors.add(curr)
                stack.extend(w_edges[curr].parent_edge_ids)
        return ancestors

    def get_active_subgraph(
        self,
        workflow_id: str,
        current_time_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return the active authority-preserved subgraph for the workflow."""
        w_edges = self._edges.get(workflow_id, {})
        active_edge_ids: List[str] = []
        revoked_edge_ids: List[str] = []
        active_nodes: Set[str] = set()

        for eid in w_edges:
            active, _ = self.is_edge_active(workflow_id, eid, current_time_sec=current_time_sec)
            if active:
                active_edge_ids.append(eid)
                active_nodes.add(w_edges[eid].source_actor)
                active_nodes.add(w_edges[eid].target_actor)
            else:
                revoked_edge_ids.append(eid)

        return {
            "workflow_id": workflow_id,
            "total_edges": len(w_edges),
            "active_edges": sorted(active_edge_ids),
            "revoked_edges": sorted(revoked_edge_ids),
            "active_nodes": sorted(active_nodes),
            "authority_preservation_ratio": (
                round(len(active_edge_ids) / len(w_edges), 4) if w_edges else 1.0
            ),
        }

    def generate_w3c_prov_receipt(
        self,
        workflow_id: str,
        revocation_id: str,
    ) -> Dict[str, Any]:
        """Generate a W3C PROV-DM conforming revocation receipt."""
        if revocation_id not in self._revocation_by_id:
            raise DelegationValidationError(f"Revocation ID '{revocation_id}' not found")

        rec = self._revocation_by_id[revocation_id]
        if rec.workflow_id != workflow_id:
            raise DelegationValidationError(
                f"Workflow mismatch for revocation '{revocation_id}': expected '{workflow_id}', got '{rec.workflow_id}'"
            )

        target_edge = self._edges[workflow_id][rec.edge_id]

        prov = {
            "standard": "W3C PROV-DM (Moreau & Missier, 2013)",
            "activityId": f"activity-vera-revocation-{rec.revocation_id}",
            "agentEntity": rec.revoker_actor,
            "outputEntity": f"revocation-record-{rec.revocation_id}",
            "actedOnBehalfOf": target_edge.token.principal,
            "wasAssociatedWith": "VERA-Edge-Revocation-Protocol (arXiv:2608.30091)",
            "wasDerivedFrom": f"delegation-edge-{rec.edge_id}",
            "wasGeneratedBy": f"revocation-record-{rec.revocation_id} wasGeneratedBy activity-vera-revocation-{rec.revocation_id}",
            "used": f"edge:{rec.edge_id}",
            "chronologySequence": 1,
            "generationTimestampIso": f"{rec.revoked_at}",
            "provContentDigest": rec.compute_digest(),
            "targetEdge": {
                "edgeId": rec.edge_id,
                "sourceActor": target_edge.source_actor,
                "targetActor": target_edge.target_actor,
                "cascading": rec.cascading,
                "reason": rec.reason,
            },
        }

        # Strict Steward Gate validation: ensure no forbidden tokens or unapproved royalty claims
        serialized = json.dumps(prov)
        forbidden_terms = [
            "Contribution Token",
            "MMCT",
            "mmctBalance",
            "85/10/5",
            "+$11,420/yr",
            "Somatic Witness",
            "Pre-ADC",
        ]
        for term in forbidden_terms:
            if term.lower() in serialized.lower():
                raise DelegationSecurityViolation(f"Steward Gate violation: receipt contains forbidden term '{term}'")

        return prov

