"""Proof-Carrying Message (PCM) Protocol with Merkle Inclusion Proofs.

Grounded in arXiv:2610.39109 ('PCM: A Proof-Carrying Message Protocol for Verifiable Multi-Agent Communication').
Enforces cryptographic evidence binding on multi-agent claims, ensuring that assertions
(e.g., test pass status, authorization mandates, payment approvals) carry tamper-evident
inclusion proofs from an append-only witness log, verified offline in linear time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


class PCMValidationError(ValueError):
    """Raised when a Proof-Carrying Message fails fail-closed validation."""
    pass


class PCMTamperDetected(ValueError):
    """Raised when cryptographic verification detects tampering or invalid proof paths."""
    pass


def canonical_json_bytes(obj: Any) -> bytes:
    """Return deterministic canonical JSON bytes with sorted keys and no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def hash_leaf(data: bytes) -> str:
    """Compute RFC 6962 / standard Merkle leaf hash with 0x00 domain separation."""
    hasher = hashlib.sha256()
    hasher.update(b"\x00" + data)
    return hasher.hexdigest()


def hash_internal_node(left_hex: str, right_hex: str) -> str:
    """Compute RFC 6962 / standard Merkle internal node hash with 0x01 domain separation."""
    left = bytes.fromhex(left_hex)
    right = bytes.fromhex(right_hex)
    hasher = hashlib.sha256()
    hasher.update(b"\x01" + left + right)
    return hasher.hexdigest()


@dataclass(frozen=True)
class MerkleInclusionProof:
    """Audit path proving inclusion of a leaf in an append-only log root."""
    leaf_index: int
    tree_size: int
    audit_path: Tuple[Tuple[str, str], ...]  # Tuple of (direction: 'left'|'right', sibling_hash: hex_str)

    def __post_init__(self) -> None:
        if isinstance(self.leaf_index, bool) or not isinstance(self.leaf_index, int) or self.leaf_index < 0:
            raise PCMValidationError("leaf_index must be a non-negative integer")
        if isinstance(self.tree_size, bool) or not isinstance(self.tree_size, int) or self.tree_size <= 0:
            raise PCMValidationError("tree_size must be a positive integer")
        if self.leaf_index >= self.tree_size:
            raise PCMValidationError("leaf_index cannot be greater than or equal to tree_size")
        if not isinstance(self.audit_path, (tuple, list)):
            raise PCMValidationError("audit_path must be a sequence of steps")
        for step in self.audit_path:
            if not isinstance(step, (tuple, list)) or len(step) != 2:
                raise PCMValidationError("Each audit path step must be a pair (direction, sibling_hash)")
            direction, sibling = step
            if direction not in ("left", "right"):
                raise PCMValidationError(f"Invalid direction in audit path: {direction!r}")
            if not isinstance(sibling, str) or not re.match(r"^[0-9a-f]{64}$", sibling.lower()):
                raise PCMValidationError(f"Invalid sibling hash in audit path: {sibling!r}")


class MerkleLog:
    """Append-only witness log storing event receipts and producing inclusion proofs."""

    def __init__(self, log_id: str, attestor_signing_key: bytes) -> None:
        if not isinstance(log_id, str) or not log_id.strip():
            raise PCMValidationError("log_id must be a non-empty string")
        if not isinstance(attestor_signing_key, bytes) or len(attestor_signing_key) < 16:
            raise PCMValidationError("attestor_signing_key must be at least 16 bytes")
        self.log_id = log_id
        self.attestor_signing_key = attestor_signing_key
        self._leaves: List[bytes] = []

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, entry: Mapping[str, Any]) -> Tuple[int, str]:
        """Append an entry, returning (leaf_index, leaf_hash)."""
        data = canonical_json_bytes(entry)
        idx = len(self._leaves)
        self._leaves.append(data)
        return idx, hash_leaf(data)

    def root_hash(self) -> str:
        """Compute the current Merkle tree root hash."""
        if not self._leaves:
            return hashlib.sha256(b"").hexdigest()

        current_level = [hash_leaf(leaf) for leaf in self._leaves]
        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    next_level.append(hash_internal_node(current_level[i], current_level[i + 1]))
                else:
                    # Duplicate or carry last node in unbalanced tree
                    next_level.append(hash_internal_node(current_level[i], current_level[i]))
            current_level = next_level
        return current_level[0]

    def sign_root(self, root: str) -> str:
        """Generate HMAC-SHA256 signature for root attestation."""
        return hmac.new(self.attestor_signing_key, root.encode("utf-8"), hashlib.sha256).hexdigest()

    def get_inclusion_proof(self, leaf_index: int) -> MerkleInclusionProof:
        """Construct audit path for leaf_index in current tree."""
        if isinstance(leaf_index, bool) or not isinstance(leaf_index, int) or leaf_index < 0 or leaf_index >= len(self._leaves):
            raise PCMValidationError(f"Invalid leaf index: {leaf_index}")

        current_level = [hash_leaf(leaf) for leaf in self._leaves]
        idx = leaf_index
        audit_path: List[Tuple[str, str]] = []

        while len(current_level) > 1:
            if idx % 2 == 0:
                # Node is left child; sibling is right child
                if idx + 1 < len(current_level):
                    audit_path.append(("right", current_level[idx + 1]))
                else:
                    audit_path.append(("right", current_level[idx]))
            else:
                # Node is right child; sibling is left child
                audit_path.append(("left", current_level[idx - 1]))

            # Move to next parent level
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    next_level.append(hash_internal_node(current_level[i], current_level[i + 1]))
                else:
                    next_level.append(hash_internal_node(current_level[i], current_level[i]))
            current_level = next_level
            idx //= 2

        return MerkleInclusionProof(
            leaf_index=leaf_index,
            tree_size=len(self._leaves),
            audit_path=tuple(audit_path),
        )


@dataclass(frozen=True)
class PCMCaveat:
    """Deterministic policy condition bound to an asserted claim."""
    caveat_type: str
    parameter_value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.caveat_type, str) or not self.caveat_type.strip():
            raise PCMValidationError("caveat_type must be a non-empty string")
        if self.caveat_type in ("max_amount_cents", "valid_until_epoch"):
            if isinstance(self.parameter_value, bool) or not isinstance(self.parameter_value, int) or self.parameter_value < 0:
                raise PCMValidationError(f"{self.caveat_type} parameter must be a non-negative integer")


@dataclass(frozen=True)
class ProofCarryingMessage:
    """Structured message containing an agent claim and its verifiable Merkle proof."""
    message_id: str
    sender_id: str
    recipient_id: str
    claim_type: str
    claim_payload: Dict[str, Any]
    attestation_log_id: str
    attestation_root: str
    inclusion_proof: MerkleInclusionProof
    attestor_signature: str
    caveats: Tuple[PCMCaveat, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for str_field, val in (
            ("message_id", self.message_id),
            ("sender_id", self.sender_id),
            ("recipient_id", self.recipient_id),
            ("claim_type", self.claim_type),
            ("attestation_log_id", self.attestation_log_id),
        ):
            if not isinstance(val, str) or not val.strip():
                raise PCMValidationError(f"{str_field} must be a non-empty string")
            if "\x00" in val:
                raise PCMValidationError(f"{str_field} cannot contain null bytes")
            if not re.match(r"^[a-zA-Z0-9_\-\.\:]+$", val):
                raise PCMValidationError(f"{str_field} contains invalid characters: {val!r}")

        if not isinstance(self.claim_payload, dict) or not self.claim_payload:
            raise PCMValidationError("claim_payload must be a non-empty dictionary")

        if not isinstance(self.attestation_root, str) or not re.match(r"^[0-9a-f]{64}$", self.attestation_root.lower()):
            raise PCMValidationError("attestation_root must be a 64-character hex string")

        if not isinstance(self.attestor_signature, str) or not re.match(r"^[0-9a-f]{64}$", self.attestor_signature.lower()):
            raise PCMValidationError("attestor_signature must be a 64-character hex string")

        if not isinstance(self.inclusion_proof, MerkleInclusionProof):
            raise PCMValidationError("inclusion_proof must be an instance of MerkleInclusionProof")

        if not isinstance(self.caveats, (tuple, list)):
            raise PCMValidationError("caveats must be a sequence of PCMCaveat")
        for cav in self.caveats:
            if not isinstance(cav, PCMCaveat):
                raise PCMValidationError(f"Invalid caveat item: {cav!r}")


@dataclass(frozen=True)
class VerificationResult:
    is_valid: bool
    verified_claim_type: str
    reason: str
    computed_root: Optional[str] = None
    failure_code: Optional[str] = None


class PCMVerifier:
    """Offline, linear-time verifier for Proof-Carrying Messages."""

    def __init__(self, trusted_attestors: Mapping[str, bytes]) -> None:
        if not isinstance(trusted_attestors, dict) or not trusted_attestors:
            raise PCMValidationError("trusted_attestors must be a non-empty mapping of log_id -> signing_key")
        for log_id, key in trusted_attestors.items():
            if not isinstance(log_id, str) or not log_id.strip():
                raise PCMValidationError("Attestor log_id must be non-empty string")
            if not isinstance(key, bytes) or len(key) < 16:
                raise PCMValidationError("Attestor key must be at least 16 bytes")
        self._trusted_attestors = dict(trusted_attestors)

    def verify_proof_path(self, leaf_hash: str, proof: MerkleInclusionProof) -> str:
        """Traverse the audit path from leaf_hash up to the calculated root."""
        current_hash = leaf_hash
        for direction, sibling in proof.audit_path:
            if direction == "left":
                current_hash = hash_internal_node(sibling, current_hash)
            elif direction == "right":
                current_hash = hash_internal_node(current_hash, sibling)
            else:
                raise PCMValidationError(f"Unknown direction in proof path: {direction}")
        return current_hash

    def verify(
        self,
        pcm: ProofCarryingMessage,
        current_epoch: Optional[int] = None,
        context_constraints: Optional[Mapping[str, Any]] = None,
    ) -> VerificationResult:
        """Verify message claim against Merkle root, attestor signature, and caveats."""
        if not isinstance(pcm, ProofCarryingMessage):
            return VerificationResult(False, "unknown", "Input must be a ProofCarryingMessage instance", failure_code="INVALID_ENVELOPE")

        # 1. Attestor Authority Check
        signing_key = self._trusted_attestors.get(pcm.attestation_log_id)
        if not signing_key:
            return VerificationResult(False, pcm.claim_type, f"Untrusted attestation log id: {pcm.attestation_log_id}", failure_code="UNTRUSTED_ATTESTOR")

        # 2. Attestor Signature Check on Root
        expected_sig = hmac.new(signing_key, pcm.attestation_root.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, pcm.attestor_signature.lower()):
            return VerificationResult(False, pcm.claim_type, "Attestor signature on Merkle root is invalid", failure_code="INVALID_ROOT_SIGNATURE")

        # 3. Leaf Hash Computation
        leaf_bytes = canonical_json_bytes(pcm.claim_payload)
        leaf_h = hash_leaf(leaf_bytes)

        # 4. Merkle Inclusion Proof Path Verification
        computed_root = self.verify_proof_path(leaf_h, pcm.inclusion_proof)
        if computed_root.lower() != pcm.attestation_root.lower():
            return VerificationResult(
                False,
                pcm.claim_type,
                f"Computed root {computed_root} does not match attestation root {pcm.attestation_root}",
                computed_root=computed_root,
                failure_code="ROOT_MISMATCH",
            )

        # 5. Caveat Verification
        constraints = context_constraints or {}
        for cav in pcm.caveats:
            if cav.caveat_type == "valid_until_epoch":
                if current_epoch is not None and current_epoch > cav.parameter_value:
                    return VerificationResult(False, pcm.claim_type, f"Claim expired: {current_epoch} > {cav.parameter_value}", failure_code="CAVEAT_EXPIRED")
            elif cav.caveat_type == "max_amount_cents":
                req_amount = constraints.get("amount_cents")
                if req_amount is not None:
                    if isinstance(req_amount, bool) or not isinstance(req_amount, int) or req_amount < 0:
                        return VerificationResult(False, pcm.claim_type, f"Invalid constraint amount: {req_amount}", failure_code="INVALID_CONSTRAINT")
                    if req_amount > cav.parameter_value:
                        return VerificationResult(False, pcm.claim_type, f"Amount exceeds caveat limit: {req_amount} > {cav.parameter_value}", failure_code="CAVEAT_BUDGET_EXCEEDED")
            elif cav.caveat_type == "allowed_tool":
                req_tool = constraints.get("tool_name")
                if req_tool is not None and req_tool != cav.parameter_value:
                    return VerificationResult(False, pcm.claim_type, f"Tool {req_tool} does not match caveat: {cav.parameter_value}", failure_code="CAVEAT_TOOL_MISMATCH")

        return VerificationResult(
            is_valid=True,
            verified_claim_type=pcm.claim_type,
            reason="Merkle inclusion path and signature verified cleanly",
            computed_root=computed_root,
        )
