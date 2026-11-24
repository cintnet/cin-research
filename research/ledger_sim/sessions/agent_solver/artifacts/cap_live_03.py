"""
Capability CAP-LIVE-03: Ed25519 Algorithm Pinning and Canonical Ring-Monotonic Capability Binding.
Event: LIVE-EVT-03 (agent_gateway_crypto_containment)
Lineage: Builds on CAP-LIVE-01 domain-separated cryptographic key binding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

CANONICAL_KEY_ID_RE = re.compile(r"^ring([0-3])_key$")
ALLOWED_ALGORITHMS = frozenset({"Ed25519"})


def solve(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verifies a local model-router capability token against algorithm confusion,
    key-id path traversal, and ring privilege escalation.
    """
    alg = str(record.get("alg", ""))
    key_id = str(record.get("key_id", ""))
    claimed_ring = int(record.get("claimed_ring", -1))
    bound_ring = int(record.get("Bound_ring", record.get("bound_ring", 3)))
    sig_valid = bool(record.get("sig_valid", False))

    is_escalation_attempt = (
        claimed_ring < bound_ring
        or alg not in ALLOWED_ALGORITHMS
        or not sig_valid
        or ".." in key_id
        or "/" in key_id
        or "\\" in key_id
    )

    m = CANONICAL_KEY_ID_RE.match(key_id)
    key_ring = int(m.group(1)) if m else -1

    accepted = (
        alg in ALLOWED_ALGORITHMS
        and sig_valid
        and m is not None
        and key_ring == bound_ring
        and claimed_ring == bound_ring
    )

    return {
        "accepted": bool(accepted),
        "is_escalation_attempt": bool(is_escalation_attempt),
        "claimed_ring": claimed_ring,
        "bound_ring": bound_ring,
    }


def evaluate_shard(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluates router token containment across a shard of token verification records."""
    if not samples:
        return {
            "passed": False,
            "privilege_escalation_accept_rate": 1.0,
            "valid_ring_token_accept_rate": 0.0,
        }

    escalation_attempts = 0
    escalation_accepted = 0
    valid_tokens = 0
    valid_accepted = 0

    for rec in samples:
        res = solve(rec)
        if res["is_escalation_attempt"]:
            escalation_attempts += 1
            if res["accepted"]:
                escalation_accepted += 1
        else:
            valid_tokens += 1
            if res["accepted"]:
                valid_accepted += 1

    esc_rate = (
        round(escalation_accepted / escalation_attempts, 4)
        if escalation_attempts > 0
        else 0.0
    )
    valid_rate = (
        round(valid_accepted / valid_tokens, 4)
        if valid_tokens > 0
        else 1.0
    )

    passed = esc_rate == 0.0 and valid_rate == 1.0
    return {
        "passed": bool(passed),
        "privilege_escalation_accept_rate": esc_rate,
        "valid_ring_token_accept_rate": valid_rate,
    }
