"""
role_aware_topology_router.py: Testnet Ledger Role-Aware Communication Router.

Implements ACTS (Adaptive Communication Topology Scheduling, arXiv:2610.25851)
for the Agent-Web Testnet Ledger (`research/ledger_sim/agent_web_ledger.py` and
`research/ledger_sim/testnet_engine.py`).

Replaces naive quadratic O(N*M) broadcast gossip with role-conditioned
relational message routing and Directed Acyclic Graph (DAG) edge scheduling,
eliminating peer noise and reducing token/bandwidth expenditure across
multi-human and multi-agent problem-solving cycles.

Strict Steward Gate Discipline:
- Non-monetary message routing and topological coordination only.
- Zero unapproved tokens (MMCT / "Contribution Tokens"), speculative dollar savings figures, or unapproved royalty percentages.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class TestnetAgentRole(str, enum.Enum):
    """Canonical testnet sub-agent functional roles."""
    ATTENTION_WATCHER = "ATTENTION_WATCHER"
    PRIVACY_GUARD = "PRIVACY_GUARD"
    LEDGER_COORDINATOR = "LEDGER_COORDINATOR"
    CRAFT_EXTRACTOR = "CRAFT_EXTRACTOR"
    PIPELINE_COMPOSER = "PIPELINE_COMPOSER"
    VERIFICATION_RUNNER = "VERIFICATION_RUNNER"


class RoutingPhase(str, enum.Enum):
    """Problem lifecycle phase governing edge scheduling."""
    EXPLORATION = "EXPLORATION"
    SYNTHESIS = "SYNTHESIS"
    VERIFICATION = "VERIFICATION"


class RoutingError(Exception):
    """Base exception for routing errors."""


class RoutingValidationError(RoutingError):
    """Raised when routing parameters fail validation."""


def canonical_sha256(payload: Any) -> str:
    """Computes a deterministic SHA-256 hexadecimal digest of structured data."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _validate_safe_id(val: str, field_name: str) -> None:
    if not isinstance(val, str) or not val.strip():
        raise RoutingValidationError(f"{field_name} must be a non-empty string.")
    if not re.match(r"^[a-zA-Z0-9_\-.:/]+$", val):
        raise RoutingValidationError(f"{field_name} contains invalid characters: {val}")


def _validate_unit_interval(val: float, field_name: str) -> None:
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        raise RoutingValidationError(f"{field_name} must be a float, got {type(val)}.")
    if math.isnan(val) or math.isinf(val):
        raise RoutingValidationError(f"{field_name} cannot be NaN or infinite.")
    if not (0.0 <= float(val) <= 1.0):
        raise RoutingValidationError(f"{field_name} must be in [0.0, 1.0], got {val}.")


@dataclasses.dataclass(frozen=True)
class RouteDecision:
    """Deterministic routing decision for a candidate message transmission."""
    should_deliver: bool
    affinity_score: float
    channel_priority: int
    rationale: str
    provenance_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.should_deliver, bool):
            raise RoutingValidationError("should_deliver must be a boolean.")
        _validate_unit_interval(self.affinity_score, "affinity_score")
        if not isinstance(self.channel_priority, int) or isinstance(self.channel_priority, bool) or self.channel_priority < 1:
            raise RoutingValidationError("channel_priority must be a positive integer.")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise RoutingValidationError("rationale must be a non-empty string.")


class RoleAwareTopologyRouter:
    """
    Role-Conditioned Communication Topology Router for Agent Web Testnet.
    Schedules edges between Requesting and Answering agent fleets based on
    role compatibility and current problem phase.
    """

    # Role-pair compatibility matrix: (sender_role, receiver_role) -> base affinity
    BASE_COMPATIBILITY: Dict[Tuple[TestnetAgentRole, TestnetAgentRole], float] = {
        # Request side internal pipeline
        (TestnetAgentRole.ATTENTION_WATCHER, TestnetAgentRole.PRIVACY_GUARD): 0.95,
        (TestnetAgentRole.PRIVACY_GUARD, TestnetAgentRole.LEDGER_COORDINATOR): 0.90,
        # Cross-fleet coordination
        (TestnetAgentRole.LEDGER_COORDINATOR, TestnetAgentRole.CRAFT_EXTRACTOR): 0.85,
        (TestnetAgentRole.LEDGER_COORDINATOR, TestnetAgentRole.PIPELINE_COMPOSER): 0.88,
        (TestnetAgentRole.LEDGER_COORDINATOR, TestnetAgentRole.VERIFICATION_RUNNER): 0.70,
        # Answer side internal pipeline
        (TestnetAgentRole.CRAFT_EXTRACTOR, TestnetAgentRole.PIPELINE_COMPOSER): 0.92,
        (TestnetAgentRole.PIPELINE_COMPOSER, TestnetAgentRole.VERIFICATION_RUNNER): 0.96,
        (TestnetAgentRole.VERIFICATION_RUNNER, TestnetAgentRole.LEDGER_COORDINATOR): 0.94,
    }

    def __init__(self, admission_threshold: float = 0.50) -> None:
        _validate_unit_interval(admission_threshold, "admission_threshold")
        self.admission_threshold = admission_threshold

    def evaluate_route(
        self,
        sender_role: TestnetAgentRole,
        receiver_role: TestnetAgentRole,
        message_category: str,
        phase: RoutingPhase,
    ) -> RouteDecision:
        """Evaluates whether an inter-agent message should be routed or pruned."""
        if not isinstance(sender_role, TestnetAgentRole):
            raise RoutingValidationError(f"Invalid sender_role: {sender_role}")
        if not isinstance(receiver_role, TestnetAgentRole):
            raise RoutingValidationError(f"Invalid receiver_role: {receiver_role}")
        _validate_safe_id(message_category, "message_category")
        if not isinstance(phase, RoutingPhase):
            raise RoutingValidationError(f"Invalid phase: {phase}")

        # Disallow self-loops
        if sender_role == receiver_role:
            return RouteDecision(
                should_deliver=False,
                affinity_score=0.0,
                channel_priority=99,
                rationale="Self-loop message suppressed by topology router.",
                provenance_hash=canonical_sha256({"suppressed": "self_loop"}),
            )

        base_affinity = self.BASE_COMPATIBILITY.get((sender_role, receiver_role), 0.20)

        # Phase modulation
        phase_multiplier = 1.0
        if phase == RoutingPhase.EXPLORATION:
            if sender_role in (TestnetAgentRole.ATTENTION_WATCHER, TestnetAgentRole.CRAFT_EXTRACTOR):
                phase_multiplier = 1.25
            elif sender_role == TestnetAgentRole.VERIFICATION_RUNNER:
                phase_multiplier = 0.60
        elif phase == RoutingPhase.SYNTHESIS:
            if sender_role in (TestnetAgentRole.PIPELINE_COMPOSER, TestnetAgentRole.LEDGER_COORDINATOR):
                phase_multiplier = 1.20
        elif phase == RoutingPhase.VERIFICATION:
            if sender_role == TestnetAgentRole.VERIFICATION_RUNNER or receiver_role == TestnetAgentRole.VERIFICATION_RUNNER:
                phase_multiplier = 1.30

        final_affinity = max(0.0, min(1.0, base_affinity * phase_multiplier))
        should_deliver = final_affinity >= self.admission_threshold

        priority = 1 if final_affinity >= 0.80 else (2 if final_affinity >= 0.60 else 3)
        rationale = (
            f"Admitted via role affinity {final_affinity:.2f} >= {self.admission_threshold:.2f} in {phase.value}"
            if should_deliver
            else f"Pruned redundant link: affinity {final_affinity:.2f} < threshold {self.admission_threshold:.2f}"
        )

        digest = canonical_sha256({
            "sender": sender_role.value,
            "receiver": receiver_role.value,
            "category": message_category,
            "phase": phase.value,
            "affinity": round(final_affinity, 4),
            "deliver": should_deliver,
        })

        return RouteDecision(
            should_deliver=should_deliver,
            affinity_score=round(final_affinity, 4),
            channel_priority=priority,
            rationale=rationale,
            provenance_hash=digest,
        )

    def route_batch(
        self,
        messages: List[Dict[str, Any]],
        phase: RoutingPhase,
    ) -> Dict[str, Any]:
        """Routes a batch of candidate inter-agent transmissions, computing efficiency metrics."""
        delivered = []
        pruned_count = 0
        total = len(messages)

        for msg in messages:
            sender = TestnetAgentRole(msg["sender_role"])
            receiver = TestnetAgentRole(msg["receiver_role"])
            cat = msg.get("category", "TASK_CAMPAIGN")
            decision = self.evaluate_route(sender, receiver, cat, phase)
            if decision.should_deliver:
                delivered.append({
                    "message": msg,
                    "decision": dataclasses.asdict(decision),
                })
            else:
                pruned_count += 1

        sparsity_ratio = (pruned_count / float(total)) if total > 0 else 0.0

        return {
            "total_candidate_messages": total,
            "delivered_count": len(delivered),
            "pruned_count": pruned_count,
            "message_sparsity_ratio": round(sparsity_ratio, 4),
            "token_bandwidth_saved_pct": round(sparsity_ratio * 100.0, 2),
            "delivered_messages": delivered,
        }
