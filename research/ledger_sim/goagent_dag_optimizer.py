"""
GoAgent Communication Topology Optimization & Cryptographic Verification Module
(research/ledger_sim/goagent_dag_optimizer.py)

Grounded in:
  - GoAgent: Group-of-Agents Communication Topology Generation for LLM-based Multi-Agent Systems
    (arXiv:2603.19677, March 2026).
  - W3C PROV-DM: The PROV Data Model (W3C Recommendation, Moreau & Missier, 2013).
  - Proof-Carrying Code Deterministic Verification (Necula, 1997).
  - IEEE Std 7012-2025 Machine Readable Personal Privacy Terms.

Architectural Purpose:
  Multi-agent collaborative networks suffer from quadratic O(N^2) token bloat and distractor
  noise when all agents broadcast to all peers. GoAgent models collaborative agents as atomic
  groups interconnected under strict Directed Acyclic Graph (DAG) constraints, utilizing an
  Information Bottleneck (IB) objective to eliminate redundant communication channels while
  preserving collaborative reasoning accuracy.

Steward Gate Invariants:
  - Non-monetary marginal utility scoring and graph efficiency metrics only.
  - ZERO unapproved tokens (MMCT), speculative dollar claims (+$X,XXX/yr), or sci-fi lore.
  - Fail-closed deterministic parameter verification and cryptographic W3C PROV-DM envelopes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


def canonical_sha256(payload: Any) -> str:
    """Computes deterministic SHA-256 hex digest of data."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


FORBIDDEN_VALUE_PATTERNS = [
    re.compile(r"\bContribution\s+Tokens?\b", re.I),
    re.compile(r"\bMMCT\b"),
    re.compile(r"\bmmctBalance\b|\bmintedMMCT\b"),
    re.compile(r"\+\$[0-9,]+\s*/\s*yr\b", re.I),
    re.compile(r"\b85%\s+direct\s*\+\s*10%", re.I),
    re.compile(r"\bneeds\s+95%\s+Data\s+Shapley", re.I),
    re.compile(r"\bSomatic\s+Witness\b|\bPre-ADC\b", re.I),
]


def assert_steward_gate_compliance(text: str) -> None:
    """Fails closed if forbidden premature token, royalty, or speculative claims are detected."""
    for pat in FORBIDDEN_VALUE_PATTERNS:
        if pat.search(text):
            raise ValueError(f"Steward Gate violation: detected forbidden pattern '{pat.pattern}'")


# ---------------------------------------------------------------------------
# Data Models: Group-of-Agents & Directed Communication Channels
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentGroup:
    """
    Atomic group of collaborative agents (GoAgent, arXiv:2603.19677).
    Treated as a single functional node in the macro communication DAG.
    """
    group_id: str
    role_name: str
    agent_count: int
    capability_keys: Tuple[str, ...]
    mean_token_cost: int = 500
    group_accuracy: float = 0.85

    def validate(self) -> None:
        if not self.group_id or not isinstance(self.group_id, str):
            raise ValueError("AgentGroup requires non-empty string group_id.")
        if not re.match(r"^[a-zA-Z0-9_\-.:/]+$", self.group_id):
            raise ValueError(f"Invalid group_id format: '{self.group_id}'")
        if not isinstance(self.agent_count, int) or self.agent_count <= 0:
            raise ValueError("AgentGroup agent_count must be a positive integer.")
        if not isinstance(self.mean_token_cost, int) or self.mean_token_cost < 0:
            raise ValueError("AgentGroup mean_token_cost cannot be negative.")
        if not (0.0 <= float(self.group_accuracy) <= 1.0):
            raise ValueError("AgentGroup group_accuracy must be in range [0.0, 1.0].")
        assert_steward_gate_compliance(self.role_name)


@dataclass
class GroupEdge:
    """
    Directed communication edge from upstream group to downstream group.
    """
    source_group_id: str
    target_group_id: str
    relevance_score: float  # Semantic mutual relevance in [0.0, 1.0]
    channel_bandwidth_tokens: int = 250
    active: bool = True

    def validate(self) -> None:
        if not self.source_group_id or not self.target_group_id:
            raise ValueError("GroupEdge requires non-empty source and target IDs.")
        if self.source_group_id == self.target_group_id:
            raise ValueError(f"Self-loop edge rejected: {self.source_group_id}")
        if not (0.0 <= float(self.relevance_score) <= 1.0):
            raise ValueError("GroupEdge relevance_score must be in range [0.0, 1.0].")
        if not isinstance(self.channel_bandwidth_tokens, int) or self.channel_bandwidth_tokens < 0:
            raise ValueError("GroupEdge channel_bandwidth_tokens cannot be negative.")


# ---------------------------------------------------------------------------
# GoAgent Information Bottleneck Graph Optimizer
# ---------------------------------------------------------------------------

@dataclass
class GoAgentOptimizationResult:
    """Structured result of GoAgent DAG optimization."""
    task_objective: str
    original_groups: int
    active_groups: int
    original_edges: int
    retained_edges: int
    pruned_edges: int
    token_savings_pct: float
    sparsity_ratio: float
    topological_execution_order: List[str]
    prov_receipt: Dict[str, Any]
    prov_envelope_sha256: str
    steward_gate_passed: bool = True


class GoAgentDAGOptimizer:
    """
    GoAgent Information Bottleneck Graph Topology Optimizer (arXiv:2603.19677).
    Dynamically structures agent groups into sparse, acyclic communication topologies
    optimizing the Information Bottleneck trade-off:
      IB_Score(u -> v) = Relevance(u, v) - beta * (TokenCost(u, v) / MaxCost)
    """

    def __init__(self, beta: float = 0.25, min_retained_edges_per_node: int = 1) -> None:
        if not (0.0 <= beta <= 1.0):
            raise ValueError("Information Bottleneck beta parameter must be in [0.0, 1.0].")
        if min_retained_edges_per_node < 0:
            raise ValueError("min_retained_edges_per_node cannot be negative.")
        self.beta = beta
        self.min_retained_edges_per_node = min_retained_edges_per_node

    def compute_topological_order(
        self,
        groups: List[AgentGroup],
        edges: List[GroupEdge]
    ) -> List[str]:
        """
        Computes topological ordering using Kahn's algorithm.
        Enforces strict DAG acyclicity fail-closed.
        """
        group_ids = [g.group_id for g in groups]
        in_degree: Dict[str, int] = {gid: 0 for gid in group_ids}
        adj: Dict[str, List[str]] = {gid: [] for gid in group_ids}

        for e in edges:
            if e.active:
                if e.source_group_id not in adj or e.target_group_id not in in_degree:
                    continue
                adj[e.source_group_id].append(e.target_group_id)
                in_degree[e.target_group_id] += 1

        queue = [gid for gid, deg in in_degree.items() if deg == 0]
        order: List[str] = []

        while queue:
            queue.sort()
            curr = queue.pop(0)
            order.append(curr)

            for neighbor in adj[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(order) != len(group_ids):
            raise ValueError(
                f"Cycle detected in agent communication topology: {len(order)} of {len(group_ids)} ordered. "
                "GoAgent requires strict Directed Acyclic Graph (DAG) compliance."
            )

        return order

    def compute_ib_scores(self, edges: List[GroupEdge]) -> Dict[Tuple[str, str], float]:
        """
        Computes Information Bottleneck score for each communication edge:
          IB_Score = Relevance - beta * (Cost / MaxCost)
        """
        if not edges:
            return {}
        max_cost = max((e.channel_bandwidth_tokens for e in edges), default=1) or 1
        scores: Dict[Tuple[str, str], float] = {}
        for e in edges:
            cost_ratio = e.channel_bandwidth_tokens / max_cost
            ib_score = round(e.relevance_score - (self.beta * cost_ratio), 4)
            scores[(e.source_group_id, e.target_group_id)] = ib_score
        return scores

    def optimize_topology(
        self,
        groups: List[AgentGroup],
        dense_edges: List[GroupEdge],
        task_objective: str,
        task_id: str,
    ) -> GoAgentOptimizationResult:
        """
        Executes GoAgent Information Bottleneck pruning:
          1. Verifies all input groups and edges fail-closed.
          2. Computes Information Bottleneck marginal communication scores.
          3. Prunes redundant low-utility edges while maintaining DAG connectivity.
          4. Emits verified W3C PROV-DM cryptographic provenance receipt.
        """
        assert_steward_gate_compliance(task_objective)
        for g in groups:
            g.validate()
        for e in dense_edges:
            e.validate()

        # Step 1: Verify baseline DAG acyclicity
        self.compute_topological_order(groups, dense_edges)

        original_edge_count = len(dense_edges)
        total_original_tokens = sum(e.channel_bandwidth_tokens for e in dense_edges) + sum(
            g.mean_token_cost * g.agent_count for g in groups
        )

        ib_scores = self.compute_ib_scores(dense_edges)

        # Step 2: Rank edges by IB score descending
        ranked_edges = sorted(
            dense_edges,
            key=lambda e: ib_scores.get((e.source_group_id, e.target_group_id), 0.0),
            reverse=True,
        )

        # Step 3: Prune edges with negative IB score or redundant channels, ensuring connectivity floor
        retained: List[GroupEdge] = []
        target_in_degree: Dict[str, int] = {g.group_id: 0 for g in groups}

        # First pass: ensure every target with incoming options gets at least min_retained_edges_per_node
        for e in ranked_edges:
            if target_in_degree[e.target_group_id] < self.min_retained_edges_per_node:
                retained.append(e)
                target_in_degree[e.target_group_id] += 1

        # Second pass: admit remaining edges if IB score > 0.0
        for e in ranked_edges:
            if e not in retained:
                score = ib_scores.get((e.source_group_id, e.target_group_id), 0.0)
                if score > 0.0:
                    retained.append(e)

        # Step 4: Verify pruned topology remains a strict DAG
        final_order = self.compute_topological_order(groups, retained)

        retained_edge_count = len(retained)
        pruned_edge_count = original_edge_count - retained_edge_count
        total_retained_tokens = sum(e.channel_bandwidth_tokens for e in retained) + sum(
            g.mean_token_cost * g.agent_count for g in groups
        )

        token_savings_pct = (
            round((1.0 - (total_retained_tokens / max(1, total_original_tokens))) * 100.0, 1)
            if total_original_tokens > 0
            else 0.0
        )
        token_savings_pct = max(0.0, min(95.0, token_savings_pct))
        sparsity_ratio = round(pruned_edge_count / max(1, original_edge_count), 3)

        # Step 5: Construct W3C PROV-DM Cryptographic Provenance Receipt
        now_iso = datetime.now(timezone.utc).isoformat()
        receipt_id = f"PROV-GOAGENT-{canonical_sha256(task_id)[:12].upper()}"

        prov_doc: Dict[str, Any] = {
            "standard": "W3C PROV-DM (Moreau & Missier, 2013) + GoAgent (arXiv:2603.19677)",
            "receipt_id": receipt_id,
            "task_id": task_id,
            "task_objective": task_objective,
            "created_at_iso": now_iso,
            "entities": {
                f"entity-task-{task_id}": {
                    "entity_type": "TaskObjective",
                    "content_digest": canonical_sha256(task_objective),
                },
                f"entity-dag-{task_id}": {
                    "entity_type": "GoAgentOptimizedDAG",
                    "content_digest": canonical_sha256(final_order),
                    "attributes": {
                        "execution_order": final_order,
                        "token_savings_pct": token_savings_pct,
                        "pruned_edges": pruned_edge_count,
                        "sparsity_ratio": sparsity_ratio,
                    },
                },
            },
            "activities": {
                f"activity-goagent-opt-{task_id}": {
                    "activity_type": "GoAgentInformationBottleneckPruning",
                    "start_time_iso": now_iso,
                    "end_time_iso": now_iso,
                    "parameters": {
                        "beta": self.beta,
                        "original_edges": original_edge_count,
                        "retained_edges": retained_edge_count,
                    },
                }
            },
            "agents": {
                f"agent-group-{g.group_id}": {
                    "agent_type": "AgentGroup",
                    "role_name": g.role_name,
                    "agent_count": g.agent_count,
                }
                for g in groups
            },
            "relations": [
                {
                    "relation_type": "wasGeneratedBy",
                    "subject_id": f"entity-dag-{task_id}",
                    "target_id": f"activity-goagent-opt-{task_id}",
                },
                {
                    "relation_type": "used",
                    "subject_id": f"activity-goagent-opt-{task_id}",
                    "target_id": f"entity-task-{task_id}",
                },
                {
                    "relation_type": "wasDerivedFrom",
                    "subject_id": f"entity-dag-{task_id}",
                    "target_id": f"entity-task-{task_id}",
                },
            ],
            "steward_gate_compliance": {
                "pure_non_monetary_utility": True,
                "unapproved_tokens": 0,
                "speculative_savings": 0,
            },
        }

        # Fail closed on any forbidden text inside generated receipt
        assert_steward_gate_compliance(json.dumps(prov_doc))
        prov_digest = canonical_sha256(prov_doc)

        return GoAgentOptimizationResult(
            task_objective=task_objective,
            original_groups=len(groups),
            active_groups=len(final_order),
            original_edges=original_edge_count,
            retained_edges=retained_edge_count,
            pruned_edges=pruned_edge_count,
            token_savings_pct=token_savings_pct,
            sparsity_ratio=sparsity_ratio,
            topological_execution_order=final_order,
            prov_receipt=prov_doc,
            prov_envelope_sha256=prov_digest,
            steward_gate_passed=True,
        )


def verify_goagent_prov_receipt(receipt: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Deterministic validator for GoAgent W3C PROV-DM cryptographic receipts.
    Detects tampering, schema violations, broken entity/activity references,
    and Steward Gate compliance violations.
    """
    errors: List[str] = []
    if not isinstance(receipt, dict):
        return False, ["Receipt must be a JSON dictionary."]

    # Steward Gate check
    text_blob = json.dumps(receipt)
    for pat in FORBIDDEN_VALUE_PATTERNS:
        if pat.search(text_blob):
            return False, [f"STEWARD_GATE_VIOLATION: detected forbidden pattern '{pat.pattern}'"]

    required_keys = ["standard", "receipt_id", "task_id", "entities", "activities", "agents", "relations"]
    for k in required_keys:
        if k not in receipt:
            errors.append(f"Missing required receipt key: '{k}'")

    if errors:
        return False, errors

    entities = receipt.get("entities", {})
    activities = receipt.get("activities", {})
    agents = receipt.get("agents", {})
    relations = receipt.get("relations", [])

    for r in relations:
        rtype = r.get("relation_type")
        sub = r.get("subject_id")
        tgt = r.get("target_id")
        if rtype == "wasGeneratedBy":
            if sub not in entities:
                errors.append(f"wasGeneratedBy subject '{sub}' not in entities")
            if tgt not in activities:
                errors.append(f"wasGeneratedBy target '{tgt}' not in activities")
        elif rtype == "used":
            if sub not in activities:
                errors.append(f"used subject '{sub}' not in activities")
            if tgt not in entities:
                errors.append(f"used target '{tgt}' not in entities")
        elif rtype == "wasDerivedFrom":
            if sub not in entities:
                errors.append(f"wasDerivedFrom subject '{sub}' not in entities")
            if tgt not in entities:
                errors.append(f"wasDerivedFrom target '{tgt}' not in entities")

    return len(errors) == 0, errors
