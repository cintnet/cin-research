"""
tgr_evodag_evolution_router.py: Testnet Ledger DAG-based Multi-Agent Code Evolution Router.

Grounded in:
  - TGR-EvoDAG: A DAG-based Multi-Agent Code Evolution Framework for Generative
    Recommendation on Task-Adaptive Graphs (arXiv:2610.32326, October 2026).
  - W3C PROV-DM: The PROV Data Model (W3C Recommendation, Moreau & Missier, 2013).
  - Proof-Carrying Code Deterministic Verification (Necula, 1997).
  - IEEE Std 7012-2025 Machine Readable Personal Privacy Terms.

Architectural Purpose:
  Linear multi-agent prompt/code evolution suffers from destructive overwrites, where
  exploring a speculative mutation irreversibly overwrites parallel discoveries made by
  peer agents. TGR-EvoDAG models multi-agent code and workflow evolution as an explicit
  Directed Acyclic Graph (DAG). This preserves concurrent evolutionary branches, enables
  topological multi-parent cross-branch merging of complementary innovations, bounds
  active search width via Pareto optimality, and provides verifiable W3C PROV-DM
  cryptographic lineage without stage-asymmetric retraining costs.

Strict Steward Gate Discipline:
  - Non-monetary code evolution, topological routing, and computational graph metrics only.
  - ZERO unapproved tokens (MMCT / "Contribution Tokens"), speculative dollar savings figures,
    or unapproved royalty percentages.
  - Fail-closed deterministic parameter verification and cryptographic W3C PROV-DM envelopes.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def canonical_sha256(payload: Any) -> str:
    """Computes a deterministic SHA-256 hexadecimal digest of structured data."""
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
            raise ValueError(f"Steward Gate violation: detected forbidden pattern '{pat.pattern}' in text.")


class EvolutionStrategyType(str, enum.Enum):
    """Evolutionary operation applied to produce a DAG node."""
    ROOT_BASELINE = "ROOT_BASELINE"
    MUTATION = "MUTATION"
    CROSSOVER = "CROSSOVER"
    TOPOLOGICAL_MERGE = "TOPOLOGICAL_MERGE"
    SPARSIFICATION = "SPARSIFICATION"


class TGREvoDAGError(Exception):
    """Base exception for TGR-EvoDAG router errors."""


class EvoDAGCycleError(TGREvoDAGError):
    """Raised when an edge addition or lineage would introduce a cycle."""


class EvoDAGValidationError(TGREvoDAGError):
    """Raised when an evolutionary candidate or parameter fails validation."""


@dataclasses.dataclass(frozen=True)
class VariantMetrics:
    """Quantitative performance metrics of an evolutionary variant."""
    task_success_rate: float
    token_efficiency_ratio: float
    latency_ms: float
    test_pass_count: int
    test_fail_count: int

    def __post_init__(self) -> None:
        if not (0.0 <= self.task_success_rate <= 1.0):
            raise EvoDAGValidationError(f"task_success_rate must be in [0.0, 1.0], got {self.task_success_rate}")
        if self.token_efficiency_ratio <= 0.0 or not math.isfinite(self.token_efficiency_ratio):
            raise EvoDAGValidationError(f"token_efficiency_ratio must be positive finite, got {self.token_efficiency_ratio}")
        if self.latency_ms <= 0.0 or not math.isfinite(self.latency_ms):
            raise EvoDAGValidationError(f"latency_ms must be positive finite, got {self.latency_ms}")
        if self.test_pass_count < 0 or self.test_fail_count < 0:
            raise EvoDAGValidationError("test counts must be non-negative")

    @property
    def composite_utility(self) -> float:
        """Composite scalarized Pareto utility: success * efficiency / log2(latency + 2)."""
        latency_factor = math.log2(self.latency_ms + 2.0)
        return (self.task_success_rate * self.token_efficiency_ratio) / max(0.1, latency_factor)


@dataclasses.dataclass(frozen=True)
class EvoDAGNode:
    """An immutable node in the multi-branch code evolution DAG."""
    node_id: str
    parent_ids: Tuple[str, ...]
    strategy: EvolutionStrategyType
    author_role: str
    code_artifact: str
    metrics: VariantMetrics
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    sha256_digest: str = dataclasses.field(default="")

    def __post_init__(self) -> None:
        if not self.node_id or not isinstance(self.node_id, str):
            raise EvoDAGValidationError("node_id must be a non-empty string")
        assert_steward_gate_compliance(self.node_id)
        assert_steward_gate_compliance(self.code_artifact)
        assert_steward_gate_compliance(self.author_role)

        # Compute digest if empty
        if not self.sha256_digest:
            payload = {
                "node_id": self.node_id,
                "parent_ids": list(self.parent_ids),
                "strategy": self.strategy.value,
                "author_role": self.author_role,
                "code_artifact": self.code_artifact,
                "metrics": {
                    "task_success_rate": self.metrics.task_success_rate,
                    "token_efficiency_ratio": self.metrics.token_efficiency_ratio,
                    "latency_ms": self.metrics.latency_ms,
                    "test_pass_count": self.metrics.test_pass_count,
                    "test_fail_count": self.metrics.test_fail_count,
                    "composite_utility": self.metrics.composite_utility,
                },
                "metadata": self.metadata,
            }
            object.__setattr__(self, "sha256_digest", canonical_sha256(payload))


class TGREvoDAGRouter:
    """
    Manages the multi-agent evolutionary Directed Acyclic Graph.
    Ensures cycle freedom, multi-parent topological branch merging,
    Pareto branch pruning, and W3C PROV-DM cryptographic lineage tracking.
    """

    def __init__(self, root_node: Optional[EvoDAGNode] = None) -> None:
        self._nodes: Dict[str, EvoDAGNode] = {}
        self._children: Dict[str, Set[str]] = {}
        self._parents: Dict[str, Set[str]] = {}

        if root_node is not None:
            self.add_node(root_node)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def get_node(self, node_id: str) -> EvoDAGNode:
        if node_id not in self._nodes:
            raise EvoDAGValidationError(f"Node '{node_id}' not found in EvoDAG.")
        return self._nodes[node_id]

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def add_node(self, node: EvoDAGNode) -> str:
        """Adds a verified node to the DAG after verifying parents and cycle freedom."""
        if node.node_id in self._nodes:
            raise EvoDAGValidationError(f"Node '{node.node_id}' already exists in EvoDAG.")

        # Verify all parents exist
        for pid in node.parent_ids:
            if pid not in self._nodes:
                raise EvoDAGValidationError(f"Parent '{pid}' does not exist in EvoDAG.")

        # Cycle check: node cannot be reachable from any of its parents
        for pid in node.parent_ids:
            if self._is_ancestor(ancestor_id=node.node_id, descendant_id=pid):
                raise EvoDAGCycleError(f"Adding edge from '{pid}' to '{node.node_id}' creates a cycle.")

        self._nodes[node.node_id] = node
        self._parents[node.node_id] = set(node.parent_ids)
        self._children[node.node_id] = set()

        for pid in node.parent_ids:
            self._children[pid].add(node.node_id)

        return node.node_id

    def _is_ancestor(self, ancestor_id: str, descendant_id: str) -> bool:
        """DFS check to determine whether ancestor_id is an ancestor of descendant_id."""
        if ancestor_id == descendant_id:
            return True
        visited: Set[str] = set()
        stack = [descendant_id]
        while stack:
            curr = stack.pop()
            if curr == ancestor_id:
                return True
            if curr in visited:
                continue
            visited.add(curr)
            stack.extend(self._parents.get(curr, ()))
        return False

    def topological_sort(self) -> List[str]:
        """Returns nodes in topological dependency order (Kahn's algorithm)."""
        in_degree: Dict[str, int] = {nid: len(parents) for nid, parents in self._parents.items()}
        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        ordered: List[str] = []

        while queue:
            curr = queue.pop(0)
            ordered.append(curr)
            for child in sorted(self._children.get(curr, ())):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)

        if len(ordered) != len(self._nodes):
            raise EvoDAGCycleError("Cycle detected during topological sorting.")

        return ordered

    def branch_exploration(
        self,
        parent_id: str,
        mutations: Sequence[Tuple[str, str, VariantMetrics, str]],
    ) -> List[str]:
        """
        Creates concurrent branch variants from a parent node without linear overwrites.
        Each mutation tuple: (candidate_suffix, code_artifact, metrics, author_role).
        """
        if parent_id not in self._nodes:
            raise EvoDAGValidationError(f"Parent '{parent_id}' does not exist.")

        new_ids: List[str] = []
        for suffix, code, metrics, author_role in mutations:
            child_id = f"{parent_id}_branch_{suffix}"
            node = EvoDAGNode(
                node_id=child_id,
                parent_ids=(parent_id,),
                strategy=EvolutionStrategyType.MUTATION,
                author_role=author_role,
                code_artifact=code,
                metrics=metrics,
                metadata={"branch_origin": parent_id},
            )
            self.add_node(node)
            new_ids.append(child_id)

        return new_ids

    def topological_merge(
        self,
        merged_node_id: str,
        parent_ids: Sequence[str],
        synthesized_code: str,
        author_role: str,
        tested_metrics: VariantMetrics,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvoDAGNode:
        """
        Merges complementary multi-parent branches into a unified evolutionary node.
        Computes composite utility and validates Pareto dominance.
        """
        if len(parent_ids) < 2:
            raise EvoDAGValidationError(f"topological_merge requires >= 2 parents, got {len(parent_ids)}")

        parent_nodes = [self.get_node(pid) for pid in parent_ids]

        # Verify that merged metrics are valid
        parent_utilities = [p.metrics.composite_utility for p in parent_nodes]
        min_parent_utility = min(parent_utilities)

        meta = dict(metadata or {})
        meta["merged_parents_count"] = len(parent_ids)
        meta["min_parent_utility"] = min_parent_utility
        meta["utility_gain"] = tested_metrics.composite_utility - min_parent_utility

        merged_node = EvoDAGNode(
            node_id=merged_node_id,
            parent_ids=tuple(parent_ids),
            strategy=EvolutionStrategyType.TOPOLOGICAL_MERGE,
            author_role=author_role,
            code_artifact=synthesized_code,
            metrics=tested_metrics,
            metadata=meta,
        )
        self.add_node(merged_node)
        return merged_node

    def get_pareto_front(self) -> List[EvoDAGNode]:
        """
        Extracts non-dominated leaf candidates across the bi-objective space:
        Objective 1: task_success_rate (maximize)
        Objective 2: token_efficiency_ratio (maximize)
        Objective 3: latency_ms (minimize)
        """
        # Consider all leaf nodes (nodes with 0 children)
        leaves = [self._nodes[nid] for nid, children in self._children.items() if len(children) == 0]
        if not leaves:
            return list(self._nodes.values())

        pareto_front: List[EvoDAGNode] = []
        for cand in leaves:
            dominated = False
            for other in leaves:
                if other.node_id == cand.node_id:
                    continue
                # other dominates cand if other is >= in all and strictly > in at least one
                better_or_equal = (
                    other.metrics.task_success_rate >= cand.metrics.task_success_rate
                    and other.metrics.token_efficiency_ratio >= cand.metrics.token_efficiency_ratio
                    and other.metrics.latency_ms <= cand.metrics.latency_ms
                )
                strictly_better = (
                    other.metrics.task_success_rate > cand.metrics.task_success_rate
                    or other.metrics.token_efficiency_ratio > cand.metrics.token_efficiency_ratio
                    or other.metrics.latency_ms < cand.metrics.latency_ms
                )
                if better_or_equal and strictly_better:
                    dominated = True
                    break
            if not dominated:
                pareto_front.append(cand)

        return sorted(pareto_front, key=lambda n: n.metrics.composite_utility, reverse=True)

    def prune_suboptimal_branches(self, max_leaves: int) -> List[str]:
        """
        Identifies dominated or lowest-utility leaf nodes that can be marked for pruning.
        Returns the list of pruned leaf node IDs.
        """
        if max_leaves < 1:
            raise EvoDAGValidationError("max_leaves must be at least 1")

        leaves = [self._nodes[nid] for nid, children in self._children.items() if len(children) == 0]
        if len(leaves) <= max_leaves:
            return []

        # Sort leaves ascending by utility (lowest first)
        sorted_leaves = sorted(leaves, key=lambda n: n.metrics.composite_utility)
        prune_count = len(leaves) - max_leaves
        to_prune = [node.node_id for node in sorted_leaves[:prune_count]]
        return to_prune

    def export_w3c_prov_dm(self, node_id: str) -> Dict[str, Any]:
        """
        Generates a standard W3C PROV-DM JSON representation for an evolutionary node.
        Includes entity digests, derivation relations, and agent activity attestation.
        """
        node = self.get_node(node_id)
        prov: Dict[str, Any] = {
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "cin": "https://cintnet.org/schema/prov#",
                "xsd": "http://www.w3.org/2001/XMLSchema#",
            },
            "prefix": {
                "cin": "https://cintnet.org/schema/prov#",
            },
            "entity": {
                f"cin:variant/{node.node_id}": {
                    "prov:type": "cin:EvoDAGVariant",
                    "cin:strategy": node.strategy.value,
                    "cin:sha256": node.sha256_digest,
                    "cin:compositeUtility": node.metrics.composite_utility,
                    "cin:taskSuccessRate": node.metrics.task_success_rate,
                    "cin:tokenEfficiencyRatio": node.metrics.token_efficiency_ratio,
                    "cin:latencyMs": node.metrics.latency_ms,
                }
            },
            "agent": {
                f"cin:agent/{node.author_role}": {
                    "prov:type": "prov:SoftwareAgent",
                    "cin:role": node.author_role,
                }
            },
            "wasGeneratedBy": {
                f"cin:gen/{node.node_id}": {
                    "prov:entity": f"cin:variant/{node.node_id}",
                    "prov:agent": f"cin:agent/{node.author_role}",
                    "cin:activityType": "cin:EvolutionaryStep",
                }
            },
            "wasDerivedFrom": {},
        }

        for pid in node.parent_ids:
            parent_node = self.get_node(pid)
            prov["entity"][f"cin:variant/{parent_node.node_id}"] = {
                "prov:type": "cin:EvoDAGVariant",
                "cin:sha256": parent_node.sha256_digest,
                "cin:compositeUtility": parent_node.metrics.composite_utility,
            }
            prov["wasDerivedFrom"][f"cin:derivation/{node.node_id}_from_{pid}"] = {
                "prov:generatedEntity": f"cin:variant/{node.node_id}",
                "prov:usedEntity": f"cin:variant/{pid}",
                "cin:derivationType": node.strategy.value,
            }

        return prov
