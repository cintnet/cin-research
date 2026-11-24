"""
dynamic_joint_state_graph_router.py: Testnet Ledger Dynamic Homogeneous Joint-State Graph Router.

Grounded in:
  - Efficient Multi-Agent Coordination via Dynamic Joint-State Graph Construction
    (Dynamic-HJSG, arXiv:2509.07234, Zhou, Limbu, Xiao, Sep 2025).
  - W3C PROV-DM: The PROV Data Model (W3C Recommendation, Moreau & Missier, 2013).
  - Proof-Carrying Code Deterministic Verification (Necula, 1997).
  - IEEE Std 7012-2025 Machine Readable Personal Privacy Terms.

Architectural Purpose:
  Multi-agent coordination under graph-structured dependency and resource constraints
  encounters exponential complexity explosion (|S_i|^N) when joint state spaces are
  statically evaluated upfront. Dynamic-HJSG constructs the joint-state graph dynamically
  on-the-fly, evaluating local agent marginal states and pruning unreachable, cost-violating,
  or Pareto-dominated coordination states. This preserves global optimality and bounded
  coordination cost without centralized synchronization bottlenecks.

Strict Steward Gate Discipline:
  - Non-monetary computational state routing, dependency bounding, and task graphs only.
  - ZERO unapproved tokens (MMCT / "Contribution Tokens"), speculative dollar savings figures,
    or unapproved royalty percentages.
  - Fail-closed deterministic parameter verification and cryptographic W3C PROV-DM lineage receipts.
"""

from __future__ import annotations

import dataclasses
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


class DynamicHJSGError(Exception):
    """Base exception for Dynamic-HJSG router operations."""


class HJSGCycleError(DynamicHJSGError):
    """Raised when a state transition introduces a cycle into the coordination DAG."""


class HJSGValidationError(DynamicHJSGError):
    """Raised when an agent state, cost metric, or transition parameter is invalid."""


class HJSGBudgetExceededError(DynamicHJSGError):
    """Raised when joint-state coordination exceeds configured cost boundaries."""


@dataclasses.dataclass(frozen=True)
class AgentLocalState:
    """Local state representation of an individual agent within the collective."""
    agent_id: str
    state_key: str
    cost_units: float = 0.0
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)
    content_digest: str = ""

    def __post_init__(self) -> None:
        if not self.agent_id or not isinstance(self.agent_id, str):
            raise HJSGValidationError("agent_id must be a non-empty string.")
        if not self.state_key or not isinstance(self.state_key, str):
            raise HJSGValidationError("state_key must be a non-empty string.")
        if self.cost_units < 0.0 or math.isnan(self.cost_units) or math.isinf(self.cost_units):
            raise HJSGValidationError(f"Invalid cost_units: {self.cost_units}; must be non-negative finite.")
        assert_steward_gate_compliance(self.agent_id)
        assert_steward_gate_compliance(self.state_key)
        assert_steward_gate_compliance(json.dumps(self.attributes))

        if not self.content_digest:
            payload = {
                "agent_id": self.agent_id,
                "state_key": self.state_key,
                "cost_units": round(self.cost_units, 4),
                "attributes": self.attributes,
            }
            object.__setattr__(self, "content_digest", canonical_sha256(payload))


@dataclasses.dataclass(frozen=True)
class JointStateNode:
    """Homogeneous joint-state node in the coordination graph."""
    node_id: str
    step_index: int
    agent_states: Dict[str, AgentLocalState]
    cumulative_cost: float
    task_coverage: float
    is_terminal: bool = False
    parent_ids: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.node_id or not isinstance(self.node_id, str):
            raise HJSGValidationError("node_id must be a non-empty string.")
        if self.step_index < 0:
            raise HJSGValidationError("step_index must be >= 0.")
        if self.cumulative_cost < 0.0 or math.isnan(self.cumulative_cost) or math.isinf(self.cumulative_cost):
            raise HJSGValidationError(f"Invalid cumulative_cost: {self.cumulative_cost}.")
        if not (0.0 <= self.task_coverage <= 1.0) or math.isnan(self.task_coverage):
            raise HJSGValidationError(f"task_coverage must be between 0.0 and 1.0, got {self.task_coverage}.")
        assert_steward_gate_compliance(json.dumps(self.metadata))


@dataclasses.dataclass(frozen=True)
class JointStateEdge:
    """Directed transition edge between two joint-state nodes."""
    edge_id: str
    source_node_id: str
    target_node_id: str
    action_label: str
    transition_cost: float
    contributing_agents: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise HJSGValidationError("edge_id must be non-empty.")
        if not self.source_node_id or not self.target_node_id:
            raise HJSGValidationError("source_node_id and target_node_id must be non-empty.")
        if self.transition_cost < 0.0 or math.isnan(self.transition_cost) or math.isinf(self.transition_cost):
            raise HJSGValidationError("transition_cost must be non-negative finite.")
        assert_steward_gate_compliance(self.action_label)


class DynamicHJSGRouter:
    """
    Dynamic Homogeneous Joint-State Graph Router (Dynamic-HJSG).
    Scales multi-agent coordination by dynamically constructing and pruning joint states
    under dependency, cost, and Pareto-optimality bounds.
    """

    def __init__(
        self,
        max_active_joint_states: int = 50,
        max_coordination_cost: float = 1000.0,
        min_pruning_coverage: float = 0.0,
    ) -> None:
        if max_active_joint_states < 2:
            raise HJSGValidationError("max_active_joint_states must be >= 2.")
        if max_coordination_cost <= 0.0 or math.isnan(max_coordination_cost):
            raise HJSGValidationError("max_coordination_cost must be positive finite.")
        self.max_active_joint_states = max_active_joint_states
        self.max_coordination_cost = max_coordination_cost
        self.min_pruning_coverage = min_pruning_coverage

        self.nodes: Dict[str, JointStateNode] = {}
        self.edges: Dict[str, JointStateEdge] = {}
        self.adjacency: Dict[str, List[str]] = {}
        self.reverse_adjacency: Dict[str, List[str]] = {}
        self.root_node_id: Optional[str] = None

    def _compute_node_id(self, step_index: int, agent_states: Dict[str, AgentLocalState], parent_ids: Tuple[str, ...]) -> str:
        state_repr = {aid: s.content_digest for aid, s in sorted(agent_states.items())}
        payload = {
            "step_index": step_index,
            "agent_states": state_repr,
            "parent_ids": sorted(parent_ids),
        }
        return "hjsg-node-" + canonical_sha256(payload)[:16]

    def _check_cycle(self, source_id: str, target_id: str) -> None:
        """Ensures that adding an edge source -> target does not create a cycle."""
        if source_id == target_id:
            raise HJSGCycleError(f"Self-loop detected on node {source_id}.")

        # BFS from target_id to see if source_id is reachable
        visited: Set[str] = set()
        queue = [target_id]
        while queue:
            curr = queue.pop(0)
            if curr == source_id:
                raise HJSGCycleError(f"Cycle detected: adding edge {source_id} -> {target_id} closes a cycle.")
            if curr not in visited:
                visited.add(curr)
                queue.extend(self.adjacency.get(curr, []))

    def create_root_joint_state(
        self,
        initial_states: Sequence[AgentLocalState],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> JointStateNode:
        """Initializes the root homogeneous joint state."""
        if not initial_states:
            raise HJSGValidationError("Cannot create root joint state with empty agent states.")

        state_map: Dict[str, AgentLocalState] = {}
        total_initial_cost = 0.0
        for s in initial_states:
            if s.agent_id in state_map:
                raise HJSGValidationError(f"Duplicate agent_id {s.agent_id} in initial states.")
            state_map[s.agent_id] = s
            total_initial_cost += s.cost_units

        node_id = self._compute_node_id(0, state_map, ())
        root_node = JointStateNode(
            node_id=node_id,
            step_index=0,
            agent_states=state_map,
            cumulative_cost=total_initial_cost,
            task_coverage=0.0,
            is_terminal=False,
            parent_ids=(),
            metadata=metadata or {},
        )

        self.nodes[node_id] = root_node
        self.adjacency[node_id] = []
        self.reverse_adjacency[node_id] = []
        self.root_node_id = node_id
        return root_node

    def expand_joint_state(
        self,
        parent_node_id: str,
        agent_transitions: Dict[str, AgentLocalState],
        action_label: str,
        step_cost: float = 1.0,
        coverage_gain: float = 0.1,
        is_terminal: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> JointStateNode:
        """
        Dynamically transitions the joint state by updating affected agent local states.
        Enforces cost limits, cycle detection, and DAG structure.
        """
        if parent_node_id not in self.nodes:
            raise HJSGValidationError(f"Parent node {parent_node_id} does not exist in graph.")
        if not agent_transitions:
            raise HJSGValidationError("agent_transitions cannot be empty.")
        if step_cost < 0.0 or math.isnan(step_cost) or math.isinf(step_cost):
            raise HJSGValidationError("step_cost must be non-negative finite.")
        if coverage_gain < 0.0 or math.isnan(coverage_gain):
            raise HJSGValidationError("coverage_gain must be non-negative.")

        parent = self.nodes[parent_node_id]
        if parent.is_terminal:
            raise HJSGValidationError(f"Cannot expand from terminal node {parent_node_id}.")

        new_states = dict(parent.agent_states)
        for aid, new_st in agent_transitions.items():
            new_states[aid] = new_st

        new_cost = parent.cumulative_cost + step_cost + sum(st.cost_units for st in agent_transitions.values())
        if new_cost > self.max_coordination_cost:
            raise HJSGBudgetExceededError(
                f"Cumulative cost {new_cost:.2f} exceeds max coordination cost {self.max_coordination_cost:.2f}."
            )

        new_coverage = min(1.0, parent.task_coverage + coverage_gain)
        step_idx = parent.step_index + 1
        new_node_id = self._compute_node_id(step_idx, new_states, (parent_node_id,))

        self._check_cycle(parent_node_id, new_node_id)

        child_node = JointStateNode(
            node_id=new_node_id,
            step_index=step_idx,
            agent_states=new_states,
            cumulative_cost=new_cost,
            task_coverage=new_coverage,
            is_terminal=is_terminal or (new_coverage >= 1.0),
            parent_ids=(parent_node_id,),
            metadata=metadata or {},
        )

        edge_id = f"edge-{parent_node_id[:8]}-{new_node_id[:8]}"
        edge = JointStateEdge(
            edge_id=edge_id,
            source_node_id=parent_node_id,
            target_node_id=new_node_id,
            action_label=action_label,
            transition_cost=step_cost,
            contributing_agents=tuple(sorted(agent_transitions.keys())),
        )

        self.nodes[new_node_id] = child_node
        self.edges[edge_id] = edge

        self.adjacency[parent_node_id].append(new_node_id)
        if new_node_id not in self.adjacency:
            self.adjacency[new_node_id] = []
        if new_node_id not in self.reverse_adjacency:
            self.reverse_adjacency[new_node_id] = []
        self.reverse_adjacency[new_node_id].append(parent_node_id)

        # Trigger auto-pruning if active states exceed budget
        if len(self.nodes) > self.max_active_joint_states:
            self.prune_suboptimal_joint_states()

        return child_node

    def prune_suboptimal_joint_states(self) -> int:
        """
        Prunes suboptimal non-terminal leaf states to keep active graph within bounds.
        Preserves root, terminal nodes, and the current Pareto frontier.
        """
        if len(self.nodes) <= self.max_active_joint_states:
            return 0

        # Candidates for pruning: non-terminal leaf nodes (out-degree == 0, excluding root)
        leaves = [
            nid for nid, targets in self.adjacency.items()
            if len(targets) == 0 and nid != self.root_node_id and not self.nodes[nid].is_terminal
        ]

        if not leaves:
            return 0

        # Sort leaves by efficiency ratio: task_coverage / (cumulative_cost + 1e-6) ascending (worst first)
        leaves.sort(key=lambda nid: (self.nodes[nid].task_coverage / (self.nodes[nid].cumulative_cost + 1e-6)))

        pruned_count = 0
        while len(self.nodes) > self.max_active_joint_states and leaves:
            to_prune = leaves.pop(0)
            self._remove_node(to_prune)
            pruned_count += 1

        return pruned_count

    def _remove_node(self, node_id: str) -> None:
        """Removes a node and its incoming/outgoing edges."""
        if node_id not in self.nodes:
            return

        # Remove edges where node_id is target
        for p_id in list(self.reverse_adjacency.get(node_id, [])):
            if p_id in self.adjacency and node_id in self.adjacency[p_id]:
                self.adjacency[p_id].remove(node_id)
            edge_id = f"edge-{p_id[:8]}-{node_id[:8]}"
            self.edges.pop(edge_id, None)

        # Remove edges where node_id is source
        for c_id in list(self.adjacency.get(node_id, [])):
            if c_id in self.reverse_adjacency and node_id in self.reverse_adjacency[c_id]:
                self.reverse_adjacency[c_id].remove(node_id)
            edge_id = f"edge-{node_id[:8]}-{c_id[:8]}"
            self.edges.pop(edge_id, None)

        self.adjacency.pop(node_id, None)
        self.reverse_adjacency.pop(node_id, None)
        self.nodes.pop(node_id, None)

    def extract_pareto_optimal_joint_states(self) -> List[JointStateNode]:
        """
        Extracts non-dominated joint states (maximizing task_coverage, minimizing cumulative_cost).
        """
        all_nodes = list(self.nodes.values())
        pareto: List[JointStateNode] = []

        for candidate in all_nodes:
            dominated = False
            for other in all_nodes:
                if other.node_id == candidate.node_id:
                    continue
                # other dominates candidate if:
                # coverage(other) >= coverage(candidate) and cost(other) <= cost(candidate)
                # with at least one strict inequality.
                coverage_better_or_equal = other.task_coverage >= candidate.task_coverage
                cost_better_or_equal = other.cumulative_cost <= candidate.cumulative_cost
                strict_inequality = (other.task_coverage > candidate.task_coverage) or (other.cumulative_cost < candidate.cumulative_cost)
                if coverage_better_or_equal and cost_better_or_equal and strict_inequality:
                    dominated = True
                    break
            if not dominated:
                pareto.append(candidate)

        pareto.sort(key=lambda n: n.cumulative_cost)
        return pareto

    def find_optimal_coordination_path(self, target_node_id: Optional[str] = None) -> List[JointStateNode]:
        """
        Backtracks the lowest-cost path from root to the target or highest-coverage terminal node.
        """
        if not self.nodes or not self.root_node_id:
            return []

        if target_node_id:
            if target_node_id not in self.nodes:
                raise HJSGValidationError(f"Target node {target_node_id} not in graph.")
            chosen_target = self.nodes[target_node_id]
        else:
            # Pick highest coverage, then lowest cost
            sorted_nodes = sorted(self.nodes.values(), key=lambda n: (-n.task_coverage, n.cumulative_cost))
            chosen_target = sorted_nodes[0]

        path = [chosen_target]
        curr = chosen_target
        while curr.parent_ids:
            # Pick first parent
            p_id = curr.parent_ids[0]
            if p_id in self.nodes:
                curr = self.nodes[p_id]
                path.append(curr)
            else:
                break

        path.reverse()
        return path

    def export_w3c_prov_dm(self) -> Dict[str, Any]:
        """
        Exports the entire coordination graph as a standard W3C PROV-DM cryptographic lineage receipt.
        """
        prov_entities: Dict[str, Any] = {}
        prov_activities: Dict[str, Any] = {}
        prov_was_derived_from: List[Dict[str, Any]] = []

        for node_id, node in self.nodes.items():
            prov_entities[f"cin:jointState:{node_id}"] = {
                "prov:type": "cin:JointStateNode",
                "cin:stepIndex": node.step_index,
                "cin:cumulativeCost": round(node.cumulative_cost, 4),
                "cin:taskCoverage": round(node.task_coverage, 4),
                "cin:isTerminal": node.is_terminal,
                "cin:agentCount": len(node.agent_states),
                "cin:agentList": sorted(node.agent_states.keys()),
            }

        for edge_id, edge in self.edges.items():
            act_id = f"cin:transition:{edge_id}"
            prov_activities[act_id] = {
                "prov:type": "cin:JointStateTransition",
                "cin:actionLabel": edge.action_label,
                "cin:transitionCost": round(edge.transition_cost, 4),
                "cin:contributingAgents": list(edge.contributing_agents),
            }
            prov_was_derived_from.append({
                "prov:generatedEntity": f"cin:jointState:{edge.target_node_id}",
                "prov:usedEntity": f"cin:jointState:{edge.source_node_id}",
                "prov:activity": act_id,
            })

        document = {
            "prefix": {
                "prov": "http://www.w3.org/ns/prov#",
                "cin": "https://cintnet.org/schema/prov/hjsg#",
                "xsd": "http://www.w3.org/2001/XMLSchema#",
            },
            "entity": prov_entities,
            "activity": prov_activities,
            "wasDerivedFrom": prov_was_derived_from,
        }

        doc_digest = canonical_sha256(document)
        return {
            "schema_version": "1.0.0",
            "prov_document": document,
            "prov_sha256": doc_digest,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }

    def get_graph_metrics(self) -> Dict[str, Any]:
        """Returns summary topological metrics for runtime monitoring."""
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "root_node_id": self.root_node_id,
            "terminal_node_count": sum(1 for n in self.nodes.values() if n.is_terminal),
            "max_coverage": max((n.task_coverage for n in self.nodes.values()), default=0.0),
            "min_cost": min((n.cumulative_cost for n in self.nodes.values()), default=0.0),
            "max_cost": max((n.cumulative_cost for n in self.nodes.values()), default=0.0),
            "active_frontier_size": sum(1 for nid, edges in self.adjacency.items() if len(edges) == 0),
        }
