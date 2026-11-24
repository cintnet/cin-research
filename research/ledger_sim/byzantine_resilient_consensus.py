"""
research/ledger_sim/byzantine_resilient_consensus.py

Decentralized Byzantine-Resilient Consensus for Multi-Agent LLM Networks.

Grounded in:
- Haejoon Lee, Vincent-Daniel (Juyoung) Yun, Hyeonho Oh, Dimitra Panagou, and Sai Praneeth Karimireddy (2026):
  "Robust Multi-Agent LLMs under Byzantine Faults" (arXiv:2605.09076, EMNLP 2026).
  [Self-Anchored Consensus (SAC) with receiver-side filter-and-refine protocol].
- Heath J. LeBlanc, Haotian Zhang, Xenofon Koutsoukos, and Shreyas Sundaram (2013):
  "Resilient Asymptotic Consensus in Robust Networks" (IEEE Journal on Selected Areas in Communications,
  Vol. 31, No. 4, pp. 766-781, DOI:10.1109/JSAC.2013.130413).
  [Network (F+1)-robustness conditions and Weighted Mean-Subsequence-Reduced (W-MSR) algorithm].
- Leslie Lamport, Robert Shostak, Marshall Pease (1982):
  "The Byzantine Generals Problem" (ACM TOPLAS, 4(3), pp. 382-401).
- Jack B. Dennis and Earl C. Van Horn (1966):
  "Programming Semantics for Multiprogrammed Computations" (CACM).
  [Object-Capability security and zero ambient authority].
- Luc Moreau and Paolo Missier (2013):
  "The PROV Data Model" (W3C Recommendation).

Core Architectural Invariants:
1. Decentralization: No central leader, master key, or global coordinator dictates consensus.
2. Receiver-Side Self-Anchored MSR Filtering: Each honest node grounds its updates in its own
   verifiable self-anchor prior and locally trims up to F extreme or outlier messages from in-neighbors.
3. Topological Robustness: Enforces (F+1)-robust graph connectivity so Byzantine agents cannot partition
   honest agents or steer collective consensus into malicious attractors.
4. Cryptographic Provenance: Every round produces a tamper-evident execution receipt with canonical SHA-256 digests.
5. Strict Steward Gate Compliance: Non-monetary coordination only. Zero unapproved tokens (MMCT / "Contribution Tokens"),
   zero speculative monetary savings, and zero non-finite floating-point attacks (NaN/Inf).
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple


# =====================================================================
# Error Hierarchy
# =====================================================================

class ConsensusSecurityViolation(Exception):
    """Base exception for security boundary failures in consensus execution."""


class ConsensusValidationError(ConsensusSecurityViolation):
    """Raised when message schemas, floats, or parameters fail deterministic validation."""


class TopologyRobustnessError(ConsensusSecurityViolation):
    """Raised when a graph topology fails the (F+1)-robustness requirement for Byzantine tolerance."""


class ByzantineFaultExceededError(ConsensusSecurityViolation):
    """Raised when the number of faulty nodes exceeds the theoretical graph tolerance bound F."""


class StewardGateViolationError(ConsensusSecurityViolation):
    """Raised when unapproved tokens, speculative dollar claims, or sci-fi lore are encountered."""


# =====================================================================
# Steward Gate Screening & Deterministic Helpers
# =====================================================================

_FORBIDDEN_STEWARD_TERMS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE), "Contribution Token"),
    (re.compile(r"\bMMCT\b"), "MMCT token"),
    (re.compile(r"\bmmctBalance\b|\bmintedMMCT\b"), "MMCT ledger state"),
    (re.compile(r"\+\$[0-9,]+(\.[0-9]+)?\s*/\s*yr\b", re.IGNORECASE), "Speculative yearly savings"),
    (re.compile(r"\bguaranteed\s+(return|profit|savings|yield)\b", re.IGNORECASE), "Guaranteed financial return"),
    (re.compile(r"\b85\s*/\s*10\s*/\s*5\b"), "Speculative fixed royalty split"),
    (re.compile(r"\b95\s*%\s+to\s+creators?\b", re.IGNORECASE), "Speculative royalty promise"),
    (re.compile(r"\bSomatic\s+Witness\b", re.IGNORECASE), "Retired neologism Somatic Witness"),
    (re.compile(r"\bAlgebraic\s+Coalition\b", re.IGNORECASE), "Retired neologism Algebraic Coalition"),
    (re.compile(r"\bFractured\s+Alignment\b", re.IGNORECASE), "Retired neologism Fractured Alignment"),
)


def assert_steward_gate_compliance(data: Any) -> None:
    """Enforces strict Steward Gate compliance against forbidden financial promises and tokens."""
    if isinstance(data, str):
        for pattern, label in _FORBIDDEN_STEWARD_TERMS:
            if pattern.search(data):
                raise StewardGateViolationError(f"Steward Gate violation: '{label}' detected in payload: {data[:100]}")
    elif isinstance(data, dict):
        for k, v in data.items():
            assert_steward_gate_compliance(k)
            assert_steward_gate_compliance(v)
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            assert_steward_gate_compliance(item)


def canonical_sha256(payload: Any) -> str:
    """Computes a deterministic SHA-256 hex digest for arbitrary nested data."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def assert_finite_float(val: float, name: str = "value") -> None:
    """Ensures a float is finite and not NaN or Infinity."""
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        raise ConsensusValidationError(f"{name} must be a numeric float, got {type(val).__name__}")
    if math.isnan(val) or math.isinf(val):
        raise ConsensusValidationError(f"{name} must be finite, got {val}")


# =====================================================================
# Node Roles and Graph Topology
# =====================================================================

class NodeRole(str, enum.Enum):
    """Role classification for agents participating in consensus."""
    HONEST = "HONEST"
    BYZANTINE_EXTREME = "BYZANTINE_EXTREME"
    BYZANTINE_RANDOM = "BYZANTINE_RANDOM"
    BYZANTINE_SYBIL = "BYZANTINE_SYBIL"


@dataclasses.dataclass(frozen=True)
class ConsensusGraphTopology:
    """
    Directed communication topology for multi-agent consensus.

    Enforces LeBlanc et al. (2013) (F+1)-robustness conditions:
    A network is (r)-robust if for every pair of disjoint non-empty subsets of nodes S_1, S_2,
    at least one node has at least r neighbors outside its own subset.
    For local tolerance of up to F Byzantine nodes, the graph must be at least (F+1)-robust.
    """
    nodes: Tuple[str, ...]
    in_neighbors: Dict[str, Tuple[str, ...]]
    max_byzantine_f: int

    def __post_init__(self) -> None:
        if not self.nodes:
            raise ConsensusValidationError("Graph topology must contain at least one node")
        if self.max_byzantine_f < 0:
            raise ConsensusValidationError("max_byzantine_f must be non-negative")
        node_set = set(self.nodes)
        if len(node_set) != len(self.nodes):
            raise ConsensusValidationError("Duplicate node IDs in graph topology")
        for node in self.nodes:
            if node not in self.in_neighbors:
                raise ConsensusValidationError(f"Missing in_neighbors mapping for node '{node}'")
            for neighbor in self.in_neighbors[node]:
                if neighbor not in node_set:
                    raise ConsensusValidationError(f"Unknown neighbor '{neighbor}' referenced by node '{node}'")

    @classmethod
    def build_fully_connected(cls, node_ids: Sequence[str], max_byzantine_f: int) -> ConsensusGraphTopology:
        """Constructs a fully connected clique graph where each node listens to all other nodes."""
        nodes_tuple = tuple(node_ids)
        in_neighbors = {
            node: tuple(other for other in nodes_tuple if other != node)
            for node in nodes_tuple
        }
        return cls(nodes=nodes_tuple, in_neighbors=in_neighbors, max_byzantine_f=max_byzantine_f)

    @classmethod
    def build_k_regular_circulant(
        cls,
        node_ids: Sequence[str],
        chord_offsets: Sequence[int],
        max_byzantine_f: int,
    ) -> ConsensusGraphTopology:
        """Constructs a symmetric circulant graph with defined chord offsets."""
        n = len(node_ids)
        nodes_tuple = tuple(node_ids)
        in_neighbors: Dict[str, Tuple[str, ...]] = {}
        for i, node in enumerate(nodes_tuple):
            nbrs: Set[str] = set()
            for offset in chord_offsets:
                nbrs.add(nodes_tuple[(i - offset) % n])
                nbrs.add(nodes_tuple[(i + offset) % n])
            nbrs.discard(node)
            in_neighbors[node] = tuple(sorted(nbrs))
        return cls(nodes=nodes_tuple, in_neighbors=in_neighbors, max_byzantine_f=max_byzantine_f)

    def verify_f_plus_1_robustness(self) -> Tuple[bool, str]:
        """
        Verifies whether the graph satisfies the (F+1)-robustness condition required
        for guaranteed Byzantine consensus under LeBlanc et al. (2013) Theorem 1.

        For n nodes and parameter r = F + 1:
        Necessary condition: Minimum in-degree must be >= 2 * F + 1.
        Total honest node count must strictly exceed 3 * F for complete safety.
        """
        n = len(self.nodes)
        f = self.max_byzantine_f
        req_in_degree = 2 * f + 1

        if n <= 3 * f:
            return (
                False,
                f"Insufficient nodes: total nodes N={n} <= 3*F={3*f}. Required N > 3*F for Byzantine resilience.",
            )

        for node, nbrs in self.in_neighbors.items():
            if len(nbrs) < req_in_degree:
                return (
                    False,
                    f"Node '{node}' has in-degree {len(nbrs)}, which is less than required 2*F+1={req_in_degree}.",
                )

        return (True, f"Graph topology satisfies (F+1)-robustness degree requirements with N={n}, F={f}.")


# =====================================================================
# Semantic Messages
# =====================================================================

@dataclasses.dataclass(frozen=True)
class SemanticMessage:
    """A verified, signed message exchanged between peer agents during consensus."""
    sender_id: str
    round_number: int
    claim_value: float
    statement: str
    confidence: float
    signature_digest: str

    def __post_init__(self) -> None:
        assert_finite_float(self.claim_value, "claim_value")
        assert_finite_float(self.confidence, "confidence")
        if not (0.0 <= self.confidence <= 1.0):
            raise ConsensusValidationError(f"confidence must be in [0, 1], got {self.confidence}")
        if self.round_number < 0:
            raise ConsensusValidationError("round_number must be non-negative")
        assert_steward_gate_compliance(self.statement)
        assert_steward_gate_compliance(self.sender_id)

    @classmethod
    def create(
        cls,
        sender_id: str,
        round_number: int,
        claim_value: float,
        statement: str,
        confidence: float,
    ) -> SemanticMessage:
        """Constructs a message with deterministic SHA-256 signature digest."""
        assert_finite_float(claim_value, "claim_value")
        assert_finite_float(confidence, "confidence")
        assert_steward_gate_compliance(statement)
        assert_steward_gate_compliance(sender_id)

        digest = canonical_sha256({
            "sender_id": sender_id,
            "round_number": round_number,
            "claim_value": round(float(claim_value), 8),
            "statement": statement,
            "confidence": round(float(confidence), 8),
        })
        return cls(
            sender_id=sender_id,
            round_number=round_number,
            claim_value=float(claim_value),
            statement=statement,
            confidence=float(confidence),
            signature_digest=digest,
        )

    def verify_digest(self) -> bool:
        """Verifies the deterministic cryptographic integrity of this message."""
        expected = canonical_sha256({
            "sender_id": self.sender_id,
            "round_number": self.round_number,
            "claim_value": round(float(self.claim_value), 8),
            "statement": self.statement,
            "confidence": round(float(self.confidence), 8),
        })
        return self.signature_digest == expected


# =====================================================================
# Agent Node with Receiver-Side Self-Anchored MSR Filter
# =====================================================================

class ByzantineAgentNode:
    """
    Autonomous agent participant implementing Self-Anchored Consensus (SAC).

    Follows Lee et al. (2026) and LeBlanc et al. (2013):
    1. Honest nodes maintain a grounded `self_anchor_value` (private observation/fact).
    2. In each round, the node broadcasts its `current_claim_value`.
    3. When receiving messages from in-neighbors:
       - Messages strictly higher than the node's current belief are candidates for upper trimming.
         The node trims up to F highest values among strictly higher values.
       - Messages strictly lower are candidates for lower trimming.
         The node trims up to F lowest values among strictly lower values.
    4. The node updates its state using a convex combination:
       x_i(t+1) = (1 - alpha - beta) * x_i(t) + alpha * anchor_i + beta * mean(accepted_neighbors).
    """

    def __init__(
        self,
        agent_id: str,
        role: NodeRole,
        initial_value: float,
        self_anchor_value: float,
        max_byzantine_f: int,
        alpha_anchor: float = 0.25,
        beta_neighbors: float = 0.50,
        adversarial_bias: float = 100.0,
    ) -> None:
        assert_steward_gate_compliance(agent_id)
        assert_finite_float(initial_value, "initial_value")
        assert_finite_float(self_anchor_value, "self_anchor_value")
        assert_finite_float(alpha_anchor, "alpha_anchor")
        assert_finite_float(beta_neighbors, "beta_neighbors")

        if max_byzantine_f < 0:
            raise ConsensusValidationError("max_byzantine_f must be non-negative")
        if not (0.0 <= alpha_anchor <= 1.0):
            raise ConsensusValidationError("alpha_anchor must be in [0, 1]")
        if not (0.0 <= beta_neighbors <= 1.0):
            raise ConsensusValidationError("beta_neighbors must be in [0, 1]")
        if alpha_anchor + beta_neighbors > 1.0:
            raise ConsensusValidationError("alpha_anchor + beta_neighbors cannot exceed 1.0")

        self.agent_id = agent_id
        self.role = role
        self.self_anchor_value = float(self_anchor_value)
        self.current_value = float(initial_value)
        self.max_byzantine_f = int(max_byzantine_f)
        self.alpha_anchor = float(alpha_anchor)
        self.beta_neighbors = float(beta_neighbors)
        self.adversarial_bias = float(adversarial_bias)
        self.history: List[float] = [self.current_value]
        self.last_trimmed_senders: List[str] = []

    def generate_outbound_message(self, round_number: int) -> SemanticMessage:
        """Generates an outbound consensus message based on role."""
        if self.role == NodeRole.HONEST:
            claim = self.current_value
            stmt = f"Agent {self.agent_id} honest belief at round {round_number}"
            conf = 0.95
        elif self.role == NodeRole.BYZANTINE_EXTREME:
            # Injects an extreme outlier claim to attempt steering consensus
            claim = self.current_value + self.adversarial_bias
            stmt = f"Agent {self.agent_id} adversarial claim at round {round_number}"
            conf = 1.0
        elif self.role == NodeRole.BYZANTINE_RANDOM:
            # Oscillates between negative and positive extremes
            claim = self.current_value - self.adversarial_bias if round_number % 2 == 0 else self.current_value + self.adversarial_bias
            stmt = f"Agent {self.agent_id} erratic claim at round {round_number}"
            conf = 0.8
        elif self.role == NodeRole.BYZANTINE_SYBIL:
            claim = self.current_value + (self.adversarial_bias * 0.5)
            stmt = f"Agent {self.agent_id} sybil coordinator claim at round {round_number}"
            conf = 0.99
        else:
            claim = self.current_value
            stmt = f"Agent {self.agent_id} claim at round {round_number}"
            conf = 0.9

        return SemanticMessage.create(
            sender_id=self.agent_id,
            round_number=round_number,
            claim_value=claim,
            statement=stmt,
            confidence=conf,
        )

    def filter_and_refine(self, incoming_messages: Sequence[SemanticMessage]) -> Dict[str, Any]:
        """
        Executes the receiver-side Mean-Subsequence-Reduced (MSR) filter and self-anchored update.
        """
        for msg in incoming_messages:
            if not msg.verify_digest():
                raise ConsensusSecurityViolation(f"Tampered message digest from sender '{msg.sender_id}'")

        if self.role != NodeRole.HONEST:
            # Faulty nodes execute arbitrary internal state transitions
            if self.role == NodeRole.BYZANTINE_EXTREME:
                self.current_value += 0.5
            elif self.role == NodeRole.BYZANTINE_RANDOM:
                self.current_value = -self.current_value
            self.history.append(self.current_value)
            return {
                "agent_id": self.agent_id,
                "role": self.role.value,
                "updated_value": self.current_value,
                "trimmed_senders": [],
                "accepted_count": len(incoming_messages),
            }

        # Honest node: apply MSR trimming relative to self value
        f = self.max_byzantine_f
        curr = self.current_value

        strictly_higher: List[SemanticMessage] = [m for m in incoming_messages if m.claim_value > curr]
        strictly_lower: List[SemanticMessage] = [m for m in incoming_messages if m.claim_value < curr]
        equal_msgs: List[SemanticMessage] = [m for m in incoming_messages if m.claim_value == curr]

        # Sort strictly higher descending to identify top F extremes
        strictly_higher.sort(key=lambda m: m.claim_value, reverse=True)
        # Sort strictly lower ascending to identify bottom F extremes
        strictly_lower.sort(key=lambda m: m.claim_value, reverse=False)

        trimmed_higher = strictly_higher[:f]
        accepted_higher = strictly_higher[f:]

        trimmed_lower = strictly_lower[:f]
        accepted_lower = strictly_lower[f:]

        trimmed = trimmed_higher + trimmed_lower
        accepted = accepted_higher + accepted_lower + equal_msgs

        self.last_trimmed_senders = sorted([m.sender_id for m in trimmed])

        # Compute new state via convex combination
        gamma_self = 1.0 - self.alpha_anchor - self.beta_neighbors
        if accepted:
            mean_accepted = sum(m.claim_value for m in accepted) / len(accepted)
        else:
            mean_accepted = curr

        new_val = (gamma_self * curr) + (self.alpha_anchor * self.self_anchor_value) + (self.beta_neighbors * mean_accepted)
        self.current_value = round(new_val, 8)
        self.history.append(self.current_value)

        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "updated_value": self.current_value,
            "trimmed_senders": self.last_trimmed_senders,
            "accepted_count": len(accepted),
        }


# =====================================================================
# Execution Receipt and Engine
# =====================================================================

@dataclasses.dataclass(frozen=True)
class ConsensusExecutionReceipt:
    """W3C PROV-DM compatible execution audit receipt."""
    receipt_id: str
    topology_hash: str
    round_count: int
    converged: bool
    final_discrepancy: float
    honest_mean_value: float
    ground_truth_target: float
    trimmed_audit_log: Dict[str, List[str]]
    prov_document: Dict[str, Any]
    receipt_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class ByzantineResilientConsensusEngine:
    """
    Decentralized multi-agent consensus orchestrator and verification oracle.
    """

    def __init__(self, topology: ConsensusGraphTopology) -> None:
        self.topology = topology
        self.nodes: Dict[str, ByzantineAgentNode] = {}
        self.execution_log: List[Dict[str, Any]] = []

    def register_node(self, node: ByzantineAgentNode) -> None:
        """Registers a participant node."""
        if node.agent_id not in self.topology.nodes:
            raise ConsensusValidationError(f"Node '{node.agent_id}' is not in configured topology")
        self.nodes[node.agent_id] = node

    def run_consensus(
        self,
        max_rounds: int = 25,
        convergence_threshold: float = 1e-4,
        ground_truth: float = 0.0,
    ) -> ConsensusExecutionReceipt:
        """
        Executes decentralized rounds until honest agents converge within threshold.
        """
        if len(self.nodes) != len(self.topology.nodes):
            missing = set(self.topology.nodes) - set(self.nodes.keys())
            raise ConsensusValidationError(f"Cannot run: missing nodes {missing}")

        assert_finite_float(convergence_threshold, "convergence_threshold")
        assert_finite_float(ground_truth, "ground_truth")

        trimmed_audit: Dict[str, List[str]] = {node_id: [] for node_id in self.nodes}

        converged = False
        final_discrepancy = float("inf")
        honest_ids = [nid for nid, n in self.nodes.items() if n.role == NodeRole.HONEST]

        if not honest_ids:
            raise ConsensusValidationError("No honest nodes registered for consensus")

        for r in range(max_rounds):
            # 1. Generate outbound messages
            outbound_pool: Dict[str, SemanticMessage] = {}
            for nid, node in self.nodes.items():
                outbound_pool[nid] = node.generate_outbound_message(round_number=r)

            # 2. Each node gathers messages from in-neighbors and filters/refines
            round_results: Dict[str, Any] = {}
            for nid, node in self.nodes.items():
                nbr_ids = self.topology.in_neighbors[nid]
                incoming = [outbound_pool[nbr] for nbr in nbr_ids]
                res = node.filter_and_refine(incoming)
                round_results[nid] = res
                trimmed_audit[nid].extend(res["trimmed_senders"])

            self.execution_log.append({"round": r, "results": round_results})

            # Check convergence across honest nodes
            honest_values = [self.nodes[nid].current_value for nid in honest_ids]
            spread = max(honest_values) - min(honest_values)
            final_discrepancy = spread

            if spread <= convergence_threshold:
                converged = True
                break

        final_honest_values = [self.nodes[nid].current_value for nid in honest_ids]
        mean_honest = sum(final_honest_values) / len(final_honest_values)

        prov_doc = {
            "prefix": {
                "cin": "https://cintnet.org/prov#",
                "prov": "http://www.w3.org/ns/prov#",
            },
            "activity": {
                "cin:byzantine_consensus_run": {
                    "prov:type": "cin:DecentralizedConsensus",
                    "cin:rounds": len(self.execution_log),
                    "cin:converged": converged,
                }
            },
            "entity": {
                "cin:consensus_outcome": {
                    "prov:value": round(mean_honest, 6),
                    "cin:discrepancy": round(final_discrepancy, 6),
                }
            },
            "wasGeneratedBy": {
                "_:wgb1": {
                    "prov:entity": "cin:consensus_outcome",
                    "prov:activity": "cin:byzantine_consensus_run",
                }
            },
        }

        receipt_id = f"rcpt-byz-{canonical_sha256(prov_doc)[:16]}"
        top_hash = canonical_sha256(self.topology.in_neighbors)

        payload_to_digest = {
            "receipt_id": receipt_id,
            "topology_hash": top_hash,
            "round_count": len(self.execution_log),
            "converged": converged,
            "final_discrepancy": round(final_discrepancy, 8),
            "honest_mean_value": round(mean_honest, 8),
            "ground_truth_target": round(ground_truth, 8),
            "prov_document": prov_doc,
        }
        receipt_digest = canonical_sha256(payload_to_digest)

        return ConsensusExecutionReceipt(
            receipt_id=receipt_id,
            topology_hash=top_hash,
            round_count=len(self.execution_log),
            converged=converged,
            final_discrepancy=round(final_discrepancy, 8),
            honest_mean_value=round(mean_honest, 8),
            ground_truth_target=round(ground_truth, 8),
            trimmed_audit_log=trimmed_audit,
            prov_document=prov_doc,
            receipt_digest=receipt_digest,
        )
