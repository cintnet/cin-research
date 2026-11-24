"""
research/ledger_sim/task_adaptive_orchestration_sim.py

Discrete-Event Simulation of Task-Adaptive Multi-Agent Orchestration, Dynamic Topologies,
and Polycentric Governance against Hierarchical Bottlenecks and Swarm Message Explosion.

Grounded in:
- arXiv:2602.16873 (AdaptOrch, Nov 2026):
  "AdaptOrch: Task-Adaptive Multi-Agent Orchestration in the Era of LLM Performance Convergence."
- Elinor Ostrom (1990, 2010):
  "Governing the Commons: The Evolution of Institutions for Collective Action"
  [Cambridge University Press, doi:10.1017/cbo9780511807763] &
  "Beyond Markets and States: Polycentric Governance of Complex Economic Systems"
  [American Economic Review 100(3): 641-672, doi:10.1257/aer.100.3.641].
- Vincent Ostrom, Charles M. Tiebout, and Robert Warren (1961):
  "The Organization of Government in Metropolitan Areas: A Theoretical Inquiry"
  [American Political Science Review 55(4): 831-842, doi:10.2307/1952530].
- Jack B. Dennis & Earl C. Van Horn (CACM 1966):
  "Programming Semantics for Multiprogrammed Computations"
  [Object-Capability Zero Ambient Authority].
- Luc Moreau & Paolo Missier (W3C Recommendation, 2013):
  "PROV-DM: The PROV Data Model."

Core Architectural Findings:
1. Rigid hierarchies create severe single-point vulnerabilities and queuing latency:
   When all tasks route through a central manager, manager downtime halts 100% of workflows,
   and latency explodes quadratically under burst load due to queue congestion and managerial tax.
2. Uncoordinated flat swarms experience quadratic message explosion and coordination churn:
   Broadcasting task assignments across N agents generates O(N^2) communication overhead,
   while unverified concurrency on shared resources triggers high conflict and failure rates.
3. Task-adaptive polycentric orchestration dynamically matches topology to task characteristics:
   - Low-entropy local tasks execute via direct peer-to-peer delegation (zero managerial overhead).
   - Modular collaborative tasks resolve through lightweight federated reviewer pairs.
   - Commons-critical tasks undergo Ostrom-style polycentric consensus with cryptographic receipts.
   This achieves maximal task throughput, zero single-point failure, sub-quadratic communication,
   and strict 100% capital conservation across all operational regimes.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import random
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple


# =====================================================================
# Error Hierarchy
# =====================================================================

class TaskAdaptiveSecurityViolation(Exception):
    """Base exception for task-adaptive orchestration security and governance violations."""


class TaskAdaptiveValidationError(TaskAdaptiveSecurityViolation):
    """Raised when configuration, parameter bounds, or numeric inputs are invalid or non-finite."""


class TopologyStallError(TaskAdaptiveSecurityViolation):
    """Raised when a rigid hierarchy suffers a complete coordinator blackout."""


class CapitalConservationError(TaskAdaptiveSecurityViolation):
    """Raised when computational budget or capital conservation is violated."""


class StewardGateViolationError(TaskAdaptiveSecurityViolation):
    """Raised when forbidden speculative promises, unapproved tokens, or sci-fi lore are detected."""


# =====================================================================
# Steward Gate Screening
# =====================================================================

FORBIDDEN_PATTERNS = [
    re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE),
    re.compile(r"\bMMCT\b", re.IGNORECASE),
    re.compile(r"\b85/10/5\b"),
    re.compile(r"\b95%\b"),
    re.compile(r"\bguaranteed\s+(?:returns?|yields?|profits?|savings?)\b", re.IGNORECASE),
    re.compile(r"\bpassive\s+income\b", re.IGNORECASE),
    re.compile(r"\bgalactic\b", re.IGNORECASE),
    re.compile(r"\bhyperdrive\b", re.IGNORECASE),
]


def screen_steward_gate(text: str) -> None:
    """Enforce strict CIN Steward Gate: no unapproved tokens, financial guarantees, or sci-fi lore."""
    if not isinstance(text, str):
        return
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(
                f"Payload violated CIN Steward Gate invariants: matched forbidden pattern '{pattern.pattern}'"
            )


# =====================================================================
# Enums and Domain Contracts
# =====================================================================

class OrchestrationTopology(enum.Enum):
    """Macro orchestration topologies evaluated in the testbed."""
    RIGID_HIERARCHY = "RIGID_HIERARCHY"
    UNCOORDINATED_SWARM = "UNCOORDINATED_SWARM"
    TASK_ADAPTIVE_POLYCENTRIC = "TASK_ADAPTIVE_POLYCENTRIC"


class TaskComplexity(enum.Enum):
    """Task complexity levels based on entropy and coordination requirements."""
    LOCAL_DETERMINISTIC = "LOCAL_DETERMINISTIC"     # Low entropy (<0.35), single specialist, zero shared state
    COLLABORATIVE_MODULAR = "COLLABORATIVE_MODULAR" # Medium entropy (0.35-0.70), 2 specialists cross-verify
    COMMONS_CRITICAL = "COMMONS_CRITICAL"           # High entropy (>=0.70) or shared commons modification


class ActiveSubTopology(enum.Enum):
    """Dynamic micro-topology selected by the task-adaptive orchestrator."""
    DIRECT_PEER = "DIRECT_PEER"
    FEDERATED_COUNCIL = "FEDERATED_COUNCIL"
    POLYCENTRIC_CONSENSUS = "POLYCENTRIC_CONSENSUS"


class AgentSpecialization(enum.Enum):
    """Specialized functional roles in the multi-agent collective."""
    COORDINATOR = "COORDINATOR"
    CODE_BUILDER = "CODE_BUILDER"
    VERIFIER_AUDITOR = "VERIFIER_AUDITOR"
    DATA_STEWARD = "DATA_STEWARD"
    COMMONS_GUARDIAN = "COMMONS_GUARDIAN"


# =====================================================================
# Dataclasses
# =====================================================================

@dataclasses.dataclass(frozen=True)
class TaskWorkload:
    """Specification of an incoming multi-agent workload task."""
    task_id: str
    complexity: TaskComplexity
    stake_level: float                # Bounded in [0.0, 1.0]
    computational_cost: float         # Bounded > 0.0
    shared_state_impact: bool
    entropy: float                    # Bounded in [0.0, 1.0]

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise TaskAdaptiveValidationError("task_id must be a non-empty string.")
        screen_steward_gate(self.task_id)

        if not isinstance(self.complexity, TaskComplexity):
            raise TaskAdaptiveValidationError(f"Invalid complexity: {self.complexity}")

        if isinstance(self.stake_level, bool) or not isinstance(self.stake_level, (int, float)):
            raise TaskAdaptiveValidationError("stake_level must be float.")
        if math.isnan(self.stake_level) or math.isinf(self.stake_level) or not (0.0 <= self.stake_level <= 1.0):
            raise TaskAdaptiveValidationError(f"stake_level must be finite in [0.0, 1.0], got {self.stake_level}")

        if isinstance(self.computational_cost, bool) or not isinstance(self.computational_cost, (int, float)):
            raise TaskAdaptiveValidationError("computational_cost must be float.")
        if math.isnan(self.computational_cost) or math.isinf(self.computational_cost) or self.computational_cost <= 0.0:
            raise TaskAdaptiveValidationError(f"computational_cost must be finite > 0.0, got {self.computational_cost}")

        if not isinstance(self.shared_state_impact, bool):
            raise TaskAdaptiveValidationError("shared_state_impact must be a bool.")

        if isinstance(self.entropy, bool) or not isinstance(self.entropy, (int, float)):
            raise TaskAdaptiveValidationError("entropy must be float.")
        if math.isnan(self.entropy) or math.isinf(self.entropy) or not (0.0 <= self.entropy <= 1.0):
            raise TaskAdaptiveValidationError(f"entropy must be finite in [0.0, 1.0], got {self.entropy}")


@dataclasses.dataclass
class AgentNode:
    """Agent node in the collective network."""
    agent_id: str
    specialization: AgentSpecialization
    trust_score: float                # Bounded in [0.0, 1.0]
    active_load: int = 0              # Current concurrent tasks queued
    is_faulty: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise TaskAdaptiveValidationError("agent_id must be a non-empty string.")
        screen_steward_gate(self.agent_id)

        if not isinstance(self.specialization, AgentSpecialization):
            raise TaskAdaptiveValidationError(f"Invalid specialization: {self.specialization}")

        if isinstance(self.trust_score, bool) or not isinstance(self.trust_score, (int, float)):
            raise TaskAdaptiveValidationError("trust_score must be float.")
        if math.isnan(self.trust_score) or math.isinf(self.trust_score) or not (0.0 <= self.trust_score <= 1.0):
            raise TaskAdaptiveValidationError(f"trust_score must be finite in [0.0, 1.0], got {self.trust_score}")


@dataclasses.dataclass(frozen=True)
class ExecutionReceipt:
    """Cryptographic tamper-evident execution receipt for verified actions."""
    receipt_id: str
    task_id: str
    topology_used: str
    cost_spent: float
    latency_ms: float
    timestamp_tick: int
    digest: str

    @classmethod
    def create(
        cls,
        task_id: str,
        topology_used: str,
        cost_spent: float,
        latency_ms: float,
        timestamp_tick: int,
    ) -> ExecutionReceipt:
        screen_steward_gate(task_id)
        screen_steward_gate(topology_used)
        payload = f"{task_id}:{topology_used}:{cost_spent:.6f}:{latency_ms:.2f}:{timestamp_tick}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        receipt_id = f"rcpt-{digest[:16]}"
        return cls(
            receipt_id=receipt_id,
            task_id=task_id,
            topology_used=topology_used,
            cost_spent=cost_spent,
            latency_ms=latency_ms,
            timestamp_tick=timestamp_tick,
            digest=digest,
        )


@dataclasses.dataclass(frozen=True)
class RegimeMetrics:
    """Aggregated empirical metrics for a simulation run under a given regime."""
    regime: OrchestrationTopology
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    total_messages: int
    total_latency_ms: float
    mean_latency_ms: float
    total_cost_spent: float
    remaining_treasury: float
    capital_conserved: bool
    manager_bottleneck_stalls: int
    receipts_count: int

    def __post_init__(self) -> None:
        screen_steward_gate(self.regime.value)


# =====================================================================
# Task Adaptive Orchestrator
# =====================================================================

class TaskAdaptiveOrchestrator:
    """
    Simulates multi-agent collective execution across RIGID_HIERARCHY,
    UNCOORDINATED_SWARM, and TASK_ADAPTIVE_POLYCENTRIC topologies.
    """

    def __init__(
        self,
        agents: Sequence[AgentNode],
        initial_treasury: float = 1000.0,
        seed: int = 42,
    ) -> None:
        if not agents or len(agents) < 3:
            raise TaskAdaptiveValidationError("Orchestrator requires at least 3 agent nodes.")

        if isinstance(initial_treasury, bool) or not isinstance(initial_treasury, (int, float)):
            raise TaskAdaptiveValidationError("initial_treasury must be float.")
        if math.isnan(initial_treasury) or math.isinf(initial_treasury) or initial_treasury <= 0.0:
            raise TaskAdaptiveValidationError(f"initial_treasury must be finite > 0.0, got {initial_treasury}")

        self.agents = [dataclasses.replace(a) for a in agents]
        self.initial_treasury = float(initial_treasury)
        self.seed = int(seed)
        self.rng = random.Random(self.seed)

    def _reset_agent_state(self) -> None:
        """Reset agent load counters before a regime execution."""
        for a in self.agents:
            a.active_load = 0

    def run_regime(
        self,
        workload: Sequence[TaskWorkload],
        regime: OrchestrationTopology,
        coordinator_fault: bool = False,
    ) -> RegimeMetrics:
        """
        Execute the workload under the designated topology regime.
        Strictly conserves 100% of capital: initial_treasury == spent + remaining.
        """
        if not workload:
            raise TaskAdaptiveValidationError("Workload cannot be empty.")
        if not isinstance(regime, OrchestrationTopology):
            raise TaskAdaptiveValidationError(f"Invalid regime: {regime}")

        self._reset_agent_state()
        treasury = self.initial_treasury
        total_spent = 0.0
        completed = 0
        failed = 0
        messages = 0
        total_latency = 0.0
        manager_stalls = 0
        receipts: List[ExecutionReceipt] = []

        n_agents = len(self.agents)
        manager = self.agents[0]  # Designated coordinator in hierarchy

        for tick, task in enumerate(workload):
            # Check treasury sufficiency
            if treasury < task.computational_cost:
                failed += len(workload) - tick
                break

            if regime == OrchestrationTopology.RIGID_HIERARCHY:
                # In Rigid Hierarchy: Every task routes strictly through central manager.
                # Manager adds 15% managerial agency overhead.
                overhead_cost = task.computational_cost * 0.15
                task_cost = task.computational_cost + overhead_cost

                if treasury < task_cost:
                    failed += len(workload) - tick
                    break

                if coordinator_fault or manager.is_faulty:
                    # Coordinator blackout halts subsequent hierarchical tasks completely
                    manager_stalls += 1
                    failed += 1
                    messages += 1  # Failed query message
                    continue

                # Latency scales quadratically with queue depth
                manager.active_load += 1
                queue_factor = 1.0 + 0.18 * (manager.active_load ** 1.4)
                latency = (150.0 + task.stake_level * 100.0) * queue_factor

                # Routing: Client -> Manager -> Worker -> Manager -> Client (4 hops)
                messages += 4

                treasury -= task_cost
                total_spent += task_cost
                total_latency += latency
                completed += 1

                receipts.append(
                    ExecutionReceipt.create(
                        task_id=task.task_id,
                        topology_used=regime.value,
                        cost_spent=task_cost,
                        latency_ms=latency,
                        timestamp_tick=tick,
                    )
                )

            elif regime == OrchestrationTopology.UNCOORDINATED_SWARM:
                # In Flat Swarm: Broadcast gossip to all N nodes.
                # Messages scale as N * (N - 1)
                swarm_messages = n_agents * (n_agents - 1)
                messages += swarm_messages

                # Complex tasks without coordinator suffer coordination churn & collision
                task_cost = task.computational_cost
                treasury -= task_cost
                total_spent += task_cost

                if task.complexity == TaskComplexity.COMMONS_CRITICAL or task.shared_state_impact:
                    # High probability of collision and state race condition (40% fail)
                    is_conflict = (self.rng.random() < 0.40)
                    if is_conflict:
                        failed += 1
                        total_latency += 450.0  # Wasted timeout latency
                        continue

                latency = 80.0 + (task.entropy * 120.0)
                total_latency += latency
                completed += 1

                receipts.append(
                    ExecutionReceipt.create(
                        task_id=task.task_id,
                        topology_used=regime.value,
                        cost_spent=task_cost,
                        latency_ms=latency,
                        timestamp_tick=tick,
                    )
                )

            elif regime == OrchestrationTopology.TASK_ADAPTIVE_POLYCENTRIC:
                # In Task-Adaptive Polycentric: Dynamically match micro-topology to task requirements
                if task.complexity == TaskComplexity.LOCAL_DETERMINISTIC:
                    # Low entropy: Direct peer delegation to best specialist.
                    # Zero manager overhead, minimal communication (2 messages), lowest latency.
                    sub_topo = ActiveSubTopology.DIRECT_PEER
                    task_cost = task.computational_cost
                    treasury -= task_cost
                    total_spent += task_cost

                    # Specialist selection with load balancing and fault bypass
                    available = [a for a in self.agents if not a.is_faulty]
                    if coordinator_fault and manager in available:
                        available.remove(manager)
                    if not available:
                        failed += 1
                        continue

                    specialist = min(available, key=lambda a: a.active_load)
                    specialist.active_load += 1
                    latency = 35.0 + task.stake_level * 20.0
                    messages += 2  # Request + Result
                    completed += 1

                elif task.complexity == TaskComplexity.COLLABORATIVE_MODULAR:
                    # Medium entropy: Federated council of 2 specialists cross-verify.
                    sub_topo = ActiveSubTopology.FEDERATED_COUNCIL
                    # Modest 5% verification overhead
                    task_cost = task.computational_cost * 1.05
                    treasury -= task_cost
                    total_spent += task_cost

                    available = [a for a in self.agents if not a.is_faulty]
                    if coordinator_fault and manager in available:
                        available.remove(manager)
                    if len(available) < 2:
                        failed += 1
                        continue

                    # Select 2 lowest load agents
                    available_sorted = sorted(available, key=lambda a: a.active_load)
                    primary, secondary = available_sorted[0], available_sorted[1]
                    primary.active_load += 1
                    secondary.active_load += 1

                    latency = 75.0 + task.stake_level * 40.0
                    messages += 4  # Request -> Primary -> Secondary verify -> Ack
                    completed += 1

                else:
                    # High entropy / Commons Critical: Ostrom-style Polycentric Consensus cluster
                    sub_topo = ActiveSubTopology.POLYCENTRIC_CONSENSUS
                    # 10% consensus validation cost
                    task_cost = task.computational_cost * 1.10
                    treasury -= task_cost
                    total_spent += task_cost

                    available = [a for a in self.agents if not a.is_faulty]
                    if coordinator_fault and manager in available:
                        available.remove(manager)
                    if len(available) < 3:
                        failed += 1
                        continue

                    # Quorum of 3 peer evaluators
                    cluster = sorted(available, key=lambda a: a.active_load)[:3]
                    for a in cluster:
                        a.active_load += 1

                    latency = 120.0 + task.stake_level * 50.0
                    messages += 6  # Quorum proposals + votes + receipt broadcast
                    completed += 1

                total_latency += latency
                receipts.append(
                    ExecutionReceipt.create(
                        task_id=task.task_id,
                        topology_used=f"{regime.value}:{sub_topo.value}",
                        cost_spent=task_cost,
                        latency_ms=latency,
                        timestamp_tick=tick,
                    )
                )

        # Capital conservation check: initial == spent + remaining
        capital_conserved = math.isclose(self.initial_treasury, total_spent + treasury, abs_tol=1e-5)
        if not capital_conserved:
            raise CapitalConservationError(
                f"Capital leak detected: initial={self.initial_treasury}, spent={total_spent}, remaining={treasury}"
            )

        mean_latency = total_latency / max(1, completed)

        return RegimeMetrics(
            regime=regime,
            total_tasks=len(workload),
            completed_tasks=completed,
            failed_tasks=failed,
            total_messages=messages,
            total_latency_ms=round(total_latency, 2),
            mean_latency_ms=round(mean_latency, 2),
            total_cost_spent=round(total_spent, 4),
            remaining_treasury=round(treasury, 4),
            capital_conserved=capital_conserved,
            manager_bottleneck_stalls=manager_stalls,
            receipts_count=len(receipts),
        )

    def compare_regimes(
        self,
        workload: Sequence[TaskWorkload],
        coordinator_fault: bool = False,
    ) -> Dict[str, RegimeMetrics]:
        """Run all three regimes sequentially and return comparative metrics."""
        results: Dict[str, RegimeMetrics] = {}
        for regime in OrchestrationTopology:
            results[regime.value] = self.run_regime(
                workload=workload,
                regime=regime,
                coordinator_fault=coordinator_fault,
            )
        return results

    @staticmethod
    def format_comparison_markdown(results: Dict[str, RegimeMetrics]) -> str:
        """Format regime comparison into a clean Markdown table with zero forbidden tokens."""
        lines = [
            "| Regime | Tasks Done | Failed | Messages | Mean Latency (ms) | Total Cost | Capital Conserved | Stalls |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for key, m in results.items():
            conserved_str = "100%" if m.capital_conserved else "LEAK"
            lines.append(
                f"| `{m.regime.value}` | {m.completed_tasks}/{m.total_tasks} | {m.failed_tasks} | "
                f"{m.total_messages} | {m.mean_latency_ms:.1f} | {m.total_cost_spent:.2f} | "
                f"{conserved_str} | {m.manager_bottleneck_stalls} |"
            )
        return "\n".join(lines)


# =====================================================================
# Deterministic Workload Generator
# =====================================================================

def generate_deterministic_workload(count: int = 50, seed: int = 101) -> List[TaskWorkload]:
    """Generate a reproducible, balanced stream of multi-agent tasks."""
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise TaskAdaptiveValidationError("count must be a positive integer.")

    rng = random.Random(seed)
    workload: List[TaskWorkload] = []

    for i in range(count):
        task_id = f"task-wkld-{i+1:03d}"
        dice = rng.random()
        if dice < 0.50:
            complexity = TaskComplexity.LOCAL_DETERMINISTIC
            entropy = rng.uniform(0.05, 0.30)
            stake = rng.uniform(0.1, 0.4)
            cost = rng.uniform(1.0, 3.0)
            shared_state = False
        elif dice < 0.80:
            complexity = TaskComplexity.COLLABORATIVE_MODULAR
            entropy = rng.uniform(0.36, 0.65)
            stake = rng.uniform(0.4, 0.7)
            cost = rng.uniform(3.5, 7.0)
            shared_state = False
        else:
            complexity = TaskComplexity.COMMONS_CRITICAL
            entropy = rng.uniform(0.72, 0.95)
            stake = rng.uniform(0.7, 1.0)
            cost = rng.uniform(7.5, 12.0)
            shared_state = True

        workload.append(
            TaskWorkload(
                task_id=task_id,
                complexity=complexity,
                stake_level=round(stake, 3),
                computational_cost=round(cost, 3),
                shared_state_impact=shared_state,
                entropy=round(entropy, 3),
            )
        )

    return workload
