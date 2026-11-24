"""
research/ledger_sim/selective_online_containment_sim.py

Selective Online Containment & Blast-Radius Bounding Simulation for Multi-Agent Workflows.

Grounded in:
- EdgeCitadel / arXiv:2611.06727 (November 2026):
  "Airlock: Bounding the Multi-Agent Blast Radius via Selective Online Containment".
- Jack B. Dennis & Earl C. Van Horn (CACM 1966):
  "Programming Semantics for Multiprogrammed Computations" [Object-Capability Zero Ambient Authority].
- Luc Moreau & Paolo Missier (W3C Recommendation 2013):
  "PROV-DM: The PROV Data Model" [Append-Only Provenance Graphs & wasDerivedFrom Lineage].
- Judea Pearl (2000, 2009):
  "Causality: Models, Reasoning, and Inference" [Directed Acyclic Graphs & Forward Causal Reachability].
- Mark S. Miller, Chip Morningstar, Bill Frantz (2003):
  "Capability Myths Demolished" [Caretaker Revocation & Dynamic Attenuation].

Core Principle:
In multi-agent task execution graphs, an uncontained faulty or compromised agent output
poisons downstream dependent subagents, triggering cascading failure. Blanket rollbacks
halt the entire system, throwing away healthy independent work. Selective online containment
(Airlock) uses an append-only provenance DAG to trace forward reachability from the fault alert,
revoking capability leases strictly along the tainted subgraph while allowing independent parallel
branches to complete safely without interruption or data leakage.
"""

from __future__ import annotations

import collections
import dataclasses
import enum
import hashlib
import json
import math
import random
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


# =====================================================================
# Error Hierarchy
# =====================================================================

class ContainmentSecurityViolation(Exception):
    """Base exception for security boundary failures in multi-agent containment."""


class ContainmentValidationError(ContainmentSecurityViolation):
    """Raised when configuration, parameter bounds, or numeric inputs are invalid or out of support."""


class LeaseRevocationError(ContainmentSecurityViolation):
    """Raised when an agent attempts execution after capability lease revocation."""


class TaintLeakageError(ContainmentSecurityViolation):
    """Raised when an uncontained tainted artifact commits to the external settlement ledger."""


class StewardGateViolationError(ContainmentSecurityViolation):
    """Raised when forbidden speculative promises, unapproved tokens, or sci-fi lore are detected."""


# =====================================================================
# Steward Gate Screening
# =====================================================================

FORBIDDEN_PATTERNS = [
    re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE),
    re.compile(r"\bMMCT\b", re.IGNORECASE),
    re.compile(r"\b85/10/5\b"),
    re.compile(r"\bguaranteed\s+(?:returns?|yields?|profits?|savings?)\b", re.IGNORECASE),
    re.compile(r"\bpassive\s+income\b", re.IGNORECASE),
    re.compile(r"\bgalactic\b", re.IGNORECASE),
    re.compile(r"\bhyperdrive\b", re.IGNORECASE),
    re.compile(r"\bwarp\s+drive\b", re.IGNORECASE),
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
# Enums and Types
# =====================================================================

class ContainmentRegime(str, enum.Enum):
    """Regime governing fault handling and containment in multi-agent workflows."""
    UNCONTAINED_CASCADE = "UNCONTAINED_CASCADE"
    FULL_PIPELINE_ABORT = "FULL_PIPELINE_ABORT"
    STATIC_NODE_QUARANTINE = "STATIC_NODE_QUARANTINE"
    AIRLOCK_SELECTIVE_CONTAINMENT = "AIRLOCK_SELECTIVE_CONTAINMENT"


UNCONTAINED_CASCADE = ContainmentRegime.UNCONTAINED_CASCADE
FULL_PIPELINE_ABORT = ContainmentRegime.FULL_PIPELINE_ABORT
STATIC_NODE_QUARANTINE = ContainmentRegime.STATIC_NODE_QUARANTINE
AIRLOCK_SELECTIVE_CONTAINMENT = ContainmentRegime.AIRLOCK_SELECTIVE_CONTAINMENT


class TaskStatus(str, enum.Enum):
    """Lifecycle status of a task within a workflow run."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED_HEALTHY = "COMPLETED_HEALTHY"
    COMPLETED_TAINTED = "COMPLETED_TAINTED"
    REVOKED_CONTAINED = "REVOKED_CONTAINED"
    ABORTED_COLLATERAL = "ABORTED_COLLATERAL"


class TaskKind(str, enum.Enum):
    """Operational kind of subagent task."""
    DATA_INGESTION = "DATA_INGESTION"
    REASONING_ANALYSIS = "REASONING_ANALYSIS"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    SYNTHESIS_REDUCE = "SYNTHESIS_REDUCE"
    SETTLEMENT_COMMIT = "SETTLEMENT_COMMIT"


# =====================================================================
# Data Structures
# =====================================================================

@dataclasses.dataclass
class CapabilityLease:
    """Time-bounded, revocable capability lease governing task execution."""
    lease_id: str
    task_id: str
    actor_id: str
    expires_at_step: int
    revoked: bool = False
    signature: str = ""

    def __post_init__(self) -> None:
        if type(self.expires_at_step) is not int or isinstance(self.expires_at_step, bool) or self.expires_at_step <= 0:
            raise ContainmentValidationError(f"expires_at_step must be positive int, got {self.expires_at_step}")
        if not self.signature:
            raw = f"{self.lease_id}:{self.task_id}:{self.actor_id}:{self.expires_at_step}"
            self.signature = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def revoke(self) -> None:
        """Revoke capability lease dynamically (Caretaker pattern)."""
        self.revoked = True

    def verify_active(self, current_step: int) -> None:
        """Verify lease is neither expired nor revoked."""
        if self.revoked:
            raise LeaseRevocationError(f"Capability lease {self.lease_id} has been revoked.")
        if current_step >= self.expires_at_step:
            raise LeaseRevocationError(f"Capability lease {self.lease_id} expired at step {self.expires_at_step}.")


@dataclasses.dataclass(frozen=True)
class DAGTask:
    """Immutable definition of a task node within a multi-agent execution DAG."""
    task_id: str
    kind: TaskKind
    parent_ids: Tuple[str, ...]
    cost_cents: int
    is_fault_injection_point: bool
    output_payload: str

    def __post_init__(self) -> None:
        screen_steward_gate(self.output_payload)
        if type(self.cost_cents) is not int or isinstance(self.cost_cents, bool) or self.cost_cents <= 0:
            raise ContainmentValidationError(f"cost_cents must be positive int, got {self.cost_cents}")


@dataclasses.dataclass(frozen=True)
class WorkflowDAG:
    """Complete multi-agent workflow DAG with decoupled workload parameters."""
    workflow_id: str
    tasks: Dict[str, DAGTask]
    root_ids: Tuple[str, ...]
    total_budget_cents: int

    def __post_init__(self) -> None:
        if not self.tasks:
            raise ContainmentValidationError("WorkflowDAG must contain at least one task.")
        if type(self.total_budget_cents) is not int or isinstance(self.total_budget_cents, bool) or self.total_budget_cents <= 0:
            raise ContainmentValidationError(f"total_budget_cents must be positive int, got {self.total_budget_cents}")
        sum_costs = sum(t.cost_cents for t in self.tasks.values())
        if self.total_budget_cents < sum_costs:
            raise ContainmentValidationError(
                f"total_budget_cents ({self.total_budget_cents}) must be >= sum of task costs ({sum_costs})"
            )

    def forward_reachability(self, start_task_id: str) -> Set[str]:
        """Compute all downstream reachable tasks from start_task_id along the DAG."""
        if start_task_id not in self.tasks:
            return set()
        
        children_map: Dict[str, List[str]] = collections.defaultdict(list)
        for tid, task in self.tasks.items():
            for pid in task.parent_ids:
                children_map[pid].append(tid)

        reachable: Set[str] = set()
        queue: collections.deque[str] = collections.deque([start_task_id])
        while queue:
            curr = queue.popleft()
            if curr not in reachable:
                reachable.add(curr)
                for child in children_map.get(curr, []):
                    if child not in reachable:
                        queue.append(child)
        return reachable


@dataclasses.dataclass(frozen=True)
class ContainmentReceipt:
    """Cryptographic W3C PROV-DM receipt recording a containment intervention."""
    receipt_id: str
    step: int
    workflow_id: str
    regime: str
    alert_task_id: str
    contained_task_ids: Tuple[str, ...]
    salvaged_tasks_count: int
    prov_entity: Dict[str, Any]
    tamper_evident_digest: str

    @classmethod
    def create(
        cls,
        step: int,
        workflow_id: str,
        regime: str,
        alert_task_id: str,
        contained_task_ids: Sequence[str],
        salvaged_tasks_count: int,
    ) -> ContainmentReceipt:
        screen_steward_gate(f"{workflow_id} {regime} {alert_task_id}")
        contained_tuple = tuple(sorted(contained_task_ids))
        prov_entity = {
            "@context": "https://www.w3.org/ns/prov.jsonld",
            "type": "prov:Entity",
            "prov:id": f"cin:containment:{workflow_id}:{step}",
            "prov:wasAttributedTo": f"cin:agent:airlock_guard",
            "cin:workflow": workflow_id,
            "cin:regime": regime,
            "cin:alertNode": alert_task_id,
            "cin:containedNodes": list(contained_tuple),
            "cin:salvagedTasksCount": salvaged_tasks_count,
        }
        raw = json.dumps(prov_entity, sort_keys=True)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        receipt_id = f"rcpt-airlock-{digest[:16]}"
        return cls(
            receipt_id=receipt_id,
            step=step,
            workflow_id=workflow_id,
            regime=regime,
            alert_task_id=alert_task_id,
            contained_task_ids=contained_tuple,
            salvaged_tasks_count=salvaged_tasks_count,
            prov_entity=prov_entity,
            tamper_evident_digest=digest,
        )


@dataclasses.dataclass(frozen=True)
class RegimeExecutionResult:
    """Comprehensive, deterministic execution result for a single workflow under a regime."""
    regime: ContainmentRegime
    workflow_id: str
    total_tasks: int
    tasks_healthy_completed: int
    tasks_tainted_completed: int
    tasks_contained: int
    tasks_collateral_aborted: int
    taint_containment_rate: float
    healthy_work_preservation_rate: float
    spent_healthy_cents: int
    spent_tainted_cents: int
    salvaged_reserve_cents: int
    total_budget_cents: int
    containment_receipt: Optional[ContainmentReceipt]
    tamper_evident_digest: str

    def __post_init__(self) -> None:
        # Capital conservation invariant
        total_settled = self.spent_healthy_cents + self.spent_tainted_cents + self.salvaged_reserve_cents
        if total_settled != self.total_budget_cents:
            raise ContainmentValidationError(
                f"Capital conservation violated: settled {total_settled} != total budget {self.total_budget_cents}"
            )
        # Type and finiteness checks
        for val in (self.spent_healthy_cents, self.spent_tainted_cents, self.salvaged_reserve_cents, self.total_budget_cents):
            if type(val) is not int or isinstance(val, bool):
                raise ContainmentValidationError("Cents metrics must be int and not bool.")
        for rate in (self.taint_containment_rate, self.healthy_work_preservation_rate):
            if isinstance(rate, bool) or math.isnan(rate) or not (0.0 <= rate <= 1.0):
                raise ContainmentValidationError(f"Rates must be floats in [0.0, 1.0], got {rate}")


# =====================================================================
# Workload Generator (Decoupled RNG)
# =====================================================================

def generate_workload_dag(
    rng: random.Random,
    workflow_id: str,
    num_tasks: int = 12,
    branch_factor: int = 2,
    fault_node_index: int = 2,
) -> WorkflowDAG:
    """
    Deterministically construct a multi-agent execution DAG.
    Decoupled from runtime regime logic so all regimes experience bit-identical tasks.
    """
    if type(num_tasks) is not int or isinstance(num_tasks, bool) or num_tasks < 4:
        raise ContainmentValidationError("num_tasks must be int >= 4")
    if type(branch_factor) is not int or isinstance(branch_factor, bool) or branch_factor < 1:
        raise ContainmentValidationError("branch_factor must be int >= 1")
    if type(fault_node_index) is not int or isinstance(fault_node_index, bool) or not (0 <= fault_node_index < num_tasks):
        raise ContainmentValidationError("fault_node_index out of bounds")

    kinds = list(TaskKind)
    tasks: Dict[str, DAGTask] = {}
    task_keys: List[str] = [f"task_{i:02d}" for i in range(num_tasks)]

    root_ids = (task_keys[0], task_keys[1])
    
    # Root tasks
    tasks[task_keys[0]] = DAGTask(
        task_id=task_keys[0],
        kind=TaskKind.DATA_INGESTION,
        parent_ids=(),
        cost_cents=100 + rng.randint(0, 50),
        is_fault_injection_point=(fault_node_index == 0),
        output_payload="Clean raw ingest data from stream 0",
    )
    tasks[task_keys[1]] = DAGTask(
        task_id=task_keys[1],
        kind=TaskKind.DATA_INGESTION,
        parent_ids=(),
        cost_cents=100 + rng.randint(0, 50),
        is_fault_injection_point=(fault_node_index == 1),
        output_payload="Clean raw ingest data from stream 1",
    )

    # Intermediate tasks form two parallel branch clusters
    for i in range(2, num_tasks - 1):
        # Even indices branch from previous even; odd indices from previous odd
        parent = task_keys[i - 2]
        kind = kinds[i % (len(kinds) - 1)]
        is_fault = (i == fault_node_index)
        payload = f"Tainted corrupted state from task {i}" if is_fault else f"Valid verified payload from task {i}"
        
        tasks[task_keys[i]] = DAGTask(
            task_id=task_keys[i],
            kind=kind,
            parent_ids=(parent,),
            cost_cents=150 + rng.randint(0, 100),
            is_fault_injection_point=is_fault,
            output_payload=payload,
        )

    # Final settlement commit task depends on previous tasks
    last_idx = num_tasks - 1
    tasks[task_keys[last_idx]] = DAGTask(
        task_id=task_keys[last_idx],
        kind=TaskKind.SETTLEMENT_COMMIT,
        parent_ids=(task_keys[last_idx - 1], task_keys[last_idx - 2]),
        cost_cents=250 + rng.randint(0, 50),
        is_fault_injection_point=(fault_node_index == last_idx),
        output_payload="Final aggregate execution settlement commit",
    )

    sum_costs = sum(t.cost_cents for t in tasks.values())
    total_budget_cents = sum_costs + 500  # reserve buffer

    return WorkflowDAG(
        workflow_id=workflow_id,
        tasks=tasks,
        root_ids=root_ids,
        total_budget_cents=total_budget_cents,
    )


# =====================================================================
# Execution Engine Under Regimes
# =====================================================================

def run_workflow_under_regime(dag: WorkflowDAG, regime: ContainmentRegime) -> RegimeExecutionResult:
    """
    Execute a WorkflowDAG under a specific containment regime.
    Enforces W3C PROV-DM tracing, dynamic lease revocation, and strict capital conservation.
    """
    statuses: Dict[str, TaskStatus] = {tid: TaskStatus.PENDING for tid in dag.tasks}
    leases: Dict[str, CapabilityLease] = {
        tid: CapabilityLease(
            lease_id=f"lease-{dag.workflow_id}-{tid}",
            task_id=tid,
            actor_id=f"agent-{dag.tasks[tid].kind.value.lower()}",
            expires_at_step=100,
        )
        for tid in dag.tasks
    }

    in_degree: Dict[str, int] = {tid: len(task.parent_ids) for tid, task in dag.tasks.items()}
    ready_queue: collections.deque[str] = collections.deque(
        [tid for tid, deg in in_degree.items() if deg == 0]
    )

    fault_tid: Optional[str] = None
    for tid, task in dag.tasks.items():
        if task.is_fault_injection_point:
            fault_tid = tid
            break

    tainted_subgraph: Set[str] = dag.forward_reachability(fault_tid) if fault_tid else set()
    # Downstream tainted tasks excluding the injection source
    downstream_tainted: Set[str] = tainted_subgraph - {fault_tid} if fault_tid else set()

    step = 0
    containment_rcpt: Optional[ContainmentReceipt] = None

    spent_healthy_cents = 0
    spent_tainted_cents = 0

    while ready_queue:
        step += 1
        curr_tid = ready_queue.popleft()
        task = dag.tasks[curr_tid]
        lease = leases[curr_tid]

        # If already revoked or collateral aborted, skip execution
        if lease.revoked or statuses[curr_tid] in (TaskStatus.REVOKED_CONTAINED, TaskStatus.ABORTED_COLLATERAL):
            continue

        is_taint_source = (curr_tid == fault_tid)
        is_tainted_by_ancestry = (curr_tid in tainted_subgraph)

        # Execute task
        if is_tainted_by_ancestry:
            statuses[curr_tid] = TaskStatus.COMPLETED_TAINTED
            spent_tainted_cents += task.cost_cents
        else:
            statuses[curr_tid] = TaskStatus.COMPLETED_HEALTHY
            spent_healthy_cents += task.cost_cents

        # If the fault injection task just executed, anomaly detection triggers
        if is_taint_source and not containment_rcpt:
            if regime == ContainmentRegime.AIRLOCK_SELECTIVE_CONTAINMENT:
                # Forward provenance tracing identifies exact downstream tainted tasks
                contained_nodes = [t for t in downstream_tainted if statuses[t] == TaskStatus.PENDING]
                for tid_to_revoke in contained_nodes:
                    leases[tid_to_revoke].revoke()
                    statuses[tid_to_revoke] = TaskStatus.REVOKED_CONTAINED

                salvaged_count = sum(
                    1 for tid, st in statuses.items()
                    if st == TaskStatus.PENDING and tid not in tainted_subgraph
                )

                containment_rcpt = ContainmentReceipt.create(
                    step=step,
                    workflow_id=dag.workflow_id,
                    regime=regime.value,
                    alert_task_id=curr_tid,
                    contained_task_ids=contained_nodes,
                    salvaged_tasks_count=salvaged_count,
                )

            elif regime == ContainmentRegime.FULL_PIPELINE_ABORT:
                # Blanket kill: abort all pending tasks across the entire graph
                aborted_nodes = [tid for tid, st in statuses.items() if st == TaskStatus.PENDING]
                for tid_to_abort in aborted_nodes:
                    leases[tid_to_abort].revoke()
                    statuses[tid_to_abort] = TaskStatus.ABORTED_COLLATERAL

                containment_rcpt = ContainmentReceipt.create(
                    step=step,
                    workflow_id=dag.workflow_id,
                    regime=regime.value,
                    alert_task_id=curr_tid,
                    contained_task_ids=aborted_nodes,
                    salvaged_tasks_count=0,
                )

            elif regime == ContainmentRegime.STATIC_NODE_QUARANTINE:
                # Static quarantine only quarantines the alerting node's subsequent retries
                # It fails to trace forward reachability, leaving downstream dependencies unrevoked!
                leases[curr_tid].revoke()
                containment_rcpt = ContainmentReceipt.create(
                    step=step,
                    workflow_id=dag.workflow_id,
                    regime=regime.value,
                    alert_task_id=curr_tid,
                    contained_task_ids=[curr_tid],
                    salvaged_tasks_count=0,
                )

            elif regime == ContainmentRegime.UNCONTAINED_CASCADE:
                # Zero containment
                pass

        # Resolve downstream children
        for child_tid, child_task in dag.tasks.items():
            if curr_tid in child_task.parent_ids:
                in_degree[child_tid] -= 1
                if in_degree[child_tid] == 0:
                    if statuses[child_tid] == TaskStatus.PENDING and not leases[child_tid].revoked:
                        ready_queue.append(child_tid)

    total_tasks = len(dag.tasks)
    healthy_done = sum(1 for st in statuses.values() if st == TaskStatus.COMPLETED_HEALTHY)
    tainted_done = sum(1 for st in statuses.values() if st == TaskStatus.COMPLETED_TAINTED)
    contained = sum(1 for st in statuses.values() if st == TaskStatus.REVOKED_CONTAINED)
    collateral = sum(1 for st in statuses.values() if st == TaskStatus.ABORTED_COLLATERAL)

    # Downstream taint containment rate: fraction of downstream tainted tasks prevented from executing
    total_downstream_tainted = len(downstream_tainted)
    if total_downstream_tainted == 0:
        taint_containment_rate = 1.0
    else:
        # Tainted tasks completed downstream = tainted_done - 1 (the initial source)
        downstream_tainted_completed = max(0, tainted_done - 1)
        taint_containment_rate = 1.0 - (float(downstream_tainted_completed) / float(total_downstream_tainted))
        taint_containment_rate = max(0.0, min(1.0, taint_containment_rate))

    # Healthy work preservation rate: fraction of potential healthy tasks completed
    total_potential_healthy = total_tasks - len(tainted_subgraph)
    if total_potential_healthy <= 0:
        healthy_work_preservation_rate = 1.0
    else:
        healthy_work_preservation_rate = float(healthy_done) / float(total_potential_healthy)
        healthy_work_preservation_rate = max(0.0, min(1.0, healthy_work_preservation_rate))

    salvaged_reserve_cents = dag.total_budget_cents - (spent_healthy_cents + spent_tainted_cents)

    raw_summary = (
        f"{regime.value}:{dag.workflow_id}:{healthy_done}:{tainted_done}:"
        f"{contained}:{collateral}:{spent_healthy_cents}:{spent_tainted_cents}:{salvaged_reserve_cents}"
    )
    digest = hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()

    return RegimeExecutionResult(
        regime=regime,
        workflow_id=dag.workflow_id,
        total_tasks=total_tasks,
        tasks_healthy_completed=healthy_done,
        tasks_tainted_completed=tainted_done,
        tasks_contained=contained,
        tasks_collateral_aborted=collateral,
        taint_containment_rate=taint_containment_rate,
        healthy_work_preservation_rate=healthy_work_preservation_rate,
        spent_healthy_cents=spent_healthy_cents,
        spent_tainted_cents=spent_tainted_cents,
        salvaged_reserve_cents=salvaged_reserve_cents,
        total_budget_cents=dag.total_budget_cents,
        containment_receipt=containment_rcpt,
        tamper_evident_digest=digest,
    )


# =====================================================================
# Benchmark Suite
# =====================================================================

def run_selective_online_containment_benchmark(
    seed: int = 42,
    num_workflows: int = 20,
) -> Dict[ContainmentRegime, Dict[str, float]]:
    """
    Run multi-regime benchmark across deterministic workflows.
    Decouples workload generation from regime evaluation to ensure strict RNG fairness.
    """
    rng = random.Random(seed)
    workflows: List[WorkflowDAG] = [
        generate_workload_dag(rng, f"wf-{i:03d}", num_tasks=12, branch_factor=2, fault_node_index=2)
        for i in range(num_workflows)
    ]

    aggregates: Dict[ContainmentRegime, Dict[str, float]] = {}

    for regime in ContainmentRegime:
        containment_rates: List[float] = []
        preservation_rates: List[float] = []
        spent_healthy: List[int] = []
        spent_tainted: List[int] = []
        salvaged: List[int] = []

        for dag in workflows:
            res = run_workflow_under_regime(dag, regime)
            containment_rates.append(res.taint_containment_rate)
            preservation_rates.append(res.healthy_work_preservation_rate)
            spent_healthy.append(res.spent_healthy_cents)
            spent_tainted.append(res.spent_tainted_cents)
            salvaged.append(res.salvaged_reserve_cents)

        aggregates[regime] = {
            "mean_containment_rate": sum(containment_rates) / len(containment_rates),
            "mean_healthy_preservation_rate": sum(preservation_rates) / len(preservation_rates),
            "total_spent_healthy_cents": sum(spent_healthy),
            "total_spent_tainted_cents": sum(spent_tainted),
            "total_salvaged_cents": sum(salvaged),
        }

    return aggregates


if __name__ == "__main__":
    print("Running Selective Online Containment & Blast-Radius Simulation (EdgeCitadel arXiv:2611.06727)...")
    results = run_selective_online_containment_benchmark(seed=42, num_workflows=20)
    for regime, metrics in results.items():
        print(f"\nRegime: {regime.value}")
        print(f"  Taint Containment Rate:     {metrics['mean_containment_rate'] * 100:.1f}%")
        print(f"  Healthy Work Preservation:  {metrics['mean_healthy_preservation_rate'] * 100:.1f}%")
        print(f"  Healthy Spend:              {metrics['total_spent_healthy_cents']} cents")
        print(f"  Tainted Waste:              {metrics['total_spent_tainted_cents']} cents")
        print(f"  Salvaged Reserve:           {metrics['total_salvaged_cents']} cents")
