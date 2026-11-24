"""Deterministic TRAIL Trace Reasoning & Agentic Issue Localization Module.

Grounded in:
  1. TRAIL: Trace Reasoning and Agentic Issue Localization
     (Darshan Deshpande, Varun Gangal, Hersh Mehta, Jitin Krishnan, Anand Kannappan, Rebecca Qian,
      arXiv:2505.08638, May 2025).
  2. W3C PROV-DM: The PROV Data Model (Luc Moreau & Paolo Missier, W3C Recommendation 2013).
  3. IEEE 7012: Standard for Machine Readable Personal Privacy Terms and Policy Boundaries.

Provides:
  - Formal multi-layered error taxonomy (Reasoning, Planning/Coordination, System Execution).
  - Cryptographically hashed execution trace representation with temporal and causal dependency verification.
  - Deterministic root-cause issue localizer (identifying first divergence step s* and causal propagation).
  - W3C PROV-DM provenance receipt generator with cryptographic SHA-256 sealing.
  - Strict Steward Gate enforcement (zero unapproved tokens, zero speculative money promises, zero sci-fi lore).
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# Exceptions & Steward Gate Compliance
# ---------------------------------------------------------------------------

class TrailError(Exception):
    """Base exception for all TRAIL trace localization errors."""


class TrailValidationError(TrailError):
    """Raised when trace data, schema, or cryptographic digests fail validation."""


class TrailLocalizationError(TrailError):
    """Raised when trace reasoning or issue localization encounters an unrecoverable fault."""


class StewardGateViolationError(TrailError):
    """Raised when forbidden speculative monetary tokens or unapproved claims are detected."""


FORBIDDEN_STEWARD_TERMS: Tuple[str, ...] = (
    "contribution token",
    "mmct",
    "mmctbalance",
    "+$",
    "/yr",
    "85/10/5",
    "95% data shapley",
    "somatic witness",
    "pre-adc",
    "upcoding reversal",
    "algebraic coalition",
    "fractured alignment",
)


def assert_steward_gate_compliance(text: str) -> None:
    """Enforces strict Steward Gate compliance fail-closed across all strings and traces."""
    if not isinstance(text, str):
        return
    lower = text.lower()
    for term in FORBIDDEN_STEWARD_TERMS:
        if term in lower:
            raise StewardGateViolationError(
                f"Steward Gate violation: detected forbidden term {term!r} in trace payload."
            )


def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes object to deterministic canonical JSON bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    """Computes a deterministic SHA-256 hexadecimal digest of structured data."""
    if isinstance(obj, bytes):
        raw = obj
    elif isinstance(obj, str):
        raw = obj.encode("utf-8")
    else:
        raw = canonical_json_bytes(obj)
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# TRAIL Error Taxonomy (arXiv:2505.08638)
# ---------------------------------------------------------------------------

class TrailErrorFamily(str, enum.Enum):
    """Three high-level failure families formalizing agentic workflow bugs."""
    REASONING = "REASONING"
    PLANNING_COORDINATION = "PLANNING_COORDINATION"
    SYSTEM_EXECUTION = "SYSTEM_EXECUTION"


class TrailErrorCode(str, enum.Enum):
    """Fine-grained error categories within the TRAIL taxonomy."""
    # Pillar 1: Reasoning Errors
    REASONING_HALLUCINATION = "REASONING_HALLUCINATION"
    REASONING_RETRIEVAL_FAILURE = "REASONING_RETRIEVAL_FAILURE"
    REASONING_TOOL_OUTPUT_MISINTERPRETATION = "REASONING_TOOL_OUTPUT_MISINTERPRETATION"

    # Pillar 2: Planning & Coordination Errors
    PLANNING_TASK_MISUNDERSTANDING = "PLANNING_TASK_MISUNDERSTANDING"
    PLANNING_INCORRECT_TOOL_SELECTION = "PLANNING_INCORRECT_TOOL_SELECTION"
    PLANNING_GOAL_DEVIATION = "PLANNING_GOAL_DEVIATION"

    # Pillar 3: System Execution Errors
    EXECUTION_ENVIRONMENT_FAULT = "EXECUTION_ENVIRONMENT_FAULT"
    EXECUTION_RATE_LIMIT_OR_AUTH = "EXECUTION_RATE_LIMIT_OR_AUTH"
    EXECUTION_CONTRACT_VIOLATION = "EXECUTION_CONTRACT_VIOLATION"


# ---------------------------------------------------------------------------
# Structured Execution Trace Data Model
# ---------------------------------------------------------------------------

class ActionType(str, enum.Enum):
    """Discrete action primitives in agentic workflow trajectories."""
    THOUGHT = "THOUGHT"
    TOOL_INVOCATION = "TOOL_INVOCATION"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    COORDINATION_MESSAGE = "COORDINATION_MESSAGE"
    STATE_MUTATION = "STATE_MUTATION"
    FINAL_ANSWER = "FINAL_ANSWER"


@dataclass(frozen=True)
class ExecutionTraceStep:
    """Deterministic, immutable record of an individual execution step."""
    step_index: int
    agent_id: str
    action_type: ActionType
    action_payload: Dict[str, Any]
    context_dependencies: Tuple[int, ...]  # Step indices this step causally depends on
    timestamp_iso: str
    status_code: int = 200
    error_message: Optional[str] = None
    step_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.step_index, int) or self.step_index < 0:
            raise TrailValidationError(f"step_index must be non-negative integer, got {self.step_index!r}")
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise TrailValidationError("agent_id must be non-empty string")
        if not isinstance(self.action_type, ActionType):
            raise TrailValidationError(f"Invalid action_type: {self.action_type!r}")
        if not isinstance(self.action_payload, dict):
            raise TrailValidationError("action_payload must be a dict")
        if not isinstance(self.context_dependencies, tuple):
            raise TrailValidationError("context_dependencies must be a tuple of integer step indices")
        for dep in self.context_dependencies:
            if not isinstance(dep, int) or dep < 0:
                raise TrailValidationError(f"Invalid context dependency: {dep!r}")
            if dep >= self.step_index:
                raise TrailValidationError(
                    f"Causal dependency violation: step {self.step_index} depends on future/current step {dep}"
                )

        # Validate timestamp format
        try:
            datetime.fromisoformat(self.timestamp_iso.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise TrailValidationError(f"Invalid timestamp_iso format: {self.timestamp_iso!r}") from exc

        # Check Steward Gate on all string inputs
        assert_steward_gate_compliance(self.agent_id)
        assert_steward_gate_compliance(self.timestamp_iso)
        if self.error_message:
            assert_steward_gate_compliance(self.error_message)
        assert_steward_gate_compliance(json.dumps(self.action_payload))

        # Compute or verify canonical digest
        computed_digest = self.compute_digest()
        if self.step_digest and self.step_digest != computed_digest:
            raise TrailValidationError(
                f"Step {self.step_index} digest mismatch: expected {computed_digest}, got {self.step_digest}"
            )
        if not self.step_digest:
            object.__setattr__(self, "step_digest", computed_digest)

    def compute_digest(self) -> str:
        """Computes deterministic SHA-256 digest over core step fields."""
        payload_record = {
            "step_index": self.step_index,
            "agent_id": self.agent_id,
            "action_type": self.action_type.value,
            "action_payload": self.action_payload,
            "context_dependencies": list(self.context_dependencies),
            "timestamp_iso": self.timestamp_iso,
            "status_code": self.status_code,
            "error_message": self.error_message,
        }
        return canonical_sha256(payload_record)


@dataclass(frozen=True)
class ExecutionTrace:
    """Cryptographically attested trace representing a complete multi-agent workflow."""
    session_id: str
    task_objective: str
    steps: Tuple[ExecutionTraceStep, ...]
    agent_roles: Dict[str, str] = field(default_factory=dict)
    allowed_tools: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    trace_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise TrailValidationError("session_id must be non-empty string")
        if not isinstance(self.task_objective, str) or not self.task_objective.strip():
            raise TrailValidationError("task_objective must be non-empty string")
        if not isinstance(self.steps, tuple):
            raise TrailValidationError("steps must be a tuple of ExecutionTraceStep")

        assert_steward_gate_compliance(self.session_id)
        assert_steward_gate_compliance(self.task_objective)
        for role in self.agent_roles.values():
            assert_steward_gate_compliance(role)

        # Enforce step sequence continuity & strictly non-decreasing timestamps
        prev_time: Optional[datetime] = None
        for expected_idx, step in enumerate(self.steps):
            if step.step_index != expected_idx:
                raise TrailValidationError(
                    f"Trace step continuity violation: expected index {expected_idx}, got {step.step_index}"
                )
            step_time = datetime.fromisoformat(step.timestamp_iso.replace("Z", "+00:00"))
            if prev_time is not None and step_time < prev_time:
                raise TrailValidationError(
                    f"Temporal sequence inversion: step {step.step_index} time ({step.timestamp_iso}) "
                    f"is earlier than preceding step ({prev_time.isoformat()})"
                )
            prev_time = step_time

        computed_digest = self.compute_digest()
        if self.trace_digest and self.trace_digest != computed_digest:
            raise TrailValidationError(
                f"Trace digest mismatch: expected {computed_digest}, got {self.trace_digest}"
            )
        if not self.trace_digest:
            object.__setattr__(self, "trace_digest", computed_digest)

    def compute_digest(self) -> str:
        """Computes deterministic digest over session ID, objective, and step digests."""
        trace_summary = {
            "session_id": self.session_id,
            "task_objective": self.task_objective,
            "step_digests": [s.step_digest for s in self.steps],
            "agent_roles": self.agent_roles,
            "allowed_tools": {k: list(v) for k, v in self.allowed_tools.items()},
        }
        return canonical_sha256(trace_summary)


# ---------------------------------------------------------------------------
# Issue Diagnosis & W3C PROV-DM Receipt Data Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StepDiagnosis:
    """Diagnostic verdict for a single execution step."""
    step_index: int
    is_fault: bool
    error_family: Optional[TrailErrorFamily] = None
    error_code: Optional[TrailErrorCode] = None
    reason: str = ""
    evidence_digest: str = ""


@dataclass(frozen=True)
class TrailIssueLocalizationReceipt:
    """Tamper-evident, cryptographically sealed diagnostic receipt for an execution trace."""
    receipt_id: str
    session_id: str
    trace_digest: str
    total_steps: int
    has_issue: bool
    root_cause_step_index: Optional[int]
    primary_error_family: Optional[TrailErrorFamily]
    primary_error_code: Optional[TrailErrorCode]
    diagnosis_summary: str
    causal_propagation_chain: Tuple[int, ...]
    affected_steps_count: int
    trace_health_score: float
    w3c_prov_bundle: Dict[str, Any]
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        assert_steward_gate_compliance(self.diagnosis_summary)
        computed = self.compute_digest()
        if self.receipt_digest and self.receipt_digest != computed:
            raise TrailValidationError(f"Receipt digest mismatch: expected {computed}, got {self.receipt_digest}")
        if not self.receipt_digest:
            object.__setattr__(self, "receipt_digest", computed)

    def compute_digest(self) -> str:
        payload = {
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "trace_digest": self.trace_digest,
            "total_steps": self.total_steps,
            "has_issue": self.has_issue,
            "root_cause_step_index": self.root_cause_step_index,
            "primary_error_family": self.primary_error_family.value if self.primary_error_family else None,
            "primary_error_code": self.primary_error_code.value if self.primary_error_code else None,
            "diagnosis_summary": self.diagnosis_summary,
            "causal_propagation_chain": list(self.causal_propagation_chain),
            "affected_steps_count": self.affected_steps_count,
            "trace_health_score": round(self.trace_health_score, 6),
            "w3c_prov_bundle": self.w3c_prov_bundle,
        }
        return canonical_sha256(payload)


# ---------------------------------------------------------------------------
# TrailTraceIssueLocalizer (Deterministic Rule & Causal Graph Engine)
# ---------------------------------------------------------------------------

class TrailTraceIssueLocalizer:
    """Deterministic analyzer executing the TRAIL error taxonomy over structured execution traces."""

    def __init__(self, max_allowed_cyclic_repetitions: int = 3) -> None:
        if max_allowed_cyclic_repetitions < 1:
            raise TrailValidationError("max_allowed_cyclic_repetitions must be >= 1")
        self.max_allowed_cyclic_repetitions = max_allowed_cyclic_repetitions

    def diagnose_step(self, step: ExecutionTraceStep, trace: ExecutionTrace) -> StepDiagnosis:
        """Evaluates an individual step against the TRAIL error taxonomy."""
        payload = step.action_payload

        # 1. Check System Execution: Contract Violation (malformed payload, non-finite values)
        has_non_finite = self._check_nested_non_finite(payload)
        if has_non_finite:
            return StepDiagnosis(
                step_index=step.step_index,
                is_fault=True,
                error_family=TrailErrorFamily.SYSTEM_EXECUTION,
                error_code=TrailErrorCode.EXECUTION_CONTRACT_VIOLATION,
                reason="Payload contains invalid non-finite floating point numbers (NaN or Inf)",
                evidence_digest=step.step_digest,
            )

        # 2. Check System Execution: Rate Limit or Auth Error
        if step.status_code in (429, 401, 403):
            return StepDiagnosis(
                step_index=step.step_index,
                is_fault=True,
                error_family=TrailErrorFamily.SYSTEM_EXECUTION,
                error_code=TrailErrorCode.EXECUTION_RATE_LIMIT_OR_AUTH,
                reason=f"System execution failed with status {step.status_code}: {step.error_message or 'Rate limit or authentication failure'}",
                evidence_digest=step.step_digest,
            )

        # 3. Check System Execution: Environment Fault
        if step.status_code in (500, 502, 503, 504) or (
            step.error_message and any(
                term in step.error_message.lower()
                for term in ("file not found", "nosuchfile", "permission denied", "connection refused", "econnrefused")
            )
        ):
            return StepDiagnosis(
                step_index=step.step_index,
                is_fault=True,
                error_family=TrailErrorFamily.SYSTEM_EXECUTION,
                error_code=TrailErrorCode.EXECUTION_ENVIRONMENT_FAULT,
                reason=f"Environment execution fault: {step.error_message or f'HTTP {step.status_code}'}",
                evidence_digest=step.step_digest,
            )

        # 4. Check Planning: Incorrect Tool Selection
        if step.action_type == ActionType.TOOL_INVOCATION:
            tool_name = str(payload.get("tool_name", "")).strip()
            if not tool_name:
                return StepDiagnosis(
                    step_index=step.step_index,
                    is_fault=True,
                    error_family=TrailErrorFamily.PLANNING_COORDINATION,
                    error_code=TrailErrorCode.PLANNING_INCORRECT_TOOL_SELECTION,
                    reason="Tool invocation step missing mandatory 'tool_name' in payload",
                    evidence_digest=step.step_digest,
                )
            # Verify against agent allowed tools if configured
            agent_role = trace.agent_roles.get(step.agent_id, step.agent_id)
            role_allowed = trace.allowed_tools.get(agent_role) or trace.allowed_tools.get(step.agent_id)
            if role_allowed is not None and tool_name not in role_allowed:
                return StepDiagnosis(
                    step_index=step.step_index,
                    is_fault=True,
                    error_family=TrailErrorFamily.PLANNING_COORDINATION,
                    error_code=TrailErrorCode.PLANNING_INCORRECT_TOOL_SELECTION,
                    reason=f"Agent {step.agent_id!r} (role {agent_role!r}) unauthorized for tool {tool_name!r}",
                    evidence_digest=step.step_digest,
                )

        # 5. Check Reasoning: Tool Output Misinterpretation
        # If preceding step was an error/nonzero status, but current step claims ungrounded success
        if step.action_type in (ActionType.THOUGHT, ActionType.STATE_MUTATION, ActionType.FINAL_ANSWER):
            for dep_idx in step.context_dependencies:
                dep_step = trace.steps[dep_idx]
                if dep_step.action_type == ActionType.TOOL_OUTPUT:
                    dep_failed = dep_step.status_code >= 400 or (dep_step.error_message is not None)
                    claimed_success = bool(payload.get("claimed_success", False))
                    if dep_failed and claimed_success:
                        return StepDiagnosis(
                            step_index=step.step_index,
                            is_fault=True,
                            error_family=TrailErrorFamily.REASONING,
                            error_code=TrailErrorCode.REASONING_TOOL_OUTPUT_MISINTERPRETATION,
                            reason=f"Step {step.step_index} treated failed tool output from step {dep_idx} as successful",
                            evidence_digest=step.step_digest,
                        )

        # 6. Check Reasoning: Hallucination (claiming retrieved variables that do not exist in upstream dependencies)
        if "hallucinated_facts" in payload and payload["hallucinated_facts"]:
            return StepDiagnosis(
                step_index=step.step_index,
                is_fault=True,
                error_family=TrailErrorFamily.REASONING,
                error_code=TrailErrorCode.REASONING_HALLUCINATION,
                reason=f"Ungrounded assertions detected: {payload['hallucinated_facts']}",
                evidence_digest=step.step_digest,
            )

        # 7. Check Planning: Goal Deviation (cyclic repetitive calls)
        if step.action_type == ActionType.TOOL_INVOCATION and step.step_index >= self.max_allowed_cyclic_repetitions:
            tool_sig = (payload.get("tool_name"), json.dumps(payload.get("arguments", {}), sort_keys=True))
            recent_matches = 0
            for prior_idx in range(step.step_index - 1, -1, -1):
                prior_step = trace.steps[prior_idx]
                if prior_step.action_type == ActionType.TOOL_INVOCATION:
                    p_sig = (
                        prior_step.action_payload.get("tool_name"),
                        json.dumps(prior_step.action_payload.get("arguments", {}), sort_keys=True),
                    )
                    if p_sig == tool_sig:
                        recent_matches += 1
                        if recent_matches >= self.max_allowed_cyclic_repetitions:
                            return StepDiagnosis(
                                step_index=step.step_index,
                                is_fault=True,
                                error_family=TrailErrorFamily.PLANNING_COORDINATION,
                                error_code=TrailErrorCode.PLANNING_GOAL_DEVIATION,
                                reason=f"Detected cyclic non-progress loop: tool {tool_sig[0]!r} repeated {recent_matches + 1} times",
                                evidence_digest=step.step_digest,
                            )
                    else:
                        break

        # 8. Check Planning: Task Misunderstanding (direct violation of task objective constraints)
        prohibited_keywords = payload.get("violated_objective_constraints")
        if prohibited_keywords:
            return StepDiagnosis(
                step_index=step.step_index,
                is_fault=True,
                error_family=TrailErrorFamily.PLANNING_COORDINATION,
                error_code=TrailErrorCode.PLANNING_TASK_MISUNDERSTANDING,
                reason=f"Action explicitly violates task constraints: {prohibited_keywords}",
                evidence_digest=step.step_digest,
            )

        # Step is nominal
        return StepDiagnosis(
            step_index=step.step_index,
            is_fault=False,
            reason="Step execution conforms to operational and schema constraints",
            evidence_digest=step.step_digest,
        )

    def localize_trace_issues(self, trace: ExecutionTrace) -> TrailIssueLocalizationReceipt:
        """Executes full trace issue localization, computing root cause and causal propagation."""
        diagnoses: List[StepDiagnosis] = []
        for step in trace.steps:
            diag = self.diagnose_step(step, trace)
            diagnoses.append(diag)

        # Find first divergence step (root cause s*)
        root_cause_diag: Optional[StepDiagnosis] = None
        for diag in diagnoses:
            if diag.is_fault:
                root_cause_diag = diag
                break

        if root_cause_diag is None:
            # Trace is completely clean
            w3c_bundle = self._build_w3c_prov_bundle(trace, root_cause_idx=None, causal_chain=())
            receipt_id = f"trail-rcpt-{trace.session_id}-clean"
            return TrailIssueLocalizationReceipt(
                receipt_id=receipt_id,
                session_id=trace.session_id,
                trace_digest=trace.trace_digest,
                total_steps=len(trace.steps),
                has_issue=False,
                root_cause_step_index=None,
                primary_error_family=None,
                primary_error_code=None,
                diagnosis_summary="All execution steps verified nominal; zero taxonomy violations detected.",
                causal_propagation_chain=(),
                affected_steps_count=0,
                trace_health_score=1.0,
                w3c_prov_bundle=w3c_bundle,
            )

        s_star = root_cause_diag.step_index
        causal_chain = self._compute_causal_propagation(trace, s_star)
        total_steps = len(trace.steps)
        affected_count = len(causal_chain)
        health_score = max(0.0, 1.0 - (affected_count / max(1, total_steps)))

        w3c_bundle = self._build_w3c_prov_bundle(trace, root_cause_idx=s_star, causal_chain=causal_chain)
        receipt_id = f"trail-rcpt-{trace.session_id}-s{s_star}"
        summary = (
            f"Root-cause fault located at step {s_star} ({root_cause_diag.error_code.value}): "
            f"{root_cause_diag.reason}. Causal propagation affected {affected_count} downstream step(s)."
        )

        return TrailIssueLocalizationReceipt(
            receipt_id=receipt_id,
            session_id=trace.session_id,
            trace_digest=trace.trace_digest,
            total_steps=total_steps,
            has_issue=True,
            root_cause_step_index=s_star,
            primary_error_family=root_cause_diag.error_family,
            primary_error_code=root_cause_diag.error_code,
            diagnosis_summary=summary,
            causal_propagation_chain=causal_chain,
            affected_steps_count=affected_count,
            trace_health_score=health_score,
            w3c_prov_bundle=w3c_bundle,
        )

    def _compute_causal_propagation(self, trace: ExecutionTrace, s_star: int) -> Tuple[int, ...]:
        """Calculates forward transitive closure of steps dependent on root cause s*."""
        affected: Set[int] = {s_star}
        for step in trace.steps:
            if step.step_index <= s_star:
                continue
            # If any dependency of step is in affected set, step is affected
            if any(dep in affected for dep in step.context_dependencies):
                affected.add(step.step_index)

        return tuple(sorted(affected))

    def _check_nested_non_finite(self, obj: Any) -> bool:
        """Recursively checks for NaN or Infinite floats in nested containers."""
        if isinstance(obj, float):
            return math.isnan(obj) or math.isinf(obj)
        if isinstance(obj, dict):
            return any(self._check_nested_non_finite(v) for v in obj.values())
        if isinstance(obj, (list, tuple, set)):
            return any(self._check_nested_non_finite(v) for v in obj)
        return False

    def _build_w3c_prov_bundle(
        self,
        trace: ExecutionTrace,
        root_cause_idx: Optional[int],
        causal_chain: Tuple[int, ...],
    ) -> Dict[str, Any]:
        """Constructs a W3C PROV-DM JSON-LD bundle representing execution and issue provenance."""
        activities: Dict[str, Any] = {}
        agents: Dict[str, Any] = {}
        entities: Dict[str, Any] = {}
        was_associated_with: List[Dict[str, str]] = []
        used_relations: List[Dict[str, str]] = []
        was_derived_from: List[Dict[str, str]] = []

        # Record agents
        for step in trace.steps:
            if step.agent_id not in agents:
                agents[step.agent_id] = {
                    "@id": f"prov:agent:{step.agent_id}",
                    "prov:type": "prov:SoftwareAgent",
                    "cin:role": trace.agent_roles.get(step.agent_id, "default_agent"),
                }

            act_id = f"prov:activity:step_{step.step_index}"
            activities[act_id] = {
                "@id": act_id,
                "prov:type": f"cin:{step.action_type.value}",
                "prov:startTime": step.timestamp_iso,
                "cin:step_index": step.step_index,
                "cin:step_digest": step.step_digest,
                "cin:is_fault": step.step_index in causal_chain,
            }

            was_associated_with.append({
                "prov:activity": act_id,
                "prov:agent": f"prov:agent:{step.agent_id}",
            })

            for dep in step.context_dependencies:
                used_relations.append({
                    "prov:activity": act_id,
                    "prov:entity": f"prov:entity:step_{dep}_output",
                })
                was_derived_from.append({
                    "prov:generatedEntity": f"prov:entity:step_{step.step_index}_output",
                    "prov:usedEntity": f"prov:entity:step_{dep}_output",
                })

            entities[f"prov:entity:step_{step.step_index}_output"] = {
                "@id": f"prov:entity:step_{step.step_index}_output",
                "cin:content_digest": step.step_digest,
            }

        return {
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "cin": "https://cintnet.org/schema/provenance#",
            },
            "@id": f"cin:prov_bundle:{trace.session_id}",
            "prov:wasGeneratedBy": f"cin:TrailTraceIssueLocalizer",
            "prov:generatedAtTime": datetime.now(timezone.utc).isoformat(),
            "cin:root_cause_step": root_cause_idx,
            "prov:Agent": agents,
            "prov:Activity": activities,
            "prov:Entity": entities,
            "prov:wasAssociatedWith": was_associated_with,
            "prov:used": used_relations,
            "prov:wasDerivedFrom": was_derived_from,
        }
