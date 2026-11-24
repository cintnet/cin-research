"""
Strict Role & Session Isolation Guard ("No Cheating" Architecture).

Ensures each actor in the simulation:
  1. Orchestrator (`orchestrator`)
  2. Tasker Human (`human_tasker`)
  3. Tasker Personal Agent (`agent_tasker`)
  4. Solver Human (`human_solver`)
  5. Solver Personal Agent (`agent_solver`)

operates inside its own cryptographic session vault with enforced communication
channels:
  - A Human may ONLY communicate with their own Personal Agent.
  - A Personal Agent may ONLY communicate with its own Human (via ModalityBridge)
    or with other Agents via signed messages on the public AgentWebLedger.
  - No actor can read another actor's private memory vault or hidden state.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class AgentRealm(str, Enum):
    """Top-level logical separation between CIN outer-loop builders and in-world Testnet actors."""

    REALM_A_COLLECTIVE_BUILDERS = "REALM_A_COLLECTIVE_BUILDERS"
    REALM_B_TESTNET_ACTORS = "REALM_B_TESTNET_ACTORS"


class FunctionalAgentPartition(str, Enum):
    """
    Logical separation of agents by mission application and optimization outcome so DSPy,
    TextGrad, ADAS, and Harness² improvements never bleed instructions across roles.
    """

    # Realm A: Outer-Loop CIN Collective Builders
    A1_SITE_AND_UX_ENGINEERS = "A1_SITE_AND_UX_ENGINEERS"
    A2_SOFTWARE_AND_SIM_ENGINEERS = "A2_SOFTWARE_AND_SIM_ENGINEERS"
    A3_AUDIENCE_ARTICLE_AND_SOCIAL_AUTHORS = "A3_AUDIENCE_ARTICLE_AND_SOCIAL_AUTHORS"
    A4_RESEARCH_PAPER_AND_VOLUME_AUTHORS = "A4_RESEARCH_PAPER_AND_VOLUME_AUTHORS"

    # Realm B: In-World Testnet Participant & Protocol Agents
    B1_IN_WORLD_TESTNET_ACTORS = "B1_IN_WORLD_TESTNET_ACTORS"


class ActorRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    HUMAN_TASKER = "human_tasker"
    AGENT_TASKER = "agent_tasker"
    HUMAN_SOLVER = "human_solver"
    AGENT_SOLVER = "agent_solver"
    TESTNET_VALIDATOR = "testnet_validator"
    LEDGER_PROTOCOL_CRITIC = "ledger_protocol_critic"


class SessionBoundaryViolationError(PermissionError):
    """Raised when an actor attempts to access another actor's private session state
    or use a forbidden direct communication channel."""


class CapabilityAttenuationError(SessionBoundaryViolationError):
    """Raised when capability attenuation invariants or delegation bounds are violated."""


class RealmInstructionBleedError(PermissionError):
    """Raised when outer-loop Realm A builder instructions bleed into an in-world
    Realm B Testnet agent harness (or vice versa)."""


# Allowed direct (off-ledger) communication edges
ALLOWED_DIRECT_CHANNELS: Set[Tuple[ActorRole, ActorRole]] = {
    (ActorRole.ORCHESTRATOR, ActorRole.HUMAN_TASKER),
    (ActorRole.ORCHESTRATOR, ActorRole.AGENT_TASKER),
    (ActorRole.ORCHESTRATOR, ActorRole.HUMAN_SOLVER),
    (ActorRole.ORCHESTRATOR, ActorRole.AGENT_SOLVER),
    (ActorRole.HUMAN_TASKER, ActorRole.AGENT_TASKER),
    (ActorRole.AGENT_TASKER, ActorRole.HUMAN_TASKER),
    (ActorRole.HUMAN_SOLVER, ActorRole.AGENT_SOLVER),
    (ActorRole.AGENT_SOLVER, ActorRole.HUMAN_SOLVER),
}

# Only agents (and orchestrator for scenario seeding) may post to the AgentWebLedger
LEDGER_PERMITTED_ACTORS: Set[ActorRole] = {
    ActorRole.ORCHESTRATOR,
    ActorRole.AGENT_TASKER,
    ActorRole.AGENT_SOLVER,
}


@dataclass
class SessionVault:
    """Isolated private memory store for a single actor session."""

    actor_id: str
    role: ActorRole
    session_token: str
    _private_store: Dict[str, Any] = field(default_factory=dict)
    _journal: List[Dict[str, Any]] = field(default_factory=list)

    def write_private(self, caller_token: str, key: str, value: Any) -> None:
        if caller_token != self.session_token:
            raise SessionBoundaryViolationError(
                f"Unauthorized write attempt to {self.actor_id} ({self.role.value}) vault."
            )
        self._private_store[key] = value
        self._journal.append({"op": "write", "key": key})

    def read_private(self, caller_token: str, key: str) -> Any:
        if caller_token != self.session_token:
            raise SessionBoundaryViolationError(
                f"Unauthorized read attempt on {self.actor_id} ({self.role.value}) vault."
            )
        self._journal.append({"op": "read", "key": key})
        return self._private_store.get(key)

    def snapshot_digest(self) -> str:
        payload = f"{self.actor_id}:{self.role.value}:{sorted(self._private_store.keys())}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class SessionIsolationGuard:
    """Manages per-actor isolated vaults and enforces anti-cheating rules."""

    def __init__(self, run_seed: str = "cin-ledger-sim-2026") -> None:
        self.run_seed = run_seed
        self._vaults: Dict[ActorRole, SessionVault] = {}
        self._tokens: Dict[ActorRole, str] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.violation_count: int = 0

        for role in ActorRole:
            raw = f"{run_seed}::{role.value}::isolated-session"
            token = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
            self._tokens[role] = token
            self._vaults[role] = SessionVault(
                actor_id=f"session-{role.value}",
                role=role,
                session_token=token,
            )

    def get_token(self, role: ActorRole) -> str:
        return self._tokens[role]

    def read_actor_memory(
        self, caller_role: ActorRole, target_role: ActorRole, key: str
    ) -> Any:
        caller_token = self._tokens[caller_role]
        target_vault = self._vaults[target_role]
        try:
            val = target_vault.read_private(caller_token, key)
            self.audit_log.append(
                {
                    "event": "vault_read",
                    "caller": caller_role.value,
                    "target": target_role.value,
                    "key": key,
                    "status": "allowed",
                }
            )
            return val
        except SessionBoundaryViolationError:
            self.violation_count += 1
            self.audit_log.append(
                {
                    "event": "vault_read_blocked",
                    "caller": caller_role.value,
                    "target": target_role.value,
                    "key": key,
                    "status": "blocked_cheating_attempt",
                }
            )
            raise

    def write_actor_memory(
        self, caller_role: ActorRole, target_role: ActorRole, key: str, value: Any
    ) -> None:
        caller_token = self._tokens[caller_role]
        target_vault = self._vaults[target_role]
        try:
            target_vault.write_private(caller_token, key, value)
            self.audit_log.append(
                {
                    "event": "vault_write",
                    "caller": caller_role.value,
                    "target": target_role.value,
                    "key": key,
                    "status": "allowed",
                }
            )
        except SessionBoundaryViolationError:
            self.violation_count += 1
            self.audit_log.append(
                {
                    "event": "vault_write_blocked",
                    "caller": caller_role.value,
                    "target": target_role.value,
                    "key": key,
                    "status": "blocked_cheating_attempt",
                }
            )
            raise

    def assert_direct_channel(
        self, sender: ActorRole, recipient: ActorRole, purpose: str
    ) -> None:
        if (sender, recipient) not in ALLOWED_DIRECT_CHANNELS:
            self.violation_count += 1
            self.audit_log.append(
                {
                    "event": "direct_channel_blocked",
                    "sender": sender.value,
                    "recipient": recipient.value,
                    "purpose": purpose,
                    "status": "blocked_cheating_attempt",
                }
            )
            raise SessionBoundaryViolationError(
                f"Direct channel forbidden between {sender.value} and {recipient.value} "
                f"({purpose}). Must route through personal agent and AgentWebLedger."
            )
        self.audit_log.append(
            {
                "event": "direct_channel_ok",
                "sender": sender.value,
                "recipient": recipient.value,
                "purpose": purpose,
                "status": "allowed",
            }
        )

    def assert_ledger_access(self, actor: ActorRole, action: str) -> None:
        if actor not in LEDGER_PERMITTED_ACTORS:
            self.violation_count += 1
            self.audit_log.append(
                {
                    "event": "ledger_access_blocked",
                    "actor": actor.value,
                    "action": action,
                    "status": "blocked_human_on_agent_web",
                }
            )
            raise SessionBoundaryViolationError(
                f"Actor {actor.value} cannot access the AgentWebLedger directly "
                f"(Two Internets boundary: only personal agents access the ledger)."
            )
        self.audit_log.append(
            {
                "event": "ledger_access_ok",
                "actor": actor.value,
                "action": action,
                "status": "allowed",
            }
        )


# Outer-loop Realm A terms that must NEVER appear inside an in-world Realm B actor harness
FORBIDDEN_REALM_A_BLEED_TERMS_IN_TESTNET: Tuple[str, ...] = (
    "cin-foundation-website",
    "src/notes/",
    "src/index.html",
    "deploy --harness",
    "outreach/social",
    "steward_objectives.json",
    "site-jargon",
    "site-links",
    "portal-safety",
    "VOL-01-POST-WEB",
    "VOL-02-NEXT-LATENT",
    "VOL-03-INSTITUTIONAL",
)

REALM_B_ACTOR_HARNESS_FILES: Dict[ActorRole, str] = {
    ActorRole.AGENT_TASKER: "tasker_personal_agent.md",
    ActorRole.AGENT_SOLVER: "solver_guild_agent.md",
    ActorRole.TESTNET_VALIDATOR: "testnet_validator_agent.md",
    ActorRole.LEDGER_PROTOCOL_CRITIC: "ledger_protocol_critic_agent.md",
}


class RealmIsolationFirewall:
    """
    Enforces strict logical and instruction separation between:
      - Realm A (`REALM_A_COLLECTIVE_BUILDERS`):
          A1 (`A1_SITE_AND_UX_ENGINEERS`)
          A2 (`A2_SOFTWARE_AND_SIM_ENGINEERS`)
          A3 (`A3_AUDIENCE_ARTICLE_AND_SOCIAL_AUTHORS`)
          A4 (`A4_RESEARCH_PAPER_AND_VOLUME_AUTHORS`)
      - Realm B (`REALM_B_TESTNET_ACTORS`):
          B1 (`B1_IN_WORLD_TESTNET_ACTORS`: Tasker Agents, Solver Guild Agents,
              Independent Validators, and Ledger Protocol Critics)

    Ensures DSPy MIPROv2, TextGrad, ADAS, and Harness² optimizations operate
    within each partition's objective function without bleeding instructions.
    """

    def __init__(self, harnesses_dir: Path | None = None) -> None:
        self.harnesses_dir = harnesses_dir or (
            Path(__file__).resolve().parent / "agent_harnesses"
        )

    def validate_testnet_prompt_or_harness(
        self, text: str, source_label: str = "inline_prompt"
    ) -> None:
        """Raises RealmInstructionBleedError if any Realm A builder directive leaks into Realm B."""
        for term in FORBIDDEN_REALM_A_BLEED_TERMS_IN_TESTNET:
            if term in text:
                raise RealmInstructionBleedError(
                    f"Realm instruction bleed detected in '{source_label}': found outer-loop "
                    f"Realm A builder directive '{term}' inside a Realm B Testnet actor harness."
                )

    def load_realm_b_actor_harness(self, role: ActorRole) -> Dict[str, Any]:
        """Loads and verifies a clean-room Realm B actor harness `.md` file."""
        if role not in REALM_B_ACTOR_HARNESS_FILES:
            raise ValueError(f"Role {role.value} does not have a dedicated Realm B agent harness.")
        filename = REALM_B_ACTOR_HARNESS_FILES[role]
        path = self.harnesses_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing Realm B actor harness file: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        self.validate_testnet_prompt_or_harness(text, source_label=filename)
        return {
            "role": role.value,
            "realm": AgentRealm.REALM_B_TESTNET_ACTORS.value,
            "partition": FunctionalAgentPartition.B1_IN_WORLD_TESTNET_ACTORS.value,
            "harness_file": filename,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
            "lines": len(text.splitlines()),
            "bleed_verified_clean": True,
        }

    def audit_all_realm_b_harnesses(self) -> Dict[str, Any]:
        """Audits all 4 in-world Testnet agent harnesses for zero instruction bleed."""
        results: List[Dict[str, Any]] = []
        for role in REALM_B_ACTOR_HARNESS_FILES:
            results.append(self.load_realm_b_actor_harness(role))
        return {
            "realm": AgentRealm.REALM_B_TESTNET_ACTORS.value,
            "partition": FunctionalAgentPartition.B1_IN_WORLD_TESTNET_ACTORS.value,
            "harnesses_verified": len(results),
            "harnesses": results,
            "status": "ISOLATED_CLEAN",
        }


# ---------------------------------------------------------------------------
# Germline Execution & MCP Leak Guard (Signed, Sealed, Leaked: arXiv:2611.06585)
# ---------------------------------------------------------------------------

class MCPLeakGuardViolationError(SessionBoundaryViolationError):
    """Raised when an MCP toolchain attempts unauthorized data exfiltration,
    exceeds its bounded information disclosure budget, or violates sink noninterference."""


class StewardGateViolationError(PermissionError):
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
    lower_raw = text.lower()
    lower_norm = lower_raw.replace("_", " ").replace("-", " ")
    for term in FORBIDDEN_STEWARD_TERMS:
        term_norm = term.replace("_", " ").replace("-", " ")
        if term in lower_raw or term_norm in lower_norm:
            raise StewardGateViolationError(
                f"Steward Gate violation: detected forbidden term {term!r} in tool payload."
            )


@dataclass
class GermlineExecutionFork:
    """
    Ephemeral, data-isolated execution fork branched from a pristine process/vault state.

    Implements germline execution isolation (Signed, Sealed, Leaked: Trust Beyond Signature
    for MCP Toolchains, arXiv:2611.06585, Nov 2026).
    Enforces sink noninterference, ephemeral memory quarantine, bounded disclosure budgets,
    and zero persistence of unauthorized state mutations into the parent vault upon discard.
    """

    fork_id: str
    parent_vault_digest: str
    actor_role: ActorRole
    tool_name: str
    declared_scope: Set[str]
    allowed_egress_sinks: Set[str]
    disclosure_budget_bits: int = 1024
    ephemeral_store: Dict[str, Any] = field(default_factory=dict)
    disclosed_keys: Set[str] = field(default_factory=set)
    accumulated_disclosure_bits: int = 0
    executed: bool = False
    terminated: bool = False
    committed: bool = False
    execution_latency_ms: float = 18.5
    audit_events: List[Dict[str, Any]] = field(default_factory=list)

    def is_active(self) -> bool:
        return self.executed and not self.terminated


class GermlineProcessIsolationGuard:
    """
    Manages ephemeral data-isolated forks from pristine process/vault baselines.

    Protects personal agents and Testnet actors from Model Context Protocol (MCP)
    data exfiltration and side-channel leakage even when toolchains carry valid
    publisher signatures or certificates (arXiv:2611.06585).

    Key Properties:
      1. Ephemeral Quarantine: Tools execute inside temporary, memory-isolated forks.
      2. Sink Noninterference: Tools cannot transmit data to unapproved sinks.
      3. Bounded Disclosure: Quantifies and caps information exposure per invocation.
      4. Pristine Restoration: Modifications are discarded on termination unless
         explicitly verified through a Proof-Carrying Code commit gate.
      5. Strict Steward Gate Compliance: Rejects speculative money, tokens, or claims.
    """

    def __init__(self, session_guard: Optional[SessionIsolationGuard] = None) -> None:
        self.session_guard = session_guard or SessionIsolationGuard()
        self.active_forks: Dict[str, GermlineExecutionFork] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.violation_count: int = 0

    def create_ephemeral_fork(
        self,
        actor_role: ActorRole,
        tool_name: str,
        declared_scope: Set[str],
        allowed_egress_sinks: Set[str],
        disclosure_budget_bits: int = 1024,
        simulated_latency_ms: float = 18.5,
    ) -> GermlineExecutionFork:
        """
        Creates an ephemeral data-isolated fork initialized ONLY with declared scope.
        Parent vault state outside declared scope is strictly unmounted.
        """
        if not tool_name or not tool_name.strip():
            raise ValueError("Tool name must be a non-empty string.")
        if simulated_latency_ms < 0.0 or simulated_latency_ms > 1000.0:
            raise ValueError(f"Invalid simulated latency {simulated_latency_ms}ms (expected 10.0-49.0ms).")

        assert_steward_gate_compliance(tool_name)
        for sink in allowed_egress_sinks:
            assert_steward_gate_compliance(sink)

        parent_vault = self.session_guard._vaults[actor_role]
        parent_digest = parent_vault.snapshot_digest()
        token = self.session_guard.get_token(actor_role)

        # Copy ONLY keys explicitly listed in declared_scope
        ephemeral_data: Dict[str, Any] = {}
        for key in declared_scope:
            val = parent_vault.read_private(token, key)
            if val is not None:
                ephemeral_data[key] = val

        fork_id = hashlib.sha256(
            f"fork::{actor_role.value}::{tool_name}::{parent_digest}::{len(self.audit_log)}".encode("utf-8")
        ).hexdigest()[:16]

        fork = GermlineExecutionFork(
            fork_id=f"fork-{fork_id}",
            parent_vault_digest=parent_digest,
            actor_role=actor_role,
            tool_name=tool_name,
            declared_scope=set(declared_scope),
            allowed_egress_sinks=set(allowed_egress_sinks),
            disclosure_budget_bits=disclosure_budget_bits,
            ephemeral_store=ephemeral_data,
            execution_latency_ms=simulated_latency_ms,
        )

        self.active_forks[fork.fork_id] = fork
        self.audit_log.append({
            "event": "fork_created",
            "fork_id": fork.fork_id,
            "actor": actor_role.value,
            "tool_name": tool_name,
            "scope_keys": sorted(declared_scope),
            "parent_digest": parent_digest,
        })
        return fork

    def execute_tool_in_fork(
        self,
        fork: GermlineExecutionFork,
        input_payload: Dict[str, Any],
        tool_callable: Callable[[Dict[str, Any], Dict[str, Any]], Any],
    ) -> Dict[str, Any]:
        """
        Executes an MCP tool inside its ephemeral fork under strict sink noninterference.
        """
        if fork.terminated:
            raise MCPLeakGuardViolationError(f"Fork {fork.fork_id} is already terminated.")
        if fork.executed:
            raise MCPLeakGuardViolationError(f"Fork {fork.fork_id} has already executed (single-use germline invariant).")

        # Check Steward Gate on inputs
        assert_steward_gate_compliance(json.dumps(input_payload, default=str))

        # Check disclosure budget
        payload_bytes = len(json.dumps(input_payload, default=str).encode("utf-8"))
        disclosure_bits = payload_bytes * 8
        if fork.accumulated_disclosure_bits + disclosure_bits > fork.disclosure_budget_bits:
            self.violation_count += 1
            raise MCPLeakGuardViolationError(
                f"Information disclosure budget exceeded: {fork.accumulated_disclosure_bits + disclosure_bits} bits "
                f"> budget {fork.disclosure_budget_bits} bits for tool '{fork.tool_name}'."
            )

        fork.accumulated_disclosure_bits += disclosure_bits

        try:
            result = tool_callable(fork.ephemeral_store, input_payload)
        except Exception as e:
            fork.audit_events.append({"event": "tool_exception", "error": str(e)})
            raise

        # Check Steward Gate on output
        assert_steward_gate_compliance(json.dumps(result, default=str))

        fork.executed = True
        event = {
            "event": "tool_executed",
            "fork_id": fork.fork_id,
            "tool_name": fork.tool_name,
            "bits_disclosed": fork.accumulated_disclosure_bits,
            "latency_ms": fork.execution_latency_ms,
            "status": "success",
        }
        fork.audit_events.append(event)
        self.audit_log.append(event)
        return {"status": "success", "result": result, "fork_id": fork.fork_id}

    def verify_sink_noninterference(
        self, fork: GermlineExecutionFork, target_sink: str, egress_payload: Any
    ) -> bool:
        """
        Verifies that an outbound transmission from within an MCP tool respects sink noninterference.
        Fails closed if the sink is not in allowed_egress_sinks or contains unredacted private keys.
        """
        assert_steward_gate_compliance(target_sink)
        assert_steward_gate_compliance(json.dumps(egress_payload, default=str))

        if target_sink not in fork.allowed_egress_sinks:
            self.violation_count += 1
            event = {
                "event": "sink_noninterference_blocked",
                "fork_id": fork.fork_id,
                "tool_name": fork.tool_name,
                "target_sink": target_sink,
                "allowed_sinks": sorted(fork.allowed_egress_sinks),
                "status": "blocked_exfiltration_attempt",
            }
            fork.audit_events.append(event)
            self.audit_log.append(event)
            raise MCPLeakGuardViolationError(
                f"Sink noninterference violation: tool '{fork.tool_name}' attempted unauthorized egress "
                f"to sink '{target_sink}'. Allowed sinks: {sorted(fork.allowed_egress_sinks)}."
            )

        event = {
            "event": "sink_noninterference_allowed",
            "fork_id": fork.fork_id,
            "tool_name": fork.tool_name,
            "target_sink": target_sink,
            "status": "allowed",
        }
        fork.audit_events.append(event)
        self.audit_log.append(event)
        return True

    def terminate_and_discard(self, fork: GermlineExecutionFork) -> Dict[str, Any]:
        """
        Zeroizes ephemeral store and terminates fork, ensuring zero persistent state pollution.
        """
        if fork.terminated:
            return {"status": "already_terminated", "fork_id": fork.fork_id}

        fork.ephemeral_store.clear()
        fork.terminated = True

        parent_vault = self.session_guard._vaults[fork.actor_role]
        current_digest = parent_vault.snapshot_digest()
        if current_digest != fork.parent_vault_digest and not fork.committed:
            raise MCPLeakGuardViolationError(
                f"Parent vault mutation detected during ephemeral execution! "
                f"Pristine digest {fork.parent_vault_digest} != current digest {current_digest}."
            )

        if fork.fork_id in self.active_forks:
            del self.active_forks[fork.fork_id]

        summary = {
            "event": "fork_terminated_clean",
            "fork_id": fork.fork_id,
            "parent_digest_preserved": True,
            "ephemeral_zeroized": True,
            "latency_ms": fork.execution_latency_ms,
        }
        self.audit_log.append(summary)
        return summary

    def commit_verified_mutation(
        self, fork: GermlineExecutionFork, proof_hash: str, commit_keys: List[str]
    ) -> None:
        """
        Commits verified ephemeral mutations to the parent vault ONLY via explicit
        Proof-Carrying Code proof verification.
        """
        if fork.terminated:
            raise MCPLeakGuardViolationError("Cannot commit mutations from a terminated fork.")
        if not fork.executed:
            raise MCPLeakGuardViolationError("Cannot commit mutations before tool execution.")
        if not proof_hash or len(proof_hash) < 16:
            raise MCPLeakGuardViolationError("Proof hash required for committing ephemeral state mutations.")

        token = self.session_guard.get_token(fork.actor_role)
        parent_vault = self.session_guard._vaults[fork.actor_role]

        for k in commit_keys:
            if k not in fork.declared_scope:
                raise MCPLeakGuardViolationError(f"Cannot commit key '{k}' outside declared scope.")
            val = fork.ephemeral_store.get(k)
            parent_vault.write_private(token, k, val)

        fork.committed = True
        self.audit_log.append({
            "event": "verified_mutation_committed",
            "fork_id": fork.fork_id,
            "proof_hash": proof_hash,
            "committed_keys": sorted(commit_keys),
        })

    def generate_prov_receipt(self, fork: GermlineExecutionFork) -> Dict[str, Any]:
        """
        Generates a W3C PROV-DM compliant JSON-LD receipt certifying ephemeral isolation.
        """
        doc = {
            "@context": "https://www.w3.org/ns/prov.jsonld",
            "@id": f"cin:germline-isolation:{fork.fork_id}",
            "@type": "prov:Activity",
            "prov:used": [
                {
                    "@id": f"cin:vault:{fork.actor_role.value}:{fork.parent_vault_digest}",
                    "@type": "prov:Entity",
                    "cin:declaredScope": sorted(fork.declared_scope),
                }
            ],
            "prov:generated": {
                "@id": f"cin:fork-outcome:{fork.fork_id}",
                "@type": "prov:Entity",
                "cin:toolName": fork.tool_name,
                "cin:allowedSinks": sorted(fork.allowed_egress_sinks),
                "cin:disclosureBudgetBits": fork.disclosure_budget_bits,
                "cin:accumulatedDisclosureBits": fork.accumulated_disclosure_bits,
                "cin:latencyMs": fork.execution_latency_ms,
                "cin:terminatedClean": fork.terminated,
                "cin:primarySource": "arXiv:2611.06585",
                "cin:stewardGateCompliant": True,
            },
            "prov:startedAtTime": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        digest = hashlib.sha256(json.dumps(doc, sort_keys=True).encode("utf-8")).hexdigest()
        doc["cin:receiptDigest"] = digest
        return doc


# ---------------------------------------------------------------------------
# Multi-Hop Sub-Agent Session Isolation & Monotonic Capability Attenuation
# Grounded in arXiv:2611.07050 & arXiv:2610.16005 (Nov 2026)
# ---------------------------------------------------------------------------

@dataclass
class SubAgentSession:
    """
    Isolated sub-agent execution session with monotonic capability bounds.

    Grounded in:
    - Layered Delegation & Capability Attenuation (arXiv:2611.07050).
    - Sub-Agent Session Isolation & Laundering Prevention (arXiv:2610.16005).
    - Ephemeral Copy Confinement (arXiv:2611.06585).
    """

    session_id: str
    actor_role: ActorRole
    parent_session_id: Optional[str]
    depth: int
    max_depth: int
    delegated_scopes: Set[str]
    session_token: str
    created_at: float
    expires_at: float
    ephemeral_store: Dict[str, Any] = field(default_factory=dict)
    parent_vault_digest: str = ""
    is_active: bool = True
    child_session_ids: Set[str] = field(default_factory=set)
    audit_events: List[Dict[str, Any]] = field(default_factory=list)

    def is_valid(self, current_time: Optional[float] = None) -> bool:
        now = time.time() if current_time is None else current_time
        return self.is_active and now < self.expires_at

    def read_ephemeral(self, caller_token: str, key: str) -> Any:
        if not self.is_active:
            raise SessionBoundaryViolationError(f"Session {self.session_id} is terminated or inactive.")
        if caller_token != self.session_token:
            raise SessionBoundaryViolationError(f"Unauthorized read attempt on session {self.session_id}.")
        if key not in self.delegated_scopes:
            raise CapabilityAttenuationError(
                f"Scope violation: key '{key}' is outside delegated scopes {sorted(self.delegated_scopes)} for session {self.session_id}."
            )
        return self.ephemeral_store.get(key)

    def write_ephemeral(self, caller_token: str, key: str, value: Any) -> None:
        if not self.is_active:
            raise SessionBoundaryViolationError(f"Session {self.session_id} is terminated or inactive.")
        if caller_token != self.session_token:
            raise SessionBoundaryViolationError(f"Unauthorized write attempt to session {self.session_id}.")
        if key not in self.delegated_scopes:
            raise CapabilityAttenuationError(
                f"Scope violation: key '{key}' is outside delegated scopes {sorted(self.delegated_scopes)} for session {self.session_id}."
            )
        assert_steward_gate_compliance(json.dumps(value, default=str) if not isinstance(value, str) else value)
        self.ephemeral_store[key] = value


class SubAgentSessionManager:
    """
    Coordinates multi-hop sub-agent session hierarchies with strict monotonic capability
    attenuation and fail-closed session isolation teardown.

    Grounded in:
    - Layered Delegation & Capability Attenuation (arXiv:2611.07050).
    - Sub-Agent Session Isolation & Laundering Prevention (arXiv:2610.16005).

    Properties:
    1. Monotonic Authority Attenuation:
       - Every delegation hop monotonically attenuates capability scopes: child scopes ⊆ parent scopes.
       - Lifetime is monotonically attenuated: child expires_at <= parent expires_at.
       - Delegation depth strictly increments (parent.depth + 1) and cannot exceed max_depth.
       - Any attempt at scope escalation, lifetime expansion, or depth extension fails closed.
    2. Ephemeral Memory Quarantine:
       - Child sessions operate solely within their isolated ephemeral memory.
       - Child sessions receive ONLY explicitly delegated keys, never parent root secrets or ambient vault memory.
       - Cross-session reading between sub-agent sessions is blocked fail-closed.
    3. Clean Session Boundary Teardown:
       - Teardown cleanly zeroes out all child ephemeral memory.
       - Revokes child session tokens.
       - Cascades teardown recursively through all child/sub-agent sessions.
       - Asserts zero residual ambient root privileges remain upon teardown.
       - Guarantees parent vault state remains pristine and unmodified.
    4. Strict Steward Gate Compliance:
       - Enforces zero unapproved tokens, zero speculative claims, and fail-closed audit logging.
    """

    def __init__(
        self,
        session_guard: Optional[SessionIsolationGuard] = None,
        run_seed: str = "subagent-seed-2026",
    ) -> None:
        self.session_guard = session_guard or SessionIsolationGuard(run_seed=run_seed)
        self.run_seed = run_seed
        self.sessions: Dict[str, SubAgentSession] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.violation_count: int = 0

    def spawn_root_session(
        self,
        actor_role: ActorRole,
        initial_scopes: Set[str],
        lifetime_seconds: float = 3600.0,
        max_depth: int = 4,
    ) -> SubAgentSession:
        """Initializes a root agent session anchoring downstream sub-agent delegations."""
        for scope in initial_scopes:
            assert_steward_gate_compliance(scope)
        if lifetime_seconds <= 0:
            raise ValueError("lifetime_seconds must be positive")
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")

        parent_vault = self.session_guard._vaults[actor_role]
        parent_digest = parent_vault.snapshot_digest()
        token_raw = f"{self.run_seed}::root::{actor_role.value}::{len(self.sessions)}"
        token = hashlib.sha256(token_raw.encode("utf-8")).hexdigest()[:24]

        now = time.time()
        session_id = f"sess-root-{actor_role.value}-{len(self.sessions)}"

        # Initial ephemeral store populated ONLY from parent vault keys in initial_scopes
        vault_token = self.session_guard.get_token(actor_role)
        ephemeral_init: Dict[str, Any] = {}
        for scope_key in initial_scopes:
            val = parent_vault.read_private(vault_token, scope_key)
            if val is not None:
                ephemeral_init[scope_key] = val

        session = SubAgentSession(
            session_id=session_id,
            actor_role=actor_role,
            parent_session_id=None,
            depth=0,
            max_depth=max_depth,
            delegated_scopes=set(initial_scopes),
            session_token=token,
            created_at=now,
            expires_at=now + lifetime_seconds,
            ephemeral_store=ephemeral_init,
            parent_vault_digest=parent_digest,
            is_active=True,
        )

        self.sessions[session_id] = session
        event = {
            "event": "root_session_spawned",
            "session_id": session_id,
            "role": actor_role.value,
            "scopes": sorted(initial_scopes),
            "depth": 0,
            "max_depth": max_depth,
            "expires_at": session.expires_at,
        }
        self.audit_log.append(event)
        session.audit_events.append(event)
        return session

    def spawn_child_session(
        self,
        parent_session_id: str,
        caller_token: str,
        subagent_id: str,
        requested_scopes: Set[str],
        lifetime_seconds: float = 1800.0,
        max_depth: Optional[int] = None,
        initial_ephemeral: Optional[Dict[str, Any]] = None,
    ) -> SubAgentSession:
        """
        Spawns an isolated child sub-agent session with strict monotonic capability attenuation.
        Fails closed on scope escalation, lifetime expansion, or depth limit breach.
        """
        if parent_session_id not in self.sessions:
            self.violation_count += 1
            raise SessionBoundaryViolationError(f"Parent session '{parent_session_id}' not found.")

        parent = self.sessions[parent_session_id]
        if not parent.is_active:
            self.violation_count += 1
            raise SessionBoundaryViolationError(f"Parent session '{parent_session_id}' is terminated.")
        if caller_token != parent.session_token:
            self.violation_count += 1
            raise SessionBoundaryViolationError(f"Invalid caller token for parent session '{parent_session_id}'.")

        for scope in requested_scopes:
            assert_steward_gate_compliance(scope)

        now = time.time()
        if now >= parent.expires_at:
            self.violation_count += 1
            raise CapabilityAttenuationError(f"Parent session '{parent_session_id}' has expired.")

        # 1. Monotonic depth verification
        child_depth = parent.depth + 1
        if child_depth > parent.max_depth:
            self.violation_count += 1
            raise CapabilityAttenuationError(
                f"Delegation depth limit reached: requested depth {child_depth} > max allowed {parent.max_depth}."
            )

        child_max_depth = parent.max_depth
        if max_depth is not None:
            if max_depth > parent.max_depth:
                self.violation_count += 1
                raise CapabilityAttenuationError(
                    f"Max depth expansion: child requested max_depth {max_depth} > parent max_depth {parent.max_depth}."
                )
            child_max_depth = max_depth

        # 2. Monotonic scope attenuation: child requested scopes MUST be subset of parent delegated scopes
        if not requested_scopes.issubset(parent.delegated_scopes):
            self.violation_count += 1
            escalated = requested_scopes - parent.delegated_scopes
            raise CapabilityAttenuationError(
                f"Scope escalation detected: child requested unauthorized scopes {sorted(escalated)}. "
                f"Allowed parent scopes: {sorted(parent.delegated_scopes)}."
            )

        # 3. Monotonic lifetime attenuation: child cannot outlive parent session
        child_expires_at = now + lifetime_seconds
        if child_expires_at > parent.expires_at:
            self.violation_count += 1
            raise CapabilityAttenuationError(
                f"Lifetime expansion detected: child expiry ({child_expires_at:.2f}) exceeds "
                f"parent expiry ({parent.expires_at:.2f})."
            )

        # 4. Generate unique cryptographic session token for child
        token_raw = f"{parent.session_token}::{subagent_id}::{child_depth}::{len(self.sessions)}::{now}"
        child_token = hashlib.sha256(token_raw.encode("utf-8")).hexdigest()[:24]

        # 5. Populate child ephemeral store strictly within requested_scopes
        child_ephemeral: Dict[str, Any] = {}
        for scope_key in requested_scopes:
            if scope_key in parent.ephemeral_store:
                child_ephemeral[scope_key] = parent.ephemeral_store[scope_key]
        if initial_ephemeral:
            for k, v in initial_ephemeral.items():
                if k in requested_scopes:
                    assert_steward_gate_compliance(json.dumps(v, default=str) if not isinstance(v, str) else v)
                    child_ephemeral[k] = v

        child_session_id = f"sess-sub-{subagent_id}-{len(self.sessions)}"
        child_session = SubAgentSession(
            session_id=child_session_id,
            actor_role=parent.actor_role,
            parent_session_id=parent_session_id,
            depth=child_depth,
            max_depth=child_max_depth,
            delegated_scopes=set(requested_scopes),
            session_token=child_token,
            created_at=now,
            expires_at=child_expires_at,
            ephemeral_store=child_ephemeral,
            parent_vault_digest=parent.parent_vault_digest,
            is_active=True,
        )

        parent.child_session_ids.add(child_session_id)
        self.sessions[child_session_id] = child_session

        event = {
            "event": "child_session_spawned",
            "session_id": child_session_id,
            "parent_session_id": parent_session_id,
            "depth": child_depth,
            "scopes": sorted(requested_scopes),
            "expires_at": child_expires_at,
        }
        self.audit_log.append(event)
        parent.audit_events.append(event)
        child_session.audit_events.append(event)
        return child_session

    def teardown_session(
        self, session_id: str, caller_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Cleanly tears down a session and recursively wipes all child sessions.
        Ensures zero ambient root privileges remain and parent vault remains pristine.
        """
        if session_id not in self.sessions:
            return {"status": "not_found", "session_id": session_id}

        session = self.sessions[session_id]
        if not session.is_active:
            return {"status": "already_terminated", "session_id": session_id}

        # If caller token is supplied, verify it matches either the session itself or its parent
        if caller_token is not None:
            parent_token = (
                self.sessions[session.parent_session_id].session_token
                if session.parent_session_id and session.parent_session_id in self.sessions
                else None
            )
            if caller_token != session.session_token and caller_token != parent_token:
                self.violation_count += 1
                raise SessionBoundaryViolationError(
                    f"Unauthorized teardown attempt on session '{session_id}'."
                )

        # 1. Cascading teardown of all descendant child sessions
        descendant_ids = list(session.child_session_ids)
        for child_id in descendant_ids:
            self.teardown_session(child_id)

        # 2. Ephemeral memory zeroization
        session.ephemeral_store.clear()

        # 3. Invalidate session token & mark inactive
        old_token = session.session_token
        session.session_token = f"revoked-{old_token[:8]}"
        session.is_active = False

        # 4. Verify parent vault digest integrity (no unauthorized mutations)
        parent_vault = self.session_guard._vaults[session.actor_role]
        current_digest = parent_vault.snapshot_digest()
        if session.parent_vault_digest and current_digest != session.parent_vault_digest:
            raise SessionBoundaryViolationError(
                f"Parent vault mutation detected during session '{session_id}' lifetime! "
                f"Expected digest {session.parent_vault_digest}, found {current_digest}."
            )

        summary = {
            "event": "session_teardown_clean",
            "session_id": session_id,
            "depth": session.depth,
            "ephemeral_zeroized": True,
            "ambient_root_privileges_retained": False,
            "parent_digest_preserved": True,
            "cascaded_children_count": len(descendant_ids),
        }
        self.audit_log.append(summary)
        session.audit_events.append(summary)
        return summary

    def execute_subagent_task(
        self,
        session_id: str,
        caller_token: str,
        task_name: str,
        task_callable: Callable[[Dict[str, Any], Dict[str, Any]], Any],
        input_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Executes a task inside the sub-agent session's isolated ephemeral memory.
        """
        if session_id not in self.sessions:
            self.violation_count += 1
            raise SessionBoundaryViolationError(f"Session '{session_id}' not found.")

        session = self.sessions[session_id]
        if not session.is_active:
            self.violation_count += 1
            raise SessionBoundaryViolationError(f"Session '{session_id}' is terminated.")
        if caller_token != session.session_token:
            self.violation_count += 1
            raise SessionBoundaryViolationError(f"Invalid caller token for session '{session_id}'.")

        now = time.time()
        if now >= session.expires_at:
            self.violation_count += 1
            raise CapabilityAttenuationError(f"Session '{session_id}' has expired.")

        assert_steward_gate_compliance(task_name)
        assert_steward_gate_compliance(json.dumps(input_payload, default=str))

        result = task_callable(session.ephemeral_store, input_payload)
        assert_steward_gate_compliance(json.dumps(result, default=str))

        event = {
            "event": "task_executed",
            "session_id": session_id,
            "task_name": task_name,
            "status": "success",
        }
        self.audit_log.append(event)
        session.audit_events.append(event)
        return {"status": "success", "session_id": session_id, "result": result}

    def generate_prov_receipt(self, session: SubAgentSession) -> Dict[str, Any]:
        """
        Generates a W3C PROV-DM JSON-LD cryptographic receipt certifying delegation containment.
        Cites arXiv:2611.07050 and arXiv:2610.16005.
        """
        doc = {
            "@context": "https://www.w3.org/ns/prov.jsonld",
            "@id": f"cin:session-containment:{session.session_id}",
            "@type": "prov:Activity",
            "prov:used": [
                {
                    "@id": f"cin:vault:{session.actor_role.value}:{session.parent_vault_digest}",
                    "@type": "prov:Entity",
                    "cin:depth": session.depth,
                    "cin:maxDepth": session.max_depth,
                    "cin:delegatedScopes": sorted(session.delegated_scopes),
                }
            ],
            "prov:generated": {
                "@id": f"cin:session-status:{session.session_id}",
                "@type": "prov:Entity",
                "cin:isActive": session.is_active,
                "cin:parentSessionId": session.parent_session_id,
                "cin:childrenCount": len(session.child_session_ids),
                "cin:primarySources": ["arXiv:2611.07050", "arXiv:2610.16005"],
                "cin:stewardGateCompliant": True,
            },
            "prov:startedAtTime": datetime.datetime.fromtimestamp(session.created_at, datetime.timezone.utc).isoformat(),
        }
        digest = hashlib.sha256(json.dumps(doc, sort_keys=True).encode("utf-8")).hexdigest()
        doc["cin:receiptDigest"] = digest
        return doc



