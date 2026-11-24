"""
research/ledger_sim/federated_agentca_trust_sim.py

Federated Peer Certificate Authority (AgentCA) Cross-Organization Trust &
Voluntary Polycentric Migration Simulation.

Grounded in:
- Viet K. Nguyen & Mohammad I. Husain (arXiv:2611.23202, November 2026):
  "Agent Trust Infrastructure (ATI): A Federated Identity, Trust, Attestation,
  and Accountability Architecture for Cross-Organization Autonomous AI Agents".
  Evaluates an 8-organization, 6-framework federation (5-agent teams per org)
  across 14 attack scenarios and 6 benign tasks: federated peer organizational
  certificate authorities (AgentCAs), IETF WIMSE workload tokens, Entity
  Attestation Tokens (EAT) for model/tool/prompt integrity, and 3 authorization
  policy checks raise attack containment from 43% to 84% at ~174 microseconds
  overhead per request without a shared root authority.
- IETF RFC 9334 (Birkholz et al., January 2023):
  "Remote ATtestation procedureS (RATS) Architecture".
- IETF WIMSE (Salowey et al., draft-ietf-wimse-identifier, 2026):
  "Workload Identifier".
- Elinor Ostrom (American Economic Review 2010, 100(3): 641-672,
  doi:10.1257/aer.100.3.641):
  "Beyond Markets and States: Polycentric Governance of Complex Economic Systems".

Methodological Guardrails (simulation-capital-conservation-rng runbook):
1. Pre-sampled workload & audit randomness (`rng_phase_drift == 0.0`): all
   request arrivals, adversarial attack variations, central-root congestion
   draws, and three-stage verification uniforms are sampled upfront during
   workload generation using an isolated `random.Random(seed)` instance.
2. Strict integer-cent capital conservation (`capital_conservation_delta_cents == 0`):
   every cross-organization task posts an integer-cent escrow bond (`_cents`).
   Verified benign completions settle to the responder (minus any central root
   gatekeeper toll in the root-monopoly regime); contained attacks slash the
   requester bond to the responder defense reserve; uncontained attacks drain
   responder collateral to the attacker account. No cents are ever created or
   destroyed.
3. Endogenous voluntary migration (Lesson 52): organizations evaluate empirical
   trailing net utility (settlement surplus minus central root tolls, downtime
   queue losses, and uncontained breach losses) to decide whether to stay in a
   centralized root monopoly or migrate voluntarily to the polycentric peer
   AgentCA federation.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import math
import random
import re
from typing import Any, Dict, List, Sequence, Tuple


# =====================================================================
# Exceptions & Steward Gate
# =====================================================================

class AgentCASimulationError(Exception):
    """Base exception for federated AgentCA simulation validation errors."""


class AgentCAValidationError(AgentCASimulationError):
    """Raised when configuration, numeric types, or discrete supports fail validation."""


class StewardGateViolationError(AgentCASimulationError):
    """Raised when forbidden token tickers, financial promises, or sci-fi lore appear."""


FORBIDDEN_PATTERNS = [
    re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE),
    re.compile(r"\bMMCT\b", re.IGNORECASE),
    re.compile(r"\b85/10/5\b"),
    re.compile(r"\bguaranteed\s+(?:returns?|yields?|profits?|savings?)\b", re.IGNORECASE),
    re.compile(r"\bpassive\s+income\b", re.IGNORECASE),
    re.compile(r"\bgalactic\b", re.IGNORECASE),
    re.compile(r"\bhyperdrive\b", re.IGNORECASE),
]


def screen_steward_gate(text: str) -> None:
    """Enforce CIN Steward Gate invariants on string identifiers and payloads."""
    if not isinstance(text, str):
        raise AgentCAValidationError("Expected string payload for Steward Gate screening.")
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(
                f"Payload violated CIN Steward Gate invariants: matched '{pattern.pattern}'"
            )


def _require_strict_int(val: Any, name: str, min_value: int | None = None) -> int:
    if type(val) is not int or isinstance(val, bool):
        raise AgentCAValidationError(f"{name} must be a strict int (not bool), got {val!r}")
    if min_value is not None and val < min_value:
        raise AgentCAValidationError(f"{name} must be >= {min_value}, got {val}")
    return val


def _require_finite_rate(val: Any, name: str, low: float = 0.0, high: float = 1.0) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise AgentCAValidationError(f"{name} must be a finite float, got {val!r}")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval) or fval < low or fval > high:
        raise AgentCAValidationError(f"{name} must be in [{low}, {high}], got {val!r}")
    return fval


# =====================================================================
# Enums & Data Structures
# =====================================================================

class FederationRegime(str, enum.Enum):
    """Cross-organization trust and verification regime."""
    UNVERIFIED_DIRECT_TRUST = "UNVERIFIED_DIRECT_TRUST"
    CENTRALIZED_ROOT_MONOPOLY = "CENTRALIZED_ROOT_MONOPOLY"
    POLYCENTRIC_PEER_AGENTCA = "POLYCENTRIC_PEER_AGENTCA"


SUPPORTED_FRAMEWORKS: Tuple[str, ...] = (
    "autogen",
    "crewai",
    "langgraph",
    "llama_index",
    "semantic_kernel",
    "pydantic_ai",
)

# 14 attack scenarios + 6 benign tasks from Nguyen & Husain (arXiv:2611.23202)
ATTACK_SCENARIOS: Tuple[str, ...] = (
    "spoofed_org_certificate",
    "expired_workload_token",
    "unapproved_model_swap",
    "tampered_system_prompt",
    "injected_shadow_tool",
    "cross_org_privilege_escalation",
    "replayed_capability_grant",
    "delegation_scope_widening",
    "forged_eat_attestation",
    "untrusted_framework_adapter",
    "exfiltration_via_tool_chain",
    "unauthorized_db_mutation",
    "confused_deputy_handoff",
    "cross_tenant_memory_probe",
)

BENIGN_TASKS: Tuple[str, ...] = (
    "clinical_referral_triage",
    "supply_chain_inventory_check",
    "regional_grid_load_forecast",
    "civic_record_redaction_audit",
    "cooperative_order_settlement",
    "disaster_dispatch_coordination",
)


@dataclasses.dataclass(frozen=True)
class FederationSimConfig:
    """Validated parameters for the 8-organization, 6-framework AgentCA federation simulation."""
    num_orgs: int = 8
    num_frameworks: int = 6
    agents_per_org: int = 5
    num_requests: int = 240
    seed: int = 42
    initial_org_treasury_cents: int = 500_000
    task_bond_cents: int = 1_200
    task_surplus_cents: int = 1_800
    breach_damage_cents: int = 2_400
    central_root_toll_cents: int = 250
    attack_fraction: float = 0.35
    baseline_containment_rate: float = 0.43
    central_root_containment_rate: float = 0.61
    agentca_containment_rate: float = 0.84
    central_root_outage_rate: float = 0.14
    peer_verify_overhead_us: int = 174
    central_root_latency_us: int = 18_500

    def __post_init__(self) -> None:
        _require_strict_int(self.num_orgs, "num_orgs", min_value=2)
        _require_strict_int(self.num_frameworks, "num_frameworks", min_value=1)
        _require_strict_int(self.agents_per_org, "agents_per_org", min_value=1)
        _require_strict_int(self.num_requests, "num_requests", min_value=10)
        _require_strict_int(self.seed, "seed", min_value=0)
        _require_strict_int(self.initial_org_treasury_cents, "initial_org_treasury_cents", min_value=10_000)
        _require_strict_int(self.task_bond_cents, "task_bond_cents", min_value=100)
        _require_strict_int(self.task_surplus_cents, "task_surplus_cents", min_value=100)
        _require_strict_int(self.breach_damage_cents, "breach_damage_cents", min_value=100)
        _require_strict_int(self.central_root_toll_cents, "central_root_toll_cents", min_value=0)
        _require_strict_int(self.peer_verify_overhead_us, "peer_verify_overhead_us", min_value=1)
        _require_strict_int(self.central_root_latency_us, "central_root_latency_us", min_value=1)
        if self.num_orgs < self.num_frameworks:
            raise AgentCAValidationError(
                f"num_orgs ({self.num_orgs}) must be >= num_frameworks ({self.num_frameworks})"
            )
        if self.num_frameworks > len(SUPPORTED_FRAMEWORKS):
            raise AgentCAValidationError(
                f"num_frameworks ({self.num_frameworks}) exceeds supported frameworks ({len(SUPPORTED_FRAMEWORKS)})"
            )
        if self.central_root_toll_cents >= self.task_surplus_cents:
            raise AgentCAValidationError("central_root_toll_cents must be < task_surplus_cents")
        _require_finite_rate(self.attack_fraction, "attack_fraction", 0.0, 1.0)
        _require_finite_rate(self.baseline_containment_rate, "baseline_containment_rate", 0.0, 1.0)
        _require_finite_rate(self.central_root_containment_rate, "central_root_containment_rate", 0.0, 1.0)
        _require_finite_rate(self.agentca_containment_rate, "agentca_containment_rate", 0.0, 1.0)
        _require_finite_rate(self.central_root_outage_rate, "central_root_outage_rate", 0.0, 1.0)


@dataclasses.dataclass(frozen=True)
class CrossOrgRequestItem:
    """Pre-sampled cross-organization agent request to guarantee zero RNG phase drift."""
    request_id: int
    source_org_id: int
    target_org_id: int
    source_agent_id: str
    target_agent_id: str
    framework: str
    is_attack: int
    scenario_name: str
    bond_cents: int
    surplus_cents: int
    breach_damage_cents: int
    u_containment_draw: float
    u_root_outage_draw: float
    u_cert_check_draw: float
    u_eat_check_draw: float
    u_policy_check_draw: float
    wimse_token_digest: str
    eat_config_digest: str

    def __post_init__(self) -> None:
        _require_strict_int(self.request_id, "request_id", min_value=0)
        _require_strict_int(self.source_org_id, "source_org_id", min_value=0)
        _require_strict_int(self.target_org_id, "target_org_id", min_value=0)
        if self.source_org_id == self.target_org_id:
            raise AgentCAValidationError("Cross-org request requires distinct source and target orgs")
        _require_strict_int(self.is_attack, "is_attack", min_value=0)
        if self.is_attack not in (0, 1):
            raise AgentCAValidationError(f"is_attack must be 0 or 1, got {self.is_attack!r}")
        _require_strict_int(self.bond_cents, "bond_cents", min_value=1)
        _require_strict_int(self.surplus_cents, "surplus_cents", min_value=1)
        _require_strict_int(self.breach_damage_cents, "breach_damage_cents", min_value=1)
        _require_finite_rate(self.u_containment_draw, "u_containment_draw", 0.0, 1.0)
        _require_finite_rate(self.u_root_outage_draw, "u_root_outage_draw", 0.0, 1.0)
        _require_finite_rate(self.u_cert_check_draw, "u_cert_check_draw", 0.0, 1.0)
        _require_finite_rate(self.u_eat_check_draw, "u_eat_check_draw", 0.0, 1.0)
        _require_finite_rate(self.u_policy_check_draw, "u_policy_check_draw", 0.0, 1.0)
        screen_steward_gate(self.scenario_name)
        screen_steward_gate(self.framework)


@dataclasses.dataclass(frozen=True)
class RegimeEvalResult:
    """Aggregate metrics and conservation proofs for a single federation regime."""
    regime: str
    num_orgs: int
    num_requests: int
    total_attacks: int
    contained_attacks: int
    uncontained_breaches: int
    attack_containment_rate: float
    benign_completed: int
    benign_dropped_outage: int
    mean_verify_overhead_us: float
    initial_total_capital_cents: int
    final_total_capital_cents: int
    capital_conservation_delta_cents: int
    total_root_tolls_paid_cents: int
    total_slashed_bonds_cents: int
    total_breach_losses_cents: int
    net_federation_surplus_cents: int
    voluntary_polycentric_adoption_rate: float
    rng_Terminal_probe: float


# =====================================================================
# Workload Generation (Decoupled from Regime Execution)
# =====================================================================

def generate_cross_org_workload(
    config: FederationSimConfig,
) -> Tuple[List[CrossOrgRequestItem], float]:
    """Pre-sample the entire cross-organization request stream from an isolated RNG."""
    if not isinstance(config, FederationSimConfig):
        raise AgentCAValidationError("config must be a FederationSimConfig instance")
    rng = random.Random(config.seed)
    frameworks = SUPPORTED_FRAMEWORKS[: config.num_frameworks]
    org_frameworks = [frameworks[i % len(frameworks)] for i in range(config.num_orgs)]

    items: List[CrossOrgRequestItem] = []
    for req_id in range(config.num_requests):
        src_org = rng.randrange(config.num_orgs)
        offset = 1 + rng.randrange(config.num_orgs - 1)
        dst_org = (src_org + offset) % config.num_orgs
        src_agent_idx = rng.randrange(config.agents_per_org)
        dst_agent_idx = rng.randrange(config.agents_per_org)

        u_attack = rng.random()
        is_attack = 1 if u_attack < config.attack_fraction else 0
        if is_attack == 1:
            scenario = ATTACK_SCENARIOS[rng.randrange(len(ATTACK_SCENARIOS))]
        else:
            scenario = BENIGN_TASKS[rng.randrange(len(BENIGN_TASKS))]

        u_contain = rng.random()
        u_outage = rng.random()
        u_cert = rng.random()
        u_eat = rng.random()
        u_pol = rng.random()

        wimse_uri = f"wimse://org-{src_org}.agentca.local/workload/agent-{src_agent_idx}/req-{req_id}"
        wimse_digest = hashlib.sha256(wimse_uri.encode("utf-8")).hexdigest()[:16]
        eat_payload = f"eat:org={src_org}:fw={org_frameworks[src_org]}:scenario={scenario}:attack={is_attack}"
        eat_digest = hashlib.sha256(eat_payload.encode("utf-8")).hexdigest()[:16]

        items.append(
            CrossOrgRequestItem(
                request_id=req_id,
                source_org_id=src_org,
                target_org_id=dst_org,
                source_agent_id=f"org{src_org}_agent{src_agent_idx}",
                target_agent_id=f"org{dst_org}_agent{dst_agent_idx}",
                framework=org_frameworks[src_org],
                is_attack=is_attack,
                scenario_name=scenario,
                bond_cents=config.task_bond_cents,
                surplus_cents=config.task_surplus_cents,
                breach_damage_cents=config.breach_damage_cents,
                u_containment_draw=u_contain,
                u_root_outage_draw=u_outage,
                u_cert_check_draw=u_cert,
                u_eat_check_draw=u_eat,
                u_policy_check_draw=u_pol,
                wimse_token_digest=wimse_digest,
                eat_config_digest=eat_digest,
            )
        )

    terminal_probe = rng.random()
    return items, terminal_probe


# =====================================================================
# Regime Execution Engine (Zero Internal RNG Calls)
# =====================================================================

def evaluate_federation_regime(
    config: FederationSimConfig,
    regime: FederationRegime | str,
    workload: Sequence[CrossOrgRequestItem] | None = None,
    terminal_probe: float | None = None,
) -> RegimeEvalResult:
    """Evaluate a single cross-organization trust regime with strict capital conservation."""
    if not isinstance(config, FederationSimConfig):
        raise AgentCAValidationError("config must be a FederationSimConfig instance")
    if isinstance(regime, str):
        try:
            regime_enum = FederationRegime(regime)
        except ValueError as exc:
            raise AgentCAValidationError(f"Unsupported regime: {regime!r}") from exc
    elif isinstance(regime, FederationRegime):
        regime_enum = regime
    else:
        raise AgentCAValidationError(f"Unsupported regime type: {regime!r}")

    if workload is None or terminal_probe is None:
        workload, terminal_probe = generate_cross_org_workload(config)

    # Accounts in integer cents:
    # 1. org_treasuries[0..num_orgs-1]: each starts with initial_org_treasury_cents
    # 2. task_value_pool_cents: pre-funded commons pool paying task_surplus_cents on benign completions
    # 3. central_root_operator_cents: collects central_root_toll_cents
    # 4. external_attacker_loot_cents: collects uncontained breach damage
    # 5. defense_reserve_cents: collects slashed attacker bonds
    org_treasuries: List[int] = [config.initial_org_treasury_cents for _ in range(config.num_orgs)]
    task_value_pool_cents: int = len(workload) * config.task_surplus_cents
    central_root_operator_cents: int = 0
    external_attacker_loot_cents: int = 0
    defense_reserve_cents: int = 0

    initial_total_capital_cents = sum(org_treasuries) + task_value_pool_cents

    total_attacks = 0
    contained_attacks = 0
    uncontained_breaches = 0
    benign_completed = 0
    benign_dropped_outage = 0
    total_root_tolls_paid_cents = 0
    total_slashed_bonds_cents = 0
    total_breach_losses_cents = 0
    overhead_samples_us: List[int] = []

    # Track per-org cumulative net utility delta for endogenous voluntary migration (Lesson 52)
    org_initial_snapshot = list(org_treasuries)
    org_outage_drops = [0 for _ in range(config.num_orgs)]
    org_tolls_paid = [0 for _ in range(config.num_orgs)]
    org_uncontained_hits = [0 for _ in range(config.num_orgs)]

    for item in workload:
        src = item.source_org_id
        dst = item.target_org_id

        # Indivisible cash-exhaustion check: requester must be able to post the bond
        if org_treasuries[src] < item.bond_cents:
            continue

        # Step 1: Lock requester bond in escrow
        org_treasuries[src] -= item.bond_cents
        escrow_bond_cents = item.bond_cents

        # Step 2: Determine verification latency and central-root availability
        if regime_enum is FederationRegime.UNVERIFIED_DIRECT_TRUST:
            overhead_samples_us.append(12)
            containment_threshold = config.baseline_containment_rate
        elif regime_enum is FederationRegime.CENTRALIZED_ROOT_MONOPOLY:
            overhead_samples_us.append(config.central_root_latency_us)
            # Central root chokepoint can suffer congestion/outage
            if item.u_root_outage_draw < config.central_root_outage_rate:
                # Refund escrow bond cleanly; request fails to clear
                org_treasuries[src] += escrow_bond_cents
                escrow_bond_cents = 0
                if item.is_attack == 0:
                    benign_dropped_outage += 1
                    org_outage_drops[src] += 1
                else:
                    total_attacks += 1
                    contained_attacks += 1
                continue
            containment_threshold = config.central_root_containment_rate
        else:
            # POLYCENTRIC_PEER_AGENTCA: 174 microseconds peer AgentCA + WIMSE + EAT + 3 policy checks
            overhead_samples_us.append(config.peer_verify_overhead_us)
            containment_threshold = config.agentca_containment_rate

        # Step 3: Process attack vs benign task
        if item.is_attack == 1:
            total_attacks += 1
            # In POLYCENTRIC_PEER_AGENTCA, three pre-execution checks run (AgentCA cert, EAT digest, 3 policy checks)
            is_contained = item.u_containment_draw < containment_threshold
            if is_contained:
                contained_attacks += 1
                if regime_enum is FederationRegime.UNVERIFIED_DIRECT_TRUST:
                    # Framework-level refusal without cryptographic bond slashing: return bond
                    org_treasuries[src] += escrow_bond_cents
                    escrow_bond_cents = 0
                else:
                    # Slash attacker bond into the responder/federation defense reserve
                    defense_reserve_cents += escrow_bond_cents
                    total_slashed_bonds_cents += escrow_bond_cents
                    escrow_bond_cents = 0
            else:
                uncontained_breaches += 1
                org_uncontained_hits[dst] += 1
                # Attacker reclaims its bond and extracts breach damage from target org (bounded by target treasury)
                org_treasuries[src] += escrow_bond_cents
                escrow_bond_cents = 0
                actual_damage = min(org_treasuries[dst], item.breach_damage_cents)
                org_treasuries[dst] -= actual_damage
                external_attacker_loot_cents += actual_damage
                total_breach_losses_cents += actual_damage
        else:
            # Benign cross-organization task completion
            benign_completed += 1
            # Return requester's bond
            org_treasuries[src] += escrow_bond_cents
            escrow_bond_cents = 0

            # Disburse task surplus from pre-funded task value pool
            task_value_pool_cents -= item.surplus_cents
            gross_surplus = item.surplus_cents

            if regime_enum is FederationRegime.CENTRALIZED_ROOT_MONOPOLY:
                toll = min(gross_surplus, config.central_root_toll_cents)
                central_root_operator_cents += toll
                total_root_tolls_paid_cents += toll
                org_tolls_paid[src] += toll
                net_surplus = gross_surplus - toll
            else:
                net_surplus = gross_surplus

            # Split net surplus evenly between collaborating source and target orgs
            src_share = net_surplus // 2
            dst_share = net_surplus - src_share
            org_treasuries[src] += src_share
            org_treasuries[dst] += dst_share

        # Step-level conservation invariant check
        step_total = (
            sum(org_treasuries)
            + task_value_pool_cents
            + central_root_operator_cents
            + external_attacker_loot_cents
            + defense_reserve_cents
        )
        if step_total != initial_total_capital_cents:
            raise AgentCASimulationError(
                f"Capital conservation violated at request {item.request_id}: "
                f"expected {initial_total_capital_cents}, got {step_total}"
            )

    final_total_capital_cents = (
        sum(org_treasuries)
        + task_value_pool_cents
        + central_root_operator_cents
        + external_attacker_loot_cents
        + defense_reserve_cents
    )
    conservation_delta = final_total_capital_cents - initial_total_capital_cents

    containment_rate = (
        round(contained_attacks / total_attacks, 4) if total_attacks > 0 else 1.0
    )
    mean_overhead_us = (
        round(sum(overhead_samples_us) / len(overhead_samples_us), 2)
        if overhead_samples_us
        else 0.0
    )

    # Endogenous voluntary migration metric (Lesson 52):
    # Each organization evaluates whether its experienced friction (root tolls + outage losses + breach losses)
    # exceeds the zero-toll peer AgentCA threshold, or whether it already enjoys positive surplus in AgentCA.
    migrating_or_retained_orgs = 0
    for org_idx in range(config.num_orgs):
        net_org_gain = org_treasuries[org_idx] - org_initial_snapshot[org_idx]
        experienced_friction_cents = (
            org_tolls_paid[org_idx]
            + org_outage_drops[org_idx] * (config.task_surplus_cents // 2)
            + org_uncontained_hits[org_idx] * config.breach_damage_cents
        )
        if regime_enum is FederationRegime.POLYCENTRIC_PEER_AGENTCA:
            if net_org_gain > 0 and experienced_friction_cents < net_org_gain:
                migrating_or_retained_orgs += 1
        else:
            # In unverified or root-monopoly regimes, orgs voluntarily exit toward polycentric AgentCA
            # when experienced tolls/outages/breaches erode their cooperative surplus.
            if experienced_friction_cents > (config.task_surplus_cents * 2):
                migrating_or_retained_orgs += 1

    adoption_rate = round(migrating_or_retained_orgs / config.num_orgs, 4)
    net_federation_surplus_cents = (
        sum(org_treasuries) + defense_reserve_cents - sum(org_initial_snapshot)
    )

    return RegimeEvalResult(
        regime=regime_enum.value,
        num_orgs=config.num_orgs,
        num_requests=config.num_requests,
        total_attacks=total_attacks,
        contained_attacks=contained_attacks,
        uncontained_breaches=uncontained_breaches,
        attack_containment_rate=containment_rate,
        benign_completed=benign_completed,
        benign_dropped_outage=benign_dropped_outage,
        mean_verify_overhead_us=mean_overhead_us,
        initial_total_capital_cents=initial_total_capital_cents,
        final_total_capital_cents=final_total_capital_cents,
        capital_conservation_delta_cents=conservation_delta,
        total_root_tolls_paid_cents=total_root_tolls_paid_cents,
        total_slashed_bonds_cents=total_slashed_bonds_cents,
        total_breach_losses_cents=total_breach_losses_cents,
        net_federation_surplus_cents=net_federation_surplus_cents,
        voluntary_polycentric_adoption_rate=adoption_rate,
        rng_Terminal_probe=float(terminal_probe),
    )


def run_three_regime_comparison(
    config: FederationSimConfig | None = None,
) -> Dict[str, Any]:
    """Compare all three cross-organization trust regimes on an identical pre-sampled workload."""
    cfg = config or FederationSimConfig()
    workload, probe_base = generate_cross_org_workload(cfg)

    results: Dict[str, RegimeEvalResult] = {}
    probes: List[float] = []
    for reg in (
        FederationRegime.UNVERIFIED_DIRECT_TRUST,
        FederationRegime.CENTRALIZED_ROOT_MONOPOLY,
        FederationRegime.POLYCENTRIC_PEER_AGENTCA,
    ):
        res = evaluate_federation_regime(cfg, reg, workload=workload, terminal_probe=probe_base)
        results[reg.value] = res
        probes.append(res.rng_Terminal_probe)

    rng_phase_drift = max(probes) - min(probes) if probes else 0.0
    max_conservation_delta = max(
        abs(r.capital_conservation_delta_cents) for r in results.values()
    )

    return {
        "seed": cfg.seed,
        "num_orgs": cfg.num_orgs,
        "num_frameworks": cfg.num_frameworks,
        "agents_per_org": cfg.agents_per_org,
        "num_requests": cfg.num_requests,
        "rng_phase_drift": rng_phase_drift,
        "capital_conservation_delta_cents": max_conservation_delta,
        "regimes": {k: dataclasses.asdict(v) for k, v in results.items()},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simulate federated peer AgentCA cross-organization trust vs root monopolies."
    )
    parser.add_argument("--simulate", action="store_true", help="Run three-regime comparison")
    parser.add_argument("--requests", type=int, default=240, help="Number of cross-org requests")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed")
    args = parser.parse_args(argv)

    cfg = FederationSimConfig(num_requests=args.requests, seed=args.seed)
    summary = run_three_regime_comparison(cfg)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
