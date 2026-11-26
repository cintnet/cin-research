"""
research/ledger_sim/polycentric_research_anti_convergence_sim.py

Polycentric Research Anti-Convergence, Human-Dyad Problem Taste &
SCITT Execution-Evidence Simulation.

Grounded in:
- Jason Fantl, Averroes Labs (https://averroeslabs.org/blog/many-agents-few-projects/,
  18 November 2026):
  "Many Agents, Few Projects: Measuring and Reducing Convergence in AI Research
  Agents' Choice of Safety Research". Across 120 combinations of four frontier
  models, 11 launch prompts, and harnesses searching 100,000 safety papers,
  two autonomous agents picked at random choose the same project ~1 time in 60
  (~60 effective projects) versus ~1 in 530 at human hackathons (~8.8x higher
  collision rate; ~1 in 35 within one lab), with 85% crowding onto two agendas
  until a shared claim registry or weighted random sampling spreads choices out.
- Shanshan Zhong, Chen Xu, Jingjie Ning, Zhengzhong Liu, Aviral Kumar, and
  Chenyan Xiong (arXiv:2611.03424, November 2026):
  "IdeaTaste: Do LLMs Share the Research Taste of Human Researchers?". Evaluates
  over 90,000 research proposals across six language models and four fields
  frozen at 2025 against actual 2026 publications, finding LLM populations reach
  only 26% of human community citation matching and 18% of concrete idea
  matching, with non-overlapping AI proposals scoring worst in blind expert review.
- Liwei Jiang, Yuanjun Chai, Margaret Li, Mickel Liu, Raymond Fok, Nouha Dziri,
  Yulia Tsvetkov, Maarten Sap, Alon Albalak, and Yejin Choi (arXiv:2510.22954):
  "Artificial Hivemind: The Open-Ended Homogeneity of Language Models (and Beyond)".
  Across 26,000 open-ended queries and 31,250 human annotations (Infinity-Chat),
  documents intra-model repetition, cross-model homogeneity, and LM-judge
  miscalibration on pluralistic human preferences.
- Shameer Thaha and Shaibi Shamsudeen
  (https://datatracker.ietf.org/doc/draft-thaha-scitt-agent-execution-evidence/,
  draft-thaha-scitt-agent-execution-evidence-02, November 2026):
  "Agent Execution Evidence: A SCITT Profile for Verifiable Records of AI Agent Runs".
  Binds registered agent identity, declared capabilities, and supervised
  operational status to a hash-chained log of model and tool calls plus
  cross-operator admission records for offline audit without raw transcript dumps.
- Elinor Ostrom (American Economic Review 2010, 100(3): 641-672,
  doi:10.1257/aer.100.3.641):
  "Beyond Markets and States: Polycentric Governance of Complex Economic Systems".

Methodological Guardrails (simulation-capital-conservation-rng runbook):
1. Pre-sampled workload & audit randomness (`rng_phase_drift == 0.0`): all
   research proposal episodes, synthetic crowding draws, polycentric registry
   slot assignments, human-vs-synthetic viability draws, and unattested/spoofed
   execution draws are sampled upfront during workload generation using an
   isolated `random.Random(seed)` instance. Zero RNG calls occur inside regime
   execution loops.
2. Strict integer-cent capital conservation (`capital_conservation_delta_cents == 0`):
   every research run locks an integer-cent compute escrow bond (`_cents`).
   Unique viable verified runs earn discovery grants from `discovery_grant_pool_cents`;
   unintentional duplicate collisions or low-viability synthetic dead-ends drain
   compute into `wasted_compute_and_spoof_pool_cents`; spoofed/unattested run
   submissions are slashed into `commons_verification_reserve_cents` when caught
   by offline SCITT execution-evidence checks.
3. Endogenous voluntary migration (Lesson 52): participating research labs and
   civic cooperatives compare realized net surplus minus bureaucratic tolls,
   duplicate-crowding compute waste, and spoofed-run losses to decide endogenously
   whether to adopt the polycentric claim-registry and SCITT evidence regime.
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

class AntiConvergenceSimError(Exception):
    """Base exception for polycentric research anti-convergence simulation errors."""


class AntiConvergenceValidationError(AntiConvergenceSimError):
    """Raised when configuration, numeric types, or discrete supports fail validation."""


class StewardGateViolationError(AntiConvergenceSimError):
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
        raise AntiConvergenceValidationError("Expected string payload for Steward Gate screening.")
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(
                f"Payload violated CIN Steward Gate invariants: matched '{pattern.pattern}'"
            )


def _require_strict_int(val: Any, name: str, min_value: int | None = None) -> int:
    if type(val) is not int or isinstance(val, bool):
        raise AntiConvergenceValidationError(f"{name} must be a strict int (not bool), got {val!r}")
    if min_value is not None and val < min_value:
        raise AntiConvergenceValidationError(f"{name} must be >= {min_value}, got {val}")
    return val


def _require_finite_rate(val: Any, name: str, low: float = 0.0, high: float = 1.0) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise AntiConvergenceValidationError(f"{name} must be a finite float, got {val!r}")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval) or fval < low or fval > high:
        raise AntiConvergenceValidationError(f"{name} must be in [{low}, {high}], got {val!r}")
    return fval


# =====================================================================
# Enums & Empirical Constants
# =====================================================================

class ResearchCoordinationRegime(str, enum.Enum):
    """Institutional coordination regime for multi-agent research and verification."""
    TOP_DOWN_AGENDA_BUREAUCRACY = "TOP_DOWN_AGENDA_BUREAUCRACY"
    UNCOORDINATED_SYNTHETIC_HIVEMIND = "UNCOORDINATED_SYNTHETIC_HIVEMIND"
    POLYCENTRIC_SCITT_DIVERSITY_COMMONS = "POLYCENTRIC_SCITT_DIVERSITY_COMMONS"


RESEARCH_DOMAINS: Tuple[str, ...] = (
    "mechanistic_interpretability",
    "hardware_attestation_verification",
    "sandbox_containment_isolation",
    "polycentric_commons_clearing",
    "adversarial_red_team_probing",
    "epistemic_calibration_auditing",
    "formal_stateful_policy_checks",
    "privacy_preserving_provenance",
)

SPOOFED_EXECUTION_VECTORS: Tuple[str, ...] = (
    "fabricated_tool_output_log",
    "unregistered_subagent_bypass",
    "omitted_failed_canary_trace",
    "tampered_package_prompt_digest",
)


@dataclasses.dataclass(frozen=True)
class AntiConvergenceConfig:
    """Validated simulation configuration grounded in Nov 2026 primary sources."""
    num_orgs: int = 12
    num_domains: int = 8
    num_project_topics: int = 240
    num_episodes: int = 360
    seed: int = 42
    initial_org_treasury_cents: int = 500_000
    compute_escrow_cents: int = 1_200
    discovery_grant_cents: int = 2_400
    spoof_collateral_loss_cents: int = 1_600
    central_bureaucracy_fee_cents: int = 380
    # Top-down central committee permits only a narrow fraction of topics (e.g. 16 of 120)
    top_down_approved_topics: int = 16
    # Fantl (Averroes Labs, Nov 2026): 85% of uncoordinated autonomous safety agents crowd onto 2 agendas
    hivemind_crowded_share: float = 0.85
    hivemind_crowded_topic_span: int = 6
    # Zhong et al. (IdeaTaste, arXiv:2611.03424): LLM populations match only 18% of concrete human ideas
    synthetic_idea_viability_rate: float = 0.18
    top_down_committee_viability_rate: float = 0.52
    human_dyad_idea_viability_rate: float = 0.74
    # Spoofed or unattested execution submission rate & offline SCITT verification catch rates
    spoofed_execution_fraction: float = 0.16
    hivemind_lm_judge_catch_rate: float = 0.25
    top_down_manual_audit_catch_rate: float = 0.60
    scitt_offline_evidence_catch_rate: float = 1.00
    # Intentional replication cap before extra runs on a topic become wasteful crowding
    intentional_replication_cap: int = 2

    def __post_init__(self) -> None:
        _require_strict_int(self.num_orgs, "num_orgs", min_value=2)
        _require_strict_int(self.num_domains, "num_domains", min_value=2)
        if self.num_orgs < self.num_domains:
            raise AntiConvergenceValidationError(
                f"num_orgs ({self.num_orgs}) must be >= num_domains ({self.num_domains})"
            )
        _require_strict_int(self.num_project_topics, "num_project_topics", min_value=12)
        _require_strict_int(self.num_episodes, "num_episodes", min_value=12)
        _require_strict_int(self.seed, "seed", min_value=0)
        _require_strict_int(self.initial_org_treasury_cents, "initial_org_treasury_cents", min_value=10_000)
        _require_strict_int(self.compute_escrow_cents, "compute_escrow_cents", min_value=100)
        _require_strict_int(self.discovery_grant_cents, "discovery_grant_cents", min_value=100)
        _require_strict_int(self.spoof_collateral_loss_cents, "spoof_collateral_loss_cents", min_value=100)
        _require_strict_int(self.central_bureaucracy_fee_cents, "central_bureaucracy_fee_cents", min_value=0)
        if self.central_bureaucracy_fee_cents >= self.discovery_grant_cents:
            raise AntiConvergenceValidationError(
                "central_bureaucracy_fee_cents must be < discovery_grant_cents"
            )
        _require_strict_int(self.top_down_approved_topics, "top_down_approved_topics", min_value=2)
        if self.top_down_approved_topics > self.num_project_topics:
            raise AntiConvergenceValidationError(
                "top_down_approved_topics must be <= num_project_topics"
            )
        _require_strict_int(self.hivemind_crowded_topic_span, "hivemind_crowded_topic_span", min_value=2)
        if self.hivemind_crowded_topic_span > self.num_project_topics:
            raise AntiConvergenceValidationError(
                "hivemind_crowded_topic_span must be <= num_project_topics"
            )
        _require_strict_int(self.intentional_replication_cap, "intentional_replication_cap", min_value=1)
        _require_finite_rate(self.hivemind_crowded_share, "hivemind_crowded_share", 0.0, 1.0)
        _require_finite_rate(self.synthetic_idea_viability_rate, "synthetic_idea_viability_rate", 0.0, 1.0)
        _require_finite_rate(self.top_down_committee_viability_rate, "top_down_committee_viability_rate", 0.0, 1.0)
        _require_finite_rate(self.human_dyad_idea_viability_rate, "human_dyad_idea_viability_rate", 0.0, 1.0)
        _require_finite_rate(self.spoofed_execution_fraction, "spoofed_execution_fraction", 0.0, 1.0)
        _require_finite_rate(self.hivemind_lm_judge_catch_rate, "hivemind_lm_judge_catch_rate", 0.0, 1.0)
        _require_finite_rate(self.top_down_manual_audit_catch_rate, "top_down_manual_audit_catch_rate", 0.0, 1.0)
        _require_finite_rate(self.scitt_offline_evidence_catch_rate, "scitt_offline_evidence_catch_rate", 0.0, 1.0)


@dataclasses.dataclass(frozen=True)
class ResearchEpisodeItem:
    """Pre-sampled multi-agent research & audit episode for zero RNG phase drift."""
    episode_id: int
    proposer_org_id: int
    verifier_org_id: int
    domain_name: str
    top_down_topic_id: int
    hivemind_topic_id: int
    polycentric_primary_topic_id: int
    polycentric_fallback_topic_id: int
    is_spoofed_execution: int
    spoof_vector_name: str
    escrow_cents: int
    grant_cents: int
    spoof_loss_cents: int
    u_viability_draw: float
    u_spoof_audit_draw: float
    scitt_execution_digest: str
    package_provenance_digest: str

    def __post_init__(self) -> None:
        _require_strict_int(self.episode_id, "episode_id", min_value=0)
        _require_strict_int(self.proposer_org_id, "proposer_org_id", min_value=0)
        _require_strict_int(self.verifier_org_id, "verifier_org_id", min_value=0)
        if self.proposer_org_id == self.verifier_org_id:
            raise AntiConvergenceValidationError("proposer_org_id and verifier_org_id must be distinct")
        _require_strict_int(self.top_down_topic_id, "top_down_topic_id", min_value=0)
        _require_strict_int(self.hivemind_topic_id, "hivemind_topic_id", min_value=0)
        _require_strict_int(self.polycentric_primary_topic_id, "polycentric_primary_topic_id", min_value=0)
        _require_strict_int(self.polycentric_fallback_topic_id, "polycentric_fallback_topic_id", min_value=0)
        _require_strict_int(self.is_spoofed_execution, "is_spoofed_execution", min_value=0)
        if self.is_spoofed_execution not in (0, 1):
            raise AntiConvergenceValidationError("is_spoofed_execution must be 0 or 1")
        _require_strict_int(self.escrow_cents, "escrow_cents", min_value=1)
        _require_strict_int(self.grant_cents, "grant_cents", min_value=1)
        _require_strict_int(self.spoof_loss_cents, "spoof_loss_cents", min_value=1)
        _require_finite_rate(self.u_viability_draw, "u_viability_draw", 0.0, 1.0)
        _require_finite_rate(self.u_spoof_audit_draw, "u_spoof_audit_draw", 0.0, 1.0)
        screen_steward_gate(self.domain_name)
        screen_steward_gate(self.spoof_vector_name)


@dataclasses.dataclass(frozen=True)
class ResearchRegimeResult:
    """Aggregate diversity, discovery, verification, and conservation metrics per regime."""
    regime: str
    num_orgs: int
    num_episodes: int
    executed_episodes: int
    distinct_topics_explored: int
    effective_project_diversity: float
    duplicate_crowding_collisions: int
    duplicate_crowding_rate: float
    viable_unique_discoveries: int
    low_taste_dead_end_runs: int
    total_spoofed_submissions: int
    caught_spoofed_submissions: int
    uncontained_spoofed_acceptances: int
    spoof_catch_rate: float
    private_diary_bytes_leaked: int
    initial_total_capital_cents: int
    final_total_capital_cents: int
    capital_conservation_delta_cents: int
    total_bureaucracy_fees_cents: int
    total_wasted_compute_and_spoof_cents: int
    total_slashed_spoof_bonds_cents: int
    net_collective_surplus_cents: int
    voluntary_polycentric_adoption_rate: float
    rng_terminal_probe: float


# =====================================================================
# Workload Generation (Decoupled from Regime Execution)
# =====================================================================

def generate_research_workload(
    config: AntiConvergenceConfig,
) -> Tuple[List[ResearchEpisodeItem], float]:
    """Pre-sample all multi-agent research episodes from an isolated RNG."""
    if not isinstance(config, AntiConvergenceConfig):
        raise AntiConvergenceValidationError("config must be an AntiConvergenceConfig instance")
    rng = random.Random(config.seed)

    items: List[ResearchEpisodeItem] = []
    for ep_id in range(config.num_episodes):
        proposer = ep_id % config.num_orgs if ep_id < config.num_orgs else rng.randrange(config.num_orgs)
        offset = 1 + rng.randrange(config.num_orgs - 1)
        verifier = (proposer + offset) % config.num_orgs
        domain = RESEARCH_DOMAINS[ep_id % config.num_domains]

        # Top-down central committee forces teams onto narrow pre-approved topic slots
        top_down_topic = rng.randrange(config.top_down_approved_topics)

        # Hivemind autonomous swarm: 85% crowd onto narrow fashionable cluster (Fantl 2026; Jiang et al. 2025)
        u_crowd = rng.random()
        if u_crowd < config.hivemind_crowded_share:
            hivemind_topic = rng.randrange(config.hivemind_crowded_topic_span)
        else:
            hivemind_topic = rng.randrange(config.num_project_topics)

        # Polycentric human-dyad + weighted random novelty draw across full topic space
        poly_primary = rng.randrange(config.num_project_topics)
        poly_fallback = (
            poly_primary + 1 + rng.randrange(config.num_project_topics - 1)
        ) % config.num_project_topics

        u_spoof = rng.random()
        is_spoofed = 1 if u_spoof < config.spoofed_execution_fraction else 0
        spoof_vec = (
            SPOOFED_EXECUTION_VECTORS[rng.randrange(len(SPOOFED_EXECUTION_VECTORS))]
            if is_spoofed == 1
            else "verified_hash_chained_run"
        )

        u_viability = rng.random()
        u_spoof_audit = rng.random()

        exec_payload = (
            f"scitt-exec:ep={ep_id}:org={proposer}:verifier={verifier}:"
            f"domain={domain}:spoof={is_spoofed}:seed={config.seed}"
        )
        exec_digest = hashlib.sha256(exec_payload.encode("utf-8")).hexdigest()[:16]
        pkg_payload = f"scitt-pkg:domain={domain}:ep={ep_id}:escrow={config.compute_escrow_cents}"
        pkg_digest = hashlib.sha256(pkg_payload.encode("utf-8")).hexdigest()[:16]

        items.append(
            ResearchEpisodeItem(
                episode_id=ep_id,
                proposer_org_id=proposer,
                verifier_org_id=verifier,
                domain_name=domain,
                top_down_topic_id=top_down_topic,
                hivemind_topic_id=hivemind_topic,
                polycentric_primary_topic_id=poly_primary,
                polycentric_fallback_topic_id=poly_fallback,
                is_spoofed_execution=is_spoofed,
                spoof_vector_name=spoof_vec,
                escrow_cents=config.compute_escrow_cents,
                grant_cents=config.discovery_grant_cents,
                spoof_loss_cents=config.spoof_collateral_loss_cents,
                u_viability_draw=u_viability,
                u_spoof_audit_draw=u_spoof_audit,
                scitt_execution_digest=exec_digest,
                package_provenance_digest=pkg_digest,
            )
        )

    terminal_probe = rng.random()
    return items, terminal_probe


def _effective_diversity_from_counts(topic_counts: Dict[int, int]) -> float:
    """Compute inverse Herfindahl-Hirschman Index (effective number of projects, Fantl 2026)."""
    total = sum(topic_counts.values())
    if total <= 0:
        return 0.0
    hhi = sum((cnt / total) ** 2 for cnt in topic_counts.values() if cnt > 0)
    if hhi <= 0.0:
        return 0.0
    return round(1.0 / hhi, 4)


# =====================================================================
# Regime Execution Engine (Zero Internal RNG Calls)
# =====================================================================

def evaluate_research_regime(
    config: AntiConvergenceConfig,
    regime: ResearchCoordinationRegime | str,
    workload: Sequence[ResearchEpisodeItem] | None = None,
    terminal_probe: float | None = None,
) -> ResearchRegimeResult:
    """Evaluate a single research coordination regime with strict integer-cent conservation."""
    if not isinstance(config, AntiConvergenceConfig):
        raise AntiConvergenceValidationError("config must be an AntiConvergenceConfig instance")
    if isinstance(regime, str):
        try:
            regime_enum = ResearchCoordinationRegime(regime)
        except ValueError as exc:
            raise AntiConvergenceValidationError(f"Unsupported regime: {regime!r}") from exc
    elif isinstance(regime, ResearchCoordinationRegime):
        regime_enum = regime
    else:
        raise AntiConvergenceValidationError(f"Unsupported regime type: {regime!r}")

    if workload is None or terminal_probe is None:
        workload, terminal_probe = generate_research_workload(config)

    # Integer-cent double-entry accounts:
    # 1. org_treasuries[0..num_orgs-1]: each starts with initial_org_treasury_cents
    # 2. discovery_grant_pool_cents: pre-funded research commons paying discovery_grant_cents on verified viable discoveries
    # 3. central_bureaucracy_operator_cents: collects central_bureaucracy_fee_cents under top-down regime
    # 4. wasted_compute_and_spoof_pool_cents: absorbs wasted duplicate compute, dead-end runs, and uncontained spoof drains
    # 5. commons_verification_reserve_cents: collects slashed bonds from caught spoofed execution claims
    org_treasuries: List[int] = [config.initial_org_treasury_cents for _ in range(config.num_orgs)]
    discovery_grant_pool_cents: int = len(workload) * config.discovery_grant_cents
    central_bureaucracy_operator_cents: int = 0
    wasted_compute_and_spoof_pool_cents: int = 0
    commons_verification_reserve_cents: int = 0

    initial_total_capital_cents = sum(org_treasuries) + discovery_grant_pool_cents
    org_initial_snapshot = list(org_treasuries)
    org_friction_suffered = [0 for _ in range(config.num_orgs)]

    topic_claim_counts: Dict[int, int] = {}
    executed_episodes = 0
    duplicate_crowding_collisions = 0
    viable_unique_discoveries = 0
    low_taste_dead_end_runs = 0
    total_spoofed_submissions = 0
    caught_spoofed_submissions = 0
    uncontained_spoofed_acceptances = 0
    total_bureaucracy_fees_cents = 0
    total_wasted_compute_and_spoof_cents = 0
    total_slashed_spoof_bonds_cents = 0
    private_diary_bytes_leaked = 0

    for item in workload:
        proposer = item.proposer_org_id
        verifier = item.verifier_org_id

        # Indivisible compute escrow check under cash exhaustion
        if org_treasuries[proposer] < item.escrow_cents:
            continue

        executed_episodes += 1
        org_treasuries[proposer] -= item.escrow_cents
        escrow_cents = item.escrow_cents

        # Select research topic according to institutional coordination mechanism
        if regime_enum is ResearchCoordinationRegime.TOP_DOWN_AGENDA_BUREAUCRACY:
            chosen_topic = item.top_down_topic_id
            viability_threshold = config.top_down_committee_viability_rate
            spoof_catch_threshold = config.top_down_manual_audit_catch_rate
        elif regime_enum is ResearchCoordinationRegime.UNCOORDINATED_SYNTHETIC_HIVEMIND:
            chosen_topic = item.hivemind_topic_id
            viability_threshold = config.synthetic_idea_viability_rate
            spoof_catch_threshold = config.hivemind_lm_judge_catch_rate
        else:
            # POLYCENTRIC_SCITT_DIVERSITY_COMMONS: check open claim registry before locking topic
            primary = item.polycentric_primary_topic_id
            if topic_claim_counts.get(primary, 0) < config.intentional_replication_cap:
                chosen_topic = primary
            elif topic_claim_counts.get(item.polycentric_fallback_topic_id, 0) < config.intentional_replication_cap:
                chosen_topic = item.polycentric_fallback_topic_id
            else:
                # Deterministic scan for the least-crowded open slot in the shared claim registry
                chosen_topic = min(
                    range(config.num_project_topics),
                    key=lambda tid: (topic_claim_counts.get(tid, 0), tid),
                )
            viability_threshold = config.human_dyad_idea_viability_rate
            spoof_catch_threshold = config.scitt_offline_evidence_catch_rate

        prior_claims = topic_claim_counts.get(chosen_topic, 0)
        topic_claim_counts[chosen_topic] = prior_claims + 1

        # Case 1: Spoofed or unattested agent execution log submission
        if item.is_spoofed_execution == 1:
            total_spoofed_submissions += 1
            is_caught = item.u_spoof_audit_draw <= spoof_catch_threshold
            if is_caught:
                caught_spoofed_submissions += 1
                # Slash spoofed bond into commons verification reserve
                commons_verification_reserve_cents += escrow_cents
                total_slashed_spoof_bonds_cents += escrow_cents
                escrow_cents = 0
            else:
                uncontained_spoofed_acceptances += 1
                # Uncaught fabricated run wastes compute escrow and inflicts downstream verification loss
                wasted_compute_and_spoof_pool_cents += escrow_cents
                total_wasted_compute_and_spoof_cents += escrow_cents
                org_friction_suffered[proposer] += escrow_cents
                escrow_cents = 0

                verifier_loss = min(org_treasuries[verifier], item.spoof_loss_cents)
                org_treasuries[verifier] -= verifier_loss
                wasted_compute_and_spoof_pool_cents += verifier_loss
                total_wasted_compute_and_spoof_cents += verifier_loss
                org_friction_suffered[verifier] += verifier_loss

        # Case 2: Unintentional duplicate crowding beyond intentional replication cap (Fantl 2026)
        elif prior_claims >= config.intentional_replication_cap:
            duplicate_crowding_collisions += 1
            # Duplicate crowded compute burns escrow without yielding new scientific coverage
            wasted_compute_and_spoof_pool_cents += escrow_cents
            total_wasted_compute_and_spoof_cents += escrow_cents
            org_friction_suffered[proposer] += escrow_cents
            escrow_cents = 0

        # Case 3: Novel or intentionally replicated topic tested against concrete idea viability (IdeaTaste)
        else:
            if item.u_viability_draw < viability_threshold:
                viable_unique_discoveries += 1
                # Return compute escrow intact and award discovery grant
                org_treasuries[proposer] += escrow_cents
                escrow_cents = 0

                discovery_grant_pool_cents -= item.grant_cents
                gross_grant = item.grant_cents

                if regime_enum is ResearchCoordinationRegime.TOP_DOWN_AGENDA_BUREAUCRACY:
                    fee = min(gross_grant, config.central_bureaucracy_fee_cents)
                    central_bureaucracy_operator_cents += fee
                    total_bureaucracy_fees_cents += fee
                    org_friction_suffered[proposer] += fee
                    net_grant = gross_grant - fee
                else:
                    net_grant = gross_grant

                # Verifier earns 20% corroboration share; proposer earns 80% discovery share
                verifier_share = net_grant // 5
                proposer_share = net_grant - verifier_share
                org_treasuries[proposer] += proposer_share
                org_treasuries[verifier] += verifier_share
            else:
                low_taste_dead_end_runs += 1
                # Non-viable synthetic or misdirected proposal consumes compute escrow
                wasted_compute_and_spoof_pool_cents += escrow_cents
                total_wasted_compute_and_spoof_cents += escrow_cents
                org_friction_suffered[proposer] += escrow_cents
                escrow_cents = 0

        # Step-level integer-cent conservation check
        step_total = (
            sum(org_treasuries)
            + discovery_grant_pool_cents
            + central_bureaucracy_operator_cents
            + wasted_compute_and_spoof_pool_cents
            + commons_verification_reserve_cents
        )
        if step_total != initial_total_capital_cents:
            raise AntiConvergenceSimError(
                f"Capital conservation violated at episode {item.episode_id}: "
                f"expected {initial_total_capital_cents}, got {step_total}"
            )

    final_total_capital_cents = (
        sum(org_treasuries)
        + discovery_grant_pool_cents
        + central_bureaucracy_operator_cents
        + wasted_compute_and_spoof_pool_cents
        + commons_verification_reserve_cents
    )
    conservation_delta = final_total_capital_cents - initial_total_capital_cents

    non_spoof_runs = max(1, executed_episodes - total_spoofed_submissions)
    duplicate_rate = round(duplicate_crowding_collisions / non_spoof_runs, 4)
    spoof_catch_rate = (
        round(caught_spoofed_submissions / total_spoofed_submissions, 4)
        if total_spoofed_submissions > 0
        else 1.0
    )
    eff_diversity = _effective_diversity_from_counts(topic_claim_counts)

    # Endogenous voluntary migration (Lesson 52):
    # Organizations evaluate realized net treasury growth versus experienced crowding/bureaucracy/spoof friction.
    adopting_orgs = 0
    for o_idx in range(config.num_orgs):
        net_org_gain = org_treasuries[o_idx] - org_initial_snapshot[o_idx]
        friction = org_friction_suffered[o_idx]
        if regime_enum is ResearchCoordinationRegime.POLYCENTRIC_SCITT_DIVERSITY_COMMONS:
            if net_org_gain > friction:
                adopting_orgs += 1
        else:
            if friction > config.discovery_grant_cents:
                adopting_orgs += 1

    adoption_rate = round(adopting_orgs / config.num_orgs, 4)
    net_collective_surplus_cents = (
        sum(org_treasuries) + commons_verification_reserve_cents - sum(org_initial_snapshot)
    )

    return ResearchRegimeResult(
        regime=regime_enum.value,
        num_orgs=config.num_orgs,
        num_episodes=config.num_episodes,
        executed_episodes=executed_episodes,
        distinct_topics_explored=len(topic_claim_counts),
        effective_project_diversity=eff_diversity,
        duplicate_crowding_collisions=duplicate_crowding_collisions,
        duplicate_crowding_rate=duplicate_rate,
        viable_unique_discoveries=viable_unique_discoveries,
        low_taste_dead_end_runs=low_taste_dead_end_runs,
        total_spoofed_submissions=total_spoofed_submissions,
        caught_spoofed_submissions=caught_spoofed_submissions,
        uncontained_spoofed_acceptances=uncontained_spoofed_acceptances,
        spoof_catch_rate=spoof_catch_rate,
        private_diary_bytes_leaked=private_diary_bytes_leaked,
        initial_total_capital_cents=initial_total_capital_cents,
        final_total_capital_cents=final_total_capital_cents,
        capital_conservation_delta_cents=conservation_delta,
        total_bureaucracy_fees_cents=total_bureaucracy_fees_cents,
        total_wasted_compute_and_spoof_cents=total_wasted_compute_and_spoof_cents,
        total_slashed_spoof_bonds_cents=total_slashed_spoof_bonds_cents,
        net_collective_surplus_cents=net_collective_surplus_cents,
        voluntary_polycentric_adoption_rate=adoption_rate,
        rng_terminal_probe=float(terminal_probe),
    )


def run_three_regime_comparison(
    config: AntiConvergenceConfig | None = None,
) -> Dict[str, Any]:
    """Compare all three research coordination regimes on an identical pre-sampled workload."""
    cfg = config or AntiConvergenceConfig()
    workload, probe_base = generate_research_workload(cfg)

    results: Dict[str, ResearchRegimeResult] = {}
    probes: List[float] = []
    for reg in (
        ResearchCoordinationRegime.TOP_DOWN_AGENDA_BUREAUCRACY,
        ResearchCoordinationRegime.UNCOORDINATED_SYNTHETIC_HIVEMIND,
        ResearchCoordinationRegime.POLYCENTRIC_SCITT_DIVERSITY_COMMONS,
    ):
        res = evaluate_research_regime(cfg, reg, workload=workload, terminal_probe=probe_base)
        results[reg.value] = res
        probes.append(res.rng_terminal_probe)

    rng_phase_drift = max(probes) - min(probes) if probes else 0.0
    max_conservation_delta = max(
        abs(r.capital_conservation_delta_cents) for r in results.values()
    )

    return {
        "seed": cfg.seed,
        "num_orgs": cfg.num_orgs,
        "num_episodes": cfg.num_episodes,
        "rng_phase_drift": rng_phase_drift,
        "capital_conservation_delta_cents": max_conservation_delta,
        "regimes": {k: dataclasses.asdict(v) for k, v in results.items()},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simulate polycentric research anti-convergence, human-dyad taste, and SCITT execution evidence."
    )
    parser.add_argument("--simulate", action="store_true", help="Run three-regime comparison")
    parser.add_argument("--episodes", type=int, default=360, help="Number of research episodes")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed")
    args = parser.parse_args(argv)

    cfg = AntiConvergenceConfig(num_episodes=args.episodes, seed=args.seed)
    summary = run_three_regime_comparison(cfg)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
