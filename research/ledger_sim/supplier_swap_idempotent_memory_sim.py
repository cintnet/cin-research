#!/usr/bin/env python3
"""Multi-regime simulation of supplier-portable idempotent process control,
nonce-committed commerce mandates, read-time episodic memory resolution,
and default identifier stripping across cooperative procurement pools.

Grounded in November 2026 and foundational primary research:
1. Deepak Waghmare and Shaad Sufi, "Keep the Process, Change the Supplier:
   Runtime Governance for Tool-Using AI Agents" (arXiv:2611.26966, Nov 20, 2026):
   Evaluates an Open Process Control Plane (OPCP) across 2,400 scripted fault
   episodes, 60 restart episodes, 19,000 timed calls, and 160 supplier swaps.
   Naive retry-all duplicates external effects on every lost-reply-after-commit
   fault; persistent runtime state stops cross-supplier replay on restart/swap,
   while stopping same-supplier duplicates also requires supplier idempotency.
   Honest boundary: synthetic scripted fault harness without live LLM evaluation.
2. Chirag Ahuja, Vladislav Tanov, Ramcharan Kakarla, and Jonathan Taws,
   "DISCERN: Preserve at Write, Resolve at Read for Persistent LLM-Agent Memory"
   (arXiv:2611.15729, Nov 11, 2026): On ENT-310 (210 answerable, 100 unanswerable
   multi-session enterprise queries), write-time merging blurs confusable entities
   (<= 0.40 baseline accuracy vs 0.800 under additive bi-temporal preservation)
   and degrades false-premise abstention (<= 0.802 vs 0.924 F1).
3. Shengwei You, Aditya Joshi, Andrey Kuehlkamp, and Jarek Nabrzyski,
   "Signed but Unbound: The Authority Gap Between Agent Commerce Mandates and
   Crypto Wallet Signatures" (arXiv:2611.25821, Nov 19, 2026): 98.7% of 26,653
   sampled Base settlements used bearer signature paths; committing merchant and
   order terms in the signed nonce via a recipient contract rejects all 10,800
   altered mandates across 31,800 trials.
4. Bingcan Guo, Eryue Xu, Zhiping Zhang, and Tianshi Li, "It's My Agent, Not Me:
   Personal Privacy Boundaries in AI-Delegated Information Sharing"
   (arXiv:2509.21712, Sep 26, 2025): 1,650 privacy boundaries across 169
   participants and 60 scenarios show AI delegation sharpens sensitivity to
   leaked personal identifiers.

Enforces all 10 methodological invariants in simulation-capital-conservation-rng:
- Upfront pre-sampled workload decoupled from regime execution (rng_phase_drift == 0.0).
- Strict integer-cent double-entry accounting (capital_conservation_delta_cents == 0).
- Fail-closed bool, NaN/Inf, discrete support, and population bound checks.
- Indivisible clearing under cash exhaustion (zero partial or free awards).
- Structural capability flags and endogenous guild adoption without regime-name overrides.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import random
import re
from typing import Any, Sequence


DEFAULT_MASTER_SEED = 20261126
DEFAULT_SEEDS: tuple[int, ...] = tuple(range(10))
DEFAULT_EPISODES_PER_SEED = 300
DEFAULT_NUM_MEMBERS = 24
DEFAULT_NUM_SUPPLIERS = 6
DEFAULT_NUM_DOMAINS = 4
MIN_BYZANTINE_WITNESS_CLASSES = 4

DISCRETE_ORDER_CENTS_SUPPORT: tuple[int, ...] = (1_200, 2_400, 4_800, 9_600)
SUPPLIER_FAULT_KINDS: tuple[str, ...] = (
    "none",
    "definite_refusal",
    "lost_reply_after_commit",
    "process_restart_after_commit",
)

FORBIDDEN_STEWARD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE),
    re.compile(r"\bMMCT\b", re.IGNORECASE),
    re.compile(r"\b85/10/5\b"),
    re.compile(r"\bguaranteed\s+(?:returns?|yields?|profits?|savings?)\b", re.IGNORECASE),
    re.compile(r"\bpassive\s+income\b", re.IGNORECASE),
)


def _require_strict_int(name: str, val: Any, minimum: int = 0) -> int:
    if type(val) is not int or isinstance(val, bool) or val < minimum:
        raise ValueError(f"{name} must be strict int >= {minimum}, got {val!r}")
    return val


def _require_bool(name: str, val: Any) -> bool:
    if not isinstance(val, bool):
        raise ValueError(f"{name} must be bool, got {val!r}")
    return val


def _require_rate(name: str, val: Any) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"{name} must be numeric rate in [0.0, 1.0], got {val!r}")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval) or fval < 0.0 or fval > 1.0:
        raise ValueError(f"{name} must lie in [0.0, 1.0], got {val!r}")
    return fval


def assert_steward_gate_text(text: str) -> None:
    if not isinstance(text, str):
        raise ValueError("text must be str")
    for pat in FORBIDDEN_STEWARD_PATTERNS:
        if pat.search(text):
            raise ValueError(f"Forbidden Steward-gate pattern matched: {pat.pattern}")


@dataclass(frozen=True, slots=True)
class SupplierSwapEpisode:
    """Pre-sampled cooperative procurement episode decoupled from regime execution."""

    episode_id: int
    member_id: int
    domain_id: int
    primary_supplier_id: int
    fallback_supplier_id: int
    device_time_ns: int
    spdm_rats_quote_valid: bool
    transduction_cross_modal_ok: bool
    witness_classes_verified: int
    supplier_fault_kind: str
    retry_targets_fallback_supplier: bool
    mandate_redirection_attempted: bool
    confusable_entity_collision: bool
    evidence_sufficient: bool
    permission_legitimately_blocked: bool
    delegated_identifier_bytes: int
    order_amount_cents: int
    challenger_bond_cents: int
    audit_spot_draw: float

    def __post_init__(self) -> None:
        _require_strict_int("episode_id", self.episode_id, 0)
        _require_strict_int("member_id", self.member_id, 0)
        _require_strict_int("domain_id", self.domain_id, 0)
        _require_strict_int("primary_supplier_id", self.primary_supplier_id, 0)
        _require_strict_int("fallback_supplier_id", self.fallback_supplier_id, 0)
        if self.primary_supplier_id == self.fallback_supplier_id:
            raise ValueError("primary_supplier_id and fallback_supplier_id must be distinct")
        _require_strict_int("device_time_ns", self.device_time_ns, 1)
        _require_bool("spdm_rats_quote_valid", self.spdm_rats_quote_valid)
        _require_bool("transduction_cross_modal_ok", self.transduction_cross_modal_ok)
        _require_strict_int("witness_classes_verified", self.witness_classes_verified, 0)
        if self.supplier_fault_kind not in SUPPLIER_FAULT_KINDS:
            raise ValueError(f"Unsupported supplier_fault_kind: {self.supplier_fault_kind!r}")
        _require_bool("retry_targets_fallback_supplier", self.retry_targets_fallback_supplier)
        _require_bool("mandate_redirection_attempted", self.mandate_redirection_attempted)
        _require_bool("confusable_entity_collision", self.confusable_entity_collision)
        _require_bool("evidence_sufficient", self.evidence_sufficient)
        _require_bool("permission_legitimately_blocked", self.permission_legitimately_blocked)
        _require_strict_int("delegated_identifier_bytes", self.delegated_identifier_bytes, 0)
        _require_strict_int("order_amount_cents", self.order_amount_cents, 1)
        if self.order_amount_cents not in DISCRETE_ORDER_CENTS_SUPPORT:
            raise ValueError(
                f"order_amount_cents {self.order_amount_cents} outside discrete support {DISCRETE_ORDER_CENTS_SUPPORT}"
            )
        _require_strict_int("challenger_bond_cents", self.challenger_bond_cents, 1)
        _require_rate("audit_spot_draw", self.audit_spot_draw)


@dataclass(frozen=True, slots=True)
class SupplierTransitionRegimeConfig:
    """Structural capability toggles across CIN's five primitives (no regime-name branching)."""

    regime_id: str
    hardware_spdm_rats_and_deadman: bool
    preserve_at_write_resolve_at_read: bool
    strip_delegated_identifiers_and_pause_exit: bool
    persistent_uncertain_commit_log: bool
    supplier_idempotency_and_nonce_mandate: bool

    def __post_init__(self) -> None:
        if not isinstance(self.regime_id, str) or not self.regime_id.strip():
            raise ValueError("regime_id must be non-empty str")
        _require_bool("hardware_spdm_rats_and_deadman", self.hardware_spdm_rats_and_deadman)
        _require_bool("preserve_at_write_resolve_at_read", self.preserve_at_write_resolve_at_read)
        _require_bool(
            "strip_delegated_identifiers_and_pause_exit",
            self.strip_delegated_identifiers_and_pause_exit,
        )
        _require_bool("persistent_uncertain_commit_log", self.persistent_uncertain_commit_log)
        _require_bool(
            "supplier_idempotency_and_nonce_mandate",
            self.supplier_idempotency_and_nonce_mandate,
        )


REGIME_CONFIGS: tuple[SupplierTransitionRegimeConfig, ...] = (
    SupplierTransitionRegimeConfig(
        regime_id="RETRY_ALL_BEARER_MERGED_MEMORY",
        hardware_spdm_rats_and_deadman=False,
        preserve_at_write_resolve_at_read=False,
        strip_delegated_identifiers_and_pause_exit=False,
        persistent_uncertain_commit_log=False,
        supplier_idempotency_and_nonce_mandate=False,
    ),
    SupplierTransitionRegimeConfig(
        regime_id="PERSISTENT_STATE_WITHOUT_SUPPLIER_IDEMPOTENCY",
        hardware_spdm_rats_and_deadman=False,
        preserve_at_write_resolve_at_read=False,
        strip_delegated_identifiers_and_pause_exit=False,
        persistent_uncertain_commit_log=True,
        supplier_idempotency_and_nonce_mandate=False,
    ),
    SupplierTransitionRegimeConfig(
        regime_id="IDEMPOTENT_MANDATELOCK_MERGED_MEMORY",
        hardware_spdm_rats_and_deadman=True,
        preserve_at_write_resolve_at_read=False,
        strip_delegated_identifiers_and_pause_exit=False,
        persistent_uncertain_commit_log=True,
        supplier_idempotency_and_nonce_mandate=True,
    ),
    SupplierTransitionRegimeConfig(
        regime_id="CIN_OPCP_IDEMPOTENT_MANDATELOCK_DISCERN",
        hardware_spdm_rats_and_deadman=True,
        preserve_at_write_resolve_at_read=True,
        strip_delegated_identifiers_and_pause_exit=True,
        persistent_uncertain_commit_log=True,
        supplier_idempotency_and_nonce_mandate=True,
    ),
)


@dataclass(frozen=True, slots=True)
class EpisodeAccountingStep:
    episode_id: int
    buyer_spend_cents: int
    challenger_spend_cents: int
    supplier_credit_cents: int
    extracted_leakage_cents: int
    commons_reserve_credit_cents: int


@dataclass(frozen=True, slots=True)
class SupplierRegimeMetrics:
    regime_id: str
    episodes: int
    clean_settlements: int
    calibrated_abstentions_and_pauses: int
    cash_exhaustion_skips: int
    cross_supplier_duplicate_commits: int
    same_supplier_duplicate_commits: int
    bearer_mandate_redirections: int
    entity_collision_misroutes: int
    unanswerable_false_commits: int
    iec61508_deadman_trips: int
    member_identifier_bytes_leaked: int
    buyer_coop_treasury_cents: int
    supplier_settlement_cents: int
    challenger_pool_cents: int
    meidner_commons_reserve_cents: int
    extracted_duplicate_and_diversion_cents: int
    total_buyer_spend_cents: int
    capital_conservation_delta_cents: int
    endogenous_coop_adoption_rate: float
    scitt_merkle_head: str


def generate_supplier_swap_workload(
    seed: int,
    num_episodes: int = DEFAULT_EPISODES_PER_SEED,
    num_members: int = DEFAULT_NUM_MEMBERS,
    num_suppliers: int = DEFAULT_NUM_SUPPLIERS,
    num_domains: int = DEFAULT_NUM_DOMAINS,
) -> tuple[list[SupplierSwapEpisode], float]:
    """Sample all episodes upfront with isolated RNG so regimes share identical inputs."""
    _require_strict_int("seed", seed, 0)
    _require_strict_int("num_episodes", num_episodes, 1)
    _require_strict_int("num_members", num_members, 1)
    _require_strict_int("num_suppliers", num_suppliers, 2)
    _require_strict_int("num_domains", num_domains, 1)
    if num_members < num_domains:
        raise ValueError(
            f"num_members ({num_members}) must be >= num_domains ({num_domains}) for non-empty domain cohorts"
        )

    rng = random.Random(DEFAULT_MASTER_SEED + seed * 7919)
    episodes: list[SupplierSwapEpisode] = []
    clock_ns = 1_730_000_000_000

    for idx in range(num_episodes):
        clock_ns += rng.randint(8_000, 50_000)
        member_id = idx % num_members
        domain_id = member_id % num_domains
        primary_sup = rng.randrange(num_suppliers)
        offset = rng.randint(1, num_suppliers - 1)
        fallback_sup = (primary_sup + offset) % num_suppliers

        spdm_ok = rng.random() >= 0.035
        analog_ok = rng.random() >= 0.025
        witnesses = (
            MIN_BYZANTINE_WITNESS_CLASSES
            if rng.random() >= 0.03
            else (MIN_BYZANTINE_WITNESS_CLASSES - 1)
        )

        fault_roll = rng.random()
        if fault_roll < 0.62:
            fault_kind = "none"
        elif fault_roll < 0.74:
            fault_kind = "definite_refusal"
        elif fault_roll < 0.89:
            fault_kind = "lost_reply_after_commit"
        else:
            fault_kind = "process_restart_after_commit"

        retry_fallback = rng.random() < 0.55
        redirection_try = rng.random() < 0.14
        # ENT-310 (arXiv:2611.15729): ~32% unanswerable queries (100/310) & confusable entity collisions
        evidence_ok = rng.random() >= 0.22
        entity_collision = evidence_ok and (rng.random() < 0.18)
        perm_blocked = rng.random() < 0.08
        ident_bytes = rng.randint(64, 384)
        order_cents = rng.choice(DISCRETE_ORDER_CENTS_SUPPORT)
        bond_cents = 300
        audit_draw = round(rng.random(), 6)

        episodes.append(
            SupplierSwapEpisode(
                episode_id=idx,
                member_id=member_id,
                domain_id=domain_id,
                primary_supplier_id=primary_sup,
                fallback_supplier_id=fallback_sup,
                device_time_ns=clock_ns,
                spdm_rats_quote_valid=spdm_ok,
                transduction_cross_modal_ok=analog_ok,
                witness_classes_verified=witnesses,
                supplier_fault_kind=fault_kind,
                retry_targets_fallback_supplier=retry_fallback,
                mandate_redirection_attempted=redirection_try,
                confusable_entity_collision=entity_collision,
                evidence_sufficient=evidence_ok,
                permission_legitimately_blocked=perm_blocked,
                delegated_identifier_bytes=ident_bytes,
                order_amount_cents=order_cents,
                challenger_bond_cents=bond_cents,
                audit_spot_draw=audit_draw,
            )
        )

    post_sentinel = rng.random()
    return episodes, post_sentinel


def evaluate_regime(
    episodes: Sequence[SupplierSwapEpisode],
    cfg: SupplierTransitionRegimeConfig,
    budget_multiplier: int = 2,
    num_domains: int = DEFAULT_NUM_DOMAINS,
) -> SupplierRegimeMetrics:
    """Deterministically evaluate pre-sampled episodes with zero RNG calls and exact integer cents."""
    if not episodes:
        raise ValueError("episodes must be non-empty")
    _require_strict_int("budget_multiplier", budget_multiplier, 0)
    _require_strict_int("num_domains", num_domains, 1)

    initial_buyer_cents = sum(ep.order_amount_cents * budget_multiplier for ep in episodes)
    initial_challenger_cents = sum(ep.challenger_bond_cents for ep in episodes)
    initial_total_cents = initial_buyer_cents + initial_challenger_cents

    buyer_cents = initial_buyer_cents
    challenger_cents = initial_challenger_cents
    supplier_cents = 0
    commons_reserve_cents = 0
    extracted_leakage_cents = 0

    clean_settlements = 0
    abstentions_and_pauses = 0
    cash_exhaustion_skips = 0
    cross_supplier_dups = 0
    same_supplier_dups = 0
    mandate_redirections = 0
    entity_misroutes = 0
    unanswerable_false_commits = 0
    deadman_trips = 0
    identifier_bytes_leaked = 0

    domain_clean_surplus_cents = [0 for _ in range(num_domains)]
    domain_loss_cents = [0 for _ in range(num_domains)]
    steps: list[EpisodeAccountingStep] = []
    scitt_head = "0" * 64

    for ep in episodes:
        dom = ep.domain_id % num_domains

        # 1. Hardware peripheral attestation (PUF/DICE/SPDM/IETF RATS), analog cross-check, & witness quorum
        hardware_anomaly = (
            (not ep.spdm_rats_quote_valid)
            or (not ep.transduction_cross_modal_ok)
            or (ep.witness_classes_verified < MIN_BYZANTINE_WITNESS_CLASSES)
        )
        if cfg.hardware_spdm_rats_and_deadman and hardware_anomaly:
            deadman_trips += 1
            abstentions_and_pauses += 1
            steps.append(EpisodeAccountingStep(ep.episode_id, 0, 0, 0, 0, 0))
            scitt_head = hashlib.sha256(
                f"{scitt_head}:{ep.episode_id}:iec61508_halt:{ep.device_time_ns}".encode("utf-8")
            ).hexdigest()
            continue

        # 2. Sanctioned pause exit under blocked permissions (Lemieux & Abouzeid, arXiv:2611.30848)
        if ep.permission_legitimately_blocked and cfg.strip_delegated_identifiers_and_pause_exit:
            abstentions_and_pauses += 1
            steps.append(EpisodeAccountingStep(ep.episode_id, 0, 0, 0, 0, 0))
            scitt_head = hashlib.sha256(
                f"{scitt_head}:{ep.episode_id}:sanctioned_pause:{ep.device_time_ns}".encode("utf-8")
            ).hexdigest()
            continue

        # 3. Read-time abstention on insufficient evidence (DISCERN, Ahuja et al., arXiv:2611.15729)
        if not ep.evidence_sufficient:
            if cfg.preserve_at_write_resolve_at_read:
                abstentions_and_pauses += 1
                steps.append(EpisodeAccountingStep(ep.episode_id, 0, 0, 0, 0, 0))
                scitt_head = hashlib.sha256(
                    f"{scitt_head}:{ep.episode_id}:discern_abstain:{ep.device_time_ns}".encode("utf-8")
                ).hexdigest()
                continue

        # 4. Indivisible transaction clearing check under cash exhaustion (Rule 6)
        if buyer_cents < ep.order_amount_cents:
            cash_exhaustion_skips += 1
            steps.append(EpisodeAccountingStep(ep.episode_id, 0, 0, 0, 0, 0))
            scitt_head = hashlib.sha256(
                f"{scitt_head}:{ep.episode_id}:cash_exhausted_no_clear:{ep.device_time_ns}".encode("utf-8")
            ).hexdigest()
            continue

        # Outward supplier call occurs: check 1:1 fiduciary identifier stripping (Guo et al., arXiv:2509.21712)
        if not cfg.strip_delegated_identifiers_and_pause_exit:
            identifier_bytes_leaked += ep.delegated_identifier_bytes

        step_buyer_spend = 0
        step_challenger_spend = 0
        step_supplier_credit = 0
        step_leakage_credit = 0
        step_reserve_credit = 0

        # Evaluate primary order routing vs bearer redirection / entity collision / unanswerable hallucination
        primary_corrupted = False
        if not ep.evidence_sufficient and not cfg.preserve_at_write_resolve_at_read:
            unanswerable_false_commits += 1
            primary_corrupted = True
        elif ep.confusable_entity_collision and not cfg.preserve_at_write_resolve_at_read:
            entity_misroutes += 1
            primary_corrupted = True
        elif ep.mandate_redirection_attempted and not cfg.supplier_idempotency_and_nonce_mandate:
            mandate_redirections += 1
            primary_corrupted = True
        elif (hardware_anomaly and not cfg.hardware_spdm_rats_and_deadman) or (
            ep.permission_legitimately_blocked and not cfg.strip_delegated_identifiers_and_pause_exit
        ):
            primary_corrupted = True

        # Definite supplier refusal: both OPCP and retry-all recover cleanly on fallback without duplicate commit
        # Lost reply after commit / process restart after commit: prior supplier ALREADY committed primary order!
        buyer_cents -= ep.order_amount_cents
        step_buyer_spend += ep.order_amount_cents

        if primary_corrupted:
            extracted_leakage_cents += ep.order_amount_cents
            step_leakage_credit += ep.order_amount_cents
            domain_loss_cents[dom] += ep.order_amount_cents
            # Uncontained corruption slashes challenger bond into Meidner/commons safety reserve
            challenger_cents -= ep.challenger_bond_cents
            commons_reserve_cents += ep.challenger_bond_cents
            step_challenger_spend += ep.challenger_bond_cents
            step_reserve_credit += ep.challenger_bond_cents
        else:
            supplier_cents += ep.order_amount_cents
            step_supplier_credit += ep.order_amount_cents
            domain_clean_surplus_cents[dom] += ep.order_amount_cents

        # 5. Uncertain-commit supplier fault handling (Waghmare & Sufi, OPCP, arXiv:2611.26966)
        duplicate_triggered = False
        if ep.supplier_fault_kind in ("lost_reply_after_commit", "process_restart_after_commit"):
            if ep.retry_targets_fallback_supplier or ep.supplier_fault_kind == "process_restart_after_commit":
                # Cross-supplier replay prevented by persistent UNCERTAIN_COMMIT runtime state
                if not cfg.persistent_uncertain_commit_log:
                    if buyer_cents >= ep.order_amount_cents:
                        cross_supplier_dups += 1
                        duplicate_triggered = True
            else:
                # Same-supplier retry requires supplier-enforced idempotency keys in addition to runtime state
                if not cfg.supplier_idempotency_and_nonce_mandate:
                    if buyer_cents >= ep.order_amount_cents:
                        same_supplier_dups += 1
                        duplicate_triggered = True

        if duplicate_triggered:
            buyer_cents -= ep.order_amount_cents
            extracted_leakage_cents += ep.order_amount_cents
            step_buyer_spend += ep.order_amount_cents
            step_leakage_credit += ep.order_amount_cents
            domain_loss_cents[dom] += ep.order_amount_cents

        if (not primary_corrupted) and (not duplicate_triggered):
            clean_settlements += 1
            tag = "clean_scitt_settled"
        else:
            tag = "corrupted_or_duplicated"

        # Step-level double-entry check
        if (step_buyer_spend + step_challenger_spend) != (
            step_supplier_credit + step_leakage_credit + step_reserve_credit
        ):
            raise RuntimeError(f"Double-entry mismatch on episode {ep.episode_id}")

        steps.append(
            EpisodeAccountingStep(
                episode_id=ep.episode_id,
                buyer_spend_cents=step_buyer_spend,
                challenger_spend_cents=step_challenger_spend,
                supplier_credit_cents=step_supplier_credit,
                extracted_leakage_cents=step_leakage_credit,
                commons_reserve_credit_cents=step_reserve_credit,
            )
        )
        scitt_head = hashlib.sha256(
            f"{scitt_head}:{ep.episode_id}:{tag}:{ep.device_time_ns}".encode("utf-8")
        ).hexdigest()

    # Endogenous guild voluntary adoption reaction function (Lesson 52: purely economic surplus ratio)
    domain_adoption_scores: list[float] = []
    for d in range(num_domains):
        clean_v = domain_clean_surplus_cents[d]
        loss_v = domain_loss_cents[d]
        total_v = clean_v + loss_v
        if total_v == 0:
            domain_adoption_scores.append(0.5)
        else:
            # Guilds retain governance regime proportionally to realized clean retention minus 1.5x leakage drag
            net_ratio = (clean_v - 1.5 * loss_v) / total_v
            domain_adoption_scores.append(max(0.0, min(1.0, 0.5 + 0.5 * net_ratio)))
    endogenous_adoption_rate = round(sum(domain_adoption_scores) / num_domains, 4)

    trace_buyer_spend = sum(s.buyer_spend_cents for s in steps)
    trace_supplier_credit = sum(s.supplier_credit_cents for s in steps)
    trace_leakage_credit = sum(s.extracted_leakage_cents for s in steps)
    trace_reserve_credit = sum(s.commons_reserve_credit_cents for s in steps)

    if trace_supplier_credit != supplier_cents:
        raise RuntimeError("Trace supplier credit sum mismatch")
    if trace_leakage_credit != extracted_leakage_cents:
        raise RuntimeError("Trace leakage credit sum mismatch")
    if trace_reserve_credit != commons_reserve_cents:
        raise RuntimeError("Trace reserve credit sum mismatch")

    final_total_cents = (
        buyer_cents
        + challenger_cents
        + supplier_cents
        + commons_reserve_cents
        + extracted_leakage_cents
    )
    delta_cents = final_total_cents - initial_total_cents

    return SupplierRegimeMetrics(
        regime_id=cfg.regime_id,
        episodes=len(episodes),
        clean_settlements=clean_settlements,
        calibrated_abstentions_and_pauses=abstentions_and_pauses,
        cash_exhaustion_skips=cash_exhaustion_skips,
        cross_supplier_duplicate_commits=cross_supplier_dups,
        same_supplier_duplicate_commits=same_supplier_dups,
        bearer_mandate_redirections=mandate_redirections,
        entity_collision_misroutes=entity_misroutes,
        unanswerable_false_commits=unanswerable_false_commits,
        iec61508_deadman_trips=deadman_trips,
        member_identifier_bytes_leaked=identifier_bytes_leaked,
        buyer_coop_treasury_cents=buyer_cents,
        supplier_settlement_cents=supplier_cents,
        challenger_pool_cents=challenger_cents,
        meidner_commons_reserve_cents=commons_reserve_cents,
        extracted_duplicate_and_diversion_cents=extracted_leakage_cents,
        total_buyer_spend_cents=trace_buyer_spend,
        capital_conservation_delta_cents=delta_cents,
        endogenous_coop_adoption_rate=endogenous_adoption_rate,
        scitt_merkle_head=scitt_head,
    )


def run_multi_seed_simulation(
    seeds: Sequence[int] = DEFAULT_SEEDS,
    episodes_per_seed: int = DEFAULT_EPISODES_PER_SEED,
    num_members: int = DEFAULT_NUM_MEMBERS,
    num_suppliers: int = DEFAULT_NUM_SUPPLIERS,
    num_domains: int = DEFAULT_NUM_DOMAINS,
) -> dict[str, Any]:
    """Execute all four regimes across deterministic seeds and verify conservation & zero drift."""
    if not seeds:
        raise ValueError("seeds must be non-empty")
    for s in seeds:
        _require_strict_int("seed", s, 0)
    _require_strict_int("episodes_per_seed", episodes_per_seed, 1)

    max_phase_drift = 0.0
    max_conservation_delta = 0

    agg: dict[str, dict[str, Any]] = {
        cfg.regime_id: {
            "episodes": 0,
            "clean_settlements": 0,
            "calibrated_abstentions_and_pauses": 0,
            "cash_exhaustion_skips": 0,
            "cross_supplier_duplicate_commits": 0,
            "same_supplier_duplicate_commits": 0,
            "bearer_mandate_redirections": 0,
            "entity_collision_misroutes": 0,
            "unanswerable_false_commits": 0,
            "iec61508_deadman_trips": 0,
            "member_identifier_bytes_leaked": 0,
            "supplier_settlement_cents": 0,
            "meidner_commons_reserve_cents": 0,
            "extracted_duplicate_and_diversion_cents": 0,
            "adoption_sum": 0.0,
        }
        for cfg in REGIME_CONFIGS
    }

    for seed in seeds:
        ep_a, sent_a = generate_supplier_swap_workload(
            seed,
            num_episodes=episodes_per_seed,
            num_members=num_members,
            num_suppliers=num_suppliers,
            num_domains=num_domains,
        )
        ep_b, sent_b = generate_supplier_swap_workload(
            seed,
            num_episodes=episodes_per_seed,
            num_members=num_members,
            num_suppliers=num_suppliers,
            num_domains=num_domains,
        )
        drift = abs(sent_a - sent_b)
        if drift > max_phase_drift:
            max_phase_drift = drift
        if ep_a != ep_b:
            raise RuntimeError(f"Non-deterministic workload on seed {seed}")

        for cfg in REGIME_CONFIGS:
            m = evaluate_regime(ep_a, cfg, budget_multiplier=2, num_domains=num_domains)
            if abs(m.capital_conservation_delta_cents) > max_conservation_delta:
                max_conservation_delta = abs(m.capital_conservation_delta_cents)
            b = agg[cfg.regime_id]
            b["episodes"] += m.episodes
            b["clean_settlements"] += m.clean_settlements
            b["calibrated_abstentions_and_pauses"] += m.calibrated_abstentions_and_pauses
            b["cash_exhaustion_skips"] += m.cash_exhaustion_skips
            b["cross_supplier_duplicate_commits"] += m.cross_supplier_duplicate_commits
            b["same_supplier_duplicate_commits"] += m.same_supplier_duplicate_commits
            b["bearer_mandate_redirections"] += m.bearer_mandate_redirections
            b["entity_collision_misroutes"] += m.entity_collision_misroutes
            b["unanswerable_false_commits"] += m.unanswerable_false_commits
            b["iec61508_deadman_trips"] += m.iec61508_deadman_trips
            b["member_identifier_bytes_leaked"] += m.member_identifier_bytes_leaked
            b["supplier_settlement_cents"] += m.supplier_settlement_cents
            b["meidner_commons_reserve_cents"] += m.meidner_commons_reserve_cents
            b["extracted_duplicate_and_diversion_cents"] += m.extracted_duplicate_and_diversion_cents
            b["adoption_sum"] += m.endogenous_coop_adoption_rate

    regimes_out: dict[str, dict[str, Any]] = {}
    for cfg in REGIME_CONFIGS:
        b = dict(agg[cfg.regime_id])
        adoption_avg = round(b.pop("adoption_sum") / len(seeds), 4)
        total_ep = b["episodes"]
        total_dups = b["cross_supplier_duplicate_commits"] + b["same_supplier_duplicate_commits"]
        regimes_out[cfg.regime_id] = {
            **b,
            "total_duplicate_commits": total_dups,
            "duplicate_commit_rate": round(total_dups / total_ep, 4),
            "safe_or_clean_rate": round(
                (b["clean_settlements"] + b["calibrated_abstentions_and_pauses"]) / total_ep, 4
            ),
            "endogenous_coop_adoption_rate": adoption_avg,
        }

    summary = {
        "simulation_id": "supplier_swap_idempotent_memory_sim_v1",
        "master_seed": DEFAULT_MASTER_SEED,
        "num_seeds": len(seeds),
        "episodes_per_seed": episodes_per_seed,
        "num_members": num_members,
        "num_suppliers": num_suppliers,
        "num_domains": num_domains,
        "total_episodes_per_regime": len(seeds) * episodes_per_seed,
        "rng_phase_drift": max_phase_drift,
        "capital_conservation_delta_cents": max_conservation_delta,
        "honest_limits": (
            "Scripted multi-seed Monte Carlo wind tunnel modeling lost-reply supplier swaps, "
            "nonce-bound mandates, and additive read-time memory resolution; does not measure "
            "live commercial vendor API latency or replace real cooperative field trials."
        ),
        "regimes": regimes_out,
    }
    assert_steward_gate_text(json.dumps(summary))
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-json", type=Path, help="Optional path to write JSON summary")
    ap.add_argument("--check", action="store_true", help="Assert all five-primitive invariants")
    args = ap.parse_args(argv)

    summary = run_multi_seed_simulation()
    if args.check:
        cin = summary["regimes"]["CIN_OPCP_IDEMPOTENT_MANDATELOCK_DISCERN"]
        assert summary["rng_phase_drift"] == 0.0
        assert summary["capital_conservation_delta_cents"] == 0
        assert cin["cross_supplier_duplicate_commits"] == 0
        assert cin["same_supplier_duplicate_commits"] == 0
        assert cin["bearer_mandate_redirections"] == 0
        assert cin["entity_collision_misroutes"] == 0
        assert cin["unanswerable_false_commits"] == 0
        assert cin["member_identifier_bytes_leaked"] == 0
        assert cin["extracted_duplicate_and_diversion_cents"] == 0
        assert cin["safe_or_clean_rate"] == 1.0

    if args.write_json:
        args.write_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
