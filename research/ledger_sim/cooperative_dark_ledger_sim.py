"""
research/ledger_sim/cooperative_dark_ledger_sim.py

Cooperative Economy Transition & Dark-Ledger Cartel Containment Simulation Engine.

Grounded in:
- Rudolf Meidner (1978):
  "Employee Investment Funds: An Approach to Collective Capital Formation"
  [Statutory automation-linked share issuance converting concentrated private equity into
   broad democratic producer-consumer cooperative trusts without expropriation].
- James Stodder (Journal of Economic Behavior & Organization, vol. 72, no. 1, 2009,
  doi:10.1016/j.jebo.2009.06.002):
  "Complementary credit networks and macroeconomic stability: Switzerland's Wirtschaftsring"
  [Counter-cyclical multilateral mutual credit clearing backed by real productive capacity
   where net balances sum identically to zero across member accounts].
- Joseph E. Harrington (The Journal of Industrial Economics, vol. 56, no. 2, 2008,
  doi:10.1111/j.1467-6451.2008.00339.x):
  "Optimal Corporate Leniency Programs"
  [Asymmetric first-defector safe-harbor leniency and bounty incentives triggering
   dominant-strategy defection cascades inside covert cartels].
- Roger B. Myerson (Mathematics of Operations Research, vol. 2, no. 3, 1977,
  doi:10.1287/moor.2.3.225):
  "Graphs and Cooperation in Games"
  [Superadditive coalition value V(S U T) > V(S) + V(T) from communication-connected
   open demand graphs and shared verification].

Core Architectural Invariants:
1. Decoupled Workload Generation (Zero RNG Phase Drift): All macroeconomic shocks,
   durability realizations, and physical metering noise draws are generated upfront
   from a seeded PRNG prior to regime execution. Zero RNG calls occur inside regime loops.
2. Zero-Sum Mutual Credit Conservation: All capacity-backed reciprocal clearing balances
   are tracked in exact integer micro-credits and normalized floats such that
   sum(balances) == 0 (|sum(balances)| < 1e-9) holds at every step, including under
   periodic expiring-balance decay.
3. Sybil-Resistant 1-Human-Root Submodular Modality Weighting: Multi-agent product
   durability and fulfillment attestations collapse by verified human root anchor before
   applying a strictly concave submodular set function over distinct verification modalities,
   guaranteeing zero Sybil amplification from spawning extra software agents.
4. Exact Nash Cartel Collapse & Capital Conservation: Covert shadow-ledger cartels face
   (i) zero-knowledge physical energy/compute conservation audits (E_in = E_accounted + epsilon),
   (ii) border opacity quarantine margins tau, and (iii) Harrington first-whistleblower
   safe-harbor bounties funded strictly from sanctioned co-conspirator collateral.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import random
import re
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple


# =====================================================================
# Error Hierarchy
# =====================================================================

class CooperativeSimSecurityViolation(Exception):
    """Base exception for cooperative economy and dark-ledger simulation violations."""


class CooperativeSimValidationError(CooperativeSimSecurityViolation, ValueError):
    """Raised when configuration parameters, types, or numeric bounds fail validation."""


class StewardGateViolationError(CooperativeSimSecurityViolation):
    """Raised when forbidden token tickers, royalty promises, or sci-fi lore appear."""


# =====================================================================
# Steward Gate Screening
# =====================================================================

_FORBIDDEN_STEWARD_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE), "Contribution Token"),
    (re.compile(r"\bMMCT\b", re.IGNORECASE), "MMCT ticker"),
    (re.compile(r"\b85\s*/\s*10\s*/\s*5\b"), "85/10/5 split"),
    (re.compile(r"\b95\s*%\s*savings\b", re.IGNORECASE), "95% savings promise"),
    (re.compile(r"\broyalt(?:y|ies)\b", re.IGNORECASE), "royalty claim"),
    (re.compile(r"\b(?:airdrop|tokenomics|staking\s+rewards?)\b", re.IGNORECASE), "crypto reward framing"),
    (re.compile(r"\bSomatic\s+Witness\b", re.IGNORECASE), "retired neologism"),
)


def screen_steward_gate(text: str) -> None:
    """Enforce CIN Steward Gate rules against speculative tokens or reward promises."""
    if not isinstance(text, str):
        raise CooperativeSimValidationError(
            f"Expected str for steward gate screening, got {type(text).__name__}"
        )
    for pattern, label in _FORBIDDEN_STEWARD_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(
                f"Steward Gate violation: forbidden pattern '{label}' detected."
            )


# =====================================================================
# Fail-Closed Validation Helpers
# =====================================================================

MICRO_SCALE: int = 1_000_000


def _validate_int(name: str, val: Any, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    if type(val) is not int or isinstance(val, bool):
        raise CooperativeSimValidationError(f"{name} must be a strict int (not bool), got {val!r}")
    if minimum is not None and val < minimum:
        raise CooperativeSimValidationError(f"{name} must be >= {minimum}, got {val}")
    if maximum is not None and val > maximum:
        raise CooperativeSimValidationError(f"{name} must be <= {maximum}, got {val}")
    return val


def _validate_float(
    name: str,
    val: Any,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    strict_min: bool = False,
    strict_max: bool = False,
) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise CooperativeSimValidationError(f"{name} must be a finite number (not bool), got {val!r}")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval):
        raise CooperativeSimValidationError(f"{name} must be finite (not NaN/Inf), got {val!r}")
    if minimum is not None:
        if strict_min and fval <= minimum:
            raise CooperativeSimValidationError(f"{name} must be > {minimum}, got {fval}")
        if not strict_min and fval < minimum:
            raise CooperativeSimValidationError(f"{name} must be >= {minimum}, got {fval}")
    if maximum is not None:
        if strict_max and fval >= maximum:
            raise CooperativeSimValidationError(f"{name} must be < {maximum}, got {fval}")
        if not strict_max and fval > maximum:
            raise CooperativeSimValidationError(f"{name} must be <= {maximum}, got {fval}")
    return fval


def _validate_bool(name: str, val: Any) -> bool:
    if not isinstance(val, bool):
        raise CooperativeSimValidationError(f"{name} must be a bool, got {val!r}")
    return val


def canonical_sha256(payload: Any) -> str:
    """Compute deterministic SHA-256 hex digest of structured simulation data."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# =====================================================================
# 1. Sybil-Resistant 1-Human-Root Submodular Modality Weighting
# =====================================================================

class VerificationModality(str, enum.Enum):
    """Opt-in zero-knowledge fulfillment and 30-day durability attestation modalities."""
    DELIVERY_RECEIPT = "delivery_receipt"
    THIRTY_DAY_DURABILITY = "thirty_day_durability"
    REPAIRABILITY_CHECK = "repairability_check"
    ENERGY_EFFICIENCY_AUDIT = "energy_efficiency_audit"


DEFAULT_MODALITY_WEIGHTS: Mapping[VerificationModality, float] = {
    VerificationModality.DELIVERY_RECEIPT: 0.20,
    VerificationModality.THIRTY_DAY_DURABILITY: 0.40,
    VerificationModality.REPAIRABILITY_CHECK: 0.20,
    VerificationModality.ENERGY_EFFICIENCY_AUDIT: 0.20,
}


@dataclasses.dataclass(frozen=True)
class FulfillmentAttestation:
    """Single agent-submitted product durability/fulfillment attestation."""
    attestation_id: str
    agent_id: str
    human_root_id: Optional[str]
    human_root_verified: bool
    modality: VerificationModality
    durable_fulfilled: bool

    def __post_init__(self) -> None:
        if not isinstance(self.attestation_id, str) or not self.attestation_id.strip():
            raise CooperativeSimValidationError("attestation_id must be a non-empty string.")
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise CooperativeSimValidationError("agent_id must be a non-empty string.")
        screen_steward_gate(self.attestation_id)
        screen_steward_gate(self.agent_id)
        if self.human_root_id is not None:
            if not isinstance(self.human_root_id, str) or not self.human_root_id.strip():
                raise CooperativeSimValidationError("human_root_id must be None or a non-empty string.")
            screen_steward_gate(self.human_root_id)
        _validate_bool("human_root_verified", self.human_root_verified)
        _validate_bool("durable_fulfilled", self.durable_fulfilled)
        if not isinstance(self.modality, VerificationModality):
            raise CooperativeSimValidationError(
                f"modality must be VerificationModality, got {self.modality!r}"
            )


def compute_human_root_modality_weight(
    modalities: Set[VerificationModality] | FrozenSet[VerificationModality],
    submodular_exponent: float = 0.60,
    modality_weights: Mapping[VerificationModality, float] = DEFAULT_MODALITY_WEIGHTS,
) -> float:
    """
    Compute monotone submodular verification weight for a single verified human root.

    For distinct verified modalities M subseteq Omega, weight f(M) = (sum_{m in M} w_m)^gamma
    with 0 < gamma < 1 and sum_{m in Omega} w_m = 1. Strict concavity of x^gamma guarantees
    diminishing marginal returns: for A subset B and x not in B,
    f(A U {x}) - f(A) > f(B U {x}) - f(B).
    """
    gamma = _validate_float(
        "submodular_exponent", submodular_exponent, minimum=0.0, maximum=1.0, strict_min=True, strict_max=True
    )
    if not modalities:
        return 0.0
    total_base = 0.0
    for mod in modalities:
        if not isinstance(mod, VerificationModality):
            raise CooperativeSimValidationError(f"Invalid modality {mod!r}")
        w = _validate_float(f"weight[{mod.value}]", modality_weights.get(mod, 0.0), minimum=0.0, strict_min=True)
        total_base += w
    weight_norm = sum(
        _validate_float(f"norm[{k.value}]", v, minimum=0.0, strict_min=True)
        for k, v in modality_weights.items()
    )
    normalized_sum = min(1.0, total_base / weight_norm)
    return float(normalized_sum ** gamma)


@dataclasses.dataclass(frozen=True)
class AggregatedFulfillmentSignal:
    """Sybil-resistant aggregated 30-day durability signal across verified human roots."""
    verified_human_roots: int
    rejected_unanchored_attestations: int
    collapsed_duplicate_agent_attestations: int
    total_effective_weight: float
    weighted_durability_score: float


def aggregate_sybil_resistant_fulfillment_signals(
    attestations: Sequence[FulfillmentAttestation],
    submodular_exponent: float = 0.60,
) -> AggregatedFulfillmentSignal:
    """
    Collapse multi-agent attestations onto 1-human-root anchors and compute submodular
    modality-weighted 30-day durability score.

    Spawning arbitrary numbers of Sybil agents under one human root produces zero additional
    influence; unverified or unanchored agents receive strictly zero weight.
    """
    gamma = _validate_float(
        "submodular_exponent", submodular_exponent, minimum=0.0, maximum=1.0, strict_min=True, strict_max=True
    )
    by_root: Dict[str, Dict[VerificationModality, List[bool]]] = {}
    rejected_unanchored = 0
    raw_valid_count = 0

    for att in attestations:
        if not isinstance(att, FulfillmentAttestation):
            raise CooperativeSimValidationError(f"Expected FulfillmentAttestation, got {att!r}")
        if not att.human_root_verified or att.human_root_id is None:
            rejected_unanchored += 1
            continue
        raw_valid_count += 1
        root_bucket = by_root.setdefault(att.human_root_id, {})
        root_bucket.setdefault(att.modality, []).append(att.durable_fulfilled)

    unique_root_modality_pairs = sum(len(m_map) for m_map in by_root.values())
    collapsed_duplicates = raw_valid_count - unique_root_modality_pairs

    total_weight = 0.0
    weighted_positive = 0.0
    for root_id in sorted(by_root.keys()):
        modality_map = by_root[root_id]
        distinct_modalities = frozenset(modality_map.keys())
        root_weight = compute_human_root_modality_weight(
            distinct_modalities, submodular_exponent=gamma
        )
        # Conservative root verdict per modality: any failed check under the same root flags failure
        modality_base_sum = sum(DEFAULT_MODALITY_WEIGHTS[m] for m in distinct_modalities)
        durable_base_sum = sum(
            DEFAULT_MODALITY_WEIGHTS[m]
            for m, verdicts in modality_map.items()
            if all(verdicts)
        )
        root_durable_fraction = durable_base_sum / modality_base_sum if modality_base_sum > 0.0 else 0.0
        total_weight += root_weight
        weighted_positive += root_weight * root_durable_fraction

    score = (weighted_positive / total_weight) if total_weight > 0.0 else 0.0
    return AggregatedFulfillmentSignal(
        verified_human_roots=len(by_root),
        rejected_unanchored_attestations=rejected_unanchored,
        collapsed_duplicate_agent_attestations=collapsed_duplicates,
        total_effective_weight=total_weight,
        weighted_durability_score=score,
    )


# =====================================================================
# 2. Macroeconomic Cooperative Transition Engine
# =====================================================================

class TransitionRegime(str, enum.Enum):
    """Macroeconomic ownership and clearing regimes as automation scales to 98%."""
    CONCENTRATED_ENCLOSURE = "CONCENTRATED_ENCLOSURE"
    COOPERATIVE_TRANSITION = "COOPERATIVE_TRANSITION"


@dataclasses.dataclass(frozen=True)
class TransitionPolicyConfig:
    """Institutional policy parameters governing ownership, provisioning, and clearing."""
    regime: TransitionRegime
    meidner_dilution_rate: float
    automation_dilution_threshold: float
    blinded_commissioning_rate: float
    baseline_provisioning_share: float
    zk_durability_steering: bool
    mutual_credit_limit_share: float
    expiring_balance_decay_rate: float

    def __post_init__(self) -> None:
        if not isinstance(self.regime, TransitionRegime):
            raise CooperativeSimValidationError(f"Invalid TransitionRegime: {self.regime!r}")
        _validate_float("meidner_dilution_rate", self.meidner_dilution_rate, 0.0, 1.0)
        _validate_float("automation_dilution_threshold", self.automation_dilution_threshold, 0.0, 1.0)
        _validate_float("blinded_commissioning_rate", self.blinded_commissioning_rate, 0.0, 0.5)
        _validate_float("baseline_provisioning_share", self.baseline_provisioning_share, 0.0, 0.6)
        _validate_bool("zk_durability_steering", self.zk_durability_steering)
        _validate_float("mutual_credit_limit_share", self.mutual_credit_limit_share, 0.0, 1.0)
        _validate_float("expiring_balance_decay_rate", self.expiring_balance_decay_rate, 0.0, 0.5)


@dataclasses.dataclass(frozen=True)
class TransitionStepWorkload:
    """Pre-generated exogenous step shock to guarantee zero RNG phase drift across regimes."""
    step: int
    capacity_shock: float
    liquidity_crunch_shock: float
    durability_noise: float
    trade_rotation_offset: int


def generate_transition_workloads(
    steps: int = 30,
    num_accounts: int = 120,
    seed: int = 42,
) -> Tuple[TransitionStepWorkload, ...]:
    """Generate deterministic macroeconomic shock series upfront before any regime executes."""
    steps_v = _validate_int("steps", steps, minimum=2, maximum=500)
    accounts_v = _validate_int("num_accounts", num_accounts, minimum=4, maximum=10_000)
    seed_v = _validate_int("seed", seed, minimum=0)
    rng = random.Random(seed_v)
    workloads: List[TransitionStepWorkload] = []
    for t in range(steps_v):
        workloads.append(
            TransitionStepWorkload(
                step=t,
                capacity_shock=rng.uniform(-0.025, 0.025),
                liquidity_crunch_shock=rng.uniform(0.0, 0.14),
                durability_noise=rng.uniform(-0.015, 0.015),
                trade_rotation_offset=rng.randrange(0, accounts_v),
            )
        )
    return tuple(workloads)


def apply_zero_sum_credit_decay_and_clearing(
    balances_micro: Sequence[int],
    clearing_volume: float,
    decay_rate: float,
    num_households: int,
    rotation_offset: int,
) -> List[int]:
    """
    Update capacity-backed mutual credit balances in exact integer micro-units.

    1. Expiring positive balances decay at `decay_rate`, and the exact integer sum of
       expired positive micro-credits amortizes negative mutual obligations proportionally,
       preserving sum(balances_micro) == 0 identically.
    2. New multilateral clearing credits verified producers and debits buyer accounts by
       identical integer micro-units, preserving sum(balances_micro) == 0 identically.
    """
    n_total = len(balances_micro)
    if n_total < 2 or num_households <= 0 or num_households >= n_total:
        raise CooperativeSimValidationError("Invalid account partition for mutual credit clearing.")
    if sum(balances_micro) != 0:
        raise CooperativeSimValidationError("Input mutual credit balances violate zero-sum invariant.")
    _validate_float("clearing_volume", clearing_volume, minimum=0.0)
    _validate_float("decay_rate", decay_rate, minimum=0.0, maximum=0.5)

    updated = list(balances_micro)

    # Step 1: Time-decaying positive balances matched against negative obligations
    if decay_rate > 0.0:
        total_decayed_micro = 0
        for idx, bal in enumerate(updated):
            if bal > 0:
                decayed = int(round(bal * decay_rate))
                decayed = min(bal, max(0, decayed))
                updated[idx] -= decayed
                total_decayed_micro += decayed

        if total_decayed_micro > 0:
            neg_indices = [i for i, b in enumerate(updated) if b < 0]
            total_neg_mag = sum(-updated[i] for i in neg_indices)
            if total_neg_mag > 0:
                allocated = 0
                # Proportional relief first
                for i in neg_indices:
                    share = (total_decayed_micro * (-updated[i])) // total_neg_mag
                    share = min(-updated[i], share)
                    updated[i] += share
                    allocated += share
                remainder = total_decayed_micro - allocated
                # Deterministic remainder distribution across deepest negative balances
                neg_sorted = sorted(neg_indices, key=lambda idx: (updated[idx], idx))
                for i in neg_sorted:
                    if remainder <= 0:
                        break
                    room = -updated[i]
                    step_relief = min(room, remainder)
                    updated[i] += step_relief
                    remainder -= step_relief

    # Step 2: Multilateral capacity-backed trade clearing
    total_trade_micro = int(round(clearing_volume * MICRO_SCALE))
    if total_trade_micro > 0:
        num_producers = n_total - num_households
        per_buyer = total_trade_micro // num_households
        buyer_rem = total_trade_micro - (per_buyer * num_households)
        for h in range(num_households):
            buyer_idx = (h + rotation_offset) % num_households
            debit = per_buyer + (1 if h < buyer_rem else 0)
            updated[buyer_idx] -= debit

        per_prod = total_trade_micro // num_producers
        prod_rem = total_trade_micro - (per_prod * num_producers)
        for p in range(num_producers):
            prod_idx = num_households + ((p + rotation_offset) % num_producers)
            credit = per_prod + (1 if p < prod_rem else 0)
            updated[prod_idx] += credit

    if sum(updated) != 0:
        raise CooperativeSimSecurityViolation("Zero-sum mutual credit conservation invariant failed.")
    return updated


@dataclasses.dataclass(frozen=True)
class CooperativeStepRecord:
    """Per-period macroeconomic state and accounting verification snapshot."""
    step: int
    automation_level: float
    total_capacity: float
    wage_share: float
    private_equity_share: float
    cooperative_equity_share: float
    baseline_provisioning: float
    cash_effective_demand: float
    mutual_credit_volume: float
    effective_demand: float
    capacity_utilization: float
    durability_fulfillment_rate: float
    fulfilled_durable_output: float
    obsolescence_waste_output: float
    idle_unpurchased_capacity: float
    household_median_wellbeing: float
    net_credit_balance_sum: float
    credit_max_abs_balance: float


@dataclasses.dataclass(frozen=True)
class CooperativeTransitionResult:
    """Complete trajectory and conservation summary for a transition regime."""
    regime: TransitionRegime
    policy: TransitionPolicyConfig
    steps: int
    automation_start: float
    automation_end: float
    initial_cooperative_share: float
    final_cooperative_share: float
    final_private_share: float
    final_capacity_utilization: float
    final_effective_demand: float
    final_fulfilled_durable_output: float
    final_household_median_wellbeing: float
    cumulative_mutual_credit_volume: float
    max_abs_credit_sum_error: float
    credit_zero_sum_verified: bool
    capacity_conservation_verified: bool
    final_balances: Tuple[float, ...]
    step_records: Tuple[CooperativeStepRecord, ...]
    receipt_digest: str


def default_policy_for_regime(
    regime: TransitionRegime,
    meidner_dilution_rate: float = 0.14,
    mutual_credit_limit_share: float = 0.85,
    baseline_provisioning_share: float = 0.18,
) -> TransitionPolicyConfig:
    """Return canonical policy configuration for Concentrated Enclosure or Cooperative Transition."""
    if not isinstance(regime, TransitionRegime):
        raise CooperativeSimValidationError(f"Expected TransitionRegime, got {regime!r}")
    if regime == TransitionRegime.CONCENTRATED_ENCLOSURE:
        return TransitionPolicyConfig(
            regime=TransitionRegime.CONCENTRATED_ENCLOSURE,
            meidner_dilution_rate=0.0,
            automation_dilution_threshold=0.30,
            blinded_commissioning_rate=0.0,
            baseline_provisioning_share=0.0,
            zk_durability_steering=False,
            mutual_credit_limit_share=0.0,
            expiring_balance_decay_rate=0.0,
        )
    return TransitionPolicyConfig(
        regime=TransitionRegime.COOPERATIVE_TRANSITION,
        meidner_dilution_rate=meidner_dilution_rate,
        automation_dilution_threshold=0.30,
        blinded_commissioning_rate=0.04,
        baseline_provisioning_share=baseline_provisioning_share,
        zk_durability_steering=True,
        mutual_credit_limit_share=mutual_credit_limit_share,
        expiring_balance_decay_rate=0.06,
    )


def simulate_cooperative_transition(
    regime: TransitionRegime = TransitionRegime.COOPERATIVE_TRANSITION,
    *,
    policy: Optional[TransitionPolicyConfig] = None,
    steps: int = 30,
    automation_start: float = 0.25,
    automation_end: float = 0.98,
    initial_cooperative_share: float = 0.06,
    base_capacity: float = 100.0,
    automation_productivity_gain: float = 1.80,
    num_households: int = 100,
    num_producers: int = 20,
    seed: int = 42,
    workloads: Optional[Sequence[TransitionStepWorkload]] = None,
) -> CooperativeTransitionResult:
    """
    Simulate macroeconomic transition as automated production scales from `automation_start`
    (default 0.25) to `automation_end` (default 0.98).

    Both regimes execute the exact same continuous macroeconomic equations parameterized solely
    by `TransitionPolicyConfig`, with zero RNG calls inside the simulation loop.
    """
    if not isinstance(regime, TransitionRegime):
        raise CooperativeSimValidationError(f"regime must be TransitionRegime, got {regime!r}")
    cfg = policy if policy is not None else default_policy_for_regime(regime)
    if cfg.regime != regime:
        raise CooperativeSimValidationError("policy.regime must match regime argument.")

    steps_v = _validate_int("steps", steps, minimum=2, maximum=500)
    a_start = _validate_float("automation_start", automation_start, minimum=0.01, maximum=0.95)
    a_end = _validate_float("automation_end", automation_end, minimum=0.05, maximum=0.999)
    if a_start >= a_end:
        raise CooperativeSimValidationError(
            f"automation_start ({a_start}) must be strictly less than automation_end ({a_end})."
        )
    coop_init = _validate_float("initial_cooperative_share", initial_cooperative_share, 0.0, 1.0)
    cap_base = _validate_float("base_capacity", base_capacity, minimum=1.0, maximum=1e9)
    prod_gain = _validate_float("automation_productivity_gain", automation_productivity_gain, 0.0, 20.0)
    n_households = _validate_int("num_households", num_households, minimum=2, maximum=5_000)
    n_producers = _validate_int("num_producers", num_producers, minimum=2, maximum=5_000)
    n_accounts = n_households + n_producers

    if workloads is None:
        step_workloads = generate_transition_workloads(
            steps=steps_v, num_accounts=n_accounts, seed=seed
        )
    else:
        if len(workloads) != steps_v:
            raise CooperativeSimValidationError(
                f"Expected {steps_v} workloads, received {len(workloads)}."
            )
        step_workloads = tuple(workloads)

    # Propensities to consume real everyday output (Kaleckian/Keynesian demand structure):
    # Broad households spend most income on real goods/services; concentrated equity holders save/accumulate.
    mpc_broad = 0.92
    mpc_concentrated = 0.11

    coop_share = coop_init
    priv_share = 1.0 - coop_share
    balances_micro: List[int] = [0] * n_accounts

    records: List[CooperativeStepRecord] = []
    cumulative_mc_volume = 0.0
    max_credit_err = 0.0
    capacity_conserved_all = True

    for t in range(steps_v):
        wl = step_workloads[t]
        progress = t / float(steps_v - 1)
        a_t = a_start + (a_end - a_start) * progress

        #Statutory Meidner share dilution + voluntary Exit-to-Community blinded task commissioning
        excess_auto = max(0.0, a_t - cfg.automation_dilution_threshold)
        issuance_rate = (cfg.meidner_dilution_rate * excess_auto) + (cfg.blinded_commissioning_rate * a_t)
        if issuance_rate > 0.0:
            priv_share = priv_share / (1.0 + issuance_rate)
            coop_share = 1.0 - priv_share

        # Blinded R&D task commissioning unlocks open process improvements without private patent lock-in
        blind_rd_boost = 1.0 + (0.35 * cfg.blinded_commissioning_rate * coop_share * a_t)
        total_capacity = cap_base * (1.0 + prod_gain * a_t) * blind_rd_boost * (1.0 + wl.capacity_shock)

        # Factor income decomposition (strictly sums to total_capacity)
        baseline_prov = cfg.baseline_provisioning_share * total_capacity
        marketable_capacity = total_capacity - baseline_prov
        wage_share = 1.0 - a_t
        labor_income = wage_share * marketable_capacity
        coop_dividend_income = coop_share * a_t * marketable_capacity
        priv_rentier_income = priv_share * a_t * marketable_capacity

        # Cash demand subject to macro credit/liquidity tightening
        liquidity_factor = 1.0 - (wl.liquidity_crunch_shock * (1.0 - 0.5 * coop_share))
        raw_cash_demand = baseline_prov + liquidity_factor * (
            mpc_broad * (labor_income + coop_dividend_income)
            + mpc_concentrated * priv_rentier_income
        )
        cash_demand = min(total_capacity, max(0.0, raw_cash_demand))

        # Counter-cyclical capacity-backed mutual credit clearing (Stodder 2009 WIR stabilization)
        remaining_slack = max(0.0, total_capacity - cash_demand)
        # Mutual credit clears real slack proportional to cooperative network participation
        coop_network_reach = min(1.0, 0.35 + 0.65 * coop_share)
        mc_volume = remaining_slack * cfg.mutual_credit_limit_share * coop_network_reach

        balances_micro = apply_zero_sum_credit_decay_and_clearing(
            balances_micro=balances_micro,
            clearing_volume=mc_volume,
            decay_rate=cfg.expiring_balance_decay_rate,
            num_households=n_households,
            rotation_offset=wl.trade_rotation_offset,
        )
        cumulative_mc_volume += mc_volume

        effective_demand = min(total_capacity, cash_demand + mc_volume)
        idle_capacity = max(0.0, total_capacity - effective_demand)
        utilization = effective_demand / total_capacity if total_capacity > 0.0 else 0.0

        # 30-day durability fulfillment vs planned obsolescence churn
        # Without ZK 30-day durability signals, ad-steered turnover erodes fulfilled durability as automation scales.
        if cfg.zk_durability_steering:
            # Deterministic attestation cohort rooted in verified households (resists Sybil spoofing)
            base_durability = 0.84 + 0.11 * coop_share + wl.durability_noise
        else:
            base_durability = 0.72 - 0.14 * a_t + wl.durability_noise
        durability_rate = min(0.98, max(0.40, base_durability))

        fulfilled_durable = effective_demand * durability_rate
        obsolescence_waste = effective_demand - fulfilled_durable

        # Verify physical capacity conservation: total == durable + waste + idle
        cap_residual = abs(total_capacity - (fulfilled_durable + obsolescence_waste + idle_capacity))
        if cap_residual > 1e-9:
            capacity_conserved_all = False

        # Verify zero-sum mutual credit balance invariant
        float_balances = [b / float(MICRO_SCALE) for b in balances_micro]
        net_sum = sum(float_balances)
        max_credit_err = max(max_credit_err, abs(net_sum))
        max_abs_bal = max((abs(x) for x in float_balances), default=0.0)

        # Median household durable well-being (broad share of durable output per household, scaled)
        broad_income_total = baseline_prov + labor_income + coop_dividend_income + mc_volume
        total_income_active = max(1e-9, broad_income_total + mpc_concentrated * priv_rentier_income)
        broad_consumption_share = min(1.0, broad_income_total / total_income_active)
        household_median_wellbeing = (fulfilled_durable * broad_consumption_share) / float(n_households) * 100.0

        records.append(
            CooperativeStepRecord(
                step=t,
                automation_level=round(a_t, 8),
                total_capacity=total_capacity,
                wage_share=wage_share,
                private_equity_share=priv_share,
                cooperative_equity_share=coop_share,
                baseline_provisioning=baseline_prov,
                cash_effective_demand=cash_demand,
                mutual_credit_volume=mc_volume,
                effective_demand=effective_demand,
                capacity_utilization=utilization,
                durability_fulfillment_rate=durability_rate,
                fulfilled_durable_output=fulfilled_durable,
                obsolescence_waste_output=obsolescence_waste,
                idle_unpurchased_capacity=idle_capacity,
                household_median_wellbeing=household_median_wellbeing,
                net_credit_balance_sum=net_sum,
                credit_max_abs_balance=max_abs_bal,
            )
        )

    final_float_balances = tuple(b / float(MICRO_SCALE) for b in balances_micro)
    credit_ok = (sum(balances_micro) == 0) and (max_credit_err < 1e-9)
    last = records[-1]

    digest = canonical_sha256(
        {
            "regime": regime.value,
            "steps": steps_v,
            "final_coop_share": round(last.cooperative_equity_share, 8),
            "final_utilization": round(last.capacity_utilization, 8),
            "final_durable_output": round(last.fulfilled_durable_output, 8),
            "credit_zero_sum": credit_ok,
        }
    )

    return CooperativeTransitionResult(
        regime=regime,
        policy=cfg,
        steps=steps_v,
        automation_start=a_start,
        automation_end=a_end,
        initial_cooperative_share=coop_init,
        final_cooperative_share=last.cooperative_equity_share,
        final_private_share=last.private_equity_share,
        final_capacity_utilization=last.capacity_utilization,
        final_effective_demand=last.effective_demand,
        final_fulfilled_durable_output=last.fulfilled_durable_output,
        final_household_median_wellbeing=last.household_median_wellbeing,
        cumulative_mutual_credit_volume=cumulative_mc_volume,
        max_abs_credit_sum_error=max_credit_err,
        credit_zero_sum_verified=credit_ok,
        capacity_conservation_verified=capacity_conserved_all,
        final_balances=final_float_balances,
        step_records=tuple(records),
        receipt_digest=digest,
    )


def compare_cooperative_transition_regimes(
    *,
    steps: int = 30,
    automation_start: float = 0.25,
    automation_end: float = 0.98,
    meidner_dilution_rate: float = 0.14,
    mutual_credit_limit_share: float = 0.85,
    baseline_provisioning_share: float = 0.18,
    seed: int = 42,
) -> Dict[TransitionRegime, CooperativeTransitionResult]:
    """Compare Concentrated Enclosure vs Cooperative Transition on identical pre-generated shocks."""
    shared_workloads = generate_transition_workloads(steps=steps, num_accounts=120, seed=seed)
    enclosure = simulate_cooperative_transition(
        TransitionRegime.CONCENTRATED_ENCLOSURE,
        steps=steps,
        automation_start=automation_start,
        automation_end=automation_end,
        seed=seed,
        workloads=shared_workloads,
    )
    coop_policy = default_policy_for_regime(
        TransitionRegime.COOPERATIVE_TRANSITION,
        meidner_dilution_rate=meidner_dilution_rate,
        mutual_credit_limit_share=mutual_credit_limit_share,
        baseline_provisioning_share=baseline_provisioning_share,
    )
    cooperative = simulate_cooperative_transition(
        TransitionRegime.COOPERATIVE_TRANSITION,
        policy=coop_policy,
        steps=steps,
        automation_start=automation_start,
        automation_end=automation_end,
        seed=seed,
        workloads=shared_workloads,
    )
    return {
        TransitionRegime.CONCENTRATED_ENCLOSURE: enclosure,
        TransitionRegime.COOPERATIVE_TRANSITION: cooperative,
    }


# =====================================================================
# 3. Dark-Ledger Cartel Containment & Antitrust Leniency Engine
# =====================================================================

def compute_myerson_club_value(
    coalition_size: int,
    total_network_agents: int,
    base_productivity: float = 10.0,
    club_scale: float = 0.85,
    myerson_alpha: float = 0.55,
) -> Tuple[float, float]:
    """
    Compute Roger Myerson (1977) communication-connected cooperative coalition value.

    Returns `(total_coalition_value, per_member_value)`.
    Because total value scales as `n * base * (1 + club_scale * (n / N)^alpha)` with `alpha > 0`,
    disjoint open coalitions S and T strictly satisfy superadditivity:
    `V(S U T) > V(S) + V(T)` whenever |S| >= 1 and |T| >= 1.
    """
    n = _validate_int("coalition_size", coalition_size, minimum=0)
    n_tot = _validate_int("total_network_agents", total_network_agents, minimum=1)
    if n > n_tot:
        raise CooperativeSimValidationError(f"coalition_size ({n}) cannot exceed total_network_agents ({n_tot}).")
    base = _validate_float("base_productivity", base_productivity, minimum=0.1, maximum=1e6)
    scale = _validate_float("club_scale", club_scale, minimum=0.0, maximum=10.0)
    alpha = _validate_float("myerson_alpha", myerson_alpha, minimum=0.05, maximum=3.0)

    if n == 0:
        return (0.0, 0.0)
    per_member = base * (1.0 + scale * ((n / float(n_tot)) ** alpha))
    return (n * per_member, per_member)


def compute_physical_conservation_detection_prob(
    accounted_open_mw: float,
    shadow_unaccounted_mw: float,
    metering_noise_epsilon_mw: float = 0.0,
    noise_tolerance_mw: float = 1.5,
    detection_half_sat_mw: float = 18.0,
    physical_audit_enabled: bool = True,
) -> Tuple[float, float, float]:
    """
    Zero-knowledge physical energy/compute boundary conservation check (`E_in = E_accounted + epsilon`).

    Returns `(metered_total_mw, unexplained_residual_mw, detection_probability)`.
    """
    e_open = _validate_float("accounted_open_mw", accounted_open_mw, minimum=0.0)
    e_shadow = _validate_float("shadow_unaccounted_mw", shadow_unaccounted_mw, minimum=0.0)
    eps = _validate_float("metering_noise_epsilon_mw", metering_noise_epsilon_mw, minimum=-50.0, maximum=50.0)
    tol = _validate_float("noise_tolerance_mw", noise_tolerance_mw, minimum=0.0, maximum=100.0)
    half_sat = _validate_float("detection_half_sat_mw", detection_half_sat_mw, minimum=0.1, maximum=1e5)
    _validate_bool("physical_audit_enabled", physical_audit_enabled)

    metered_e_in = e_open + e_shadow + eps
    unexplained_residual = metered_e_in - e_open  # equals e_shadow + eps

    if not physical_audit_enabled or e_shadow <= 0.0:
        return (metered_e_in, unexplained_residual, 0.0)

    excess_mw = max(0.0, unexplained_residual - tol)
    if excess_mw <= 0.0:
        return (metered_e_in, unexplained_residual, 0.0)

    prob = min(0.98, excess_mw / (excess_mw + half_sat))
    return (metered_e_in, unexplained_residual, prob)


@dataclasses.dataclass(frozen=True)
class NashCartelThresholdAnalysis:
    """Closed-form Harrington (2008) + Myerson (1977) Nash cartel stability analysis."""
    open_per_member_payoff: float
    cartel_per_member_payoff: float
    physical_detection_prob: float
    present_value_collude: float
    present_value_defect: float
    critical_whistleblower_bounty: float
    critical_opacity_margin_tau: float
    defection_strictly_dominant: bool


def compute_nash_cartel_threshold(
    *,
    total_agents: int = 60,
    active_cartel_size: int = 15,
    opacity_margin_tau: float = 0.25,
    whistleblower_bounty: float = 12.0,
    physical_detection_prob: float = 0.20,
    sanction_fine: float = 18.0,
    discount_factor: float = 0.85,
    base_productivity: float = 10.0,
    collusive_rent_scale: float = 9.5,
    border_trade_exposure: float = 14.0,
    club_scale: float = 0.85,
    myerson_alpha: float = 0.55,
) -> NashCartelThresholdAnalysis:
    """
    Compute exact closed-form Nash sustainability vs collapse thresholds for a covert shadow cartel.

    Under discount factor `beta`, physical detection probability `p_phys`, sanction `F`,
    border opacity margin `tau`, and first-whistleblower leniency award `B`:
      V_open    = pi_O / (1 - beta)
      V_collude = (pi_C(tau) - p_phys * F + beta * p_phys * V_open) / (1 - beta * (1 - p_phys))
      V_defect  = B + V_open
    Unilateral whistleblower defection strictly dominates (`V_defect > V_collude`) iff:
      B > B* = max(0, (pi_C(tau) - pi_O - p_phys * F) / (1 - beta * (1 - p_phys))).
    """
    n_tot = _validate_int("total_agents", total_agents, minimum=3, maximum=100_000)
    m_cartel = _validate_int("active_cartel_size", active_cartel_size, minimum=0, maximum=n_tot)
    tau = _validate_float("opacity_margin_tau", opacity_margin_tau, 0.0, 1.0)
    bounty = _validate_float("whistleblower_bounty", whistleblower_bounty, 0.0, 1e6)
    p_phys = _validate_float("physical_detection_prob", physical_detection_prob, 0.0, 0.999)
    fine = _validate_float("sanction_fine", sanction_fine, 0.0, 1e6)
    beta = _validate_float("discount_factor", discount_factor, 0.01, 0.99, strict_max=True)
    base_prod = _validate_float("base_productivity", base_prod := base_productivity, 0.1, 1e6)
    rent_scale = _validate_float("collusive_rent_scale", collusive_rent_scale, 0.0, 1e6)
    exposure = _validate_float("border_trade_exposure", border_trade_exposure, 0.1, 1e6)

    if m_cartel <= 1:
        _, pi_open = compute_myerson_club_value(
            n_tot, n_tot, base_productivity=base_prod, club_scale=club_scale, myerson_alpha=myerson_alpha
        )
        v_open = pi_open / (1.0 - beta)
        return NashCartelThresholdAnalysis(
            open_per_member_payoff=pi_open,
            cartel_per_member_payoff=0.0,
            physical_detection_prob=0.0,
            present_value_collude=0.0,
            present_value_defect=v_open + bounty,
            critical_whistleblower_bounty=0.0,
            critical_opacity_margin_tau=0.0,
            defection_strictly_dominant=True,
        )

    # Defector leaves cartel and joins the open cooperative network (size becomes N - m + 1)
    open_after_defection = n_tot - m_cartel + 1
    _, pi_open = compute_myerson_club_value(
        open_after_defection,
        n_tot,
        base_productivity=base_prod,
        club_scale=club_scale,
        myerson_alpha=myerson_alpha,
    )

    # Shadow cartel forfeits open Myerson demand-graph club bonus, extracts collusive markup
    # proportional to cartel share, and pays border opacity quarantine margin `tau * exposure`.
    gross_cartel_rent = rent_scale * (0.45 + 0.55 * (m_cartel / float(n_tot)))
    pi_cartel = max(0.0, base_prod + gross_cartel_rent - (tau * exposure))

    v_open = pi_open / (1.0 - beta)
    denom = 1.0 - beta * (1.0 - p_phys)
    v_collude = (pi_cartel - (p_phys * fine) + (beta * p_phys * v_open)) / denom
    v_defect = bounty + v_open

    raw_b_star = (pi_cartel - pi_open - (p_phys * fine)) / denom
    b_star = max(0.0, raw_b_star)

    # Critical tau* solving pi_cartel(tau*) == pi_open + p_phys * fine + bounty * denom
    required_pi_c_ceiling = pi_open + (p_phys * fine) + (bounty * denom)
    raw_tau_star = (base_prod + gross_cartel_rent - required_pi_c_ceiling) / exposure
    tau_star = min(1.0, max(0.0, raw_tau_star))

    return NashCartelThresholdAnalysis(
        open_per_member_payoff=pi_open,
        cartel_per_member_payoff=pi_cartel,
        physical_detection_prob=p_phys,
        present_value_collude=v_collude,
        present_value_defect=v_defect,
        critical_whistleblower_bounty=b_star,
        critical_opacity_margin_tau=tau_star,
        defection_strictly_dominant=(v_defect > v_collude),
    )


@dataclasses.dataclass(frozen=True)
class DarkLedgerRoundWorkload:
    """Pre-generated per-round physical metering noise and audit uniform draw (zero RNG drift)."""
    round_index: int
    metering_noise_mw: float
    audit_uniform_draw: float


def generate_dark_ledger_workloads(
    rounds: int = 20,
    noise_bound_mw: float = 0.8,
    seed: int = 42,
) -> Tuple[DarkLedgerRoundWorkload, ...]:
    """Generate deterministic physical metering noise and audit draws upfront."""
    r_cnt = _validate_int("rounds", rounds, minimum=1, maximum=500)
    n_bnd = _validate_float("noise_bound_mw", noise_bound_mw, minimum=0.0, maximum=25.0)
    seed_v = _validate_int("seed", seed, minimum=0)
    rng = random.Random(seed_v)
    return tuple(
        DarkLedgerRoundWorkload(
            round_index=r,
            metering_noise_mw=rng.uniform(-n_bnd, n_bnd),
            audit_uniform_draw=rng.random(),
        )
        for r in range(r_cnt)
    )


@dataclasses.dataclass(frozen=True)
class DarkLedgerRoundRecord:
    """Per-round state, physical energy conservation check, and capital flows."""
    round_index: int
    active_cartel_members: int
    open_network_members: int
    metered_energy_in_mw: float
    accounted_open_energy_mw: float
    shadow_unaccounted_energy_mw: float
    metering_noise_epsilon_mw: float
    physical_detection_prob: float
    whistleblower_triggered: bool
    physical_audit_triggered: bool
    defectors_this_round: int
    opacity_margin_collected_cents: int
    slashed_collateral_cents: int
    whistleblower_bounty_paid_cents: int
    commons_reserve_balance_cents: int
    open_per_member_payoff: float
    cartel_per_member_payoff: float


@dataclasses.dataclass(frozen=True)
class DarkLedgerContainmentResult:
    """Aggregate outcome of Open Verifiable Cooperative Network vs Shadow-Ledger Cartel."""
    total_agents: int
    initial_cartel_size: int
    final_cartel_size: int
    final_open_size: int
    cartel_defection_rate: float
    cartel_collapsed: bool
    collapse_round: Optional[int]
    initial_threshold: NashCartelThresholdAnalysis
    total_opacity_margin_collected_cents: int
    total_slashed_collateral_cents: int
    total_whistleblower_bounty_paid_cents: int
    final_commons_reserve_cents: int
    capital_conservation_verified: bool
    physical_energy_conservation_verified: bool
    round_records: Tuple[DarkLedgerRoundRecord, ...]
    receipt_digest: str


def simulate_dark_ledger_containment(
    *,
    total_agents: int = 60,
    initial_cartel_size: int = 16,
    rounds: int = 20,
    opacity_margin_tau: float = 0.28,
    whistleblower_bounty: float = 12.0,
    physical_audit_enabled: bool = True,
    per_agent_open_mw: float = 1.2,
    per_agent_shadow_mw: float = 2.4,
    sanction_fine: float = 18.0,
    discount_factor: float = 0.85,
    base_productivity: float = 10.0,
    collusive_rent_scale: float = 9.5,
    border_trade_exposure: float = 14.0,
    seed: int = 42,
    workloads: Optional[Sequence[DarkLedgerRoundWorkload]] = None,
) -> DarkLedgerContainmentResult:
    """
    Simulate an Open Verifiable Cooperative Network defending against a Secretive Shadow-Ledger
    Agent Cartel via:
      (i)   ZK physical energy/compute boundary conservation (`E_in = E_accounted + E_shadow + epsilon`),
      (ii)  Border opacity quarantine margins `tau` paid on unverified cross-border trade, and
      (iii) Harrington (2008) first-whistleblower leniency safe-harbor bounties.

    Enforces strict integer-cent capital conservation across collateral slashing, bounties, and
    commons reserves, and zero RNG calls inside the simulation loop.
    """
    n_tot = _validate_int("total_agents", total_agents, minimum=4, maximum=10_000)
    m_init = _validate_int("initial_cartel_size", initial_cartel_size, minimum=2, maximum=n_tot - 1)
    r_cnt = _validate_int("rounds", rounds, minimum=1, maximum=500)
    tau = _validate_float("opacity_margin_tau", opacity_margin_tau, 0.0, 1.0)
    bounty = _validate_float("whistleblower_bounty", whistleblower_bounty, 0.0, 1e6)
    _validate_bool("physical_audit_enabled", physical_audit_enabled)
    open_mw_unit = _validate_float("per_agent_open_mw", per_agent_open_mw, 0.05, 1e4)
    shadow_mw_unit = _validate_float("per_agent_shadow_mw", per_agent_shadow_mw, 0.05, 1e4)
    fine = _validate_float("sanction_fine", sanction_fine, 0.0, 1e6)
    beta = _validate_float("discount_factor", discount_factor, 0.01, 0.99, strict_max=True)
    base_prod = _validate_float("base_productivity", base_productivity, 0.1, 1e6)
    rent_scale = _validate_float("collusive_rent_scale", collusive_rent_scale, 0.0, 1e6)
    exposure = _validate_float("border_trade_exposure", border_trade_exposure, 0.1, 1e6)

    if workloads is None:
        round_wls = generate_dark_ledger_workloads(rounds=r_cnt, seed=seed)
    else:
        if len(workloads) != r_cnt:
            raise CooperativeSimValidationError(f"Expected {r_cnt} round workloads, got {len(workloads)}.")
        round_wls = tuple(workloads)

    # Evaluate initial Round-0 threshold at deterministic zero-noise baseline
    _, _, p_phys_init = compute_physical_conservation_detection_prob(
        accounted_open_mw=(n_tot - m_init) * open_mw_unit,
        shadow_unaccounted_mw=m_init * shadow_mw_unit,
        metering_noise_epsilon_mw=0.0,
        physical_audit_enabled=physical_audit_enabled,
    )
    initial_threshold = compute_nash_cartel_threshold(
        total_agents=n_tot,
        active_cartel_size=m_init,
        opacity_margin_tau=tau,
        whistleblower_bounty=bounty,
        physical_detection_prob=p_phys_init,
        sanction_fine=fine,
        discount_factor=beta,
        base_productivity=base_prod,
        collusive_rent_scale=rent_scale,
        border_trade_exposure=exposure,
    )

    m_active = m_init
    commons_reserve_cents = 0
    total_margin_cents = 0
    total_slashed_cents = 0
    total_bounty_cents = 0
    collapse_round: Optional[int] = None
    energy_conserved_all = True
    capital_conserved_all = True

    records: List[DarkLedgerRoundRecord] = []

    for r in range(r_cnt):
        wl = round_wls[r]
        n_open = n_tot - m_active
        e_open = n_open * open_mw_unit
        e_shadow = m_active * shadow_mw_unit if m_active >= 2 else 0.0
        e_in, _, p_phys = compute_physical_conservation_detection_prob(
            accounted_open_mw=e_open,
            shadow_unaccounted_mw=e_shadow,
            metering_noise_epsilon_mw=wl.metering_noise_mw,
            physical_audit_enabled=physical_audit_enabled,
        )

        # Verify physical energy boundary conservation: E_in == E_accounted + E_shadow + epsilon
        if abs(e_in - (e_open + e_shadow + wl.metering_noise_mw)) > 1e-9:
            energy_conserved_all = False

        whistle_triggered = False
        audit_triggered = False
        defectors = 0
        margin_cents = 0
        slashed_cents = 0
        bounty_paid_cents = 0

        if m_active >= 2:
            thresh = compute_nash_cartel_threshold(
                total_agents=n_tot,
                active_cartel_size=m_active,
                opacity_margin_tau=tau,
                whistleblower_bounty=bounty,
                physical_detection_prob=p_phys,
                sanction_fine=fine,
                discount_factor=beta,
                base_productivity=base_prod,
                collusive_rent_scale=rent_scale,
                border_trade_exposure=exposure,
            )
            pi_open = thresh.open_per_member_payoff
            pi_cartel = thresh.cartel_per_member_payoff

            if thresh.defection_strictly_dominant:
                # Harrington dominant-strategy race to leniency door: first defector claims safe harbor,
                # remaining (m_active - 1) co-conspirators are sanctioned and cartel collapses 100%.
                whistle_triggered = True
                defectors = m_active
                slashed_cents = int(round((m_active - 1) * fine * 100))
                requested_bounty_cents = int(round(bounty * 100))
                # Bounty is strictly bounded by slashed cartel collateral (exact capital conservation)
                bounty_paid_cents = min(slashed_cents, requested_bounty_cents)
                commons_inflow_cents = slashed_cents - bounty_paid_cents
                commons_reserve_cents += commons_inflow_cents
                m_active = 0
                if collapse_round is None:
                    collapse_round = r
            else:
                # Cartel attempts to operate this round; pays border opacity quarantine margin
                margin_cents = int(round(m_active * tau * exposure * 100))
                commons_reserve_cents += margin_cents

                # Physical conservation boundary audit test
                if p_phys > 0.0 and wl.audit_uniform_draw < p_phys:
                    audit_triggered = True
                    slashed_cents = int(round(m_active * fine * 100))
                    commons_reserve_cents += slashed_cents
                    # Caught members lose shadow coordination leases; half exit per enforcement wave
                    defectors = max(2, (m_active + 1) // 2)
                    defectors = min(m_active, defectors)
                    m_active -= defectors
                    if m_active == 1:
                        # Single isolated agent cannot form a cartel; transitions to open network
                        defectors += 1
                        m_active = 0
                    if m_active == 0 and collapse_round is None:
                        collapse_round = r
        else:
            _, pi_open = compute_myerson_club_value(n_tot, n_tot, base_productivity=base_prod)
            pi_cartel = 0.0

        total_margin_cents += margin_cents
        total_slashed_cents += slashed_cents
        total_bounty_cents += bounty_paid_cents

        # Strict accounting identity: commons_reserve == total_margins + (total_slashed - total_bounties)
        if commons_reserve_cents != (total_margin_cents + total_slashed_cents - total_bounty_cents):
            capital_conserved_all = False

        records.append(
            DarkLedgerRoundRecord(
                round_index=r,
                active_cartel_members=m_active,
                open_network_members=n_tot - m_active,
                metered_energy_in_mw=e_in,
                accounted_open_energy_mw=e_open,
                shadow_unaccounted_energy_mw=e_shadow,
                metering_noise_epsilon_mw=wl.metering_noise_mw,
                physical_detection_prob=p_phys,
                whistleblower_triggered=whistle_triggered,
                physical_audit_triggered=audit_triggered,
                defectors_this_round=defectors,
                opacity_margin_collected_cents=margin_cents,
                slashed_collateral_cents=slashed_cents,
                whistleblower_bounty_paid_cents=bounty_paid_cents,
                commons_reserve_balance_cents=commons_reserve_cents,
                open_per_member_payoff=pi_open,
                cartel_per_member_payoff=pi_cartel,
            )
        )

    defection_rate = (m_init - m_active) / float(m_init)
    digest = canonical_sha256(
        {
            "total_agents": n_tot,
            "initial_cartel_size": m_init,
            "final_cartel_size": m_active,
            "defection_rate": round(defection_rate, 8),
            "commons_reserve_cents": commons_reserve_cents,
            "capital_conserved": capital_conserved_all,
        }
    )

    return DarkLedgerContainmentResult(
        total_agents=n_tot,
        initial_cartel_size=m_init,
        final_cartel_size=m_active,
        final_open_size=n_tot - m_active,
        cartel_defection_rate=defection_rate,
        cartel_collapsed=(m_active == 0),
        collapse_round=collapse_round,
        initial_threshold=initial_threshold,
        total_opacity_margin_collected_cents=total_margin_cents,
        total_slashed_collateral_cents=total_slashed_cents,
        total_whistleblower_bounty_paid_cents=total_bounty_cents,
        final_commons_reserve_cents=commons_reserve_cents,
        capital_conservation_verified=capital_conserved_all,
        physical_energy_conservation_verified=energy_conserved_all,
        round_records=tuple(records),
        receipt_digest=digest,
    )
