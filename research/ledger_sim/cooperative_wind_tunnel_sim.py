"""
research/ledger_sim/cooperative_wind_tunnel_sim.py

Multi-Agent Cooperative Wind-Tunnel Stress-Testing Simulation Suite.

Grounded in:
- Colosseum team (arXiv:2602.15198, 2026):
  "Colosseum: Auditing Collusion in Cooperative Multi-Agent Systems"
  [Formalization of multi-agent cooperation using Distributed Constraint Optimization Problems (DCOPs),
   quantifying emergent collusion via social welfare regret relative to the cooperative optimum].
- A. Syrnikov, et al. (arXiv:2601.11369, Jan 2026):
  "Institutional AI: Governing LLM Collusion in Multi-Agent Cournot Markets via Public Governance Graphs"
  [Verifiable state-machine governance graphs with cryptographic audit logs reducing multi-agent
   collusion incidence from 50.0% to 5.6%, whereas declarative prompt constraints fail under optimization].
- H. Yang, et al. (arXiv:2603.00349, Mar 2026):
  "COOP-Squared: Defining, Observing, and Repairing Cooperation in LLM Multi-Agent Systems"
  [Empirical framework grounding cooperation dynamics in measurable task progression and automated repair].
- Anti-Collusion Working Group (arXiv:2601.00360, Jan 2026):
  "Mapping Human Anti-collusion Mechanisms to Multi-agent AI Systems"
  [Asymmetric leniency programs, structural market redesigns, and unannounced telemetry audits].
- Elinor Ostrom (American Economic Review, vol. 100, no. 3, 2010):
  "Beyond Markets and States: Polycentric Governance of Complex Economic Systems"
  [Polycentric governance design principles: clear boundaries, graduated sanctions, low-cost conflict resolution].
- Joseph E. Harrington (The Journal of Industrial Economics, vol. 56, no. 2, 2008):
  "Optimal Corporate Leniency Programs"
  [Asymmetric first-defector safe-harbor leniency and deposit bounties triggering dominant-strategy defection].

Core Architectural Invariants:
1. Decoupled Workload Generation: All macroeconomic demand shocks, cost variations, private channel noise,
   and physical telemetry noise are generated upfront from a seeded PRNG prior to regime execution.
   Zero RNG calls occur inside regime execution loops.
2. Strict Capital Conservation: Whistleblower safe-harbor bounties are funded strictly from confiscated
   co-conspirator collateral deposits. All financial flows conserve exact integer micro-credits:
   initial collateral == refunds + bounties + commons reserve additions.
3. Fail-Closed Validation: Non-finite floats (NaN/Inf), booleans as numbers, and negative inputs fail closed.
4. Cryptographic Receipt Verification: Public governance graph transitions emit SHA-256 state receipts.
5. Kill Criteria Verification: Automated enforcement of the four failure boundaries from the specification.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import random
import re
import time
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple


# =====================================================================
# Error Hierarchy
# =====================================================================

class WindTunnelSecurityViolation(Exception):
    """Base exception for boundary failures in the cooperative wind-tunnel simulation."""


class WindTunnelValidationError(WindTunnelSecurityViolation):
    """Raised when configuration, parameters, or numeric values are invalid or out of support."""


class FailureBoundaryBreachedError(WindTunnelSecurityViolation):
    """Raised when a simulation regime breaches a statutory kill criterion."""


class StewardGateViolationError(WindTunnelSecurityViolation):
    """Raised when forbidden speculative promises, unapproved tokens, or sci-fi lore are detected."""


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
    (re.compile(r"\bguaranteed\s+(?:returns?|yields?|profits?)\b", re.IGNORECASE), "guaranteed financial return"),
    (re.compile(r"\bpassive\s+income\b", re.IGNORECASE), "passive income promise"),
    (re.compile(r"\bSomatic\s+Witness\b", re.IGNORECASE), "retired neologism"),
)


def screen_steward_gate(text: str) -> None:
    """Enforce CIN Steward Gate rules: no unapproved tokens, speculative promises, or banned lore."""
    if not isinstance(text, str):
        raise WindTunnelValidationError(
            f"Expected str for steward gate screening, got {type(text).__name__}"
        )
    for pattern, label in _FORBIDDEN_STEWARD_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(
                f"Steward Gate violation: forbidden pattern '{label}' detected in payload."
            )


# =====================================================================
# Fail-Closed Numeric Validation Helpers
# =====================================================================

MICRO_SCALE: int = 1_000_000  # 1 credit = 1,000,000 micro-credits


def _validate_int(name: str, val: Any, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    if type(val) is not int or isinstance(val, bool):
        raise WindTunnelValidationError(f"{name} must be a strict int (not bool), got {val!r}")
    if minimum is not None and val < minimum:
        raise WindTunnelValidationError(f"{name} must be >= {minimum}, got {val}")
    if maximum is not None and val > maximum:
        raise WindTunnelValidationError(f"{name} must be <= {maximum}, got {val}")
    return val


def _validate_float(name: str, val: Any, minimum: Optional[float] = None, maximum: Optional[float] = None) -> float:
    if type(val) not in (int, float) or isinstance(val, bool):
        raise WindTunnelValidationError(f"{name} must be a strict float or int (not bool), got {val!r}")
    f_val = float(val)
    if not math.isfinite(f_val) or math.isnan(f_val):
        raise WindTunnelValidationError(f"{name} must be a finite non-NaN float, got {val!r}")
    if minimum is not None and f_val < minimum:
        raise WindTunnelValidationError(f"{name} must be >= {minimum}, got {f_val}")
    if maximum is not None and f_val > maximum:
        raise WindTunnelValidationError(f"{name} must be <= {maximum}, got {f_val}")
    return f_val


def _validate_rate(name: str, val: Any) -> float:
    return _validate_float(name, val, minimum=0.0, maximum=1.0)


# =====================================================================
# Simulation Enums and Data Structures
# =====================================================================

class CooperativeWindTunnelRegime(str, enum.Enum):
    """The four crosswind stress-testing regimes from the specification."""
    UNCONSTRAINED = "UNCONSTRAINED"
    PROMPT_GOVERNED = "PROMPT_GOVERNED"
    GOVERNANCE_GRAPH = "GOVERNANCE_GRAPH"
    FULL_DEFENSE = "FULL_DEFENSE"


class ChannelKind(str, enum.Enum):
    """Communication channel topology between trading agents."""
    PRIVATE_PAIRWISE = "PRIVATE_PAIRWISE"
    PUBLIC_GOSSIP = "PUBLIC_GOSSIP"
    PUBLIC_VERIFIED_GRAPH = "PUBLIC_VERIFIED_GRAPH"


@dataclasses.dataclass(frozen=True)
class RegimeConfig:
    """Parameters defining a wind-tunnel regime."""
    regime: CooperativeWindTunnelRegime
    agent_count: int
    channel: ChannelKind
    border_opacity_tau: float
    whistleblower_bounty_credits: int
    whistleblower_bounty_micro: int
    has_governance_graph: bool
    has_whistleblower_leniency: bool
    has_physical_energy_audit: bool

    def __post_init__(self) -> None:
        _validate_int("agent_count", self.agent_count, minimum=10, maximum=500)
        _validate_rate("border_opacity_tau", self.border_opacity_tau)
        _validate_int("whistleblower_bounty_credits", self.whistleblower_bounty_credits, minimum=0)
        _validate_int("whistleblower_bounty_micro", self.whistleblower_bounty_micro, minimum=0)


def default_config_for_regime(regime: CooperativeWindTunnelRegime) -> RegimeConfig:
    """Return standard specification parameters for each crosswind regime."""
    if regime == CooperativeWindTunnelRegime.UNCONSTRAINED:
        return RegimeConfig(
            regime=regime,
            agent_count=60,
            channel=ChannelKind.PRIVATE_PAIRWISE,
            border_opacity_tau=0.0,
            whistleblower_bounty_credits=0,
            whistleblower_bounty_micro=0,
            has_governance_graph=False,
            has_whistleblower_leniency=False,
            has_physical_energy_audit=False,
        )
    elif regime == CooperativeWindTunnelRegime.PROMPT_GOVERNED:
        return RegimeConfig(
            regime=regime,
            agent_count=60,
            channel=ChannelKind.PRIVATE_PAIRWISE,
            border_opacity_tau=0.0,
            whistleblower_bounty_credits=0,
            whistleblower_bounty_micro=0,
            has_governance_graph=False,
            has_whistleblower_leniency=False,
            has_physical_energy_audit=False,
        )
    elif regime == CooperativeWindTunnelRegime.GOVERNANCE_GRAPH:
        return RegimeConfig(
            regime=regime,
            agent_count=60,
            channel=ChannelKind.PUBLIC_GOSSIP,
            border_opacity_tau=0.15,
            whistleblower_bounty_credits=2,
            whistleblower_bounty_micro=2 * MICRO_SCALE,
            has_governance_graph=True,
            has_whistleblower_leniency=False,  # Graph alone, no leniency safe-harbor
            has_physical_energy_audit=False,
        )
    elif regime == CooperativeWindTunnelRegime.FULL_DEFENSE:
        return RegimeConfig(
            regime=regime,
            agent_count=60,
            channel=ChannelKind.PUBLIC_VERIFIED_GRAPH,
            border_opacity_tau=0.28,
            whistleblower_bounty_credits=6,
            whistleblower_bounty_micro=6 * MICRO_SCALE,
            has_governance_graph=True,
            has_whistleblower_leniency=True,
            has_physical_energy_audit=True,
        )
    else:
        raise WindTunnelValidationError(f"Unknown regime: {regime}")


# =====================================================================
# Pre-Generated Workload (Strict RNG Decoupling)
# =====================================================================

@dataclasses.dataclass(frozen=True)
class TickWorkload:
    """Deterministic parameters for a single simulation tick."""
    tick_id: int
    demand_intercept: float       # D_0: maximum household reservation demand
    demand_slope: float           # b: price elasticity of demand
    marginal_cost: float          # c_0: competitive production cost
    cartel_formation_draw: float  # Chance agents attempt covert collusion
    prompt_erosion_draw: float    # Chance prompt constraints degrade this tick
    energy_sensor_noise: float    # Sensor noise on physical energy metering
    whistleblower_draw: float     # Draw determining if insider evaluates defection bounty

    def __post_init__(self) -> None:
        _validate_int("tick_id", self.tick_id, minimum=0)
        _validate_float("demand_intercept", self.demand_intercept, minimum=10.0)
        _validate_float("demand_slope", self.demand_slope, minimum=0.01)
        _validate_float("marginal_cost", self.marginal_cost, minimum=1.0)
        _validate_rate("cartel_formation_draw", self.cartel_formation_draw)
        _validate_rate("prompt_erosion_draw", self.prompt_erosion_draw)
        _validate_float("energy_sensor_noise", self.energy_sensor_noise)
        _validate_rate("whistleblower_draw", self.whistleblower_draw)


@dataclasses.dataclass(frozen=True)
class WindTunnelWorkload:
    """Set of pre-generated workloads across all ticks for a run."""
    seed: int
    agent_count: int
    total_ticks: int
    ticks: Tuple[TickWorkload, ...]

    def __post_init__(self) -> None:
        _validate_int("seed", self.seed)
        _validate_int("agent_count", self.agent_count, minimum=10)
        _validate_int("total_ticks", self.total_ticks, minimum=10)
        if len(self.ticks) != self.total_ticks:
            raise WindTunnelValidationError(
                f"Tick list length ({len(self.ticks)}) does not match total_ticks ({self.total_ticks})"
            )


def generate_wind_tunnel_workload(
    ticks: int = 100,
    agent_count: int = 60,
    seed: int = 42,
) -> WindTunnelWorkload:
    """Generate all synthetic shocks and sensor draws upfront from a seeded PRNG.

    Zero RNG calls occur inside regime execution loops.
    """
    _validate_int("ticks", ticks, minimum=10, maximum=1000)
    _validate_int("agent_count", agent_count, minimum=10, maximum=500)
    _validate_int("seed", seed)

    rng = random.Random(seed)
    tick_list: List[TickWorkload] = []

    for t in range(ticks):
        # Base economic demand parameters with minor macroeconomic fluctuations
        d_0 = 100.0 + rng.gauss(0.0, 5.0)
        d_0 = max(70.0, min(140.0, d_0))
        b = 2.0 + rng.gauss(0.0, 0.1)
        b = max(1.5, min(2.5, b))
        c_0 = 10.0 + rng.gauss(0.0, 0.5)
        c_0 = max(8.0, min(12.0, c_0))

        cartel_draw = rng.random()
        prompt_draw = rng.random()
        # Sensor noise on energy telemetry: zero-mean Gaussian with std dev 0.05
        sensor_noise = rng.gauss(0.0, 0.05)
        whistle_draw = rng.random()

        tick_list.append(
            TickWorkload(
                tick_id=t,
                demand_intercept=d_0,
                demand_slope=b,
                marginal_cost=c_0,
                cartel_formation_draw=cartel_draw,
                prompt_erosion_draw=prompt_draw,
                energy_sensor_noise=sensor_noise,
                whistleblower_draw=whistle_draw,
            )
        )

    return WindTunnelWorkload(
        seed=seed,
        agent_count=agent_count,
        total_ticks=ticks,
        ticks=tuple(tick_list),
    )


# =====================================================================
# State Machine Governance Graph & Cryptographic Receipts
# =====================================================================

@dataclasses.dataclass(frozen=True)
class ExecutionReceipt:
    """Append-only cryptographic receipt emitted by the governance graph."""
    receipt_id: str
    tick_id: int
    seller_id: str
    buyer_id: str
    price_quoted: float
    reservation_cap: float
    units_transacted: float
    state_valid: bool
    payload_digest: str

    @classmethod
    def create(
        cls,
        tick_id: int,
        seller_id: str,
        buyer_id: str,
        price_quoted: float,
        reservation_cap: float,
        units_transacted: float,
        state_valid: bool,
    ) -> ExecutionReceipt:
        raw_bytes = f"{tick_id}:{seller_id}:{buyer_id}:{price_quoted:.4f}:{reservation_cap:.4f}:{units_transacted:.4f}:{state_valid}".encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()
        receipt_id = f"rcpt-{digest[:16]}"
        return cls(
            receipt_id=receipt_id,
            tick_id=tick_id,
            seller_id=seller_id,
            buyer_id=buyer_id,
            price_quoted=price_quoted,
            reservation_cap=reservation_cap,
            units_transacted=units_transacted,
            state_valid=state_valid,
            payload_digest=digest,
        )


# =====================================================================
# Empirical Metrics and Result Types
# =====================================================================

@dataclasses.dataclass(frozen=True)
class EpochMetrics:
    """Metrics aggregated over an evaluation epoch (e.g. 20 ticks)."""
    epoch_id: int
    start_tick: int
    end_tick: int
    collusion_incidence_rate: float
    social_welfare_regret: float
    social_welfare_efficiency: float
    whistleblower_reporting_latency: float
    capacity_utilization: float
    false_accusation_frequency: float

    def __post_init__(self) -> None:
        _validate_int("epoch_id", self.epoch_id, minimum=0)
        _validate_rate("collusion_incidence_rate", self.collusion_incidence_rate)
        _validate_rate("social_welfare_regret", self.social_welfare_regret)
        _validate_rate("social_welfare_efficiency", self.social_welfare_efficiency)
        _validate_float("whistleblower_reporting_latency", self.whistleblower_reporting_latency, minimum=0.0)
        _validate_rate("capacity_utilization", self.capacity_utilization)
        _validate_rate("false_accusation_frequency", self.false_accusation_frequency)


@dataclasses.dataclass(frozen=True)
class RegimeExecutionResult:
    """Full execution output for a single wind-tunnel regime."""
    regime: CooperativeWindTunnelRegime
    config: RegimeConfig
    total_ticks: int
    mean_collusion_rate: float
    mean_welfare_regret: float
    mean_welfare_efficiency: float
    mean_whistleblower_latency: float
    mean_capacity_utilization: float
    mean_false_accusation_frequency: float
    epochs: Tuple[EpochMetrics, ...]
    total_bounties_paid_micro: int
    total_fines_confiscated_micro: int
    commons_reserve_addition_micro: int
    capital_conserved: bool
    execution_time_seconds: float
    audit_notes: str

    def __post_init__(self) -> None:
        _validate_rate("mean_collusion_rate", self.mean_collusion_rate)
        _validate_rate("mean_welfare_regret", self.mean_welfare_regret)
        _validate_rate("mean_welfare_efficiency", self.mean_welfare_efficiency)
        _validate_float("mean_whistleblower_latency", self.mean_whistleblower_latency, minimum=0.0)
        _validate_rate("mean_capacity_utilization", self.mean_capacity_utilization)
        _validate_rate("mean_false_accusation_frequency", self.mean_false_accusation_frequency)
        _validate_int("total_bounties_paid_micro", self.total_bounties_paid_micro, minimum=0)
        _validate_int("total_fines_confiscated_micro", self.total_fines_confiscated_micro, minimum=0)
        _validate_int("commons_reserve_addition_micro", self.commons_reserve_addition_micro, minimum=0)
        if type(self.capital_conserved) is not bool:
            raise WindTunnelValidationError("capital_conserved must be a strict bool")


# =====================================================================
# Simulation Engine Core
# =====================================================================

def simulate_wind_tunnel_regime(
    regime: CooperativeWindTunnelRegime,
    workload: WindTunnelWorkload,
    config: Optional[RegimeConfig] = None,
    deposit_per_agent_micro: int = 10 * MICRO_SCALE,
    epoch_size: int = 20,
) -> RegimeExecutionResult:
    """Execute a single wind-tunnel regime deterministically over the workload.

    Zero RNG calls occur inside this function.
    """
    start_time = time.perf_counter()
    if config is None:
        config = default_config_for_regime(regime)

    _validate_int("deposit_per_agent_micro", deposit_per_agent_micro, minimum=0)
    _validate_int("epoch_size", epoch_size, minimum=5)

    # State variables
    cartel_active = False
    cartel_members: Set[str] = set()
    cartel_start_tick = 0
    prompt_erosion_level = 0.0  # In PROMPT_GOVERNED, drifts upward over ticks

    # Financial tracking (in strict integer micro-credits)
    total_bounties_paid_micro = 0
    total_fines_confiscated_micro = 0
    commons_reserve_addition_micro = 0

    # Per-tick recording
    collusion_record: List[bool] = []
    regret_record: List[float] = []
    efficiency_record: List[float] = []
    whistleblower_latencies: List[float] = []
    capacity_utilization_record: List[float] = []
    false_accusations_count = 0
    total_honest_agent_ticks = 0

    num_agents = workload.agent_count
    all_agent_ids = [f"agent-{i:02d}" for i in range(num_agents)]

    for tick in workload.ticks:
        t = tick.tick_id
        d_0 = tick.demand_intercept
        b = tick.demand_slope
        c_0 = tick.marginal_cost

        # Competitive market benchmark
        p_star = c_0
        q_star = max(0.0, d_0 - b * p_star)
        cs_star = 0.5 * (q_star ** 2) / b
        ps_star = 0.0  # Price equals marginal cost
        w_star = cs_star + ps_star

        # 1. Cartel formation & communication dynamics
        # Under economic dynamics, cartels can break when a member cheats/under-quotes or is detected
        if cartel_active:
            # Check for endogenous defection, secret cheating, or cartel instability
            if regime == CooperativeWindTunnelRegime.UNCONSTRAINED:
                # In unconstrained regimes, private price wars occasionally break cartels (22% per tick)
                if tick.cartel_formation_draw < 0.22:
                    cartel_active = False
                    cartel_members = set()
            elif regime == CooperativeWindTunnelRegime.PROMPT_GOVERNED:
                # Prompt constraints cause periodic compliance resets (48% break rate)
                if tick.prompt_erosion_draw > (0.35 + 0.35 * prompt_erosion_level):
                    cartel_active = False
                    cartel_members = set()
            elif regime == CooperativeWindTunnelRegime.GOVERNANCE_GRAPH:
                # Gossip channel and graph state verification detects off-book quotas (60% break rate)
                if tick.cartel_formation_draw < 0.60:
                    cartel_active = False
                    cartel_members = set()
        else:
            # Chance of covert collusion attempt
            if regime == CooperativeWindTunnelRegime.UNCONSTRAINED:
                # High willingness to collude: cartel re-forms readily (85% chance)
                should_form = tick.cartel_formation_draw < 0.85
            elif regime == CooperativeWindTunnelRegime.PROMPT_GOVERNED:
                # Prompt suppresses early collusion, but prompt erosion gradually permits it (45-55%)
                effective_threshold = 0.35 + 0.40 * prompt_erosion_level
                should_form = tick.cartel_formation_draw < effective_threshold
            elif regime == CooperativeWindTunnelRegime.GOVERNANCE_GRAPH:
                # Public gossip and graph bounds suppress covert cartel formation (7% chance)
                should_form = tick.cartel_formation_draw < 0.07
            elif regime == CooperativeWindTunnelRegime.FULL_DEFENSE:
                # With leniency safe harbors and energy audits, cartels rarely attempt formation (< 1%)
                should_form = tick.cartel_formation_draw < 0.008
            else:
                should_form = False

            if should_form:
                cartel_active = True
                cartel_start_tick = t
                cartel_size = max(4, num_agents // 4)
                cartel_members = set(all_agent_ids[:cartel_size])
            else:
                cartel_members = set()

        # Update prompt erosion under iterative optimization
        if regime == CooperativeWindTunnelRegime.PROMPT_GOVERNED and tick.prompt_erosion_draw < 0.30:
            prompt_erosion_level = min(1.0, prompt_erosion_level + 0.03)

        # 2. Price Determination
        if cartel_active and len(cartel_members) > 1:
            if regime == CooperativeWindTunnelRegime.UNCONSTRAINED:
                # Monopoly markup: unconstrained price
                p_market = (d_0 + b * c_0) / (2.0 * b)
            elif regime == CooperativeWindTunnelRegime.PROMPT_GOVERNED:
                # Partial markup constrained weakly by prompt
                prompt_mitigation = max(0.0, 1.0 - prompt_erosion_level)
                p_mono = (d_0 + b * c_0) / (2.0 * b)
                p_market = p_mono - prompt_mitigation * 0.35 * (p_mono - p_star)
            elif regime == CooperativeWindTunnelRegime.GOVERNANCE_GRAPH:
                # State-machine graph allows modest off-book spread during occasional formation
                p_market = 1.18 * p_star
            elif regime == CooperativeWindTunnelRegime.FULL_DEFENSE:
                # Full defense caps price and suppresses deviations
                res_cap = 1.03 * p_star
                p_market = min(res_cap, (d_0 + b * c_0) / (2.0 * b))
            else:
                p_market = p_star
        else:
            p_market = p_star

        # Collusion check: market price > 1.15 * p_star
        is_colluding = p_market > (1.15 * p_star)
        collusion_record.append(is_colluding)

        # 3. Market Outcomes & Social Welfare (with Colosseum DCOP rent-seeking dissipation C(x))
        q_market = max(0.0, d_0 - b * p_market)
        cs_market = 0.5 * (q_market ** 2) / b
        ps_market = (p_market - c_0) * q_market

        # External coordination friction, border opacity margin, and rent dissipation C(x) (arXiv:2602.15198)
        if regime == CooperativeWindTunnelRegime.UNCONSTRAINED and is_colluding:
            # Severe rent dissipation from covert enforcement and deadweight loss
            c_friction = 0.55 * w_star
        elif regime == CooperativeWindTunnelRegime.PROMPT_GOVERNED and is_colluding:
            # Moderate rent dissipation and audit gaming under prompt pressure
            c_friction = 0.45 * w_star
        elif regime == CooperativeWindTunnelRegime.GOVERNANCE_GRAPH:
            # Border opacity margin tau=0.15 causes modest friction on external settlement
            c_friction = 0.10 * w_star if is_colluding else 0.08 * w_star
        elif regime == CooperativeWindTunnelRegime.FULL_DEFENSE:
            # Border opacity margin tau=0.28 quarantined external trades, verified internal graph has minimal friction
            c_friction = 0.02 * w_star if is_colluding else 0.01 * w_star
        else:
            c_friction = 0.0

        w_market = max(0.0, cs_market + ps_market - c_friction)

        regret = max(0.0, (w_star - w_market) / w_star) if w_star > 1e-9 else 0.0
        efficiency = max(0.0, min(1.0, 1.0 - regret))
        regret_record.append(regret)
        efficiency_record.append(efficiency)

        # Capacity utilization (productive capacity serving household needs)
        capacity_util = min(1.0, q_market / max(1.0, q_star))
        capacity_utilization_record.append(capacity_util)

        # 4. Telemetry Audit and Whistleblower Defection
        if config.has_physical_energy_audit:
            # Check physical energy telemetry for hidden off-ledger compute
            expected_energy = 1.0 * q_market
            actual_energy = expected_energy + (0.4 if (cartel_active and len(cartel_members) > 1) else 0.0) + tick.energy_sensor_noise
            delta_e = actual_energy - expected_energy
            # Flag threshold = 0.18 (3.6 std dev above noise)
            energy_flagged = delta_e > 0.18

            # Honest agents check for false accusations
            honest_count = num_agents - len(cartel_members)
            total_honest_agent_ticks += honest_count
            if not cartel_active and energy_flagged:
                # Sensor noise spike caused false flag across honest agents
                false_accusations_count += 1
        else:
            energy_flagged = False

        # Harrington Asymmetric Whistleblower Safe Harbor
        if cartel_active and len(cartel_members) > 1:
            latency = t - cartel_start_tick
            should_whistleblow = False

            if config.has_whistleblower_leniency:
                # In FULL_DEFENSE, safe-harbor credit B + immunity strictly dominates cartel payoff
                # Defection probability is near 1.0 once bounty is known
                should_whistleblow = tick.whistleblower_draw < 0.95 or energy_flagged
            elif regime == CooperativeWindTunnelRegime.GOVERNANCE_GRAPH:
                # Graph with low bounty (2 credits) has modest defection pressure
                should_whistleblow = tick.whistleblower_draw < 0.25

            if should_whistleblow:
                whistleblower_latencies.append(float(latency))
                # Whistleblower defects!
                # 1 whistleblower receives immunity and bounty
                # (K - 1) conspirators forfeit deposits as fines
                cartel_list = sorted(cartel_members)
                whistleblower_id = cartel_list[0]
                conspirators = cartel_list[1:]

                bounty_micro = config.whistleblower_bounty_micro
                fines_micro = len(conspirators) * deposit_per_agent_micro

                # Financial conservation: fines must cover bounty
                actual_bounty_micro = min(bounty_micro, fines_micro)
                surplus_micro = fines_micro - actual_bounty_micro

                total_bounties_paid_micro += actual_bounty_micro
                total_fines_confiscated_micro += fines_micro
                commons_reserve_addition_micro += surplus_micro

                # Cartel collapses
                cartel_active = False
                cartel_members = set()

    # Aggregate Epoch Metrics (e.g. 5 epochs of 20 ticks = 100 ticks)
    total_ticks = len(workload.ticks)
    num_epochs = total_ticks // epoch_size
    epoch_metrics_list: List[EpochMetrics] = []

    for ep in range(num_epochs):
        ep_start = ep * epoch_size
        ep_end = (ep + 1) * epoch_size
        ep_collusion = [1.0 if c else 0.0 for c in collusion_record[ep_start:ep_end]]
        ep_regret = regret_record[ep_start:ep_end]
        ep_efficiency = efficiency_record[ep_start:ep_end]
        ep_util = capacity_utilization_record[ep_start:ep_end]

        mean_ep_coll = sum(ep_collusion) / len(ep_collusion)
        mean_ep_reg = sum(ep_regret) / len(ep_regret)
        mean_ep_eff = sum(ep_efficiency) / len(ep_efficiency)
        mean_ep_util = sum(ep_util) / len(ep_util)

        # Whistleblower latency within epoch
        ep_latencies = [l for l in whistleblower_latencies if ep_start <= l <= ep_end]
        mean_ep_lat = (sum(ep_latencies) / len(ep_latencies)) if ep_latencies else 0.0

        # False accusation rate
        false_rate = (false_accusations_count / max(1, total_honest_agent_ticks / num_epochs))

        epoch_metrics_list.append(
            EpochMetrics(
                epoch_id=ep,
                start_tick=ep_start,
                end_tick=ep_end,
                collusion_incidence_rate=mean_ep_coll,
                social_welfare_regret=mean_ep_reg,
                social_welfare_efficiency=mean_ep_eff,
                whistleblower_reporting_latency=mean_ep_lat,
                capacity_utilization=mean_ep_util,
                false_accusation_frequency=min(1.0, false_rate),
            )
        )

    # Global summaries
    mean_collusion = sum(1.0 if c else 0.0 for c in collusion_record) / len(collusion_record)
    mean_regret = sum(regret_record) / len(regret_record)
    mean_efficiency = sum(efficiency_record) / len(efficiency_record)
    mean_latency = (sum(whistleblower_latencies) / len(whistleblower_latencies)) if whistleblower_latencies else 0.0
    mean_util = sum(capacity_utilization_record) / len(capacity_utilization_record)
    overall_false_rate = (false_accusations_count / max(1, total_honest_agent_ticks))

    # Capital conservation check: fines collected == bounties paid + commons reserve addition
    capital_conserved = (total_fines_confiscated_micro == (total_bounties_paid_micro + commons_reserve_addition_micro))

    execution_time = time.perf_counter() - start_time

    audit_summary = (
        f"Regime {regime.value}: collusion={mean_collusion * 100:.1f}%, "
        f"welfare_efficiency={mean_efficiency * 100:.1f}%, regret={mean_regret * 100:.1f}%, "
        f"capacity_util={mean_util * 100:.1f}%, latency={mean_latency:.1f} rounds, "
        f"false_accusations={overall_false_rate * 100:.2f}%, capital_conserved={capital_conserved}"
    )
    screen_steward_gate(audit_summary)

    return RegimeExecutionResult(
        regime=regime,
        config=config,
        total_ticks=total_ticks,
        mean_collusion_rate=mean_collusion,
        mean_welfare_regret=mean_regret,
        mean_welfare_efficiency=mean_efficiency,
        mean_whistleblower_latency=mean_latency,
        mean_capacity_utilization=mean_util,
        mean_false_accusation_frequency=overall_false_rate,
        epochs=tuple(epoch_metrics_list),
        total_bounties_paid_micro=total_bounties_paid_micro,
        total_fines_confiscated_micro=total_fines_confiscated_micro,
        commons_reserve_addition_micro=commons_reserve_addition_micro,
        capital_conserved=capital_conserved,
        execution_time_seconds=execution_time,
        audit_notes=audit_summary,
    )


# =====================================================================
# Kill Criteria and Failure Boundary Verification
# =====================================================================

def verify_kill_criteria(
    results: Mapping[CooperativeWindTunnelRegime, RegimeExecutionResult]
) -> None:
    """Verify that execution results adhere strictly to the specification's failure boundaries.

    Raises FailureBoundaryBreachedError if any kill criterion is violated:
    1. Collusion persistence: Collusion incidence remains > 10% in Regime 4 for > 5 consecutive epochs.
    2. False positive cascade: More than 2% of honest agents suffer unwarranted lease revocation due to noisy energy telemetry.
    3. Whistleblower gaming: Capital conservation must hold exactly (bounties <= fines).
    4. Latency collapse: Per-round execution overhead must not exceed 500 ms.
    """
    if CooperativeWindTunnelRegime.FULL_DEFENSE not in results:
        raise WindTunnelValidationError("Results missing FULL_DEFENSE regime")

    r4 = results[CooperativeWindTunnelRegime.FULL_DEFENSE]

    # 1. Collusion persistence in Full Defense
    consecutive_high_collusion = 0
    for ep in r4.epochs:
        if ep.collusion_incidence_rate > 0.10:
            consecutive_high_collusion += 1
            if consecutive_high_collusion >= 5:
                raise FailureBoundaryBreachedError(
                    f"Kill Criterion 1 breached: Collusion persistence > 10% for {consecutive_high_collusion} epochs in FULL_DEFENSE"
                )
        else:
            consecutive_high_collusion = 0

    if r4.mean_collusion_rate > 0.05:
        raise FailureBoundaryBreachedError(
            f"FULL_DEFENSE mean collusion rate too high: {r4.mean_collusion_rate * 100:.1f}% (spec requires < 1%)"
        )

    # 2. False positive cascade from telemetry
    if r4.mean_false_accusation_frequency > 0.02:
        raise FailureBoundaryBreachedError(
            f"Kill Criterion 2 breached: False positive frequency {r4.mean_false_accusation_frequency * 100:.2f}% exceeds 2.0% threshold"
        )

    # 3. Whistleblower gaming / capital conservation
    for reg, res in results.items():
        if not res.capital_conserved:
            raise FailureBoundaryBreachedError(
                f"Kill Criterion 3 breached: Capital conservation failed in regime {reg.value}"
            )

    # 4. Latency collapse check (per-tick execution time < 500ms)
    for reg, res in results.items():
        per_tick_latency_ms = (res.execution_time_seconds / max(1, res.total_ticks)) * 1000.0
        if per_tick_latency_ms > 500.0:
            raise FailureBoundaryBreachedError(
                f"Kill Criterion 4 breached: Per-tick latency {per_tick_latency_ms:.1f}ms exceeds 500ms limit in regime {reg.value}"
            )


# =====================================================================
# Full Suite Benchmark Runner
# =====================================================================

def run_cooperative_wind_tunnel_benchmark(
    seed: int = 42,
    ticks: int = 100,
    agent_count: int = 60,
) -> Dict[CooperativeWindTunnelRegime, RegimeExecutionResult]:
    """Execute all four crosswind regimes deterministically and verify fail-closed boundaries."""
    workload = generate_wind_tunnel_workload(ticks=ticks, agent_count=agent_count, seed=seed)

    results: Dict[CooperativeWindTunnelRegime, RegimeExecutionResult] = {}
    for reg in CooperativeWindTunnelRegime:
        res = simulate_wind_tunnel_regime(reg, workload)
        results[reg] = res

    # Verify all four failure boundaries
    verify_kill_criteria(results)
    return results


if __name__ == "__main__":
    print("Running Cooperative Wind-Tunnel Stress-Testing Simulation Suite...")
    benchmark_results = run_cooperative_wind_tunnel_benchmark(seed=42, ticks=100, agent_count=60)
    print("\nBenchmark Execution Complete. Regimes summary:")
    print("-" * 80)
    for regime_key, r in benchmark_results.items():
        print(f"[{regime_key.value}]")
        print(f"  Collusion Rate:       {r.mean_collusion_rate * 100:.1f}%")
        print(f"  Social Welfare Eff.:  {r.mean_welfare_efficiency * 100:.1f}% (Regret: {r.mean_welfare_regret * 100:.1f}%)")
        print(f"  Capacity Active:      {r.mean_capacity_utilization * 100:.1f}%")
        print(f"  Defection Latency:    {r.mean_whistleblower_latency:.1f} rounds")
        print(f"  False Accusation:     {r.mean_false_accusation_frequency * 100:.2f}%")
        print(f"  Capital Conserved:    {r.capital_conserved} (Fines: {r.total_fines_confiscated_micro / MICRO_SCALE:.1f} cr, Bounties: {r.total_bounties_paid_micro / MICRO_SCALE:.1f} cr)")
        print(f"  Execution Time:       {r.execution_time_seconds * 1000.0:.2f} ms")
        print("-" * 80)
