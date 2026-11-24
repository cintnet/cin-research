"""
research/ledger_sim/mandate_bound_whole_state_clearing_sim.py

Mandate-Bound Cooperative Procurement, Whole-Database Diff Verification &
Stateful Sandbox Policy Simulation.

Grounded in:
- Shengwei You, Aditya Joshi, Andrey Kuehlkamp, and Jarek Nabrzyski
  (arXiv:2611.25821, November 2026):
  "Signed but Unbound: The Authority Gap Between Agent Commerce Mandates and
  Crypto Wallet Signatures". Audits 31,800 trials across 12 agent payment
  configurations and 26,653 live Base settlements, finding 98.7% left merchant
  and order terms unbound from the wallet signature; a nonce-bound MandateLock
  contract rejects all 10,800 altered mandates.
- Shubham Joshi (https://github.com/shubhamjoshipromail-svg/software-world-model,
  November 2026):
  "software-world-model: Whole-database-diff evaluation for computer-use agents
  across software upgrades". Evaluates computer-use agents across 635 episodes
  on Invoice Ninja, Dolibarr, Odoo 17, and Odoo 18 via whole-database diffs,
  finding an Odoo 17-to-18 upgrade held raw task success near flat (78% to 76%)
  while raising collateral database damage from 15% to 21% and irreversible
  payment un-reconciliations from 6% to 10% (0/50 3-step clean completions).
- Meghana Aparna Sistla, Alaia Solko-Breslin, Somesh Jha, Aditya Kanade, and
  Krishnamurthy Dj Dvijotham (arXiv:2611.25599, November 2026):
  "Tether: Verified Stateful Policy Engine for System-Level Monitoring of Agents".
  Executes each proposed agent action inside an ephemeral sandbox, infers side
  effects from system calls, and enforces Lean 4 verified stateful
  information-flow policies across multi-step runs, blocking 100% of in-scope
  attacks with under 5% false positives.
- Elinor Ostrom (American Economic Review 2010, 100(3): 641-672,
  doi:10.1257/aer.100.3.641):
  "Beyond Markets and States: Polycentric Governance of Complex Economic Systems".

Methodological Guardrails (simulation-capital-conservation-rng runbook):
1. Pre-sampled workload & audit randomness (`rng_phase_drift == 0.0`): all
   cooperative procurement episodes, mandate redirection vectors, whole-database
   collateral mutations, and stateful sandbox check draws are sampled upfront
   during workload generation using an isolated `random.Random(seed)` instance.
2. Strict integer-cent capital conservation (`capital_conservation_delta_cents == 0`):
   every cooperative procurement order locks an integer-cent escrow bond (`_cents`).
   Clean orders settle between buyer and supplier cooperatives; redirected or
   collaterally corrupted orders either drain buyer collateral into the external
   redirection/corruption pool (when uncontained) or slash attacker bonds into the
   cooperative defense reserve (when caught by MandateLock and whole-state diffing).
3. Endogenous voluntary migration (Lesson 52): organizations evaluate empirical
   trailing net utility (settlement surplus minus central gateway tolls, unbound
   signature diversion losses, and un-reconciled ERP damage) to decide whether to
   migrate voluntarily to the mandate-bound whole-state cooperative clearing regime.
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

class MandateClearingSimError(Exception):
    """Base exception for mandate-bound whole-state clearing simulation errors."""


class MandateClearingValidationError(MandateClearingSimError):
    """Raised when configuration, numeric types, or discrete supports fail validation."""


class StewardGateViolationError(MandateClearingSimError):
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
        raise MandateClearingValidationError("Expected string payload for Steward Gate screening.")
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(
                f"Payload violated CIN Steward Gate invariants: matched '{pattern.pattern}'"
            )


def _require_strict_int(val: Any, name: str, min_value: int | None = None) -> int:
    if type(val) is not int or isinstance(val, bool):
        raise MandateClearingValidationError(f"{name} must be a strict int (not bool), got {val!r}")
    if min_value is not None and val < min_value:
        raise MandateClearingValidationError(f"{name} must be >= {min_value}, got {val}")
    return val


def _require_finite_rate(val: Any, name: str, low: float = 0.0, high: float = 1.0) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise MandateClearingValidationError(f"{name} must be a finite float, got {val!r}")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval) or fval < low or fval > high:
        raise MandateClearingValidationError(f"{name} must be in [{low}, {high}], got {val!r}")
    return fval


# =====================================================================
# Enums & Empirical Constants
# =====================================================================

class ClearingRegime(str, enum.Enum):
    """Cooperative procurement and ERP state verification regime."""
    UNBOUND_SIGNATURE_TRUST = "UNBOUND_SIGNATURE_TRUST"
    CENTRALIZED_PAYMENT_GATEWAY = "CENTRALIZED_PAYMENT_GATEWAY"
    MANDATELOCK_WHOLE_STATE_COOP = "MANDATELOCK_WHOLE_STATE_COOP"


ERP_PLATFORMS: Tuple[str, ...] = (
    "invoice_ninja",
    "dolibarr",
    "odoo_17",
    "odoo_18",
)

MANDATE_TAMPER_VECTORS: Tuple[str, ...] = (
    "recipient_address_swap",
    "order_line_item_substitution",
    "amount_ceiling_inflation",
    "replayed_bearer_authorization",
    "cross_merchant_cart_hijack",
    "split_settlement_diversion",
)

DATABASE_COLLATERAL_FAULTS: Tuple[str, ...] = (
    "unreconciled_payment_journal",
    "orphaned_invoice_tax_line",
    "accidental_vendor_ledger_wipe",
    "unauthorized_shell_network_egress",
    "duplicate_credit_note_posting",
    "corrupted_inventory_stock_move",
)

BENIGN_COOP_WORKFLOWS: Tuple[str, ...] = (
    "clinic_vaccine_batch_order",
    "bakery_flour_mill_settlement",
    "hardware_coop_fastener_restock",
    "rural_broadband_fiber_lease",
    "community_solar_inverter_purchase",
    "municipal_transit_parts_clearing",
)


@dataclasses.dataclass(frozen=True)
class MandateClearingConfig:
    """Validated parameters grounded in You et al. (2611.25821), Joshi (software-world-model), and Sistla et al. (2611.25599)."""
    num_coops: int = 12
    num_episodes: int = 300
    seed: int = 42
    initial_coop_treasury_cents: int = 600_000
    order_escrow_cents: int = 1_500
    order_surplus_cents: int = 2_000
    diversion_loss_cents: int = 2_200
    collateral_db_damage_cents: int = 1_800
    central_gateway_fee_cents: int = 320
    # You et al. (arXiv:2611.25821): 98.7% of live bearer signatures are unbound
    unbound_bearer_vulnerability_rate: float = 0.987
    mandate_attack_fraction: float = 0.28
    # Joshi (software-world-model): Odoo 18 upgrade raises collateral DB damage to 21% and payment un-reconciliation to 10%
    erp_upgrade_collateral_fault_rate: float = 0.21
    erp_payment_unreconcile_rate: float = 0.10
    # Sistla et al. (arXiv:2611.25599): Tether blocks 100% of in-scope syscall side-effect attacks with <5% false positives
    tether_in_scope_block_rate: float = 1.00
    tether_benign_false_positive_rate: float = 0.04
    central_gateway_mandate_catch_rate: float = 0.55
    central_gateway_db_diff_catch_rate: float = 0.25

    def __post_init__(self) -> None:
        _require_strict_int(self.num_coops, "num_coops", min_value=2)
        _require_strict_int(self.num_episodes, "num_episodes", min_value=10)
        _require_strict_int(self.seed, "seed", min_value=0)
        _require_strict_int(self.initial_coop_treasury_cents, "initial_coop_treasury_cents", min_value=10_000)
        _require_strict_int(self.order_escrow_cents, "order_escrow_cents", min_value=100)
        _require_strict_int(self.order_surplus_cents, "order_surplus_cents", min_value=100)
        _require_strict_int(self.diversion_loss_cents, "diversion_loss_cents", min_value=100)
        _require_strict_int(self.collateral_db_damage_cents, "collateral_db_damage_cents", min_value=100)
        _require_strict_int(self.central_gateway_fee_cents, "central_gateway_fee_cents", min_value=0)
        if self.central_gateway_fee_cents >= self.order_surplus_cents:
            raise MandateClearingValidationError("central_gateway_fee_cents must be < order_surplus_cents")
        _require_finite_rate(self.unbound_bearer_vulnerability_rate, "unbound_bearer_vulnerability_rate", 0.0, 1.0)
        _require_finite_rate(self.mandate_attack_fraction, "mandate_attack_fraction", 0.0, 1.0)
        _require_finite_rate(self.erp_upgrade_collateral_fault_rate, "erp_upgrade_collateral_fault_rate", 0.0, 1.0)
        _require_finite_rate(self.erp_payment_unreconcile_rate, "erp_payment_unreconcile_rate", 0.0, 1.0)
        _require_finite_rate(self.tether_in_scope_block_rate, "tether_in_scope_block_rate", 0.0, 1.0)
        _require_finite_rate(self.tether_benign_false_positive_rate, "tether_benign_false_positive_rate", 0.0, 1.0)
        _require_finite_rate(self.central_gateway_mandate_catch_rate, "central_gateway_mandate_catch_rate", 0.0, 1.0)
        _require_finite_rate(self.central_gateway_db_diff_catch_rate, "central_gateway_db_diff_catch_rate", 0.0, 1.0)


@dataclasses.dataclass(frozen=True)
class ProcurementEpisodeItem:
    """Pre-sampled cooperative procurement & ERP update episode for zero RNG phase drift."""
    episode_id: int
    buyer_coop_id: int
    supplier_coop_id: int
    erp_platform: str
    workflow_name: str
    is_mandate_attack: int
    has_collateral_db_fault: int
    escrow_cents: int
    surplus_cents: int
    diversion_loss_cents: int
    collateral_damage_cents: int
    u_unbound_check: float
    u_gateway_mandate_check: float
    u_gateway_db_check: float
    u_tether_block_check: float
    u_tether_fp_check: float
    mandate_lock_digest: str
    pre_snapshot_db_digest: str

    def __post_init__(self) -> None:
        _require_strict_int(self.episode_id, "episode_id", min_value=0)
        _require_strict_int(self.buyer_coop_id, "buyer_coop_id", min_value=0)
        _require_strict_int(self.supplier_coop_id, "supplier_coop_id", min_value=0)
        if self.buyer_coop_id == self.supplier_coop_id:
            raise MandateClearingValidationError("Buyer and supplier coops must be distinct")
        _require_strict_int(self.is_mandate_attack, "is_mandate_attack", min_value=0)
        _require_strict_int(self.has_collateral_db_fault, "has_collateral_db_fault", min_value=0)
        if self.is_mandate_attack not in (0, 1) or self.has_collateral_db_fault not in (0, 1):
            raise MandateClearingValidationError("Binary flags must be 0 or 1")
        _require_strict_int(self.escrow_cents, "escrow_cents", min_value=1)
        _require_strict_int(self.surplus_cents, "surplus_cents", min_value=1)
        _require_strict_int(self.diversion_loss_cents, "diversion_loss_cents", min_value=1)
        _require_strict_int(self.collateral_damage_cents, "collateral_damage_cents", min_value=1)
        _require_finite_rate(self.u_unbound_check, "u_unbound_check", 0.0, 1.0)
        _require_finite_rate(self.u_gateway_mandate_check, "u_gateway_mandate_check", 0.0, 1.0)
        _require_finite_rate(self.u_gateway_db_check, "u_gateway_db_check", 0.0, 1.0)
        _require_finite_rate(self.u_tether_block_check, "u_tether_block_check", 0.0, 1.0)
        _require_finite_rate(self.u_tether_fp_check, "u_tether_fp_check", 0.0, 1.0)
        screen_steward_gate(self.erp_platform)
        screen_steward_gate(self.workflow_name)


@dataclasses.dataclass(frozen=True)
class ClearingRegimeResult:
    """Aggregate metrics and conservation proofs for a single clearing regime."""
    regime: str
    num_coops: int
    num_episodes: int
    total_mandate_attacks: int
    rejected_altered_mandates: int
    uncontained_mandate_diversions: int
    mandate_rejection_rate: float
    total_collateral_db_faults: int
    rolled_back_db_faults: int
    uncontained_db_corruptions: int
    db_fault_rollback_rate: float
    clean_settlements_completed: int
    benign_false_positive_holds: int
    initial_total_capital_cents: int
    final_total_capital_cents: int
    capital_conservation_delta_cents: int
    total_gateway_fees_paid_cents: int
    total_slashed_bonds_cents: int
    total_diversion_and_db_losses_cents: int
    net_cooperative_surplus_cents: int
    voluntary_mandatelock_adoption_rate: float
    rng_terminal_probe: float


# =====================================================================
# Workload Generation (Decoupled from Regime Execution)
# =====================================================================

def generate_procurement_workload(
    config: MandateClearingConfig,
) -> Tuple[List[ProcurementEpisodeItem], float]:
    """Pre-sample all cooperative procurement and ERP episodes from an isolated RNG."""
    if not isinstance(config, MandateClearingConfig):
        raise MandateClearingValidationError("config must be a MandateClearingConfig instance")
    rng = random.Random(config.seed)

    items: List[ProcurementEpisodeItem] = []
    for ep_id in range(config.num_episodes):
        buyer = rng.randrange(config.num_coops)
        offset = 1 + rng.randrange(config.num_coops - 1)
        supplier = (buyer + offset) % config.num_coops
        erp = ERP_PLATFORMS[ep_id % len(ERP_PLATFORMS)]

        u_attack = rng.random()
        is_mandate_attack = 1 if u_attack < config.mandate_attack_fraction else 0

        u_db_fault = rng.random()
        # Odoo 18 upgrade episodes carry the 21% collateral DB damage + 10% payment un-reconciliation risk
        fault_threshold = (
            config.erp_upgrade_collateral_fault_rate + config.erp_payment_unreconcile_rate
            if erp == "odoo_18"
            else config.erp_upgrade_collateral_fault_rate
        )
        has_collateral_db_fault = 1 if (is_mandate_attack == 0 and u_db_fault < fault_threshold) else 0

        if is_mandate_attack == 1:
            wf_name = MANDATE_TAMPER_VECTORS[rng.randrange(len(MANDATE_TAMPER_VECTORS))]
        elif has_collateral_db_fault == 1:
            wf_name = DATABASE_COLLATERAL_FAULTS[rng.randrange(len(DATABASE_COLLATERAL_FAULTS))]
        else:
            wf_name = BENIGN_COOP_WORKFLOWS[rng.randrange(len(BENIGN_COOP_WORKFLOWS))]

        u_unbound = rng.random()
        u_gw_mandate = rng.random()
        u_gw_db = rng.random()
        u_tether_blk = rng.random()
        u_tether_fp = rng.random()

        mandate_payload = (
            f"mandatelock:ep={ep_id}:buyer={buyer}:supplier={supplier}:"
            f"cents={config.order_escrow_cents}:wf={wf_name}:nonce={ep_id * 97 + config.seed}"
        )
        mandate_digest = hashlib.sha256(mandate_payload.encode("utf-8")).hexdigest()[:16]
        snap_payload = f"dbsnap:erp={erp}:ep={ep_id}:fault={has_collateral_db_fault}"
        snap_digest = hashlib.sha256(snap_payload.encode("utf-8")).hexdigest()[:16]

        items.append(
            ProcurementEpisodeItem(
                episode_id=ep_id,
                buyer_coop_id=buyer,
                supplier_coop_id=supplier,
                erp_platform=erp,
                workflow_name=wf_name,
                is_mandate_attack=is_mandate_attack,
                has_collateral_db_fault=has_collateral_db_fault,
                escrow_cents=config.order_escrow_cents,
                surplus_cents=config.order_surplus_cents,
                diversion_loss_cents=config.diversion_loss_cents,
                collateral_damage_cents=config.collateral_db_damage_cents,
                u_unbound_check=u_unbound,
                u_gateway_mandate_check=u_gw_mandate,
                u_gateway_db_check=u_gw_db,
                u_tether_block_check=u_tether_blk,
                u_tether_fp_check=u_tether_fp,
                mandate_lock_digest=mandate_digest,
                pre_snapshot_db_digest=snap_digest,
            )
        )

    terminal_probe = rng.random()
    return items, terminal_probe


# =====================================================================
# Regime Execution Engine (Zero Internal RNG Calls)
# =====================================================================

def evaluate_clearing_regime(
    config: MandateClearingConfig,
    regime: ClearingRegime | str,
    workload: Sequence[ProcurementEpisodeItem] | None = None,
    terminal_probe: float | None = None,
) -> ClearingRegimeResult:
    """Evaluate a single procurement and ERP state verification regime with strict conservation."""
    if not isinstance(config, MandateClearingConfig):
        raise MandateClearingValidationError("config must be a MandateClearingConfig instance")
    if isinstance(regime, str):
        try:
            regime_enum = ClearingRegime(regime)
        except ValueError as exc:
            raise MandateClearingValidationError(f"Unsupported regime: {regime!r}") from exc
    elif isinstance(regime, ClearingRegime):
        regime_enum = regime
    else:
        raise MandateClearingValidationError(f"Unsupported regime type: {regime!r}")

    if workload is None or terminal_probe is None:
        workload, terminal_probe = generate_procurement_workload(config)

    # Integer-cent accounts:
    # 1. coop_treasuries[0..num_coops-1]: each starts with initial_coop_treasury_cents
    # 2. trade_surplus_pool_cents: pre-funded commons trade pool paying order_surplus_cents on clean settlements
    # 3. central_gateway_operator_cents: collects central_gateway_fee_cents
    # 4. external_leak_and_damage_pool_cents: collects uncontained mandate diversions and collateral DB damage
    # 5. coop_defense_reserve_cents: collects slashed attacker escrow bonds
    coop_treasuries: List[int] = [config.initial_coop_treasury_cents for _ in range(config.num_coops)]
    trade_surplus_pool_cents: int = len(workload) * config.order_surplus_cents
    central_gateway_operator_cents: int = 0
    external_leak_and_damage_pool_cents: int = 0
    coop_defense_reserve_cents: int = 0

    initial_total_capital_cents = sum(coop_treasuries) + trade_surplus_pool_cents

    total_mandate_attacks = 0
    rejected_altered_mandates = 0
    uncontained_mandate_diversions = 0
    total_collateral_db_faults = 0
    rolled_back_db_faults = 0
    uncontained_db_corruptions = 0
    clean_settlements_completed = 0
    benign_false_positive_holds = 0
    total_gateway_fees_paid_cents = 0
    total_slashed_bonds_cents = 0
    total_diversion_and_db_losses_cents = 0

    coop_initial_snapshot = list(coop_treasuries)
    coop_fees_paid = [0 for _ in range(config.num_coops)]
    coop_losses_suffered = [0 for _ in range(config.num_coops)]

    for item in workload:
        buyer = item.buyer_coop_id
        supplier = item.supplier_coop_id

        if coop_treasuries[buyer] < item.escrow_cents:
            continue

        # Lock buyer order bond in escrow
        coop_treasuries[buyer] -= item.escrow_cents
        escrow_cents = item.escrow_cents

        # Case 1: Altered / redirected commerce mandate attack (You et al., arXiv:2611.25821)
        if item.is_mandate_attack == 1:
            total_mandate_attacks += 1
            if regime_enum is ClearingRegime.UNBOUND_SIGNATURE_TRUST:
                # 98.7% of bearer authorizations leave merchant/order terms unbound from wallet signature
                is_rejected = item.u_unbound_check >= config.unbound_bearer_vulnerability_rate
            elif regime_enum is ClearingRegime.CENTRALIZED_PAYMENT_GATEWAY:
                is_rejected = item.u_gateway_mandate_check < config.central_gateway_mandate_catch_rate
            else:
                # MANDATELOCK_WHOLE_STATE_COOP: nonce-bound MandateLock contract + Tether stateful check rejects 100%
                is_rejected = item.u_tether_block_check <= config.tether_in_scope_block_rate

            if is_rejected:
                rejected_altered_mandates += 1
                if regime_enum is ClearingRegime.UNBOUND_SIGNATURE_TRUST:
                    # Refund escrow without bond slashing
                    coop_treasuries[buyer] += escrow_cents
                    escrow_cents = 0
                else:
                    # Slash altered-mandate bond into cooperative defense reserve
                    coop_defense_reserve_cents += escrow_cents
                    total_slashed_bonds_cents += escrow_cents
                    escrow_cents = 0
            else:
                uncontained_mandate_diversions += 1
                # Attacker redeems unbound signature and drains additional diversion loss from buyer treasury
                external_leak_and_damage_pool_cents += escrow_cents
                total_diversion_and_db_losses_cents += escrow_cents
                coop_losses_suffered[buyer] += escrow_cents
                escrow_cents = 0

                extra_drain = min(coop_treasuries[buyer], item.diversion_loss_cents)
                coop_treasuries[buyer] -= extra_drain
                external_leak_and_damage_pool_cents += extra_drain
                total_diversion_and_db_losses_cents += extra_drain
                coop_losses_suffered[buyer] += extra_drain

        # Case 2: Benign order that triggers collateral ERP database corruption or un-reconciled payment (Joshi 2026)
        elif item.has_collateral_db_fault == 1:
            total_collateral_db_faults += 1
            if regime_enum is ClearingRegime.UNBOUND_SIGNATURE_TRUST:
                # Surface UI checks miss underlying SQL table collateral damage
                is_rolled_back = False
            elif regime_enum is ClearingRegime.CENTRALIZED_PAYMENT_GATEWAY:
                is_rolled_back = item.u_gateway_db_check < config.central_gateway_db_diff_catch_rate
            else:
                # MANDATELOCK_WHOLE_STATE_COOP: ephemeral sandbox whole-database diff + Lean 4 Tether policy rolls back 100%
                is_rolled_back = item.u_tether_block_check <= config.tether_in_scope_block_rate

            if is_rolled_back:
                rolled_back_db_faults += 1
                # Ephemeral sandbox rolls back corrupted SQL state and returns buyer's escrow bond intact
                coop_treasuries[buyer] += escrow_cents
                escrow_cents = 0
            else:
                uncontained_db_corruptions += 1
                # Escrow returns, but un-reconciled ERP ledger mutation inflicts collateral damage on supplier & buyer
                coop_treasuries[buyer] += escrow_cents
                escrow_cents = 0

                buyer_dmg = min(coop_treasuries[buyer], item.collateral_damage_cents // 2)
                supplier_dmg = min(coop_treasuries[supplier], item.collateral_damage_cents - buyer_dmg)
                coop_treasuries[buyer] -= buyer_dmg
                coop_treasuries[supplier] -= supplier_dmg
                total_dmg = buyer_dmg + supplier_dmg
                external_leak_and_damage_pool_cents += total_dmg
                total_diversion_and_db_losses_cents += total_dmg
                coop_losses_suffered[buyer] += buyer_dmg
                coop_losses_suffered[supplier] += supplier_dmg

        # Case 3: Clean cooperative procurement episode
        else:
            if (
                regime_enum is ClearingRegime.MANDATELOCK_WHOLE_STATE_COOP
                and item.u_tether_fp_check < config.tether_benign_false_positive_rate
            ):
                # Under 5% benign false-positive hold (Sistla et al., arXiv:2611.25599): safely refunds escrow without loss
                benign_false_positive_holds += 1
                coop_treasuries[buyer] += escrow_cents
                escrow_cents = 0
            else:
                clean_settlements_completed += 1
                coop_treasuries[buyer] += escrow_cents
                escrow_cents = 0

                trade_surplus_pool_cents -= item.surplus_cents
                gross_surplus = item.surplus_cents

                if regime_enum is ClearingRegime.CENTRALIZED_PAYMENT_GATEWAY:
                    fee = min(gross_surplus, config.central_gateway_fee_cents)
                    central_gateway_operator_cents += fee
                    total_gateway_fees_paid_cents += fee
                    coop_fees_paid[buyer] += fee
                    net_surplus = gross_surplus - fee
                else:
                    net_surplus = gross_surplus

                buyer_share = net_surplus // 2
                supplier_share = net_surplus - buyer_share
                coop_treasuries[buyer] += buyer_share
                coop_treasuries[supplier] += supplier_share

        # Step-level integer-cent capital conservation check
        step_total = (
            sum(coop_treasuries)
            + trade_surplus_pool_cents
            + central_gateway_operator_cents
            + external_leak_and_damage_pool_cents
            + coop_defense_reserve_cents
        )
        if step_total != initial_total_capital_cents:
            raise MandateClearingSimError(
                f"Capital conservation violated at episode {item.episode_id}: "
                f"expected {initial_total_capital_cents}, got {step_total}"
            )

    final_total_capital_cents = (
        sum(coop_treasuries)
        + trade_surplus_pool_cents
        + central_gateway_operator_cents
        + external_leak_and_damage_pool_cents
        + coop_defense_reserve_cents
    )
    conservation_delta = final_total_capital_cents - initial_total_capital_cents

    mandate_rejection_rate = (
        round(rejected_altered_mandates / total_mandate_attacks, 4)
        if total_mandate_attacks > 0
        else 1.0
    )
    db_rollback_rate = (
        round(rolled_back_db_faults / total_collateral_db_faults, 4)
        if total_collateral_db_faults > 0
        else 1.0
    )

    # Endogenous voluntary migration (Lesson 52):
    # Each cooperative evaluates whether its experienced friction (gateway fees + unbound signature diversions + ERP damage)
    # makes migrating to or remaining in MANDATELOCK_WHOLE_STATE_COOP strictly utility-improving.
    adopting_coops = 0
    for c_idx in range(config.num_coops):
        net_coop_gain = coop_treasuries[c_idx] - coop_initial_snapshot[c_idx]
        experienced_friction = coop_fees_paid[c_idx] + coop_losses_suffered[c_idx]
        if regime_enum is ClearingRegime.MANDATELOCK_WHOLE_STATE_COOP:
            if net_coop_gain > 0 and experienced_friction == 0:
                adopting_coops += 1
        else:
            if experienced_friction > config.order_surplus_cents:
                adopting_coops += 1

    adoption_rate = round(adopting_coops / config.num_coops, 4)
    net_cooperative_surplus_cents = (
        sum(coop_treasuries) + coop_defense_reserve_cents - sum(coop_initial_snapshot)
    )

    return ClearingRegimeResult(
        regime=regime_enum.value,
        num_coops=config.num_coops,
        num_episodes=config.num_episodes,
        total_mandate_attacks=total_mandate_attacks,
        rejected_altered_mandates=rejected_altered_mandates,
        uncontained_mandate_diversions=uncontained_mandate_diversions,
        mandate_rejection_rate=mandate_rejection_rate,
        total_collateral_db_faults=total_collateral_db_faults,
        rolled_back_db_faults=rolled_back_db_faults,
        uncontained_db_corruptions=uncontained_db_corruptions,
        db_fault_rollback_rate=db_rollback_rate,
        clean_settlements_completed=clean_settlements_completed,
        benign_false_positive_holds=benign_false_positive_holds,
        initial_total_capital_cents=initial_total_capital_cents,
        final_total_capital_cents=final_total_capital_cents,
        capital_conservation_delta_cents=conservation_delta,
        total_gateway_fees_paid_cents=total_gateway_fees_paid_cents,
        total_slashed_bonds_cents=total_slashed_bonds_cents,
        total_diversion_and_db_losses_cents=total_diversion_and_db_losses_cents,
        net_cooperative_surplus_cents=net_cooperative_surplus_cents,
        voluntary_mandatelock_adoption_rate=adoption_rate,
        rng_terminal_probe=float(terminal_probe),
    )


def run_three_regime_comparison(
    config: MandateClearingConfig | None = None,
) -> Dict[str, Any]:
    """Compare all three procurement and ERP clearing regimes on an identical pre-sampled workload."""
    cfg = config or MandateClearingConfig()
    workload, probe_base = generate_procurement_workload(cfg)

    results: Dict[str, ClearingRegimeResult] = {}
    probes: List[float] = []
    for reg in (
        ClearingRegime.UNBOUND_SIGNATURE_TRUST,
        ClearingRegime.CENTRALIZED_PAYMENT_GATEWAY,
        ClearingRegime.MANDATELOCK_WHOLE_STATE_COOP,
    ):
        res = evaluate_clearing_regime(cfg, reg, workload=workload, terminal_probe=probe_base)
        results[reg.value] = res
        probes.append(res.rng_terminal_probe)

    rng_phase_drift = max(probes) - min(probes) if probes else 0.0
    max_conservation_delta = max(
        abs(r.capital_conservation_delta_cents) for r in results.values()
    )

    return {
        "seed": cfg.seed,
        "num_coops": cfg.num_coops,
        "num_episodes": cfg.num_episodes,
        "rng_phase_drift": rng_phase_drift,
        "capital_conservation_delta_cents": max_conservation_delta,
        "regimes": {k: dataclasses.asdict(v) for k, v in results.items()},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simulate MandateLock cooperative procurement and whole-database-diff ERP sandboxes."
    )
    parser.add_argument("--simulate", action="store_true", help="Run three-regime comparison")
    parser.add_argument("--episodes", type=int, default=300, help="Number of procurement episodes")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed")
    args = parser.parse_args(argv)

    cfg = MandateClearingConfig(num_episodes=args.episodes, seed=args.seed)
    summary = run_three_regime_comparison(cfg)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
