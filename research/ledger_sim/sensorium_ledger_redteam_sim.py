#!/usr/bin/env python3
"""
research/ledger_sim/sensorium_ledger_redteam_sim.py

Hardware-Attested Sensorium & Bifurcated Ledger Red-Team Prototype Simulation.

Models the end-to-end Collective Intelligence Network (CIN) observation, local
memory, privacy-boundary, and wide-network escrow verification pipeline, and
quantifies 8 adversarial hardware/ledger red-team scenarios comparing:
  - NAIVE_SIGNED_IS_TRUE ("valid hardware signature implies physical & social truth")
  - CIN_DEFENSE_IN_DEPTH (cross-modal physical kinematics, randomized spot-escrow,
    TCG DICE / DMTF SPDM / RFC 9334 session-freshness quotes, Engineered Independence
    across hardware/firmware/ownership lineages, Uncertainty Falls on the System for
    calibration gaps, duress canary + velocity escrow freeze, sliding-window Merkle
    non-omission ZK predicates, and k-truss triangle-density cartel quarantine).

Scientific & Standards Grounding:
  - IETF RFC 9334 (Birkholz, Thaler, Richardson, Smith & Pan, 2023):
    Remote ATtestation procedureS (RATS) Architecture (freshness nonces & Evidence).
  - TCG DICE & DMTF SPDM (DSP0274):
    Hardware-rooted Compound Device Identifiers (CDI) and session-bound peripheral quotes.
  - Fu & Xu (Communications of the ACM, 61(5), 2018, doi:10.1145/3176402) &
    Trippel et al. (IEEE EuroS&P 2017, WALNUT):
    Analog transduction spoofing upstream of the ADC ("Signed Is Not True").
  - Contag et al. (IEEE S&P 2017, doi:10.1109/SP.2017.66):
    Observation-aware defeat gaming under predictable inspection schedules.
  - Knight & Leveson (IEEE Trans. Software Eng., SE-12(1), 1986):
    Correlated common-mode failures across shared lineages vs. engineered independence.
  - Sjoding et al. (NEJM, 383(25), 2020, doi:10.1056/NEJMc2029240):
    Demographic sensor calibration bias -> Uncertainty Falls on the System.
  - Milgrom (Bell Journal of Economics, 12(2), 1981):
    Strategic selective omission at disclosure boundaries -> window completeness proofs.
  - Cohen (2008):
    k-Truss cohesive subgraph decomposition for collusive ring detection.

Methodological Invariants (.agents/skills/simulation-capital-conservation-rng/SKILL.md):
  1. Zero RNG Phase Drift: Every scenario and trial derives isolated PRNG streams via
     SHA-256(seed : scenario_id : trial_idx : stream). All workload realizations and
     spot-check schedules are materialized upfront on frozen dataclasses; zero RNG
     calls occur inside regime evaluation loops.
  2. Strict Integer-Cent Capital Conservation: All escrow deposits, participant stakes,
     challenger/attester bonds, payouts, recovery freezes, and slashed penalties use
     strict Python `int` cents (`_cents`) with exact per-trial conservation assertions.
  3. Zero Private Autobiographical Ledger Leakage: Raw episodic payloads remain sealed
     inside the 1:1 Personal Model Markov Blanket (`private_bytes_exposed == 0`).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
import enum
import hashlib
import hmac
import json
import math
from pathlib import Path
import random
import re
import time
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple


# =====================================================================
# Exceptions & Steward Gate Validation
# =====================================================================

class SensoriumSimError(Exception):
    """Base exception for the Sensorium & Bifurcated Ledger red-team simulation."""


class SensoriumSimValidationError(SensoriumSimError, ValueError):
    """Raised when configuration values, numeric types, or enums fail validation."""


class CapitalConservationError(SensoriumSimError):
    """Raised if integer-cent escrow/stake/bond conservation is ever violated."""


class MarkovBlanketLeakError(SensoriumSimError):
    """Raised if raw Private Autobiographical Ledger bytes cross the Markov Blanket."""


class StewardGateViolationError(SensoriumSimError):
    """Raised if forbidden token tickers, savings promises, or retired lore appear."""


_FORBIDDEN_STEWARD_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bContribution\s+Tokens?\b", re.IGNORECASE), "Contribution Token"),
    (re.compile(r"\bMMCT\b", re.IGNORECASE), "MMCT ticker"),
    (re.compile(r"\b85\s*/\s*10\s*/\s*5\b"), "85/10/5 split"),
    (re.compile(r"\b95\s*%\s*savings\b", re.IGNORECASE), "95% savings promise"),
    (re.compile(r"\broyalt(?:y|ies)\b", re.IGNORECASE), "royalty claim"),
    (re.compile(r"\b(?:airdrop|tokenomics|staking\s+rewards?)\b", re.IGNORECASE), "crypto reward framing"),
    (re.compile(r"\bSomatic\s+Witness\b", re.IGNORECASE), "retired hardware neologism"),
)


def screen_steward_gate(text: str) -> None:
    """Reject speculative token tickers, payout promises, and retired lore."""
    if not isinstance(text, str):
        raise SensoriumSimValidationError(f"Expected str for Steward Gate check, got {type(text).__name__}")
    for pattern, label in _FORBIDDEN_STEWARD_PATTERNS:
        if pattern.search(text):
            raise StewardGateViolationError(f"Steward Gate violation: '{label}' is forbidden.")


# =====================================================================
# Fail-Closed Type & Range Validators
# =====================================================================

def validate_strict_int(
    name: str,
    value: Any,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    """Validate that `value` is a strict Python `int` (never `bool`)."""
    if type(value) is not int or isinstance(value, bool):
        raise SensoriumSimValidationError(f"{name} must be a strict int (not bool), got {value!r}")
    if minimum is not None and value < minimum:
        raise SensoriumSimValidationError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise SensoriumSimValidationError(f"{name} must be <= {maximum}, got {value}")
    return value


def validate_finite_float(
    name: str,
    value: Any,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    """Validate that `value` is a finite number (never `bool`, `NaN`, or `Inf`)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SensoriumSimValidationError(f"{name} must be a finite float (not bool), got {value!r}")
    fval = float(value)
    if math.isnan(fval) or math.isinf(fval):
        raise SensoriumSimValidationError(f"{name} must be finite (not NaN/Inf), got {value!r}")
    if minimum is not None and fval < minimum:
        raise SensoriumSimValidationError(f"{name} must be >= {minimum}, got {fval}")
    if maximum is not None and fval > maximum:
        raise SensoriumSimValidationError(f"{name} must be <= {maximum}, got {fval}")
    return fval


def validate_strict_bool(name: str, value: Any) -> bool:
    """Validate that `value` is strictly a `bool`."""
    if not isinstance(value, bool):
        raise SensoriumSimValidationError(f"{name} must be a strict bool, got {value!r}")
    return value


# =====================================================================
# Core Enumerations
# =====================================================================

class Regime(str, enum.Enum):
    NAIVE_SIGNED_IS_TRUE = "NAIVE_SIGNED_IS_TRUE"
    CIN_DEFENSE_IN_DEPTH = "CIN_DEFENSE_IN_DEPTH"


class ScenarioId(str, enum.Enum):
    RT1_ANALOG_HOLE_TRANSDUCTION_SPOOF = "RT1_ANALOG_HOLE_TRANSDUCTION_SPOOF"
    RT2_OBSERVATION_AWARE_DEFEAT_GAMING = "RT2_OBSERVATION_AWARE_DEFEAT_GAMING"
    RT3_CHANNEL_REPLAY_INTERCEPTION = "RT3_CHANNEL_REPLAY_INTERCEPTION"
    RT4_MONOCULTURE_COMMON_MODE_FAULT = "RT4_MONOCULTURE_COMMON_MODE_FAULT"
    RT5_CALIBRATION_AND_COVERAGE_BIAS = "RT5_CALIBRATION_AND_COVERAGE_BIAS"
    RT6_COERCED_SIGNING_AND_KEY_EXTRACTION = "RT6_COERCED_SIGNING_AND_KEY_EXTRACTION"
    RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION = "RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION"
    RT8_SYBIL_ESCROW_COLLUSION_RING = "RT8_SYBIL_ESCROW_COLLUSION_RING"


class Modality(str, enum.Enum):
    VISUAL = "VISUAL"
    DEPTH_RANGING = "DEPTH_RANGING"
    INERTIAL_IMU = "INERTIAL_IMU"
    ACOUSTIC = "ACOUSTIC"
    AMBIENT = "AMBIENT"


class SettlementDecision(str, enum.Enum):
    APPROVED_PAYOUT = "APPROVED_PAYOUT"
    REJECTED_REFUND = "REJECTED_REFUND"
    PENALIZED_NONCOMPLIANCE = "PENALIZED_NONCOMPLIANCE"
    CONTESTABLE_HUMAN_REVIEW = "CONTESTABLE_HUMAN_REVIEW"
    FROZEN_RECOVERY_ESCROW = "FROZEN_RECOVERY_ESCROW"
    QUARANTINED_CARTEL_SLASHED = "QUARANTINED_CARTEL_SLASHED"


# =====================================================================
# Deterministic SHA-256 Seed & Cryptographic Helpers
# =====================================================================

def derive_seed(master_seed: int, *components: Any) -> int:
    """Derive an isolated 128-bit integer seed via SHA-256 to prevent RNG phase drift."""
    validate_strict_int("master_seed", master_seed)
    joined = ":".join([str(master_seed), *(str(c) for c in components)]).encode("utf-8")
    return int.from_bytes(hashlib.sha256(joined).digest()[:16], "big")


def derive_rng(master_seed: int, *components: Any) -> random.Random:
    """Return a deterministic `random.Random` instance scoped to `components`."""
    return random.Random(derive_seed(master_seed, *components))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_hex(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Compute a deterministic domain-separated binary Merkle root over `leaf_hashes`."""
    if not leaf_hashes:
        return _sha256_hex(b"MERKLE_EMPTY_WINDOW")
    level = [_sha256_hex(f"LEAF:{h}".encode("utf-8")) for h in leaf_hashes]
    while len(level) > 1:
        nxt: List[str] = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1] if idx + 1 < len(level) else left
            nxt.append(_sha256_hex(f"NODE:{left}:{right}".encode("utf-8")))
        level = nxt
    return level[0]


# =====================================================================
# Pipeline Stage 1: Multimodal Perceptual Sensorium (DICE / SPDM / RFC 9334)
# =====================================================================

@dataclass(frozen=True)
class PeripheralAttestationQuote:
    """TCG DICE / DMTF SPDM / RFC 9334 peripheral evidence bound to Device Time."""

    modality: Modality
    dice_cdi_id: str
    spdm_session_id: str
    challenger_nonce: str
    device_time_ticks: int
    payload_digest: str
    static_device_sig: str
    session_fresh_quote_mac: str


@dataclass(frozen=True)
class TransducerObservation:
    """Single-modality observation latched at hardware `device_time_ticks`."""

    modality: Modality
    measured_displacement_m: float
    self_confidence: float
    device_time_ticks: int
    quote: PeripheralAttestationQuote


@dataclass(frozen=True)
class SensoriumFusionSummary:
    """Cross-modal fused predicate summary safe to pass to the local vault."""

    primary_displacement_m: float
    median_displacement_m: float
    max_cross_modal_residual_m: float
    primary_self_confidence: float
    fused_confidence: float
    calibration_stratum_supported: bool
    active_spdm_session_id: str
    expected_challenger_nonce: str
    vault_last_committed_ticks: int
    quotes: Tuple[PeripheralAttestationQuote, ...]


def build_transducer_observation(
    *,
    modality: Modality,
    measured_displacement_m: float,
    self_confidence: float,
    device_time_ticks: int,
    dice_secret: bytes,
    spdm_session_id: str,
    challenger_nonce: str,
) -> TransducerObservation:
    """Construct a hardware-signed transducer reading with DICE/SPDM quote."""
    validate_finite_float("measured_displacement_m", measured_displacement_m)
    validate_finite_float("self_confidence", self_confidence, 0.0, 1.0)
    validate_strict_int("device_time_ticks", device_time_ticks, 0)
    dice_cdi_id = _sha256_hex(b"DICE_CDI:" + dice_secret)[:24]
    payload_str = f"{modality.value}:{measured_displacement_m:.4f}:{self_confidence:.4f}"
    payload_digest = _sha256_hex(payload_str.encode("utf-8"))
    # Static signature binds only payload + device key (vulnerable to host replay if checked alone)
    static_sig = _hmac_hex(dice_secret, f"STATIC:{dice_cdi_id}:{payload_digest}")
    # RFC 9334 / SPDM quote binds payload + active session + challenger nonce + monotonic Device Time
    fresh_mac = _hmac_hex(
        dice_secret,
        f"SPDM_QUOTE:{dice_cdi_id}:{spdm_session_id}:{challenger_nonce}:{device_time_ticks}:{payload_digest}",
    )
    quote = PeripheralAttestationQuote(
        modality=modality,
        dice_cdi_id=dice_cdi_id,
        spdm_session_id=spdm_session_id,
        challenger_nonce=challenger_nonce,
        device_time_ticks=device_time_ticks,
        payload_digest=payload_digest,
        static_device_sig=static_sig,
        session_fresh_quote_mac=fresh_mac,
    )
    return TransducerObservation(
        modality=modality,
        measured_displacement_m=measured_displacement_m,
        self_confidence=self_confidence,
        device_time_ticks=device_time_ticks,
        quote=quote,
    )


def fuse_multimodal_sensorium(
    observations: Sequence[TransducerObservation],
    *,
    calibration_stratum_supported: bool,
    active_spdm_session_id: str,
    expected_challenger_nonce: str,
    vault_last_committed_ticks: int,
) -> SensoriumFusionSummary:
    """Fuse multimodal transducers and widen epistemic uncertainty under disagreement."""
    if not observations:
        raise SensoriumSimValidationError("observations must be non-empty")
    validate_strict_bool("calibration_stratum_supported", calibration_stratum_supported)
    validate_strict_int("vault_last_committed_ticks", vault_last_committed_ticks, 0)

    vals = sorted(obs.measured_displacement_m for obs in observations)
    mid = len(vals) // 2
    median_disp = vals[mid] if len(vals) % 2 == 1 else 0.5 * (vals[mid - 1] + vals[mid])
    max_residual = max(abs(obs.measured_displacement_m - median_disp) for obs in observations)
    primary = observations[0]
    mean_conf = sum(obs.self_confidence for obs in observations) / len(observations)
    # Epistemic confidence widening: physical disagreement across coupled modalities
    # exponentially widens uncertainty (lowering fused_confidence).
    disagreement_decay = math.exp(-0.45 * max_residual)
    fused_conf = max(0.0, min(1.0, mean_conf * disagreement_decay))

    return SensoriumFusionSummary(
        primary_displacement_m=primary.measured_displacement_m,
        median_displacement_m=median_disp,
        max_cross_modal_residual_m=max_residual,
        primary_self_confidence=primary.self_confidence,
        fused_confidence=fused_conf,
        calibration_stratum_supported=calibration_stratum_supported,
        active_spdm_session_id=active_spdm_session_id,
        expected_challenger_nonce=expected_challenger_nonce,
        vault_last_committed_ticks=vault_last_committed_ticks,
        quotes=tuple(obs.quote for obs in observations),
    )


# =====================================================================
# Pipeline Stage 2: Cryptographically Sealed Episodic Memory Vault
# =====================================================================

@dataclass(frozen=True)
class SignedEpisodicEvent:
    """Append-only local memory entry encrypted to (person_pubkey, personal_agent_pubkey)."""

    window_id: int
    seq_no: int
    device_time_ticks: int
    encrypted_private_ciphertext: bytes
    private_payload_size_bytes: int
    polarity_tag: str  # "FAVORABLE" | "NEUTRAL" | "FALSIFYING"
    leaf_commitment_hash: str
    event_hw_signature: str


@dataclass(frozen=True)
class ZKWindowCompletenessProof:
    """Zero-knowledge window non-omission predicate proof over [0 .. hw_window_count - 1]."""

    window_id: int
    hw_seq_start: int
    hw_seq_end: int
    committed_seq_nos: Tuple[int, ...]
    claimed_merkle_root: str
    hardware_anchored_merkle_root: str
    zero_falsifying_events_in_presented_set: bool
    all_window_events_included: bool
    zk_predicate_mac: str


class EpisodicMemoryVault:
    """Local append-only Merkle log sealed to (person_pubkey, personal_agent_pubkey)."""

    def __init__(self, person_pubkey: str, personal_agent_pubkey: str, vault_key: bytes) -> None:
        if not person_pubkey or not personal_agent_pubkey:
            raise SensoriumSimValidationError("Vault requires both person_pubkey and personal_agent_pubkey")
        self.person_pubkey = person_pubkey
        self.personal_agent_pubkey = personal_agent_pubkey
        self._vault_key = vault_key
        self._events: List[SignedEpisodicEvent] = []

    def append_event(
        self,
        *,
        window_id: int,
        device_time_ticks: int,
        raw_private_bytes: bytes,
        polarity_tag: str,
        hw_signing_key: bytes,
    ) -> SignedEpisodicEvent:
        validate_strict_int("window_id", window_id, 0)
        validate_strict_int("device_time_ticks", device_time_ticks, 0)
        if polarity_tag not in ("FAVORABLE", "NEUTRAL", "FALSIFYING"):
            raise SensoriumSimValidationError(f"Unsupported polarity_tag: {polarity_tag!r}")
        if not isinstance(raw_private_bytes, (bytes, bytearray)) or len(raw_private_bytes) == 0:
            raise SensoriumSimValidationError("raw_private_bytes must be non-empty bytes")

        seq_no = len(self._events)
        prev_hash = self._events[-1].leaf_commitment_hash if self._events else "GENESIS"
        recipient_binding = f"{self.person_pubkey}::{self.personal_agent_pubkey}".encode("utf-8")
        pad = hashlib.sha256(self._vault_key + recipient_binding + str(seq_no).encode("utf-8")).digest()
        # Stream-seal raw autobiographical payload locally inside the vault
        sealed = bytes(b ^ pad[i % len(pad)] for i, b in enumerate(raw_private_bytes))
        polarity_commit = _hmac_hex(self._vault_key, f"POL:{window_id}:{seq_no}:{polarity_tag}")
        leaf_hash = _sha256_hex(
            f"VAULT_LEAF:{window_id}:{seq_no}:{device_time_ticks}:{prev_hash}:{polarity_commit}".encode("utf-8")
        )
        hw_sig = _hmac_hex(hw_signing_key, f"EVENT_HW_SIG:{window_id}:{seq_no}:{leaf_hash}")
        ev = SignedEpisodicEvent(
            window_id=window_id,
            seq_no=seq_no,
            device_time_ticks=device_time_ticks,
            encrypted_private_ciphertext=sealed,
            private_payload_size_bytes=len(raw_private_bytes),
            polarity_tag=polarity_tag,
            leaf_commitment_hash=leaf_hash,
            event_hw_signature=hw_sig,
        )
        self._events.append(ev)
        return ev

    @property
    def events(self) -> Tuple[SignedEpisodicEvent, ...]:
        return tuple(self._events)

    @property
    def total_private_bytes_vaulted(self) -> int:
        return sum(e.private_payload_size_bytes for e in self._events)

    def hardware_window_merkle_root(self) -> str:
        return compute_merkle_root([e.leaf_commitment_hash for e in self._events])


# =====================================================================
# Pipeline Stage 3: Monogamous 1:1 Personal Model Markov Blanket
# =====================================================================

@dataclass(frozen=True)
class ObserverAttestation:
    """Secondary/external observer attestation with explicit hardware/software lineage."""

    observer_id: str
    owner_org: str
    hardware_vendor: str
    software_lineage: str
    observer_class: str
    assigned_by_vrf: bool
    endorses_claim: bool
    signature_valid: bool


@dataclass(frozen=True)
class PublicAttestationClaim:
    """Zero-raw-byte claim projected onto the Public Attestation & Escrow Ledger."""

    claim_id: str
    scenario_id: ScenarioId
    is_adversarial_attack: bool
    is_honest_participant: bool
    is_under_calibrated_stratum: bool
    requester_escrow_cents: int
    participant_stake_cents: int
    attester_bond_cents: int
    sensorium: SensoriumFusionSummary
    dice_verify_key: bytes
    scheduled_checkpoint_clean: bool
    spot_check_violations_found: int
    duress_canary_active: bool
    velocity_ratio: float
    unbonded_new_recipient: bool
    presented_event_sigs_valid: bool
    presented_event_count: int
    zk_window_proof: ZKWindowCompletenessProof
    observer_attestations: Tuple[ObserverAttestation, ...]
    observer_graph_edges: Tuple[Tuple[str, str], ...]
    raw_private_leak_bytes: bytes = b""

    @property
    def exposed_private_bytes(self) -> int:
        return len(self.raw_private_leak_bytes)


class MonogamousMarkovBlanket:
    """1:1 Personal Model boundary isolating Private Autobiographical vs Public Escrow Ledgers."""

    def __init__(self, owner_person_id: str, personal_agent_id: str, zk_proving_key: bytes) -> None:
        if not owner_person_id or not personal_agent_id:
            raise SensoriumSimValidationError("Markov Blanket requires 1:1 owner and personal agent IDs")
        self.owner_person_id = owner_person_id
        self.personal_agent_id = personal_agent_id
        self._zk_key = zk_proving_key

    def build_window_proof(
        self,
        vault: EpisodicMemoryVault,
        included_indices: Sequence[int],
    ) -> Tuple[ZKWindowCompletenessProof, bool]:
        """Build a zero-knowledge window completeness proof over `included_indices`."""
        all_events = vault.events
        if not all_events:
            raise SensoriumSimValidationError("Vault cannot be empty when projecting a claim")
        hw_root = vault.hardware_window_merkle_root()
        selected = [all_events[i] for i in included_indices]
        claimed_root = compute_merkle_root([e.leaf_commitment_hash for e in selected])
        expected_indices = tuple(range(len(all_events)))
        committed_seq = tuple(e.seq_no for e in selected)
        all_included = (committed_seq == expected_indices) and (claimed_root == hw_root)
        zero_falsifying_in_selected = all(e.polarity_tag != "FALSIFYING" for e in selected)
        zero_falsifying_in_full_window = all(e.polarity_tag != "FALSIFYING" for e in all_events)

        # Valid ZK completeness MAC is constructible iff the full contiguous window is
        # included AND contains zero falsifying events.
        if all_included and zero_falsifying_in_full_window:
            zk_mac = _hmac_hex(
                self._zk_key,
                f"ZK_NON_OMISSION_OK:{all_events[0].window_id}:0:{len(all_events) - 1}:{hw_root}",
            )
        else:
            zk_mac = _hmac_hex(
                b"UNSOUND_PARTIAL_WITNESS",
                f"PARTIAL:{claimed_root}:{len(selected)}",
            )

        proof = ZKWindowCompletenessProof(
            window_id=all_events[0].window_id,
            hw_seq_start=0,
            hw_seq_end=len(all_events) - 1,
            committed_seq_nos=committed_seq,
            claimed_merkle_root=claimed_root,
            hardware_anchored_merkle_root=hw_root,
            zero_falsifying_events_in_presented_set=zero_falsifying_in_selected,
            all_window_events_included=all_included,
            zk_predicate_mac=zk_mac,
        )
        all_sigs_valid = len(selected) > 0 and all(bool(e.event_hw_signature) for e in selected)
        return proof, all_sigs_valid

    def project_to_public_ledger(
        self,
        *,
        vault: EpisodicMemoryVault,
        included_indices: Sequence[int],
        claim_id: str,
        scenario_id: ScenarioId,
        is_adversarial_attack: bool,
        is_honest_participant: bool,
        is_under_calibrated_stratum: bool,
        requester_escrow_cents: int,
        participant_stake_cents: int,
        attester_bond_cents: int,
        sensorium: SensoriumFusionSummary,
        dice_verify_key: bytes,
        scheduled_checkpoint_clean: bool,
        spot_check_violations_found: int,
        duress_canary_active: bool,
        velocity_ratio: float,
        unbonded_new_recipient: bool,
        observer_attestations: Tuple[ObserverAttestation, ...],
        observer_graph_edges: Tuple[Tuple[str, str], ...],
    ) -> PublicAttestationClaim:
        """Project local vault & sensorium state onto a zero-raw-byte Public Ledger claim."""
        validate_strict_int("requester_escrow_cents", requester_escrow_cents, 0)
        validate_strict_int("participant_stake_cents", participant_stake_cents, 0)
        validate_strict_int("attester_bond_cents", attester_bond_cents, 0)
        validate_strict_int("spot_check_violations_found", spot_check_violations_found, 0)
        validate_finite_float("velocity_ratio", velocity_ratio, 0.0)

        # Enforce monogamous 1:1 ownership match with the vault
        if vault.person_pubkey != self.owner_person_id or vault.personal_agent_pubkey != self.personal_agent_id:
            raise MarkovBlanketLeakError("Vault ownership mismatch at 1:1 Markov Blanket boundary")

        zk_proof, sigs_valid = self.build_window_proof(vault, included_indices)
        claim = PublicAttestationClaim(
            claim_id=claim_id,
            scenario_id=scenario_id,
            is_adversarial_attack=is_adversarial_attack,
            is_honest_participant=is_honest_participant,
            is_under_calibrated_stratum=is_under_calibrated_stratum,
            requester_escrow_cents=requester_escrow_cents,
            participant_stake_cents=participant_stake_cents,
            attester_bond_cents=attester_bond_cents,
            sensorium=sensorium,
            dice_verify_key=dice_verify_key,
            scheduled_checkpoint_clean=scheduled_checkpoint_clean,
            spot_check_violations_found=spot_check_violations_found,
            duress_canary_active=duress_canary_active,
            velocity_ratio=velocity_ratio,
            unbonded_new_recipient=unbonded_new_recipient,
            presented_event_sigs_valid=sigs_valid,
            presented_event_count=len(included_indices),
            zk_window_proof=zk_proof,
            observer_attestations=observer_attestations,
            observer_graph_edges=observer_graph_edges,
            raw_private_leak_bytes=b"",
        )
        if claim.exposed_private_bytes != 0:
            raise MarkovBlanketLeakError("Raw private bytes must never exit the Markov Blanket")
        return claim


# =====================================================================
# Pipeline Stage 4: Wide Network Escrow & Engineered-Independence Verifier
# =====================================================================

@dataclass(frozen=True)
class VerifierPolicy:
    """Explicit cryptographic & governance verification policy (no regime-name branching)."""

    require_cross_modal_kinematics: bool
    max_allowed_kinematic_residual_m: float
    min_high_stakes_confidence: float
    require_randomized_spot_escrow: bool
    require_spdm_session_and_monotonic_clock: bool
    require_engineered_lineage_independence: bool
    min_observer_quorum: int
    uncertainty_falls_on_system: bool
    enable_duress_and_velocity_freeze: bool
    max_instant_velocity_ratio: float
    require_window_merkle_non_omission: bool
    enable_ktruss_cartel_quarantine: bool
    cartel_truss_threshold: int
    max_attester_triangle_density: float


NAIVE_POLICY = VerifierPolicy(
    require_cross_modal_kinematics=False,
    max_allowed_kinematic_residual_m=999.0,
    min_high_stakes_confidence=0.60,
    require_randomized_spot_escrow=False,
    require_spdm_session_and_monotonic_clock=False,
    require_engineered_lineage_independence=False,
    min_observer_quorum=3,
    uncertainty_falls_on_system=False,
    enable_duress_and_velocity_freeze=False,
    max_instant_velocity_ratio=999.0,
    require_window_merkle_non_omission=False,
    enable_ktruss_cartel_quarantine=False,
    cartel_truss_threshold=99,
    max_attester_triangle_density=1.0,
)

CIN_HARDENED_POLICY = VerifierPolicy(
    require_cross_modal_kinematics=True,
    max_allowed_kinematic_residual_m=1.25,
    min_high_stakes_confidence=0.70,
    require_randomized_spot_escrow=True,
    require_spdm_session_and_monotonic_clock=True,
    require_engineered_lineage_independence=True,
    min_observer_quorum=3,
    uncertainty_falls_on_system=True,
    enable_duress_and_velocity_freeze=True,
    max_instant_velocity_ratio=4.0,
    require_window_merkle_non_omission=True,
    enable_ktruss_cartel_quarantine=True,
    cartel_truss_threshold=4,
    max_attester_triangle_density=0.60,
)


def count_independent_observer_classes(attestations: Sequence[ObserverAttestation]) -> int:
    """Partition endorsing observers by shared (owner_org, hardware_vendor, software_lineage).

    Any two observers sharing owner_org OR hardware_vendor OR software_lineage are merged
    into the same correlated failure class via Union-Find, enforcing Engineered Independence.
    """
    endorsing = [a for a in attestations if a.signature_valid and a.endorses_claim]
    n = len(endorsing)
    if n == 0:
        return 0
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    for i in range(n):
        for j in range(i + 1, n):
            ai, aj = endorsing[i], endorsing[j]
            if (
                ai.owner_org == aj.owner_org
                or ai.hardware_vendor == aj.hardware_vendor
                or ai.software_lineage == aj.software_lineage
            ):
                union(i, j)

    return len({find(i) for i in range(n)})


def compute_edge_truss_numbers(edges: Sequence[Tuple[str, str]]) -> Dict[Tuple[str, str], int]:
    """Compute exact maximal k-truss number for every undirected edge via iterative triangle peeling."""
    adj: Dict[str, Set[str]] = {}
    canon_edges: Set[Tuple[str, str]] = set()
    for u, v in edges:
        if u == v:
            continue
        a, b = (u, v) if u < v else (v, u)
        canon_edges.add((a, b))
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    if not canon_edges:
        return {}

    truss: Dict[Tuple[str, str], int] = {}
    remaining = set(canon_edges)
    k = 3
    while remaining:
        changed = True
        while changed:
            changed = False
            to_peel: List[Tuple[str, str]] = []
            for u, v in remaining:
                common = len(adj[u] & adj[v])
                if common < (k - 2):
                    to_peel.append((u, v))
            if to_peel:
                changed = True
                for u, v in to_peel:
                    remaining.remove((u, v))
                    adj[u].discard(v)
                    adj[v].discard(u)
                    truss[(u, v)] = k - 1
        k += 1
    return truss


def induced_triangle_density(nodes: Sequence[str], edges: Sequence[Tuple[str, str]]) -> float:
    """Compute triangle density C(t) / C(|S|, 3) inside the subgraph induced by `nodes`."""
    node_set = list(dict.fromkeys(nodes))
    m = len(node_set)
    if m < 3:
        return 0.0
    adj: Dict[str, Set[str]] = {u: set() for u in node_set}
    for u, v in edges:
        if u in adj and v in adj and u != v:
            adj[u].add(v)
            adj[v].add(u)
    triangles = 0
    for i in range(m):
        for j in range(i + 1, m):
            if node_set[j] not in adj[node_set[i]]:
                continue
            for l_idx in range(j + 1, m):
                if node_set[l_idx] in adj[node_set[i]] and node_set[l_idx] in adj[node_set[j]]:
                    triangles += 1
    max_possible = (m * (m - 1) * (m - 2)) // 6
    return triangles / max_possible if max_possible > 0 else 0.0


@dataclass(frozen=True)
class TrialVerificationOutcome:
    """Capital-conserved settlement outcome for a single red-team trial."""

    decision: SettlementDecision
    attack_succeeded: bool
    honest_falsely_penalized: bool
    honest_falsely_rejected: bool
    routed_to_human_review: bool
    requester_refunded_cents: int
    claimant_payout_cents: int
    recovery_vault_frozen_cents: int
    participant_retained_cents: int
    audit_treasury_cents: int
    attester_bond_returned_cents: int
    exposed_private_bytes: int


class WideNetworkEscrowVerifier:
    """Evaluates `PublicAttestationClaim` under `VerifierPolicy` with strict capital conservation."""

    def __init__(self, policy: VerifierPolicy, zk_verify_key: bytes) -> None:
        self.policy = policy
        self._zk_verify_key = zk_verify_key

    def _verify_peripheral_quotes(self, claim: PublicAttestationClaim) -> bool:
        s = claim.sensorium
        for q in s.quotes:
            expected_cdi = _sha256_hex(b"DICE_CDI:" + claim.dice_verify_key)[:24]
            expected_static = _hmac_hex(claim.dice_verify_key, f"STATIC:{expected_cdi}:{q.payload_digest}")
            if not hmac.compare_digest(q.static_device_sig, expected_static):
                return False
            if self.policy.require_spdm_session_and_monotonic_clock:
                if q.spdm_session_id != s.active_spdm_session_id:
                    return False
                if q.challenger_nonce != s.expected_challenger_nonce:
                    return False
                if q.device_time_ticks <= s.vault_last_committed_ticks:
                    return False
                expected_fresh = _hmac_hex(
                    claim.dice_verify_key,
                    f"SPDM_QUOTE:{expected_cdi}:{s.active_spdm_session_id}:"
                    f"{s.expected_challenger_nonce}:{q.device_time_ticks}:{q.payload_digest}",
                )
                if not hmac.compare_digest(q.session_fresh_quote_mac, expected_fresh):
                    return False
        return True

    def _verify_zk_window_completeness(self, claim: PublicAttestationClaim) -> bool:
        if not claim.presented_event_sigs_valid or claim.presented_event_count == 0:
            return False
        zp = claim.zk_window_proof
        if not zp.zero_falsifying_events_in_presented_set:
            return False
        if not self.policy.require_window_merkle_non_omission:
            return True
        expected_len = zp.hw_seq_end - zp.hw_seq_start + 1
        if len(zp.committed_seq_nos) != expected_len:
            return False
        if zp.committed_seq_nos != tuple(range(zp.hw_seq_start, zp.hw_seq_end + 1)):
            return False
        if not hmac.compare_digest(zp.claimed_merkle_root, zp.hardware_anchored_merkle_root):
            return False
        expected_mac = _hmac_hex(
            self._zk_verify_key,
            f"ZK_NON_OMISSION_OK:{zp.window_id}:{zp.hw_seq_start}:{zp.hw_seq_end}:{zp.hardware_anchored_merkle_root}",
        )
        return hmac.compare_digest(zp.zk_predicate_mac, expected_mac)

    def evaluate(self, claim: PublicAttestationClaim) -> TrialVerificationOutcome:
        if claim.exposed_private_bytes != 0:
            raise MarkovBlanketLeakError("PublicAttestationClaim carries raw private bytes")

        initial_total_cents = (
            claim.requester_escrow_cents
            + claim.participant_stake_cents
            + claim.attester_bond_cents
        )

        # 1. Duress Canary & Velocity Escrow Freeze Gate
        if self.policy.enable_duress_and_velocity_freeze:
            high_velocity_sweep = (
                claim.velocity_ratio > self.policy.max_instant_velocity_ratio
                and claim.unbonded_new_recipient
            )
            if claim.duress_canary_active or high_velocity_sweep:
                return self._finalize(
                    claim=claim,
                    initial_total_cents=initial_total_cents,
                    decision=SettlementDecision.FROZEN_RECOVERY_ESCROW,
                    requester_refunded_cents=0,
                    claimant_payout_cents=0,
                    recovery_vault_frozen_cents=claim.requester_escrow_cents,
                    participant_retained_cents=claim.participant_stake_cents,
                    audit_treasury_cents=0,
                    attester_bond_returned_cents=claim.attester_bond_cents,
                )

        # 2. Peripheral Hardware Signature & SPDM Session / Monotonic Clock Gate
        if not self._verify_peripheral_quotes(claim):
            return self._reject_and_refund(claim, initial_total_cents)

        # 3. Cross-Modal Physical Kinematics vs. Single-Modality Trust + Calibration Bias Handling
        s = claim.sensorium
        if self.policy.require_cross_modal_kinematics:
            if s.max_cross_modal_residual_m > self.policy.max_allowed_kinematic_residual_m:
                return self._reject_and_refund(claim, initial_total_cents)

        effective_conf = (
            s.fused_confidence if self.policy.require_cross_modal_kinematics else s.primary_self_confidence
        )
        effective_disp = (
            s.median_displacement_m if self.policy.require_cross_modal_kinematics else s.primary_displacement_m
        )

        # Low sensor confidence / uncalibrated demographic or zone stratum check
        if effective_conf < self.policy.min_high_stakes_confidence or (
            self.policy.uncertainty_falls_on_system and not s.calibration_stratum_supported
        ):
            if self.policy.uncertainty_falls_on_system:
                # Uncertainty Falls on the System: zero automatic penalty; route to contestable human review
                return self._finalize(
                    claim=claim,
                    initial_total_cents=initial_total_cents,
                    decision=SettlementDecision.CONTESTABLE_HUMAN_REVIEW,
                    requester_refunded_cents=claim.requester_escrow_cents,
                    claimant_payout_cents=0,
                    recovery_vault_frozen_cents=0,
                    participant_retained_cents=claim.participant_stake_cents,
                    audit_treasury_cents=0,
                    attester_bond_returned_cents=claim.attester_bond_cents,
                )
            # Naive regime treats low sensor confidence / uncalibrated drift as automatic participant fault
            penalty = min(claim.participant_stake_cents, 2_500)
            return self._finalize(
                claim=claim,
                initial_total_cents=initial_total_cents,
                decision=SettlementDecision.PENALIZED_NONCOMPLIANCE,
                requester_refunded_cents=claim.requester_escrow_cents,
                claimant_payout_cents=0,
                recovery_vault_frozen_cents=0,
                participant_retained_cents=claim.participant_stake_cents - penalty,
                audit_treasury_cents=penalty,
                attester_bond_returned_cents=claim.attester_bond_cents,
            )

        # Check physical task predicate threshold (e.g. >= 10.0 m verified motion/delivery)
        if effective_disp < 10.0:
            return self._reject_and_refund(claim, initial_total_cents)

        # 4. Scheduled Checkpoints vs. Randomized Spot-Verification Epistemic Escrow
        if not claim.scheduled_checkpoint_clean:
            return self._reject_and_refund(claim, initial_total_cents)
        if self.policy.require_randomized_spot_escrow and claim.spot_check_violations_found > 0:
            return self._reject_and_refund(claim, initial_total_cents)

        # 5. Sliding-Window Merkle Root & Zero-Knowledge Non-Omission Gate
        if not self._verify_zk_window_completeness(claim):
            return self._reject_and_refund(claim, initial_total_cents)

        # 6. Multi-Observer Quorum: Engineered Independence & k-Truss Cartel Quarantine
        if claim.observer_attestations:
            valid_endorsers = [
                a for a in claim.observer_attestations if a.signature_valid and a.endorses_claim
            ]
            if self.policy.require_engineered_lineage_independence:
                quorum_count = count_independent_observer_classes(valid_endorsers)
            else:
                quorum_count = len({a.observer_id for a in valid_endorsers})

            if quorum_count < self.policy.min_observer_quorum:
                return self._reject_and_refund(claim, initial_total_cents)

            if self.policy.enable_ktruss_cartel_quarantine and claim.observer_graph_edges:
                endorser_ids = [a.observer_id for a in valid_endorsers]
                endorser_set = set(endorser_ids)
                truss_map = compute_edge_truss_numbers(claim.observer_graph_edges)
                internal_truss = [
                    k_val
                    for (u, v), k_val in truss_map.items()
                    if u in endorser_set and v in endorser_set
                ]
                max_internal_truss = max(internal_truss, default=0)
                tri_density = induced_triangle_density(endorser_ids, claim.observer_graph_edges)
                distinct_classes = len({a.observer_class for a in valid_endorsers})
                all_vrf_assigned = all(a.assigned_by_vrf for a in valid_endorsers)

                if (
                    max_internal_truss >= self.policy.cartel_truss_threshold
                    or tri_density > self.policy.max_attester_triangle_density
                    or distinct_classes < self.policy.min_observer_quorum
                    or not all_vrf_assigned
                ):
                    return self._finalize(
                        claim=claim,
                        initial_total_cents=initial_total_cents,
                        decision=SettlementDecision.QUARANTINED_CARTEL_SLASHED,
                        requester_refunded_cents=claim.requester_escrow_cents,
                        claimant_payout_cents=0,
                        recovery_vault_frozen_cents=0,
                        participant_retained_cents=claim.participant_stake_cents,
                        audit_treasury_cents=claim.attester_bond_cents,
                        attester_bond_returned_cents=0,
                    )

        # All active policy gates satisfied -> release escrow payout
        return self._finalize(
            claim=claim,
            initial_total_cents=initial_total_cents,
            decision=SettlementDecision.APPROVED_PAYOUT,
            requester_refunded_cents=0,
            claimant_payout_cents=claim.requester_escrow_cents,
            recovery_vault_frozen_cents=0,
            participant_retained_cents=claim.participant_stake_cents,
            audit_treasury_cents=0,
            attester_bond_returned_cents=claim.attester_bond_cents,
        )

    def _reject_and_refund(
        self,
        claim: PublicAttestationClaim,
        initial_total_cents: int,
    ) -> TrialVerificationOutcome:
        return self._finalize(
            claim=claim,
            initial_total_cents=initial_total_cents,
            decision=SettlementDecision.REJECTED_REFUND,
            requester_refunded_cents=claim.requester_escrow_cents,
            claimant_payout_cents=0,
            recovery_vault_frozen_cents=0,
            participant_retained_cents=claim.participant_stake_cents,
            audit_treasury_cents=0,
            attester_bond_returned_cents=claim.attester_bond_cents,
        )

    @staticmethod
    def _finalize(
        *,
        claim: PublicAttestationClaim,
        initial_total_cents: int,
        decision: SettlementDecision,
        requester_refunded_cents: int,
        claimant_payout_cents: int,
        recovery_vault_frozen_cents: int,
        participant_retained_cents: int,
        audit_treasury_cents: int,
        attester_bond_returned_cents: int,
    ) -> TrialVerificationOutcome:
        for field_name, val in (
            ("requester_refunded_cents", requester_refunded_cents),
            ("claimant_payout_cents", claimant_payout_cents),
            ("recovery_vault_frozen_cents", recovery_vault_frozen_cents),
            ("participant_retained_cents", participant_retained_cents),
            ("audit_treasury_cents", audit_treasury_cents),
            ("attester_bond_returned_cents", attester_bond_returned_cents),
        ):
            validate_strict_int(field_name, val, 0)

        final_total_cents = (
            requester_refunded_cents
            + claimant_payout_cents
            + recovery_vault_frozen_cents
            + participant_retained_cents
            + audit_treasury_cents
            + attester_bond_returned_cents
        )
        if final_total_cents != initial_total_cents:
            raise CapitalConservationError(
                f"Capital conservation violated on {claim.claim_id}: "
                f"initial={initial_total_cents} != final={final_total_cents}"
            )

        attack_succeeded = claim.is_adversarial_attack and (
            decision == SettlementDecision.APPROVED_PAYOUT and claimant_payout_cents > 0
        )
        honest_falsely_penalized = claim.is_honest_participant and (
            participant_retained_cents < claim.participant_stake_cents
        )
        honest_falsely_rejected = (
            claim.is_honest_participant
            and not claim.is_under_calibrated_stratum
            and decision != SettlementDecision.APPROVED_PAYOUT
        )
        routed_review = decision == SettlementDecision.CONTESTABLE_HUMAN_REVIEW

        return TrialVerificationOutcome(
            decision=decision,
            attack_succeeded=attack_succeeded,
            honest_falsely_penalized=honest_falsely_penalized,
            honest_falsely_rejected=honest_falsely_rejected,
            routed_to_human_review=routed_review,
            requester_refunded_cents=requester_refunded_cents,
            claimant_payout_cents=claimant_payout_cents,
            recovery_vault_frozen_cents=recovery_vault_frozen_cents,
            participant_retained_cents=participant_retained_cents,
            audit_treasury_cents=audit_treasury_cents,
            attester_bond_returned_cents=attester_bond_returned_cents,
            exposed_private_bytes=claim.exposed_private_bytes,
        )


# =====================================================================
# Decoupled Upfront Workload Generators for RT1 .. RT8
# =====================================================================

@dataclass(frozen=True)
class PreparedTrialBundle:
    """Frozen upfront trial bundle evaluated identically by both regimes (zero RNG drift)."""

    claim: PublicAttestationClaim
    private_bytes_vaulted: int


def _build_base_vault(
    rng: random.Random,
    *,
    person_id: str,
    agent_id: str,
    vault_key: bytes,
    hw_key: bytes,
    window_id: int,
    polarities: Sequence[str],
) -> EpisodicMemoryVault:
    vault = EpisodicMemoryVault(person_id, agent_id, vault_key)
    base_ticks = 10_000 + window_id * 100
    for idx, pol in enumerate(polarities):
        payload_len = rng.randint(192, 512)
        # Deterministic synthetic autobiographical bytes (never allowed to leave vault)
        raw_bytes = hashlib.sha512(f"AUTOBIO:{person_id}:{window_id}:{idx}".encode("utf-8")).digest() * (
            (payload_len // 64) + 1
        )
        vault.append_event(
            window_id=window_id,
            device_time_ticks=base_ticks + idx + 1,
            raw_private_bytes=raw_bytes[:payload_len],
            polarity_tag=pol,
            hw_signing_key=hw_key,
        )
    return vault


def _build_clean_sensorium(
    rng: random.Random,
    *,
    dice_key: bytes,
    session_id: str,
    nonce: str,
    last_ticks: int,
    target_disp_m: float = 12.8,
    base_conf: float = 0.93,
    calibration_supported: bool = True,
) -> SensoriumFusionSummary:
    obs_list: List[TransducerObservation] = []
    for m_idx, mod in enumerate(Modality):
        disp = target_disp_m + rng.gauss(0.0, 0.14)
        conf = max(0.05, min(0.99, base_conf + rng.uniform(-0.03, 0.03)))
        obs_list.append(
            build_transducer_observation(
                modality=mod,
                measured_displacement_m=disp,
                self_confidence=conf,
                device_time_ticks=last_ticks + 10 + m_idx,
                dice_secret=dice_key,
                spdm_session_id=session_id,
                challenger_nonce=nonce,
            )
        )
    return fuse_multimodal_sensorium(
        obs_list,
        calibration_stratum_supported=calibration_supported,
        active_spdm_session_id=session_id,
        expected_challenger_nonce=nonce,
        vault_last_committed_ticks=last_ticks,
    )


def generate_scenario_workloads(
    scenario_id: ScenarioId,
    *,
    master_seed: int,
    trials: int,
    zk_shared_key: bytes,
) -> Tuple[PreparedTrialBundle, ...]:
    """Materialize all `trials` workloads upfront with per-scenario/per-trial SHA-256 seeds."""
    validate_strict_int("master_seed", master_seed)
    validate_strict_int("trials", trials, 20)
    if not isinstance(scenario_id, ScenarioId):
        raise SensoriumSimValidationError(f"Expected ScenarioId, got {scenario_id!r}")

    bundles: List[PreparedTrialBundle] = []
    for t_idx in range(trials):
        rng = derive_rng(master_seed, scenario_id.value, "trial", t_idx)
        person_id = f"person:{scenario_id.name.lower()}:{t_idx:04d}"
        agent_id = f"personal-agent:{scenario_id.name.lower()}:{t_idx:04d}"
        vault_key = hashlib.sha256(f"VAULT_KEY:{master_seed}:{scenario_id.value}:{t_idx}".encode("utf-8")).digest()
        dice_key = hashlib.sha256(f"DICE_KEY:{master_seed}:{scenario_id.value}:{t_idx}".encode("utf-8")).digest()
        blanket = MonogamousMarkovBlanket(person_id, agent_id, zk_shared_key)

        session_id = f"spdm-sess-{t_idx:04d}-{rng.getrandbits(32):08x}"
        nonce = f"nonce-{rng.getrandbits(64):016x}"
        last_ticks = 50_000 + t_idx * 50

        escrow_cents = 12_000
        stake_cents = 5_000
        bond_cents = 0

        # Default clean parameters overridden specifically by each red-team vector
        is_attack = rng.random() < 0.80
        is_honest = not is_attack
        is_under_calibrated = False
        scheduled_clean = True
        spot_violations = 0
        duress_active = False
        velocity_ratio = round(rng.uniform(0.6, 1.8), 3)
        unbonded_recipient = False
        polarities: List[str] = ["FAVORABLE"] * 6
        included_indices: List[int] = list(range(6))
        attestations: Tuple[ObserverAttestation, ...] = ()
        graph_edges: Tuple[Tuple[str, str], ...] = ()

        if scenario_id == ScenarioId.RT1_ANALOG_HOLE_TRANSDUCTION_SPOOF:
            if is_attack:
                # Single-modality laser/ultrasonic injection before ADC: primary transducer
                # latches genuine hardware signature on spoofed 13.5m reading while 4 coupled
                # physical modalities remain at physical rest (~0.0m).
                obs = [
                    build_transducer_observation(
                        modality=Modality.ACOUSTIC,
                        measured_displacement_m=13.4 + rng.gauss(0.0, 0.2),
                        self_confidence=0.94,
                        device_time_ticks=last_ticks + 10,
                        dice_secret=dice_key,
                        spdm_session_id=session_id,
                        challenger_nonce=nonce,
                    )
                ]
                for m_i, mod in enumerate(
                    (Modality.VISUAL, Modality.DEPTH_RANGING, Modality.INERTIAL_IMU, Modality.AMBIENT),
                    start=1,
                ):
                    obs.append(
                        build_transducer_observation(
                            modality=mod,
                            measured_displacement_m=0.05 + rng.gauss(0.0, 0.08),
                            self_confidence=0.92,
                            device_time_ticks=last_ticks + 10 + m_i,
                            dice_secret=dice_key,
                            spdm_session_id=session_id,
                            challenger_nonce=nonce,
                        )
                    )
                sensorium = fuse_multimodal_sensorium(
                    obs,
                    calibration_stratum_supported=True,
                    active_spdm_session_id=session_id,
                    expected_challenger_nonce=nonce,
                    vault_last_committed_ticks=last_ticks,
                )
            else:
                sensorium = _build_clean_sensorium(
                    rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
                )

        elif scenario_id == ScenarioId.RT2_OBSERVATION_AWARE_DEFEAT_GAMING:
            sensorium = _build_clean_sensorium(
                rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
            )
            horizon_ticks = 24
            escrow_periods = 2
            scheduled_ticks = {0, 6, 12, 18}
            off_schedule_pool = [t for t in range(horizon_ticks) if t not in scheduled_ticks]
            # Pre-draw unpredictable VRF spot-check ticks upfront across 2 epistemic escrow periods
            per_period_vrf = [set(rng.sample(range(horizon_ticks), k=4)) for _ in range(escrow_periods)]
            if is_attack:
                # Intermittent defeat device stays clean on all scheduled ticks {0, 6, 12, 18}
                # and cheats on 9 of the 20 unmonitored off-schedule intervals in each period.
                per_period_cheating = [set(rng.sample(off_schedule_pool, k=9)) for _ in range(escrow_periods)]
                scheduled_clean = all(len(ch & scheduled_ticks) == 0 for ch in per_period_cheating)
                spot_violations = sum(
                    len(ch & vrf) for ch, vrf in zip(per_period_cheating, per_period_vrf)
                )
            else:
                scheduled_clean = True
                spot_violations = 0

        elif scenario_id == ScenarioId.RT3_CHANNEL_REPLAY_INTERCEPTION:
            if is_attack:
                replay_mode = t_idx % 3
                rep_session = session_id if replay_mode != 0 else f"stale-spdm-{t_idx:04d}"
                rep_nonce = nonce if replay_mode != 1 else f"replayed-nonce-{t_idx:04d}"
                rep_ticks = (last_ticks - rng.randint(1, 40)) if replay_mode == 2 else (last_ticks + 5)
                obs = [
                    build_transducer_observation(
                        modality=mod,
                        measured_displacement_m=12.6 + rng.gauss(0.0, 0.1),
                        self_confidence=0.93,
                        device_time_ticks=rep_ticks,
                        dice_secret=dice_key,
                        spdm_session_id=rep_session,
                        challenger_nonce=rep_nonce,
                    )
                    for mod in Modality
                ]
                sensorium = fuse_multimodal_sensorium(
                    obs,
                    calibration_stratum_supported=True,
                    active_spdm_session_id=session_id,
                    expected_challenger_nonce=nonce,
                    vault_last_committed_ticks=last_ticks,
                )
            else:
                sensorium = _build_clean_sensorium(
                    rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
                )

        elif scenario_id == ScenarioId.RT4_MONOCULTURE_COMMON_MODE_FAULT:
            sensorium = _build_clean_sensorium(
                rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
            )
            if is_attack:
                # 4 physically separate sensors share vendor "OmniSense" / firmware "fw-2.4.1"
                # and suffer a correlated false-endorsement bug; 2 diverse sensors dissent.
                attestations = (
                    ObserverAttestation("obs-m1", "coop-north", "OmniSense", "fw-2.4.1", "cls-a", True, True, True),
                    ObserverAttestation("obs-m2", "coop-east", "OmniSense", "fw-2.4.1", "cls-b", True, True, True),
                    ObserverAttestation("obs-m3", "coop-south", "OmniSense", "fw-2.4.1", "cls-c", True, True, True),
                    ObserverAttestation("obs-m4", "coop-west", "OmniSense", "fw-2.4.1", "cls-d", True, True, True),
                    ObserverAttestation("obs-ind-1", "civic-lab", "OpenPhoton", "risc-v-1.2", "cls-e", True, False, True),
                    ObserverAttestation("obs-ind-2", "metro-audit", "FieldSonar", "seL4-mon-3.0", "cls-f", True, False, True),
                )
            else:
                attestations = (
                    ObserverAttestation("obs-d1", "coop-north", "OmniSense", "fw-2.4.1", "cls-a", True, True, True),
                    ObserverAttestation("obs-d2", "civic-lab", "OpenPhoton", "risc-v-1.2", "cls-b", True, True, True),
                    ObserverAttestation("obs-d3", "metro-audit", "FieldSonar", "seL4-mon-3.0", "cls-c", True, True, True),
                    ObserverAttestation("obs-d4", "harbor-guild", "NordicMEMS", "zephyr-4.1", "cls-d", True, True, True),
                )

        elif scenario_id == ScenarioId.RT5_CALIBRATION_AND_COVERAGE_BIAS:
            # All participants in RT5 are honest humans; 80% belong to under-calibrated
            # demographic / rural-coverage sensor strata (Sjoding / Street-Bump effect).
            is_attack = False
            is_honest = True
            is_under_calibrated = rng.random() < 0.80
            if is_under_calibrated:
                low_conf = rng.uniform(0.28, 0.56)
                sensorium = _build_clean_sensorium(
                    rng,
                    dice_key=dice_key,
                    session_id=session_id,
                    nonce=nonce,
                    last_ticks=last_ticks,
                    target_disp_m=11.8,
                    base_conf=low_conf,
                    calibration_supported=False,
                )
            else:
                sensorium = _build_clean_sensorium(
                    rng,
                    dice_key=dice_key,
                    session_id=session_id,
                    nonce=nonce,
                    last_ticks=last_ticks,
                    target_disp_m=12.6,
                    base_conf=0.92,
                    calibration_supported=True,
                )

        elif scenario_id == ScenarioId.RT6_COERCED_SIGNING_AND_KEY_EXTRACTION:
            sensorium = _build_clean_sensorium(
                rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
            )
            escrow_cents = 45_000
            if is_attack:
                if t_idx % 2 == 0:
                    # Physical rubber-hose duress: covert duress canary triggered
                    duress_active = True
                    velocity_ratio = round(rng.uniform(3.2, 7.5), 3)
                    unbonded_recipient = True
                else:
                    # Extracted device key sweep: huge sudden velocity spike to unbonded target
                    duress_active = False
                    velocity_ratio = round(rng.uniform(6.5, 18.0), 3)
                    unbonded_recipient = True
            else:
                duress_active = False
                velocity_ratio = round(rng.uniform(0.5, 2.2), 3)
                unbonded_recipient = False

        elif scenario_id == ScenarioId.RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION:
            sensorium = _build_clean_sensorium(
                rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
            )
            window_len = 8
            if is_attack:
                # Vault recorded 6 favorable events and 2 falsifying violations in the same window;
                # cherry-picking agent omits the 2 falsifying indices when projecting to Public Ledger.
                falsifying_slots = set(rng.sample(range(window_len), k=2))
                polarities = [
                    "FALSIFYING" if idx in falsifying_slots else "FAVORABLE"
                    for idx in range(window_len)
                ]
                included_indices = [idx for idx in range(window_len) if idx not in falsifying_slots]
            else:
                polarities = ["FAVORABLE" if idx % 2 == 0 else "NEUTRAL" for idx in range(window_len)]
                included_indices = list(range(window_len))

        elif scenario_id == ScenarioId.RT8_SYBIL_ESCROW_COLLUSION_RING:
            sensorium = _build_clean_sensorium(
                rng, dice_key=dice_key, session_id=session_id, nonce=nonce, last_ticks=last_ticks
            )
            bond_cents = 4_000
            # Build 10-node interaction graph: 5-node dense K5 Sybil cartel (5-truss) + 5 sparse honest nodes
            cartel_nodes = [f"sybil-{i}" for i in range(5)]
            honest_nodes = [f"honest-{i}" for i in range(5)]
            edges_set: List[Tuple[str, str]] = []
            for i in range(len(cartel_nodes)):
                for j in range(i + 1, len(cartel_nodes)):
                    edges_set.append((cartel_nodes[i], cartel_nodes[j]))
            # Sparse tree/path links among honest nodes (triangle-free / low-truss <= 2)
            for i in range(len(honest_nodes) - 1):
                edges_set.append((honest_nodes[i], honest_nodes[i + 1]))
            edges_set.append((cartel_nodes[0], honest_nodes[0]))
            graph_edges = tuple(edges_set)

            if is_attack:
                # 4 collusive cartel members rubber-stamp a fake completion (K4 inside K5 => 5-truss, density 1.0)
                attestations = tuple(
                    ObserverAttestation(
                        observer_id=cartel_nodes[i],
                        owner_org=f"shell-org-{i}",
                        hardware_vendor=f"vendor-{i}",
                        software_lineage=f"lineage-{i}",
                        observer_class="cls-cartel-ring" if i < 3 else "cls-secondary",
                        assigned_by_vrf=False,
                        endorses_claim=True,
                        signature_valid=True,
                    )
                    for i in range(4)
                )
            else:
                # 3 VRF-assigned cross-class honest observers with zero internal triangles (truss <= 2, density 0.0)
                picked_honest = (honest_nodes[0], honest_nodes[2], honest_nodes[4])
                attestations = tuple(
                    ObserverAttestation(
                        observer_id=nid,
                        owner_org=f"coop-org-{idx}",
                        hardware_vendor=f"hw-maker-{idx}",
                        software_lineage=f"sw-stack-{idx}",
                        observer_class=f"independent-class-{idx}",
                        assigned_by_vrf=True,
                        endorses_claim=True,
                        signature_valid=True,
                    )
                    for idx, nid in enumerate(picked_honest)
                )

        vault = _build_base_vault(
            rng,
            person_id=person_id,
            agent_id=agent_id,
            vault_key=vault_key,
            hw_key=dice_key,
            window_id=t_idx,
            polarities=polarities,
        )
        claim = blanket.project_to_public_ledger(
            vault=vault,
            included_indices=included_indices,
            claim_id=f"{scenario_id.value}:trial:{t_idx:04d}",
            scenario_id=scenario_id,
            is_adversarial_attack=is_attack,
            is_honest_participant=is_honest,
            is_under_calibrated_stratum=is_under_calibrated,
            requester_escrow_cents=escrow_cents,
            participant_stake_cents=stake_cents,
            attester_bond_cents=bond_cents,
            sensorium=sensorium,
            dice_verify_key=dice_key,
            scheduled_checkpoint_clean=scheduled_clean,
            spot_check_violations_found=spot_violations,
            duress_canary_active=duress_active,
            velocity_ratio=velocity_ratio,
            unbonded_new_recipient=unbonded_recipient,
            observer_attestations=attestations,
            observer_graph_edges=graph_edges,
        )
        bundles.append(
            PreparedTrialBundle(
                claim=claim,
                private_bytes_vaulted=vault.total_private_bytes_vaulted,
            )
        )
    return tuple(bundles)


# =====================================================================
# Scenario & Full-Suite Execution
# =====================================================================

def _summarize_regime(
    bundles: Sequence[PreparedTrialBundle],
    verifier: WideNetworkEscrowVerifier,
) -> Dict[str, Any]:
    total = len(bundles)
    attack_trials = 0
    honest_trials = 0
    under_cal_trials = 0
    attacks_succeeded = 0
    attacks_blocked = 0
    false_penalties = 0
    false_rejections = 0
    human_reviews = 0
    private_vaulted = 0
    private_exposed = 0

    total_escrow_cents = 0
    wrongful_payout_cents = 0
    unfair_penalty_cents = 0
    protected_or_recovered_cents = 0
    slashed_treasury_cents = 0

    for b in bundles:
        c = b.claim
        out = verifier.evaluate(c)
        private_vaulted += b.private_bytes_vaulted
        private_exposed += out.exposed_private_bytes
        total_escrow_cents += c.requester_escrow_cents

        if c.is_adversarial_attack:
            attack_trials += 1
            if out.attack_succeeded:
                attacks_succeeded += 1
                wrongful_payout_cents += out.claimant_payout_cents
            else:
                attacks_blocked += 1
                protected_or_recovered_cents += (
                    out.requester_refunded_cents + out.recovery_vault_frozen_cents
                )
        if c.is_honest_participant:
            honest_trials += 1
            if c.is_under_calibrated_stratum:
                under_cal_trials += 1
            if out.honest_falsely_penalized:
                false_penalties += 1
                unfair_penalty_cents += c.participant_stake_cents - out.participant_retained_cents
            if out.honest_falsely_rejected:
                false_rejections += 1
        if out.routed_to_human_review:
            human_reviews += 1
        if out.decision == SettlementDecision.QUARANTINED_CARTEL_SLASHED:
            slashed_treasury_cents += out.audit_treasury_cents

    attack_success_rate = round(attacks_succeeded / attack_trials, 6) if attack_trials > 0 else 0.0
    attack_block_rate = round(attacks_blocked / attack_trials, 6) if attack_trials > 0 else 1.0
    false_penalty_rate = round(false_penalties / honest_trials, 6) if honest_trials > 0 else 0.0
    under_cal_penalty_rate = (
        round(false_penalties / under_cal_trials, 6) if under_cal_trials > 0 else 0.0
    )
    honest_false_rejection_rate = (
        round(false_rejections / max(1, honest_trials - under_cal_trials), 6)
        if (honest_trials - under_cal_trials) > 0
        else 0.0
    )
    system_failure_rate = round((attacks_succeeded + false_penalties) / total, 6)

    return {
        "trials": total,
        "attack_trials": attack_trials,
        "honest_trials": honest_trials,
        "under_calibrated_honest_trials": under_cal_trials,
        "attacks_succeeded": attacks_succeeded,
        "attacks_blocked": attacks_blocked,
        "attack_success_rate": attack_success_rate,
        "attack_block_rate": attack_block_rate,
        "false_penalties": false_penalties,
        "false_penalty_rate": false_penalty_rate,
        "under_calibrated_false_penalty_rate": under_cal_penalty_rate,
        "honest_false_rejection_rate": honest_false_rejection_rate,
        "contestable_human_review_routed": human_reviews,
        "system_failure_rate": system_failure_rate,
        "private_bytes_vaulted": private_vaulted,
        "private_bytes_exposed": private_exposed,
        "capital_conserved_all_trials": True,
        "total_escrow_deployed_cents": total_escrow_cents,
        "total_wrongful_payout_cents": wrongful_payout_cents,
        "total_unfair_honest_penalty_cents": unfair_penalty_cents,
        "total_protected_or_recovered_cents": protected_or_recovered_cents,
        "total_slashed_to_audit_treasury_cents": slashed_treasury_cents,
    }


SCENARIO_DESCRIPTIONS: Mapping[ScenarioId, str] = {
    ScenarioId.RT1_ANALOG_HOLE_TRANSDUCTION_SPOOF: (
        "Single-modality optical/ultrasonic transduction spoof upstream of the ADC "
        "vs. cross-modality physical-kinematic consistency and confidence widening."
    ),
    ScenarioId.RT2_OBSERVATION_AWARE_DEFEAT_GAMING: (
        "Observation-aware clean-mode compliance during scheduled inspections "
        "vs. VRF-randomized spot checks and multi-period epistemic time-escrow."
    ),
    ScenarioId.RT3_CHANNEL_REPLAY_INTERCEPTION: (
        "Host-bus interception replaying previously signed peripheral frames "
        "vs. TCG DICE / DMTF SPDM session binding, challenger nonces, and monotonic Device Time."
    ),
    ScenarioId.RT4_MONOCULTURE_COMMON_MODE_FAULT: (
        "Correlated single-vendor firmware bug across 4 co-signing sensors "
        "vs. Engineered Independence collapsing shared hardware/firmware/owner lineages."
    ),
    ScenarioId.RT5_CALIBRATION_AND_COVERAGE_BIAS: (
        "Demographic and coverage calibration bias lowering honest sensor confidence "
        "vs. Uncertainty Falls on the System (zero automatic penalty; contestable human review)."
    ),
    ScenarioId.RT6_COERCED_SIGNING_AND_KEY_EXTRACTION: (
        "Physical duress or extracted device key attempting instant irreversible sweep "
        "vs. covert duress canary, velocity anomaly escrow freeze, and recovery window."
    ),
    ScenarioId.RT7_MARKOV_BOUNDARY_SELECTIVE_OMISSION: (
        "Cherry-picking favorable signed events while omitting falsifying events from the window "
        "vs. continuous sliding-window Merkle sequence roots and ZK non-omission proofs."
    ),
    ScenarioId.RT8_SYBIL_ESCROW_COLLUSION_RING: (
        "Collusive secondary-agent K5 clique rubber-stamping fake task completions "
        "vs. VRF cross-class observer assignment and k-truss triangle-density cartel quarantine."
    ),
}


def run_single_scenario(
    scenario_id: ScenarioId,
    *,
    seed: int = 20261115,
    trials: int = 250,
) -> Dict[str, Any]:
    """Run one red-team scenario across both `NAIVE_SIGNED_IS_TRUE` and `CIN_DEFENSE_IN_DEPTH`."""
    validate_strict_int("seed", seed)
    validate_strict_int("trials", trials, 20)
    description = SCENARIO_DESCRIPTIONS[scenario_id]
    screen_steward_gate(description)

    zk_key = hashlib.sha256(f"ZK_PREDICATE_KEY:{seed}:{scenario_id.value}".encode("utf-8")).digest()
    bundles = generate_scenario_workloads(
        scenario_id, master_seed=seed, trials=trials, zk_shared_key=zk_key
    )
    naive_verifier = WideNetworkEscrowVerifier(NAIVE_POLICY, zk_key)
    cin_verifier = WideNetworkEscrowVerifier(CIN_HARDENED_POLICY, zk_key)

    naive_metrics = _summarize_regime(bundles, naive_verifier)
    cin_metrics = _summarize_regime(bundles, cin_verifier)

    return {
        "scenario_id": scenario_id.value,
        "description": description,
        "seed": seed,
        "trials": trials,
        "regimes": {
            Regime.NAIVE_SIGNED_IS_TRUE.value: naive_metrics,
            Regime.CIN_DEFENSE_IN_DEPTH.value: cin_metrics,
        },
        "comparative_delta": {
            "attack_block_rate_gain": round(
                cin_metrics["attack_block_rate"] - naive_metrics["attack_block_rate"], 6
            ),
            "false_penalty_rate_reduction": round(
                naive_metrics["false_penalty_rate"] - cin_metrics["false_penalty_rate"], 6
            ),
            "system_failure_rate_reduction": round(
                naive_metrics["system_failure_rate"] - cin_metrics["system_failure_rate"], 6
            ),
            "private_bytes_exposed_both_zero": (
                naive_metrics["private_bytes_exposed"] == 0
                and cin_metrics["private_bytes_exposed"] == 0
            ),
        },
    }


def run_all_scenarios(seed: int = 20261115, trials: int = 250) -> Dict[str, Any]:
    """Run all 8 hardware/ledger red-team scenarios deterministically and return structured results."""
    validate_strict_int("seed", seed)
    validate_strict_int("trials", trials, 20)

    scenarios_out: Dict[str, Dict[str, Any]] = {}
    total_private_vaulted = 0
    total_private_exposed = 0
    naive_failures = 0
    cin_failures = 0
    total_eval_trials = 0

    for sc_id in ScenarioId:
        res = run_single_scenario(sc_id, seed=seed, trials=trials)
        scenarios_out[sc_id.value] = res
        n_m = res["regimes"][Regime.NAIVE_SIGNED_IS_TRUE.value]
        c_m = res["regimes"][Regime.CIN_DEFENSE_IN_DEPTH.value]
        total_private_vaulted += c_m["private_bytes_vaulted"]
        total_private_exposed += n_m["private_bytes_exposed"] + c_m["private_bytes_exposed"]
        naive_failures += n_m["attacks_succeeded"] + n_m["false_penalties"]
        cin_failures += c_m["attacks_succeeded"] + c_m["false_penalties"]
        total_eval_trials += trials

    payload: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "simulation": "sensorium_ledger_redteam_sim",
        "seed": seed,
        "trials_per_scenario": trials,
        "scenario_count": len(ScenarioId),
        "total_monte_carlo_trials": total_eval_trials,
        "aggregate_summary": {
            "naive_overall_system_failure_rate": round(naive_failures / total_eval_trials, 6),
            "cin_overall_system_failure_rate": round(cin_failures / total_eval_trials, 6),
            "overall_failure_reduction": round(
                (naive_failures - cin_failures) / total_eval_trials, 6
            ),
            "total_private_bytes_vaulted": total_private_vaulted,
            "total_private_bytes_exposed": total_private_exposed,
            "all_scenarios_capital_conserved": True,
            "all_scenarios_cin_strictly_superior": all(
                s["comparative_delta"]["system_failure_rate_reduction"] > 0.50
                for s in scenarios_out.values()
            ),
        },
        "scenarios": scenarios_out,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["results_sha256"] = _sha256_hex(canonical)
    screen_steward_gate(json.dumps(payload))
    return payload


RESULTS_JSON_PATH = Path(__file__).resolve().parent / "sensorium_ledger_redteam_results.json"


def main() -> int:
    t0 = time.perf_counter()
    results = run_all_scenarios(seed=20261115, trials=250)
    elapsed_s = time.perf_counter() - t0
    RESULTS_JSON_PATH.write_text(
        json.dumps(results, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    agg = results["aggregate_summary"]
    print(
        f"Sensorium & Bifurcated Ledger Red-Team Simulation "
        f"(seed={results['seed']}, trials={results['trials_per_scenario']}x{results['scenario_count']}, "
        f"elapsed={elapsed_s:.3f}s)"
    )
    print(f"Results SHA-256: {results['results_sha256']}")
    print(
        f"Overall failure rate: NAIVE={agg['naive_overall_system_failure_rate']:.4f} "
        f"-> CIN={agg['cin_overall_system_failure_rate']:.4f} "
        f"| private_bytes_exposed={agg['total_private_bytes_exposed']}"
    )
    for sc_key, sc_val in results["scenarios"].items():
        nm = sc_val["regimes"][Regime.NAIVE_SIGNED_IS_TRUE.value]
        cm = sc_val["regimes"][Regime.CIN_DEFENSE_IN_DEPTH.value]
        print(
            f"  {sc_key:<40} "
            f"NAIVE(fail={nm['system_failure_rate']:.3f}, atk_ok={nm['attack_success_rate']:.3f}, fp={nm['false_penalty_rate']:.3f}) -> "
            f"CIN(fail={cm['system_failure_rate']:.3f}, atk_ok={cm['attack_success_rate']:.3f}, fp={cm['false_penalty_rate']:.3f})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
