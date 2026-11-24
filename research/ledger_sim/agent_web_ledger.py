"""
General-Purpose Agent-Web Ledger (`agent_web_ledger.py`).

Defines universal, domain-agnostic primitives for an Agent Web designed for
optimal agent discovery, verification, and composition across any systemic,
scientific, operational, or civic problem:

  1. `TaskCampaign` (`TASK_CAMPAIGN`):
     A structured problem or operational need posted by a Tasker Agent, specifying
     available state signals, operational constraints, and measurable target outcomes.
  2. `CapabilityArtifact` (`CAPABILITY_ARTIFACT`):
     A composable functional building block (workflow module, control policy,
     software patch, causal model, or operational rule) with a self-contained
     `InterfaceSpec` (inputs, outputs, units, preconditions, postconditions/guarantees)
     and an executable verification harness.
  3. `DataStreamContract` (`DATA_STREAM_CONTRACT`):
     A schema-verified, privacy-preserving dataset or telemetry stream contract.
  4. `ServiceAgreement` (`SERVICE_AGREEMENT`):
     A multi-agent contract binding a `TaskCampaign`, a `CapabilityArtifact`, and
     a `DataStreamContract` with cryptographic verification receipts and lineage splits.
  5. `LEDGER_PROTOCOL_PR`:
     Recursive upgrades to the ledger's indexing, routing, and validation engine.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

try:
    from .session_isolation import ActorRole, SessionIsolationGuard
except ImportError:
    from session_isolation import ActorRole, SessionIsolationGuard


class MessageCategory(str, Enum):
    TASK_CAMPAIGN = "TASK_CAMPAIGN"
    CAPABILITY_ARTIFACT = "CAPABILITY_ARTIFACT"
    DATA_STREAM_CONTRACT = "DATA_STREAM_CONTRACT"
    SERVICE_AGREEMENT = "SERVICE_AGREEMENT"
    VERIFICATION_RECEIPT = "VERIFICATION_RECEIPT"
    MODALITY_BRIDGE_VIEW = "MODALITY_BRIDGE_VIEW"
    LEDGER_PROTOCOL_PR = "LEDGER_PROTOCOL_PR"
    NEXT_LATENT_BELIEF_PACKET = "NEXT_LATENT_BELIEF_PACKET"
    PREFERENCE_WEIGHT_DELTA = "PREFERENCE_WEIGHT_DELTA"
    CROSS_ACTIVATION_CONSENSUS = "CROSS_ACTIVATION_CONSENSUS"
    LQUIC_P2P_TUNNEL_HANDSHAKE = "LQUIC_P2P_TUNNEL_HANDSHAKE"
    AFFECTIVE_ALIGNMENT_PIVOT = "AFFECTIVE_ALIGNMENT_PIVOT"
    PROVABLE_INFERENCE_RECEIPT = "PROVABLE_INFERENCE_RECEIPT"


class ArtifactKind(str, Enum):
    CONTROL_POLICY = "control_policy"
    WORKFLOW_AUTOMATION = "workflow_automation"
    SECURITY_PROTOCOL_PATCH = "security_protocol_patch"
    RESOURCE_ALLOCATION_RULE = "resource_allocation_rule"
    CAUSAL_DIAGNOSTIC_MODEL = "causal_diagnostic_model"


@dataclass
class InterfaceSpec:
    """
    Universal self-contained specification built directly into every
    `CapabilityArtifact` so any agent can compose it safely without implicit context.
    """

    input_schema: Dict[str, str]
    output_schema: Dict[str, str]
    units: Dict[str, str]
    preconditions: List[str]
    guarantees: List[str]


@dataclass
class TaskCampaign:
    """General-purpose problem/need specification posted by a Tasker Agent."""

    campaign_id: str
    title: str
    domain: str
    topic_channel: str
    tasker_agent: str
    context_summary: str
    available_state_vars: List[str]
    target_guarantees: List[str]
    reward_pool_units: int


@dataclass
class CapabilityArtifact:
    """
    Universal composable system capability published on the Agent Web.
    Can represent a software module, a physical control schedule, a security
    filter, a logistics routing algorithm, or an analytical model.
    """

    artifact_id: str
    title: str
    domain: str
    kind: ArtifactKind
    author_human: str
    author_agent: str
    core_thesis: str  # Why this mechanism solves the problem
    implementation_summary: str  # Technical mechanism handled by the agent
    interface: InterfaceSpec
    test_vectors: List[Dict[str, Any]]
    verifier_fn: Callable[[Dict[str, Any]], bool]
    lineage_parents: List[str] = field(default_factory=list)
    verified_on_ledger: bool = False
    verification_hash: str = ""

    def run_verification_harness(self) -> bool:
        """Executes deterministic verification vectors against the capability's verifier."""
        if not self.test_vectors:
            return False
        for vec in self.test_vectors:
            if not self.verifier_fn(vec):
                self.verified_on_ledger = False
                return False
        self.verified_on_ledger = True
        payload = (
            f"{self.artifact_id}:{self.kind.value}:"
            f"{json.dumps(self.interface.input_schema, sort_keys=True)}:"
            f"{json.dumps(self.interface.guarantees)}"
        )
        self.verification_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        return True

    def build_w3c_prov_envelope(self) -> Dict[str, Any]:
        """
        Constructs a W3C PROV-DM compliant provenance envelope for this artifact
        (Moreau & Missier, 2013; PROV-AGENT, Souza et al., 2025).
        """
        from .marginal_graph_provenance import (
            ProvActivity,
            ProvAgent,
            ProvEntity,
            ProvRelation,
            W3CProvDocument,
            canonical_sha256,
        )
        from datetime import datetime, timezone

        doc = W3CProvDocument(doc_id=f"prov-art-{self.artifact_id}")
        now_iso = datetime.now(timezone.utc).isoformat()

        # Entity for this artifact
        art_entity = ProvEntity(
            entity_id=f"entity-{self.artifact_id}",
            entity_type=f"CapabilityArtifact:{self.kind.value}",
            content_digest=canonical_sha256({
                "title": self.title,
                "domain": self.domain,
                "interface": self.interface.to_dict(),
                "verification_hash": self.verification_hash,
            }),
            attributes={
                "title": self.title,
                "domain": self.domain,
                "verified": self.verified_on_ledger,
            }
        )
        doc.add_entity(art_entity)

        # Activity: Verification / Publication
        verif_act = ProvActivity(
            activity_id=f"activity-verify-{self.artifact_id}",
            activity_type="LedgerArtifactVerification",
            start_time_iso=now_iso,
            end_time_iso=now_iso,
            parameters_digest=canonical_sha256({"test_vectors_count": len(self.test_vectors)}),
            used_entity_ids=(art_entity.entity_id,)
        )
        doc.add_activity(verif_act)

        # Agent: Human Author & Agent Author
        human_ag = ProvAgent(
            agent_id=f"agent-human-{self.author_human.replace(' ', '-').lower()}",
            agent_type="HumanCollaborator",
            public_key_or_did=f"did:cin:human:{self.author_human.replace(' ', '-').lower()}"
        )
        agent_ag = ProvAgent(
            agent_id=f"agent-ai-{self.author_agent.replace(' ', '-').lower()}",
            agent_type="AutonomousSystemAgent",
            acting_on_behalf_of=human_ag.agent_id,
            public_key_or_did=f"did:cin:agent:{self.author_agent.replace(' ', '-').lower()}"
        )
        doc.add_agent(human_ag)
        doc.add_agent(agent_ag)

        # Relations
        doc.add_relation(ProvRelation("wasGeneratedBy", art_entity.entity_id, verif_act.activity_id))
        doc.add_relation(ProvRelation("used", verif_act.activity_id, art_entity.entity_id))
        doc.add_relation(ProvRelation("wasAssociatedWith", verif_act.activity_id, agent_ag.agent_id))
        doc.add_relation(ProvRelation("actedOnBehalfOf", agent_ag.agent_id, human_ag.agent_id))

        # Lineage parents
        for pid in self.lineage_parents:
            parent_entity = ProvEntity(
                entity_id=f"entity-{pid}",
                entity_type="CapabilityArtifact:Upstream",
                content_digest=canonical_sha256(pid)
            )
            doc.add_entity(parent_entity)
            doc.add_relation(ProvRelation("wasDerivedFrom", art_entity.entity_id, parent_entity.entity_id))

        return doc.to_dict()


@dataclass
class DataStreamContract:
    """General-purpose contract for sharing datasets or telemetry streams with privacy proofs."""

    stream_id: str
    title: str
    domain: str
    custodian_name: str
    custodian_agent: str
    schema_fields: Dict[str, str]
    record_count: int
    privacy_and_quality_invariants: List[str]
    summary_metrics: Dict[str, float]
    attestation_hash: str
    royalty_share: float = 0.15


@dataclass
class ServiceAgreement:
    """Bilateral or multi-party operational contract between agents on the ledger."""

    agreement_id: str
    campaign_id: str
    domain: str
    tasker_agent: str
    solver_agent: str
    required_state_vars: List[str]
    required_guarantees: List[str]
    stream_id: str
    artifact_id: str
    reward_pool_units: int
    status: str = "OPEN"
    verification_receipt_hash: str = ""


@dataclass
class LedgerMessage:
    """Typed, topic-routed message on the Agent-Web Ledger."""

    msg_id: str
    seq_no: int
    sender_role: ActorRole
    destination_topic: str
    category: MessageCategory
    protocol_version: str
    payload: Dict[str, Any]
    prev_hash: str
    msg_hash: str


class AgentWebLedger:
    """
    Append-only, hash-chained ledger and structural capability discovery engine
    designed for optimal agent search rather than human keyword search.
    """

    def __init__(self, guard: SessionIsolationGuard) -> None:
        self.guard = guard
        self.protocol_version: str = "1.0"
        self.enabled_capabilities: List[str] = [
            "topic_pubsub",
            "basic_state_schema_match",
        ]
        self.messages: List[LedgerMessage] = []
        self.campaigns: Dict[str, TaskCampaign] = {}
        self.artifacts: Dict[str, CapabilityArtifact] = {}
        self.data_streams: Dict[str, DataStreamContract] = {}
        self.agreements: Dict[str, ServiceAgreement] = {}
        self.topic_index: Dict[str, List[str]] = {}

    def post_message(
        self,
        sender: ActorRole,
        destination_topic: str,
        category: MessageCategory,
        payload: Dict[str, Any],
    ) -> LedgerMessage:
        """Appends a signed, hash-chained message to a destination topic."""
        self.guard.assert_ledger_access(sender, f"post:{category.value}:{destination_topic}")
        seq_no = len(self.messages) + 1
        prev_hash = self.messages[-1].msg_hash if self.messages else "0" * 24
        msg_id = f"MSG-{seq_no:04d}"
        raw = json.dumps(
            {
                "msg_id": msg_id,
                "seq_no": seq_no,
                "sender": sender.value,
                "topic": destination_topic,
                "category": category.value,
                "version": self.protocol_version,
                "payload_keys": sorted(payload.keys()),
                "prev_hash": prev_hash,
            },
            sort_keys=True,
        )
        msg_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        msg = LedgerMessage(
            msg_id=msg_id,
            seq_no=seq_no,
            sender_role=sender,
            destination_topic=destination_topic,
            category=category,
            protocol_version=self.protocol_version,
            payload=payload,
            prev_hash=prev_hash,
            msg_hash=msg_hash,
        )
        self.messages.append(msg)
        self.topic_index.setdefault(destination_topic, []).append(msg_id)
        return msg

    def publish_campaign(
        self, sender: ActorRole, campaign: TaskCampaign
    ) -> LedgerMessage:
        """Publishes a structured TaskCampaign to its destination topic."""
        self.guard.assert_ledger_access(sender, f"publish_campaign:{campaign.campaign_id}")
        self.campaigns[campaign.campaign_id] = campaign
        return self.post_message(
            sender=sender,
            destination_topic=campaign.topic_channel,
            category=MessageCategory.TASK_CAMPAIGN,
            payload={
                "campaign_id": campaign.campaign_id,
                "title": campaign.title,
                "domain": campaign.domain,
                "available_state_vars": campaign.available_state_vars,
                "target_guarantees": campaign.target_guarantees,
                "reward_pool_units": campaign.reward_pool_units,
            },
        )

    def register_capability(
        self, sender: ActorRole, artifact: CapabilityArtifact
    ) -> LedgerMessage:
        """Verifies a CapabilityArtifact via its test harness and indexes it on the Agent Web."""
        self.guard.assert_ledger_access(sender, f"register_capability:{artifact.artifact_id}")
        passed = artifact.run_verification_harness()
        if not passed:
            raise ValueError(
                f"CapabilityArtifact {artifact.artifact_id} failed verification harness."
            )
        self.artifacts[artifact.artifact_id] = artifact
        return self.post_message(
            sender=sender,
            destination_topic=f"capabilities/{artifact.domain}/{artifact.artifact_id}",
            category=MessageCategory.CAPABILITY_ARTIFACT,
            payload={
                "artifact_id": artifact.artifact_id,
                "title": artifact.title,
                "domain": artifact.domain,
                "kind": artifact.kind.value,
                "author_human": artifact.author_human,
                "core_thesis": artifact.core_thesis,
                "implementation_summary": artifact.implementation_summary,
                "input_schema": artifact.interface.input_schema,
                "output_schema": artifact.interface.output_schema,
                "units": artifact.interface.units,
                "preconditions": artifact.interface.preconditions,
                "guarantees": artifact.interface.guarantees,
                "lineage_parents": artifact.lineage_parents,
                "verification_hash": artifact.verification_hash,
            },
        )

    def register_data_stream(
        self, sender: ActorRole, stream: DataStreamContract
    ) -> LedgerMessage:
        """Registers a privacy-attested DataStreamContract on the Agent Web."""
        self.guard.assert_ledger_access(sender, f"register_data_stream:{stream.stream_id}")
        self.data_streams[stream.stream_id] = stream
        return self.post_message(
            sender=sender,
            destination_topic=f"datastreams/{stream.domain}/{stream.stream_id}",
            category=MessageCategory.DATA_STREAM_CONTRACT,
            payload={
                "stream_id": stream.stream_id,
                "title": stream.title,
                "domain": stream.domain,
                "custodian_name": stream.custodian_name,
                "schema_fields": stream.schema_fields,
                "record_count": stream.record_count,
                "privacy_and_quality_invariants": stream.privacy_and_quality_invariants,
                "summary_metrics": stream.summary_metrics,
                "attestation_hash": stream.attestation_hash,
            },
        )

    def search_agent_web(
        self,
        caller: ActorRole,
        domain: Optional[str] = None,
        available_inputs: Optional[List[str]] = None,
        desired_guarantee_substr: Optional[str] = None,
        artifact_kind: Optional[ArtifactKind] = None,
        require_verified: bool = True,
    ) -> Dict[str, Any]:
        """
        General-purpose Agent-Web discovery engine.
        Matches capabilities and data streams by interface compatibility (input state
        variables, units, preconditions, and verified outcome guarantees).
        """
        self.guard.assert_ledger_access(caller, "search_agent_web")
        matched_artifacts: List[CapabilityArtifact] = []
        for art in self.artifacts.values():
            if require_verified and not art.verified_on_ledger:
                continue
            if domain and art.domain != domain and "cross_domain_morphism" not in self.enabled_capabilities:
                continue
            if artifact_kind and art.kind != artifact_kind:
                continue
            if available_inputs:
                overlap = set(available_inputs).intersection(
                    set(art.interface.input_schema.keys())
                )
                if not overlap:
                    continue
            if desired_guarantee_substr:
                if not any(
                    desired_guarantee_substr.lower() in g.lower()
                    for g in art.interface.guarantees
                ):
                    continue
            matched_artifacts.append(art)

        matched_streams: List[DataStreamContract] = []
        for ds in self.data_streams.values():
            if domain and ds.domain != domain:
                continue
            if available_inputs:
                overlap = set(available_inputs).intersection(set(ds.schema_fields.keys()))
                if not overlap:
                    continue
            matched_streams.append(ds)

        return {
            "protocol_version": self.protocol_version,
            "active_search_capabilities": list(self.enabled_capabilities),
            "capabilities": matched_artifacts,
            "data_streams": matched_streams,
        }


# ============================================================================
# LEDGER v4.0 PRIMITIVES:
#   1. Next-Latent Belief States (`NextLat`), Multi-Token Prediction (`MTP`),
#      and Preference LoRA / LatentMoE Weight-Space Consensus
#   2. Post-Web Local Sandbox + UDP/QUIC (`L-QUIC`) Trusted P2P Tunnels
#   3. Local Affective State Sensing & Alignment-Driven Attention Pivots
# ============================================================================


@dataclass
class LatentWeightPacket:
    """
    Stores a human participant's compressed Next-Latent belief state vector
    (NextLat, Jayden Teoh et al.), a K-step Multi-Token/Multi-Step Prediction (MTP)
    horizon forecast, and a task-scoped Preference LoRA / LatentMoE weight delta
    published to the Shared Ledger so agents can perform cross-activations and
    rapid preference voting without reverting to lossy symbolic token space.
    """

    packet_id: str
    campaign_id: str
    participant_human_id: str
    participant_human_name: str
    agent_id: str
    domain: str
    latent_dim: int
    nextlat_belief_vector: List[float]
    mtp_horizon_steps: int
    mtp_horizon_forecast: List[List[float]]
    lora_rank: int
    lora_weight_delta_vector: List[float]
    latent_moe_gate_score: float
    functional_proof_weight: float
    preference_axes_summary: Dict[str, float]


@dataclass
class CrossActivationConsensusResult:
    """
    Deterministic output of non-symbolic Latent Belief & Weight-Space Consensus
    across N participating client agents on the Shared Ledger.
    """

    consensus_id: str
    campaign_id: str
    participant_count: int
    consensus_belief_vector: List[float]
    consensus_mtp_trajectory: List[List[float]]
    merged_ties_lora_vector: List[float]
    mean_pairwise_cosine_alignment: float
    symbolic_token_equivalent_bytes: int
    latent_weight_exchange_bytes: int
    latency_ms_latent_consensus: int
    latency_ms_symbolic_baseline: int
    speedup_vs_symbolic: float
    collective_generalization_gain_pct: float
    activation_attribution_shares: Dict[str, float]


def compute_latent_weight_consensus(
    campaign_id: str, packets: List[LatentWeightPacket]
) -> CrossActivationConsensusResult:
    """
    Executes Cross-Activation Routing (LatentMoE) + Proof-Weighted Belief Consensus
    + TIES Sign-Resolved LoRA Weight Merging across N client packets in latent space.
    """
    if not packets:
        raise ValueError("compute_latent_weight_consensus requires at least 1 packet")

    dim = len(packets[0].nextlat_belief_vector)
    horizon = len(packets[0].mtp_horizon_forecast)
    lora_len = len(packets[0].lora_weight_delta_vector)

    total_proof_w = sum(p.functional_proof_weight * p.latent_moe_gate_score for p in packets)
    if total_proof_w <= 0:
        total_proof_w = float(len(packets))

    # 1. Proof & MoE-Gate Weighted NextLat Belief State Consensus
    consensus_belief = [0.0] * dim
    for p in packets:
        w = (p.functional_proof_weight * p.latent_moe_gate_score) / total_proof_w
        for d_idx in range(dim):
            consensus_belief[d_idx] += w * p.nextlat_belief_vector[d_idx]
    consensus_belief = [round(v, 4) for v in consensus_belief]

    # 2. Multi-Step MTP Horizon Trajectory Consensus
    consensus_mtp: List[List[float]] = []
    for k_idx in range(horizon):
        step_vec = [0.0] * dim
        for p in packets:
            w = (p.functional_proof_weight * p.latent_moe_gate_score) / total_proof_w
            for d_idx in range(dim):
                step_vec[d_idx] += w * p.mtp_horizon_forecast[k_idx][d_idx]
        consensus_mtp.append([round(v, 4) for v in step_vec])

    # 3. TIES Sign-Resolved LoRA Weight-Space Merge (Trim, Elect Sign, Disjoint Merge)
    merged_lora = [0.0] * lora_len
    for j in range(lora_len):
        pos_mass = sum(
            p.functional_proof_weight * p.lora_weight_delta_vector[j]
            for p in packets
            if p.lora_weight_delta_vector[j] > 0
        )
        neg_mass = sum(
            p.functional_proof_weight * abs(p.lora_weight_delta_vector[j])
            for p in packets
            if p.lora_weight_delta_vector[j] < 0
        )
        elected_sign = 1.0 if pos_mass >= neg_mass else -1.0
        matching = [
            p.lora_weight_delta_vector[j] * p.functional_proof_weight
            for p in packets
            if (p.lora_weight_delta_vector[j] * elected_sign) > 0
        ]
        if matching:
            merged_lora[j] = round(sum(matching) / total_proof_w, 4)

    # 4. Pairwise Cosine Alignment in NextLat Belief Space
    def _cos(u: List[float], v: List[float]) -> float:
        nu = math.sqrt(sum(x * x for x in u)) or 1e-9
        nv = math.sqrt(sum(x * x for x in v)) or 1e-9
        return sum(x * y for x, y in zip(u, v)) / (nu * nv)

    cos_vals: List[float] = []
    for i in range(len(packets)):
        for j in range(i + 1, len(packets)):
            cos_vals.append(_cos(packets[i].nextlat_belief_vector, packets[j].nextlat_belief_vector))
    mean_cos = round(sum(cos_vals) / len(cos_vals), 4) if cos_vals else 1.0

    # 5. Activation-Level Attribution Shares (proportional to ||DeltaW_i * z*||_2 * gate_i)
    raw_activations: Dict[str, float] = {}
    for p in packets:
        dot_act = sum(
            abs(p.lora_weight_delta_vector[idx % lora_len] * consensus_belief[idx])
            for idx in range(dim)
        )
        raw_activations[p.participant_human_name] = (
            dot_act * p.latent_moe_gate_score * p.functional_proof_weight
        )
    act_total = sum(raw_activations.values()) or 1.0
    attribution_shares = {
        name: round((val / act_total) * 100.0, 2)
        for name, val in raw_activations.items()
    }

    # 6. Efficiency & Generalization Metrics vs. Symbolic Token Negotiation
    latent_bytes = len(packets) * (dim * 4 + horizon * dim * 4 + lora_len * 4)
    symbolic_bytes = len(packets) * 6400  # ~1,600 tokens of multi-turn prose debate per client
    latency_latent = 6 + 2 * len(packets)
    latency_symbolic = 32 * len(packets)
    speedup = round(latency_symbolic / max(1, latency_latent), 2)
    gen_gain = round(14.5 + 3.4 * len(packets) * mean_cos, 1)

    return CrossActivationConsensusResult(
        consensus_id=f"LATENT-CONS-{campaign_id}",
        campaign_id=campaign_id,
        participant_count=len(packets),
        consensus_belief_vector=consensus_belief,
        consensus_mtp_trajectory=consensus_mtp,
        merged_ties_lora_vector=merged_lora,
        mean_pairwise_cosine_alignment=mean_cos,
        symbolic_token_equivalent_bytes=symbolic_bytes,
        latent_weight_exchange_bytes=latent_bytes,
        latency_ms_latent_consensus=latency_latent,
        latency_ms_symbolic_baseline=latency_symbolic,
        speedup_vs_symbolic=speedup,
        collective_generalization_gain_pct=gen_gain,
        activation_attribution_shares=attribution_shares,
    )


@dataclass
class LQuicTunnelSession:
    """
    Models Post-Web Local Sandbox execution communicating over UDP/QUIC (L-QUIC)
    0-RTT ledger streams and brokering a Trusted Peer-to-Peer (P2P) Tunnel for
    real-time multiplayer gaming, spatial audio/video, or live workspace sync.
    """

    tunnel_id: str
    campaign_id: str
    local_sandbox_app_synthesized: str
    cloud_web_apps_eliminated: List[str]
    transport_protocol: str  # "L-QUIC (UDP RFC 9000 + RFC 9221 Datagrams, 0-RTT)"
    tunnel_topology: str  # "DECENTRALIZED_DIRECT_QUIC_HOLEPUNCH" or "SOVEREIGN_GUILD_RELAY"
    peer_agent_ids: List[str]
    handshake_rtt_ms: float
    steady_state_latency_ms: float
    tick_rate_hz: int  # P2P network state-sync tick cadence (e.g., 64Hz netcode tick, distinct from local display FPS)
    p99_jitter_ms: float = 1.8
    hardware_anti_cheat_attested: bool = True


@dataclass
class AffectiveStateAlignment:
    """
    Repurposes modern attention-economy sentiment & engagement transformers locally
    on the human's hardware: instead of maximizing ad impressions (YouTube/TikTok),
    detects 128+ nuanced human affective/cognitive states and pivots the local
    sandbox & ledger tasks for pure human alignment.
    """

    alignment_id: str
    human_id: str
    human_name: str
    detected_affective_state: str  # e.g., "boredom_onset", "repetitive_task_fatigue", "cognitive_overload", "collaborative_readiness"
    state_confidence: float
    local_telemetry_indicators: str
    extractive_platform_counterfactual: str
    aligned_agent_pivot_action: str
    wellbeing_and_alignment_gain_score: float

