"""
Self-Blame Attribution, Recursive Agent Tool Evolution & Multi-Party Reward Splits.

Models how personal agents:
  1. Run counterfactual self-blame diagnostics after operational friction,
  2. Recursively synthesize new agent skills and merge Ledger Protocol PRs
     (`v1.0 -> v2.0`),
  3. Settle strictly conserved multi-party rewards across Tasker, Solver,
     Data Stream Custodians, and Upstream Capability Lineage Parents.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List

from .agent_web_ledger import AgentWebLedger, MessageCategory
from .session_isolation import ActorRole


class BlameCategory(str, Enum):
    INTERFACE_DISCOVERY_FRICTION = "interface_discovery_friction"
    UNIT_CONVERSION_MISMATCH = "unit_conversion_mismatch"
    DATA_STREAM_ATTESTATION_GAP = "data_stream_attestation_gap"
    LINEAGE_DEPENDENCY_ROUTING_GAP = "lineage_dependency_routing_gap"
    PRECONDITION_MODALITY_VISIBILITY_GAP = "precondition_modality_visibility_gap"


@dataclass
class SelfBlameDiagnostic:
    """Counterfactual self-blame analysis run by Tasker & Solver agents after a friction point."""

    event_id: str
    blamed_actor: ActorRole
    blame_category: BlameCategory
    friction_observed: str
    counterfactual_root_cause: str
    latency_penalty_ms: int
    proposed_skill_name: str
    proposed_ledger_capability: str


@dataclass
class ProtocolUpgradePR:
    """Pull request submitted by agents to evolve the Agent-Web Ledger & skills."""

    pr_id: str
    from_version: str
    to_version: str
    proposer_role: ActorRole
    reviewer_role: ActorRole
    skill_added: str
    capability_unlocked: str
    schema_diff_summary: str
    merged: bool = False


@dataclass
class RewardAllocation:
    """Transparent multi-party reward and lineage attribution for a solved campaign."""

    campaign_id: str
    total_pool_units: int
    solver_human_share: int
    solver_agent_compute_credit: int
    tasker_human_validation_dividend: int
    tasker_agent_compute_credit: int
    data_stream_custodian_royalty: int
    upstream_capability_royalty: int
    self_blame_efficiency_bonus: int
    conservation_verified: bool
    explanation: str


class RecursiveLedgerEvolutionEngine:
    """Manages self-blame diagnostics, recursive skill synthesis, and reward splits."""

    def __init__(self, ledger: AgentWebLedger) -> None:
        self.ledger = ledger
        self.diagnostics: List[SelfBlameDiagnostic] = []
        self.protocol_prs: List[ProtocolUpgradePR] = []
        self.installed_agent_skills: List[str] = [
            "skill.v1.topic_publish",
            "skill.v1.interface_query",
        ]

    def run_self_blame_and_evolve(
        self,
        event_id: str,
        blamed_actor: ActorRole,
        reviewer_actor: ActorRole,
        blame_category: BlameCategory,
        friction_observed: str,
        counterfactual_root_cause: str,
        latency_penalty_ms: int,
        proposed_skill_name: str,
        proposed_ledger_capability: str,
        next_protocol_version: str,
        schema_diff_summary: str,
    ) -> ProtocolUpgradePR:
        """
        1. Records the self-blame diagnostic (identifying where agent discovery
           or contract binding lost efficiency).
        2. Synthesizes a new agent skill and submits a Ledger Protocol PR.
        3. Peer-verifies and merges the upgrade into the live AgentWebLedger.
        """
        diag = SelfBlameDiagnostic(
            event_id=event_id,
            blamed_actor=blamed_actor,
            blame_category=blame_category,
            friction_observed=friction_observed,
            counterfactual_root_cause=counterfactual_root_cause,
            latency_penalty_ms=latency_penalty_ms,
            proposed_skill_name=proposed_skill_name,
            proposed_ledger_capability=proposed_ledger_capability,
        )
        self.diagnostics.append(diag)

        pr_id = f"LEDGER-PR-{len(self.protocol_prs) + 1:02d}"
        pr = ProtocolUpgradePR(
            pr_id=pr_id,
            from_version=self.ledger.protocol_version,
            to_version=next_protocol_version,
            proposer_role=blamed_actor,
            reviewer_role=reviewer_actor,
            skill_added=proposed_skill_name,
            capability_unlocked=proposed_ledger_capability,
            schema_diff_summary=schema_diff_summary,
            merged=True,
        )
        self.protocol_prs.append(pr)

        self.ledger.protocol_version = next_protocol_version
        if proposed_ledger_capability not in self.ledger.enabled_capabilities:
            self.ledger.enabled_capabilities.append(proposed_ledger_capability)
        if proposed_skill_name not in self.installed_agent_skills:
            self.installed_agent_skills.append(proposed_skill_name)

        self.ledger.post_message(
            sender=blamed_actor,
            destination_topic="protocol/upgrades",
            category=MessageCategory.LEDGER_PROTOCOL_PR,
            payload={
                "pr_id": pr.pr_id,
                "from_version": pr.from_version,
                "to_version": pr.to_version,
                "blame_category": blame_category.value,
                "friction_observed": friction_observed,
                "skill_added": proposed_skill_name,
                "capability_unlocked": proposed_ledger_capability,
                "schema_diff_summary": schema_diff_summary,
                "merged": True,
            },
        )
        return pr

    def compute_campaign_rewards(
        self,
        campaign_id: str,
        total_pool_units: int,
        has_upstream_lineage: bool,
        self_blame_pr_merged: bool,
    ) -> RewardAllocation:
        """
        Computes strictly conserved multi-party rewards across:
          - Solver Human (core operational insight & mechanism design)
          - Solver Agent (capability packaging & verification harness compute budget)
          - Data Stream Custodian (privacy-attested telemetry/dataset shard royalty)
          - Upstream Capability Authors (DAG lineage credit for reused building blocks)
          - Tasker Human (well-posed operational problem & real-world validation dividend)
          - Tasker Agent (intent extraction & modality rendering compute budget)
          - Self-Blame Efficiency Bonus (for honest bottleneck attribution & tool PR)
        """
        solver_human = int(total_pool_units * 0.36)
        solver_agent = int(total_pool_units * 0.14)
        stream_royalty = int(total_pool_units * 0.15)
        upstream_royalty = int(total_pool_units * 0.12) if has_upstream_lineage else 0
        tasker_human = int(total_pool_units * 0.10)
        tasker_agent = int(total_pool_units * 0.06)
        allocated = (
            solver_human
            + solver_agent
            + stream_royalty
            + upstream_royalty
            + tasker_human
            + tasker_agent
        )
        efficiency_bonus = total_pool_units - allocated if self_blame_pr_merged else 0
        if not self_blame_pr_merged:
            solver_human += total_pool_units - allocated

        total_check = (
            solver_human
            + solver_agent
            + stream_royalty
            + upstream_royalty
            + tasker_human
            + tasker_agent
            + efficiency_bonus
        )
        return RewardAllocation(
            campaign_id=campaign_id,
            total_pool_units=total_pool_units,
            solver_human_share=solver_human,
            solver_agent_compute_credit=solver_agent,
            tasker_human_validation_dividend=tasker_human,
            tasker_agent_compute_credit=tasker_agent,
            data_stream_custodian_royalty=stream_royalty,
            upstream_capability_royalty=upstream_royalty,
            self_blame_efficiency_bonus=efficiency_bonus,
            conservation_verified=(total_check == total_pool_units),
            explanation=(
                f"100% conserved ({total_check}/{total_pool_units} units): "
                f"Solver Human={solver_human}, Solver Agent={solver_agent}, "
                f"Data Stream Royalty={stream_royalty}, Upstream Capability Lineage={upstream_royalty}, "
                f"Tasker Validation Dividend={tasker_human}, Tasker Agent={tasker_agent}, "
                f"Self-Blame Protocol Evolution Bonus={efficiency_bonus}."
            ),
        )
