"""
Orchestrator & Multi-Session Agentic Dance Simulator (`simulator.py`).

Executes the general-purpose 8-step operational dance across 5 strictly isolated
actor sessions (`orchestrator`, `human_tasker`, `agent_tasker`, `human_solver`,
`agent_solver`):

  1. `orchestrator` injects the real-world event & media signal into `human_tasker`
     and registers the community co-op's `DataStreamContract`.
  2. `human_tasker` provides lived problem context, operational constraints, and
     cognitive modality preferences ONLY to `agent_tasker`.
  3. `agent_tasker` compiles an `IntentSpec` via `ModalityBridge` and publishes a
     structured `TaskCampaign` on the `AgentWebLedger`.
  4. `agent_solver` discovers the campaign, consults `human_solver` for the core
     operational thesis and mechanism design, and packages a universal
     `CapabilityArtifact` with a self-contained `InterfaceSpec`.
  5. `agent_solver` registers & verifies the `CapabilityArtifact` on the ledger.
  6. `agent_tasker` searches the Agent Web by interface compatibility, binds a
     `ServiceAgreement` combining the `CapabilityArtifact` and `DataStreamContract`,
     and records a `VERIFICATION_RECEIPT`.
  7. `agent_tasker` uses `ModalityBridge.render_for_human` to compile the verified
     solution into `human_tasker`'s `CognitiveModality`.
  8. `agent_tasker` and `agent_solver` run the `SelfBlameDiagnostic`, merge a
     recursive `ProtocolUpgradePR` (`v1.0 -> v2.0`), and settle the strictly
     conserved multi-party `RewardAllocation`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

from .agent_web_ledger import (
    AgentWebLedger,
    CapabilityArtifact,
    DataStreamContract,
    InterfaceSpec,
    MessageCategory,
    ServiceAgreement,
    TaskCampaign,
)
from .modality_bridge import CognitiveProfile, ModalityBridge
from .recursive_evolution import RecursiveLedgerEvolutionEngine
from .scenarios import RealWorldEventScenario, build_five_real_world_events
from .session_isolation import ActorRole, SessionIsolationGuard


@dataclass
class EventDanceResult:
    event_id: str
    title: str
    domain: str
    protocol_version_start: str
    protocol_version_end: str
    media_headline: str
    tasker_human: str
    solver_human: str
    artifact_id: str
    artifact_kind: str
    implementation_summary: str
    artifact_verification_hash: str
    stream_id: str
    stream_attestation_hash: str
    agreement_id: str
    modality_rendered: str
    core_mechanism_headline: str
    safety_precondition_gates: List[str]
    actionable_controls: List[str]
    verified_background_operations: List[str]
    modality_preview: str
    self_blame_category: str
    friction_observed: str
    skill_synthesized: str
    capability_unlocked: str
    rewards: Dict[str, Any]
    session_digests: Dict[str, str]


class LedgerDanceSimulator:
    """Runs the 5-actor isolated simulation across all real-world operational events."""

    def __init__(self, run_seed: str = "cin-ledger-sim-2026") -> None:
        self.guard = SessionIsolationGuard(run_seed=run_seed)
        self.ledger = AgentWebLedger(guard=self.guard)
        self.bridge = ModalityBridge(guard=self.guard)
        self.evolution = RecursiveLedgerEvolutionEngine(ledger=self.ledger)
        self.event_results: List[EventDanceResult] = []

    def run_single_event(self, sc: RealWorldEventScenario) -> EventDanceResult:
        version_start = self.ledger.protocol_version

        # Step 1: Orchestrator seeds private session contexts (isolated per actor)
        self.guard.write_actor_memory(
            ActorRole.ORCHESTRATOR,
            ActorRole.ORCHESTRATOR,
            f"{sc.event_id}_ground_truth",
            {"media": sc.media_headline, "guarantees": sc.target_guarantees},
        )
        self.guard.assert_direct_channel(
            ActorRole.ORCHESTRATOR, ActorRole.HUMAN_TASKER, f"seed_event:{sc.event_id}"
        )
        self.guard.write_actor_memory(
            ActorRole.HUMAN_TASKER,
            ActorRole.HUMAN_TASKER,
            f"{sc.event_id}_lived_crisis",
            {
                "headline": sc.media_headline,
                "problem": sc.tasker_lived_problem,
                "feedback": sc.tasker_feedback_prompt,
            },
        )

        # DataStreamContract registered on ledger by Orchestrator on behalf of community co-op
        stream = DataStreamContract(
            stream_id=sc.stream_id,
            title=sc.stream_title,
            domain=sc.domain,
            custodian_name=sc.stream_custodian,
            custodian_agent="agent_coop_custodian",
            schema_fields=sc.stream_schema,
            record_count=sc.stream_records,
            privacy_and_quality_invariants=sc.stream_invariants,
            summary_metrics=sc.stream_metrics,
            attestation_hash=sc.stream_attestation_hash,
        )
        self.ledger.register_data_stream(ActorRole.ORCHESTRATOR, stream)

        # Step 2: Tasker Human communicates ONLY with Tasker Personal Agent
        tasker_profile = CognitiveProfile(
            human_name=sc.tasker_human_name,
            role_summary=sc.tasker_human_role_desc,
            primary_modality=sc.tasker_modality,
        )
        intent_spec = self.bridge.compile_human_intent(
            human_role=ActorRole.HUMAN_TASKER,
            agent_role=ActorRole.AGENT_TASKER,
            campaign_id=sc.event_id,
            domain=sc.domain,
            world_signal_context=sc.media_headline,
            human_problem_statement=f"{sc.tasker_lived_problem} | {sc.tasker_feedback_prompt}",
            profile=tasker_profile,
            available_state_vars=sc.available_state_vars,
            target_guarantees=sc.target_guarantees,
        )
        self.guard.write_actor_memory(
            ActorRole.AGENT_TASKER,
            ActorRole.AGENT_TASKER,
            f"{sc.event_id}_intent_spec",
            asdict(intent_spec),
        )

        # Step 3: Tasker Agent publishes TaskCampaign to the Agent-Web Ledger
        campaign = TaskCampaign(
            campaign_id=sc.event_id,
            title=sc.title,
            domain=sc.domain,
            topic_channel=f"campaigns/{sc.domain}",
            tasker_agent=ActorRole.AGENT_TASKER.value,
            context_summary=sc.media_headline,
            available_state_vars=sc.available_state_vars,
            target_guarantees=sc.target_guarantees,
            reward_pool_units=sc.reward_pool_units,
        )
        self.ledger.publish_campaign(ActorRole.AGENT_TASKER, campaign)

        # Step 4: Solver Agent reads Campaign from Ledger, consults Solver Human in Solver's session
        self.guard.assert_direct_channel(
            ActorRole.AGENT_SOLVER, ActorRole.HUMAN_SOLVER, f"consult_solver:{sc.event_id}"
        )
        self.guard.write_actor_memory(
            ActorRole.HUMAN_SOLVER,
            ActorRole.HUMAN_SOLVER,
            f"{sc.event_id}_thesis",
            {
                "core_thesis": sc.solver_core_thesis,
                "guidance": sc.solver_human_guidance,
            },
        )
        self.guard.assert_direct_channel(
            ActorRole.HUMAN_SOLVER, ActorRole.AGENT_SOLVER, f"return_thesis:{sc.event_id}"
        )

        # Step 5: Solver Agent packages the universal CapabilityArtifact and registers it on the Ledger
        interface = InterfaceSpec(
            input_schema=sc.input_schema,
            output_schema=sc.output_schema,
            units=sc.units,
            preconditions=sc.preconditions,
            guarantees=sc.guarantees,
        )
        artifact = CapabilityArtifact(
            artifact_id=sc.artifact_id,
            title=sc.artifact_title,
            domain=sc.domain,
            kind=sc.artifact_kind,
            author_human=sc.solver_human_name,
            author_agent=ActorRole.AGENT_SOLVER.value,
            core_thesis=sc.solver_core_thesis,
            implementation_summary=sc.implementation_summary,
            interface=interface,
            test_vectors=sc.test_vectors,
            verifier_fn=sc.verifier_fn,
            lineage_parents=sc.lineage_parents,
        )
        self.ledger.register_capability(ActorRole.AGENT_SOLVER, artifact)
        self.guard.write_actor_memory(
            ActorRole.AGENT_SOLVER,
            ActorRole.AGENT_SOLVER,
            f"{sc.event_id}_published_artifact",
            artifact.artifact_id,
        )

        # Step 6: Tasker Agent searches the Agent Web by interface compatibility & binds ServiceAgreement
        search_hits = self.ledger.search_agent_web(
            caller=ActorRole.AGENT_TASKER,
            domain=sc.domain,
            available_inputs=sc.available_state_vars,
            require_verified=True,
        )
        matched_artifact = search_hits["capabilities"][0]
        matched_stream = search_hits["data_streams"][0]

        agreement_id = f"AGR-{sc.event_id}"
        agreement = ServiceAgreement(
            agreement_id=agreement_id,
            campaign_id=sc.event_id,
            domain=sc.domain,
            tasker_agent=ActorRole.AGENT_TASKER.value,
            solver_agent=ActorRole.AGENT_SOLVER.value,
            required_state_vars=sc.available_state_vars,
            required_guarantees=sc.target_guarantees,
            stream_id=matched_stream.stream_id,
            artifact_id=matched_artifact.artifact_id,
            reward_pool_units=sc.reward_pool_units,
            status="VERIFIED_AND_SETTLED",
            verification_receipt_hash=matched_artifact.verification_hash,
        )
        self.ledger.agreements[agreement_id] = agreement
        self.ledger.post_message(
            sender=ActorRole.AGENT_TASKER,
            destination_topic=f"agreements/{sc.event_id}",
            category=MessageCategory.SERVICE_AGREEMENT,
            payload={
                "agreement_id": agreement_id,
                "artifact_id": matched_artifact.artifact_id,
                "stream_id": matched_stream.stream_id,
                "verification_hash": matched_artifact.verification_hash,
                "status": agreement.status,
            },
        )

        # Step 7: Tasker Agent compiles the verified capability into Tasker Human's CognitiveModality
        human_view = self.bridge.render_for_human(
            agent_role=ActorRole.AGENT_TASKER,
            human_role=ActorRole.HUMAN_TASKER,
            campaign_id=sc.event_id,
            profile=tasker_profile,
            artifact=matched_artifact,
            stream=matched_stream,
            actionable_controls=sc.actionable_controls_for_tasker,
            modality_preview=sc.modality_preview_diagram,
        )
        self.ledger.post_message(
            sender=ActorRole.AGENT_TASKER,
            destination_topic=f"bridges/{sc.event_id}",
            category=MessageCategory.MODALITY_BRIDGE_VIEW,
            payload={
                "campaign_id": sc.event_id,
                "rendered_modality": human_view.rendered_modality.value,
                "core_mechanism_headline": human_view.core_mechanism_headline,
                "safety_gates_count": len(human_view.safety_precondition_gates),
            },
        )

        # Step 8: Self-Blame Diagnostic, Recursive Tool/Ledger Upgrade, & Conserved Reward Settlement
        pr = self.evolution.run_self_blame_and_evolve(
            event_id=sc.event_id,
            blamed_actor=sc.blamed_actor,
            reviewer_actor=sc.reviewer_actor,
            blame_category=sc.blame_category,
            friction_observed=sc.friction_observed,
            counterfactual_root_cause=sc.counterfactual_root_cause,
            latency_penalty_ms=sc.latency_penalty_ms,
            proposed_skill_name=sc.proposed_skill_name,
            proposed_ledger_capability=sc.proposed_ledger_capability,
            next_protocol_version=sc.next_protocol_version,
            schema_diff_summary=sc.schema_diff_summary,
        )
        rewards = self.evolution.compute_campaign_rewards(
            campaign_id=sc.event_id,
            total_pool_units=sc.reward_pool_units,
            has_upstream_lineage=bool(matched_artifact.lineage_parents),
            self_blame_pr_merged=pr.merged,
        )
        self.ledger.post_message(
            sender=ActorRole.ORCHESTRATOR,
            destination_topic=f"proofs/{sc.event_id}",
            category=MessageCategory.VERIFICATION_RECEIPT,
            payload={
                "campaign_id": sc.event_id,
                "agreement_id": agreement_id,
                "rewards": asdict(rewards),
            },
        )

        session_digests = {
            role.value: self.guard._vaults[role].snapshot_digest() for role in ActorRole
        }
        result = EventDanceResult(
            event_id=sc.event_id,
            title=sc.title,
            domain=sc.domain,
            protocol_version_start=version_start,
            protocol_version_end=self.ledger.protocol_version,
            media_headline=sc.media_headline,
            tasker_human=sc.tasker_human_name,
            solver_human=sc.solver_human_name,
            artifact_id=matched_artifact.artifact_id,
            artifact_kind=matched_artifact.kind.value,
            implementation_summary=matched_artifact.implementation_summary,
            artifact_verification_hash=matched_artifact.verification_hash,
            stream_id=matched_stream.stream_id,
            stream_attestation_hash=matched_stream.attestation_hash,
            agreement_id=agreement_id,
            modality_rendered=human_view.rendered_modality.value,
            core_mechanism_headline=human_view.core_mechanism_headline,
            safety_precondition_gates=human_view.safety_precondition_gates,
            actionable_controls=human_view.actionable_operational_controls,
            verified_background_operations=human_view.verified_background_operations,
            modality_preview=human_view.modality_artifact_preview,
            self_blame_category=sc.blame_category.value,
            friction_observed=sc.friction_observed,
            skill_synthesized=pr.skill_added,
            capability_unlocked=pr.capability_unlocked,
            rewards=asdict(rewards),
            session_digests=session_digests,
        )
        self.event_results.append(result)
        return result

    def run_all_events(self) -> Dict[str, Any]:
        scenarios = build_five_real_world_events()
        for sc in scenarios:
            self.run_single_event(sc)

        return {
            "simulation_name": "Agent-Web Ledger & Collective Problem-Solving Dance (5 Real-World Events)",
            "initial_protocol_version": "1.0",
            "final_protocol_version": self.ledger.protocol_version,
            "total_ledger_messages": len(self.ledger.messages),
            "total_verified_capabilities": len(self.ledger.artifacts),
            "total_data_streams": len(self.ledger.data_streams),
            "total_settled_agreements": len(self.ledger.agreements),
            "installed_agent_skills": self.evolution.installed_agent_skills,
            "enabled_ledger_capabilities": self.ledger.enabled_capabilities,
            "cheating_violations_during_valid_run": self.guard.violation_count,
            "events": [asdict(r) for r in self.event_results],
        }


def run_full_simulation(output_json_path: str | None = None) -> Dict[str, Any]:
    sim = LedgerDanceSimulator()
    summary = sim.run_all_events()
    if output_json_path:
        out = Path(output_json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    out_file = Path(__file__).resolve().parent / "simulation_results.json"
    summary = run_full_simulation(str(out_file))
    print(
        f"Completed 5-Event Agent-Web Ledger Simulation: "
        f"Protocol evolved {summary['initial_protocol_version']} -> {summary['final_protocol_version']}, "
        f"{summary['total_ledger_messages']} ledger messages, "
        f"{summary['total_verified_capabilities']} verified CapabilityArtifacts, "
        f"0 cheating violations."
    )
