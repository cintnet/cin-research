"""
Universal Human Modality Bridge (`modality_bridge.py`).

Provides a domain-agnostic bidirectional compiler between a human's cognitive &
operational modality and the formal system operations on the Agent-Web Ledger:

  - Universal `CognitiveModality` modes (applicable across engineering, logistics,
    agriculture, healthcare, software, and civic coordination):
      1. `VISUAL_SYSTEM_TOPOLOGY`: Spatial layouts, flow diagrams, component maps.
      2. `STEPWISE_OPERATIONAL_RUNBOOK`: Sequential SOPs, checklists, timed triggers.
      3. `CAUSAL_DECISION_MATRIX`: Counterfactual if-then trees, risk/benefit tables.
      4. `INTERACTIVE_SIMULATION_SANDBOX`: Parameter sliders and sensitivity previews.
      5. `NARRATIVE_ANALOGY_BRIEF`: Plain-language mental models & representative cases.

  - Upward (`compile_human_intent`): Translates a human's lived problem and world
    context into a structured `IntentSpec` for the Agent Web.
  - Downward (`render_for_human`): Translates a verified `CapabilityArtifact` and
    `DataStreamContract` into a `HumanModalityView` tailored to the human's
    `CognitiveProfile`—foregrounding the core mechanism, safety preconditions,
    and actionable controls while keeping machine-verified implementation details
    in an inspectable background layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

from .agent_web_ledger import CapabilityArtifact, DataStreamContract
from .session_isolation import ActorRole, SessionIsolationGuard


class CognitiveModality(str, Enum):
    VISUAL_SYSTEM_TOPOLOGY = "visual_system_topology"
    STEPWISE_OPERATIONAL_RUNBOOK = "stepwise_operational_runbook"
    CAUSAL_DECISION_MATRIX = "causal_decision_matrix"
    INTERACTIVE_SIMULATION_SANDBOX = "interactive_simulation_sandbox"
    NARRATIVE_ANALOGY_BRIEF = "narrative_analogy_brief"


@dataclass
class CognitiveProfile:
    """General-purpose profile of how a specific human prefers to perceive and act."""

    human_name: str
    role_summary: str
    primary_modality: CognitiveModality
    secondary_modality: CognitiveModality = CognitiveModality.NARRATIVE_ANALOGY_BRIEF
    preferred_vocabulary: List[str] = field(default_factory=list)


@dataclass
class IntentSpec:
    """Universal structured intent extracted by a personal agent from its human."""

    campaign_id: str
    domain: str
    world_signal_context: str
    human_problem_statement: str
    preferred_modality: CognitiveModality
    available_state_vars: List[str]
    target_guarantees: List[str]


@dataclass
class HumanModalityView:
    """
    Universal human-compatible rendering compiled from a verified `CapabilityArtifact`
    and `DataStreamContract`. Applicable to any operational domain.
    """

    campaign_id: str
    target_human_name: str
    rendered_modality: CognitiveModality
    core_mechanism_headline: str
    representative_case_explanation: str
    safety_precondition_gates: List[str]
    actionable_operational_controls: List[str]
    verified_background_operations: List[str]
    modality_artifact_preview: str


class ModalityBridge:
    """Domain-agnostic semantic compiler between Human Modalities and Agent-Web Operations."""

    def __init__(self, guard: SessionIsolationGuard) -> None:
        self.guard = guard

    def compile_human_intent(
        self,
        human_role: ActorRole,
        agent_role: ActorRole,
        campaign_id: str,
        domain: str,
        world_signal_context: str,
        human_problem_statement: str,
        profile: CognitiveProfile,
        available_state_vars: List[str],
        target_guarantees: List[str],
    ) -> IntentSpec:
        """Personal agent listens to its human's lived problem and compiles an IntentSpec."""
        self.guard.assert_direct_channel(
            human_role, agent_role, "compile_human_intent"
        )
        return IntentSpec(
            campaign_id=campaign_id,
            domain=domain,
            world_signal_context=world_signal_context,
            human_problem_statement=human_problem_statement,
            preferred_modality=profile.primary_modality,
            available_state_vars=available_state_vars,
            target_guarantees=target_guarantees,
        )

    def render_for_human(
        self,
        agent_role: ActorRole,
        human_role: ActorRole,
        campaign_id: str,
        profile: CognitiveProfile,
        artifact: CapabilityArtifact,
        stream: DataStreamContract,
        actionable_controls: List[str],
        modality_preview: str,
    ) -> HumanModalityView:
        """
        Compiles a verified `CapabilityArtifact` and `DataStreamContract` into the
        human's preferred `CognitiveModality`, surfacing top-level safety precondition
        gates, why the solution works, and how to operate it.
        """
        self.guard.assert_direct_channel(
            agent_role, human_role, f"render_for_human:{profile.primary_modality.value}"
        )
        safety_gates = [
            f"Safety & validity gate: {pre}" for pre in artifact.interface.preconditions
        ]
        verified_bg = [
            f"Capability '{artifact.artifact_id}' ({artifact.kind.value}): {artifact.implementation_summary} [Verified: {artifact.verification_hash}]",
            f"Outcome guarantees proven: {'; '.join(artifact.interface.guarantees)}",
            f"Data stream '{stream.title}' ({stream.record_count} records) attested [{stream.attestation_hash}]",
        ]
        return HumanModalityView(
            campaign_id=campaign_id,
            target_human_name=profile.human_name,
            rendered_modality=profile.primary_modality,
            core_mechanism_headline=artifact.core_thesis,
            representative_case_explanation=(
                f"Operational validation: Calibrated against {stream.record_count} verified records "
                f"from '{stream.title}' ({stream.stream_id}), '{artifact.title}' satisfies "
                f"{', '.join(artifact.interface.guarantees)} whenever {artifact.interface.preconditions[0]}."
            ),
            safety_precondition_gates=safety_gates,
            actionable_operational_controls=actionable_controls,
            verified_background_operations=verified_bg,
            modality_artifact_preview=modality_preview,
        )
