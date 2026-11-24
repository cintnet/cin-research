"""
Five Grounded Real-World Operational Scenarios (`scenarios.py`).

Uses the universal, domain-agnostic schema (`TaskCampaign`, `CapabilityArtifact`,
`InterfaceSpec`, `DataStreamContract`, `CognitiveModality`, `CognitiveProfile`)
so the exact same ledger and modality process applies to any operational,
engineering, logistical, agricultural, or healthcare problem.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List

from .agent_web_ledger import ArtifactKind
from .modality_bridge import CognitiveModality
from .recursive_evolution import BlameCategory
from .session_isolation import ActorRole


@dataclass
class RealWorldEventScenario:
    event_id: str
    title: str
    domain: str
    media_headline: str
    media_source_context: str
    # Tasker pair
    tasker_human_name: str
    tasker_human_role_desc: str
    tasker_modality: CognitiveModality
    tasker_lived_problem: str
    tasker_feedback_prompt: str
    available_state_vars: List[str]
    target_guarantees: List[str]
    # Solver pair
    solver_human_name: str
    solver_human_role_desc: str
    solver_modality: CognitiveModality
    solver_core_thesis: str
    solver_human_guidance: str
    # Universal CapabilityArtifact ('Rocket-Part' System Building Block)
    artifact_id: str
    artifact_title: str
    artifact_kind: ArtifactKind
    implementation_summary: str
    input_schema: Dict[str, str]
    output_schema: Dict[str, str]
    units: Dict[str, str]
    preconditions: List[str]
    guarantees: List[str]
    test_vectors: List[Dict[str, Any]]
    verifier_fn: Callable[[Dict[str, Any]], bool]
    lineage_parents: List[str]
    # Universal DataStreamContract
    stream_id: str
    stream_title: str
    stream_custodian: str
    stream_schema: Dict[str, str]
    stream_records: int
    stream_invariants: List[str]
    stream_metrics: Dict[str, float]
    stream_attestation_hash: str
    # Human Modality View back to Tasker
    actionable_controls_for_tasker: List[str]
    modality_preview_diagram: str
    # Self-Blame & Recursive Evolution
    blamed_actor: ActorRole
    reviewer_actor: ActorRole
    blame_category: BlameCategory
    friction_observed: str
    counterfactual_root_cause: str
    latency_penalty_ms: int
    proposed_skill_name: str
    proposed_ledger_capability: str
    next_protocol_version: str
    schema_diff_summary: str
    reward_pool_units: int = 1000


def _verify_cap_grid_01(vec: Dict[str, Any]) -> bool:
    thd_before = float(vec["thd_pct_before"])
    damping_gain = float(vec["active_notch_gain"])
    thd_after = thd_before / (1.0 + 3.2 * damping_gain)
    temp_c = 68.0 + 1.8 * thd_after
    return thd_after < 4.5 and temp_c < 90.0


def _verify_cap_flow_02(vec: Dict[str, Any]) -> bool:
    reynolds = float(vec["reynolds_number"])
    baffle_angle_deg = float(vec["baffle_angle_deg"])
    vortex_shedding_ratio = (reynolds / 1.0e5) * (1.0 - 0.022 * baffle_angle_deg)
    return 15.0 <= baffle_angle_deg <= 32.0 and vortex_shedding_ratio < 0.75


def _verify_cap_trust_03(vec: Dict[str, Any]) -> bool:
    proof_bytes = int(vec["accumulator_proof_bytes"])
    verify_ms = float(vec["edge_verify_ms"])
    false_accept_bound = float(vec["soundness_error_exp"])
    return proof_bytes <= 1024 and verify_ms <= 2.5 and false_accept_bound <= -128.0


def _verify_cap_water_04(vec: Dict[str, Any]) -> bool:
    ec_dsm = float(vec["root_zone_ec_dsm"])
    water_saved_pct = float(vec["water_saved_pct"])
    leaching_fraction = float(vec["pulse_leaching_fraction"])
    return ec_dsm < 2.2 and water_saved_pct >= 28.0 and 0.08 <= leaching_fraction <= 0.18


def _verify_cap_care_05(vec: Dict[str, Any]) -> bool:
    stagger_hours = float(vec["stagger_window_hours"])
    adjusted_hr = float(vec["adjusted_hazard_ratio"])
    ci_upper = float(vec["confidence_upper_95"])
    return stagger_hours >= 6.0 and adjusted_hr < 1.10 and ci_upper < 1.22


def build_five_real_world_events() -> List[RealWorldEventScenario]:
    return [
        RealWorldEventScenario(
            event_id="EVT-01",
            title="Sub-Harmonic Transformer Thermal Stabilization Under Evening EV Charging",
            domain="energy_grid_operations",
            media_headline="Regional Grid Alert: Neighborhood Substation Transformers Overheating as Evening EV Fast-Charging Collides with Rooftop Inverter Harmonics",
            media_source_context="Municipal Utility Telemetry Feed & Power Systems Dispatch (Oct 2026)",
            tasker_human_name="Marek Kowalski (Municipal Co-op Substation Technician)",
            tasker_human_role_desc="Maintains 14 neighborhood 13.8kV/480V transformers; prefers visual system topologies and relay settings.",
            tasker_modality=CognitiveModality.VISUAL_SYSTEM_TOPOLOGY,
            tasker_lived_problem=(
                "Every evening at 18:30 when 40+ bidirectional EV chargers start simultaneously, "
                "5th and 7th harmonic currents ring between inverter phase-locked loops, driving our "
                "substation oil temperature past 98C even though total kW load is only at 68% capacity."
            ),
            tasker_feedback_prompt=(
                "Show me the system topology and exact inverter phase-stagger settings so our "
                "substation controller cancels the harmonic ringing without tripping household chargers."
            ),
            available_state_vars=["phase_current_waveform", "inverter_pll_bandwidth_hz", "transformer_leakage_inductance_mh"],
            target_guarantees=["total_harmonic_distortion_pct < 4.5", "oil_temp_c < 90.0"],
            solver_human_name="Dr. Ananya Rao (Control Systems & Power Electronics Engineer)",
            solver_human_role_desc="Designs distributed oscillation-damping control policies for microgrids.",
            solver_modality=CognitiveModality.INTERACTIVE_SIMULATION_SANDBOX,
            solver_core_thesis=(
                "When identical EV inverters share one transformer inductance, their phase-locked loops "
                "synchronize like metronomes on a wobbling board. Staggering each inverter bank's virtual "
                "impedance at the 5th and 7th harmonic via a 20 ms sliding-window filter cancels 82% of core heating."
            ),
            solver_human_guidance=(
                "The N=2 coupled-inverter case illustrates why phase-staggering breaks synchronization. "
                "Have my Solver Agent package the general N-inverter control policy into a verified CapabilityArtifact "
                "and test it against the co-op's waveform telemetry stream."
            ),
            artifact_id="CAP-GRID-01",
            artifact_title="Sliding-Window Harmonic Phase-Stagger Control Policy for Coupled Inverters",
            artifact_kind=ArtifactKind.CONTROL_POLICY,
            implementation_summary="Deterministic 20ms sliding-window notch controller with 14-deg bank phase stagger",
            input_schema={
                "phase_current_waveform": "float32[1024]",
                "inverter_pll_bandwidth_hz": "float64",
                "transformer_leakage_inductance_mh": "float64",
            },
            output_schema={
                "active_notch_gain": "float64",
                "predicted_thd_pct": "float64",
            },
            units={
                "inverter_pll_bandwidth_hz": "Hz",
                "transformer_leakage_inductance_mh": "mH",
                "oil_temp_c": "degC",
            },
            preconditions=[
                "transformer_leakage_inductance_mh in [0.4, 4.5]",
                "inverter_pll_bandwidth_hz <= 45.0",
                "sampling_rate_khz >= 10.0",
            ],
            guarantees=[
                "total_harmonic_distortion_pct < 4.5",
                "oil_temp_c < 90.0",
                "zero_unstable_control_poles == True",
            ],
            test_vectors=[
                {"thd_pct_before": 14.2, "active_notch_gain": 0.85},
                {"thd_pct_before": 11.8, "active_notch_gain": 0.72},
                {"thd_pct_before": 16.0, "active_notch_gain": 0.95},
            ],
            verifier_fn=_verify_cap_grid_01,
            lineage_parents=[],
            stream_id="STREAM-GRID-WAVE-01",
            stream_title="Co-op Substation 10kHz 3-Phase Telemetry Stream (Anonymized)",
            stream_custodian="Substation Telemetry Co-op #14",
            stream_schema={
                "phase_current_waveform": "float32[1024]",
                "inverter_pll_bandwidth_hz": "float64",
                "transformer_leakage_inductance_mh": "float64",
                "oil_temp_c": "float64",
            },
            stream_records=14400,
            stream_invariants=[
                "Zero household meter IDs present (k-anonymity >= 40)",
                "Calibrated Rogowski coil error <= 0.2%",
            ],
            stream_metrics={"mean_thd_pct": 13.7, "peak_oil_temp_c": 98.4},
            stream_attestation_hash="att-8f41c09e22a7b110",
            actionable_controls_for_tasker=[
                "Configure substation edge controller sliding window to 20.0 ms (128 samples @ 6.4 kHz).",
                "Set virtual harmonic impedance Z_h = 0.85 ohm at 300 Hz (5th) and 420 Hz (7th) with 14-degree phase stagger across charger banks A/B.",
                "Verified operational outcome: THD drops from 13.7% -> 3.8%, stabilizing transformer oil at 74.8C.",
            ],
            modality_preview_diagram=(
                "[3-Phase Bus] ---> [Rogowski 10kHz] ---> [20ms Phase-Stagger Controller (Gain=0.85)]\n"
                "   THD 13.7% (98.4C)                        THD 3.8% (74.8C) [CAP-GRID-01 Verified]"
            ),
            blamed_actor=ActorRole.AGENT_TASKER,
            reviewer_actor=ActorRole.AGENT_SOLVER,
            blame_category=BlameCategory.INTERFACE_DISCOVERY_FRICTION,
            friction_observed=(
                "Initial Agent-Web query searched by free-text label 'transformer overheating' "
                "and missed control policies indexed by state-variable schema."
            ),
            counterfactual_root_cause=(
                "Ledger v1.0 lacked inverted state-variable interface indexing; "
                "agents needed a structural interface-matching discovery skill."
            ),
            latency_penalty_ms=420,
            proposed_skill_name="skill.v1_1.interface_schema_indexer",
            proposed_ledger_capability="structural_interface_schema_index",
            next_protocol_version="1.1",
            schema_diff_summary="Added input_schema/output_schema inverted index to AgentWebLedger.",
            reward_pool_units=1000,
        ),
        RealWorldEventScenario(
            event_id="EVT-02",
            title="Storm-Culvert Vortex Suppression & Flash-Flood Infrastructure Retrofit",
            domain="civil_infrastructure_operations",
            media_headline="Flash-Flood Infrastructure Warning: High-Velocity Storm Culverts Failing From Inlet Flow Separation & Cavitation",
            media_source_context="Civil Hydrology Emergency Bulletin & Municipal Public Works Feed (Oct 2026)",
            tasker_human_name="Elena Rostova (Watershed Civil Works Technician)",
            tasker_human_role_desc="Fabricates bolt-on storm-drain retrofits for mountain municipalities; prefers visual spatial topologies.",
            tasker_modality=CognitiveModality.VISUAL_SYSTEM_TOPOLOGY,
            tasker_lived_problem=(
                "During 80 mm/hr cloudbursts, water entering our 2.4m concrete box culverts separates at the "
                "inlet lip, creating a standing vortex pocket that hammers the ceiling slab until rebar spalls."
            ),
            tasker_feedback_prompt=(
                "Show me the exact 3D baffle wedge layout and bolt spacing I can weld in our municipal shop "
                "this week, with a visual flow map showing where the low-pressure cavitation zone disappears."
            ),
            available_state_vars=["reynolds_number", "inlet_velocity_ms", "culvert_diameter_m"],
            target_guarantees=["vortex_shedding_ratio < 0.75", "wall_cavitation_index > 1.8"],
            solver_human_name="Prof. Marcus Vance (Hydraulic Structures & Fluid Systems Specialist)",
            solver_human_role_desc="Designs passive flow-conditioning retrofits and boundary-layer stabilizers.",
            solver_modality=CognitiveModality.VISUAL_SYSTEM_TOPOLOGY,
            solver_core_thesis=(
                "You do not need to rebuild the concrete culvert. Bolting a pair of 24-degree chevron micro-baffles "
                "0.35 diameters upstream of the inlet throat injects counter-rotating vortices that keep the flow "
                "attached to the concrete wall."
            ),
            solver_human_guidance=(
                "I'll provide the chevron geometry rules. Let my Solver Agent package the structural sizing workflow "
                "(CAP-FLOW-02) and verify dimensional unit safety against the watershed pressure-sensor stream."
            ),
            artifact_id="CAP-FLOW-02",
            artifact_title="Chevron Micro-Baffle Inlet Flow Stabilizer & Sizing Workflow",
            artifact_kind=ArtifactKind.WORKFLOW_AUTOMATION,
            implementation_summary="Parametric chevron baffle sizing & cavitation-margin verification module",
            input_schema={
                "reynolds_number": "float64",
                "inlet_velocity_ms": "float64",
                "culvert_diameter_m": "float64",
                "baffle_angle_deg": "float64",
            },
            output_schema={
                "vortex_shedding_ratio": "float64",
                "wall_cavitation_index": "float64",
            },
            units={
                "reynolds_number": "dimensionless",
                "inlet_velocity_ms": "m/s",
                "culvert_diameter_m": "m",
                "baffle_angle_deg": "deg",
            },
            preconditions=[
                "reynolds_number in [1.0e5, 2.5e6]",
                "baffle_angle_deg in [15.0, 32.0]",
            ],
            guarantees=[
                "vortex_shedding_ratio < 0.75",
                "wall_cavitation_index > 1.8",
            ],
            test_vectors=[
                {"reynolds_number": 120000.0, "baffle_angle_deg": 24.0},
                {"reynolds_number": 145000.0, "baffle_angle_deg": 26.0},
            ],
            verifier_fn=_verify_cap_flow_02,
            lineage_parents=["CAP-GRID-01"],
            stream_id="STREAM-CULVERT-02",
            stream_title="Acoustic Doppler & Pressure-Transducer Storm Culvert Telemetry Stream",
            stream_custodian="Mountain Watershed Co-op #07",
            stream_schema={
                "reynolds_number": "float64",
                "inlet_velocity_ms": "float64",
                "culvert_diameter_m": "float64",
                "peak_negative_pressure_kpa": "float64",
            },
            stream_records=6800,
            stream_invariants=[
                "Sensor calibration cross-checked across 3 orthogonal piezometers",
                "Zero private parcel coordinates exposed",
            ],
            stream_metrics={"mean_reynolds": 132000.0, "max_suction_kpa": -42.5},
            stream_attestation_hash="att-3a99d71b40e2c511",
            actionable_controls_for_tasker=[
                "Bolt two 10mm steel chevron wedges at 24.0 deg angle, height = 14 cm (0.06D), 84 cm from inlet lip.",
                "Verified operational outcome: peak ceiling suction drops by 64% and standing cavitation pocket is eliminated.",
            ],
            modality_preview_diagram=(
                "Inlet ===> [ /\\ 24-deg Chevron Baffles @ 0.35D ] ===> Attached Wall Flow\n"
                "            (Counter-vortices keep boundary attached; CAP-FLOW-02 verified: shedding = 0.56 < 0.75)"
            ),
            blamed_actor=ActorRole.AGENT_SOLVER,
            reviewer_actor=ActorRole.AGENT_TASKER,
            blame_category=BlameCategory.UNIT_CONVERSION_MISMATCH,
            friction_observed=(
                "First service agreement draft passed culvert_diameter in millimeters from shop CAD tool "
                "against CAP-FLOW-02's meter specification, requiring a retry."
            ),
            counterfactual_root_cause=(
                "Ledger v1.1 checked float64 types but did not enforce SI unit compatibility at contract binding."
            ),
            latency_penalty_ms=310,
            proposed_skill_name="skill.v1_2.si_unit_compatibility_guard",
            proposed_ledger_capability="mandatory_si_unit_validation",
            next_protocol_version="1.2",
            schema_diff_summary="Added mandatory InterfaceSpec.units compatibility validation on CapabilityArtifact <-> DataStreamContract binding.",
            reward_pool_units=1000,
        ),
        RealWorldEventScenario(
            event_id="EVT-03",
            title="Emergency Certificate Authority Compromise & Offline Medical Device Attestation",
            domain="edge_network_security",
            media_headline="Cybersecurity Alert: Root CA Compromise Forces Emergency Revocation Across 400,000 Medical & Industrial Edge Devices",
            media_source_context="Oct 2026 TLS / CA Compromise Incident Stream & Healthcare SecOps Alert",
            tasker_human_name="Devon Okafor (Regional Rural Hospital Security Custodian)",
            tasker_human_role_desc="Maintains 1,200 infusion pumps and imaging nodes on intermittent rural links; prefers stepwise operational runbooks.",
            tasker_modality=CognitiveModality.STEPWISE_OPERATIONAL_RUNBOOK,
            tasker_lived_problem=(
                "After the October CA compromise, downloading 45 MB Certificate Revocation Lists (CRLs) "
                "over our backup satellite link stalls bedside infusion pump handshakes for 18 seconds."
            ),
            tasker_feedback_prompt=(
                "Give me a step-by-step deployment runbook for an offline revocation check under 1 KB "
                "that our hospital gateway can broadcast locally so pumps verify certificates in under 2 ms."
            ),
            available_state_vars=["cert_serial_hash", "accumulator_root", "witness_bytes"],
            target_guarantees=["accumulator_proof_bytes <= 1024", "edge_verify_ms <= 2.5"],
            solver_human_name="Dr. Kenji Takahashi (Distributed Systems & Cryptographic Protocol Engineer)",
            solver_human_role_desc="Builds compact stateless revocation accumulators for constrained embedded devices.",
            solver_modality=CognitiveModality.VISUAL_SYSTEM_TOPOLOGY,
            solver_core_thesis=(
                "Instead of shipping a 45 MB blacklist of revoked certificates, invert the check: "
                "compress the active valid set into a 64-byte cryptographic accumulator root so each pump "
                "verifies a 768-byte witness offline in 1.42 milliseconds."
            ),
            solver_human_guidance=(
                "I'll specify the stateless accumulator update cycle. Let my Solver Agent package the "
                "embedded verification patch (CAP-TRUST-03) and run the cycle-count harness on the ledger."
            ),
            artifact_id="CAP-TRUST-03",
            artifact_title="Stateless 768-Byte Accumulator Revocation Filter for Embedded Gateways",
            artifact_kind=ArtifactKind.SECURITY_PROTOCOL_PATCH,
            implementation_summary="Constant-size 64B root + 768B witness verifier replacing 45MB CRL downloads",
            input_schema={
                "cert_serial_hash": "bytes32",
                "accumulator_root": "bytes64",
                "witness_bytes": "bytes768",
            },
            output_schema={
                "accumulator_proof_bytes": "int32",
                "edge_verify_ms": "float64",
                "soundness_error_exp": "float64",
            },
            units={
                "accumulator_proof_bytes": "bytes",
                "edge_verify_ms": "ms",
                "soundness_error_exp": "log2_prob",
            },
            preconditions=[
                "gateway_sync_interval_min <= 15",
                "device_sram_free_kb >= 4",
            ],
            guarantees=[
                "accumulator_proof_bytes <= 1024",
                "edge_verify_ms <= 2.5",
                "soundness_error_exp <= -128.0",
            ],
            test_vectors=[
                {"accumulator_proof_bytes": 768, "edge_verify_ms": 1.4, "soundness_error_exp": -132.0},
                {"accumulator_proof_bytes": 832, "edge_verify_ms": 1.8, "soundness_error_exp": -129.5},
            ],
            verifier_fn=_verify_cap_trust_03,
            lineage_parents=["CAP-GRID-01"],
            stream_id="STREAM-PKI-BENCH-03",
            stream_title="Embedded Medical Gateway Handshake Latency & Cycle Telemetry Stream",
            stream_custodian="Rural Hospital Defense Guild #03",
            stream_schema={
                "cert_serial_hash": "bytes32",
                "accumulator_root": "bytes64",
                "witness_bytes": "bytes768",
                "cortex_m4_cycles": "int64",
            },
            stream_records=25000,
            stream_invariants=[
                "Zero patient PHI or internal hospital IP addresses present",
                "Hardware cycle counts attested by local TPM counter",
            ],
            stream_metrics={"mean_verify_ms": 1.42, "witness_size_bytes": 768.0},
            stream_attestation_hash="att-99c14e07a211f804",
            actionable_controls_for_tasker=[
                "Step 1: Configure hospital border gateway to fetch the 64-byte accumulator root every 15 minutes.",
                "Step 2: Enable local LAN/LoRa broadcast of the 768-byte witness alongside TLS server hello.",
                "Step 3: Verified operational outcome: infusion pump handshakes complete offline in 1.42 ms (zero 18s stalls).",
            ],
            modality_preview_diagram=(
                "Runbook: [15m Gateway Sync (64B Root)] -> [Local LAN 768B Witness] -> [1.42ms Pump Handshake]\n"
                "         (Replaces 45 MB CRL download; CAP-TRUST-03 verified across 25,000 device traces)"
            ),
            blamed_actor=ActorRole.AGENT_TASKER,
            reviewer_actor=ActorRole.AGENT_SOLVER,
            blame_category=BlameCategory.DATA_STREAM_ATTESTATION_GAP,
            friction_observed=(
                "Tasker Agent delayed publishing hospital gateway benchmark traces until it could "
                "automatically prove zero internal network-topology leakage."
            ),
            counterfactual_root_cause=(
                "Ledger v1.2 lacked an automated privacy-schema sanitizer for DataStreamContract."
            ),
            latency_penalty_ms=260,
            proposed_skill_name="skill.v1_3.stream_privacy_attestor",
            proposed_ledger_capability="automated_stream_privacy_proof",
            next_protocol_version="1.3",
            schema_diff_summary="Added automated privacy_and_quality_invariants verification hook prior to register_data_stream.",
            reward_pool_units=1000,
        ),
        RealWorldEventScenario(
            event_id="EVT-04",
            title="Root-Zone Soil Salinity Flushing Under 35% Cooperative Drought Water Cut",
            domain="agricultural_resource_operations",
            media_headline="Agricultural Basin Report: Rising Capillary Salinity Threatens 180,000 Acres of Smallholder Orchards as Water Allocations Drop 35%",
            media_source_context="Regional Watershed Cooperative Telemetry & Drought Dispatch (Oct 2026)",
            tasker_human_name="Mateo Solis (Smallholder Orchard & Irrigation Co-op Coordinator)",
            tasker_human_role_desc="Coordinates 85 family orchards sharing a brackish canal; prefers stepwise valve schedules and moisture thresholds.",
            tasker_modality=CognitiveModality.STEPWISE_OPERATIONAL_RUNBOOK,
            tasker_lived_problem=(
                "Our well water conductivity hit 1.9 dS/m this summer. Standard daily trickle drip leaves "
                "a salt crust right at the 30 cm feeder-root boundary, scorching trees while we face a 30% water cut."
            ),
            tasker_feedback_prompt=(
                "Give me a practical pre-dawn valve-pulsing schedule tied to our 30 cm soil tensiometers "
                "that flushes salt below 55 cm without exceeding our reduced cooperative water quota."
            ),
            available_state_vars=["soil_ec_dsm", "matric_potential_kpa", "irrigation_pulse_duration_min"],
            target_guarantees=["root_zone_ec_dsm < 2.2", "water_saved_pct >= 28.0"],
            solver_human_name="Dr. Layla Haddad (Vadose-Zone Agronomist & Irrigation Systems Engineer)",
            solver_human_role_desc="Designs sensor-driven pulsed irrigation schedules for arid and brackish watersheds.",
            solver_modality=CognitiveModality.INTERACTIVE_SIMULATION_SANDBOX,
            solver_core_thesis=(
                "Salt rises during daytime evaporation when micropores stay half-wet. Replacing daily trickle "
                "with a pre-dawn dual-pulse—a 25-minute wetting front at 03:30 AM, a 90-minute pause to dissolve "
                "salt rims, and a 40-minute gravity flush at 05:00 AM—carries dissolved salt below the roots using 31.5% less water."
            ),
            solver_human_guidance=(
                "The 90-minute dissolution pause between pulses is the key operational lever. Have my Solver Agent "
                "package the valve-control rule (CAP-WATER-04) and validate it against the 85-orchard sensor stream."
            ),
            artifact_id="CAP-WATER-04",
            artifact_title="Pre-Dawn Dual-Pulse Capillary Break & Salinity Leaching Schedule",
            artifact_kind=ArtifactKind.RESOURCE_ALLOCATION_RULE,
            implementation_summary="Tensiometer-triggered two-stage valve schedule (25m wet / 90m dissolve / 40m flush)",
            input_schema={
                "soil_ec_dsm": "float64",
                "matric_potential_kpa": "float64",
                "irrigation_pulse_duration_min": "float64",
            },
            output_schema={
                "root_zone_ec_dsm": "float64",
                "water_saved_pct": "float64",
                "pulse_leaching_fraction": "float64",
            },
            units={
                "soil_ec_dsm": "dS/m",
                "matric_potential_kpa": "kPa",
                "irrigation_pulse_duration_min": "min",
            },
            preconditions=[
                "matric_potential_kpa in [-65.0, -18.0]",
                "clay_fraction_pct <= 38.0",
            ],
            guarantees=[
                "root_zone_ec_dsm < 2.2",
                "water_saved_pct >= 28.0",
            ],
            test_vectors=[
                {"root_zone_ec_dsm": 1.74, "water_saved_pct": 31.5, "pulse_leaching_fraction": 0.12},
                {"root_zone_ec_dsm": 1.89, "water_saved_pct": 29.2, "pulse_leaching_fraction": 0.14},
            ],
            verifier_fn=_verify_cap_water_04,
            lineage_parents=["CAP-FLOW-02"],
            stream_id="STREAM-ORCHARD-SOIL-04",
            stream_title="85-Orchard Capacitive Tensiometer & Soil Conductivity Stream",
            stream_custodian="Valley Irrigation Co-op #19",
            stream_schema={
                "soil_ec_dsm": "float64",
                "matric_potential_kpa": "float64",
                "irrigation_pulse_duration_min": "float64",
                "depth_cm": "int32",
            },
            stream_records=19200,
            stream_invariants=[
                "Farm boundary coordinates blinded via geodesic grid aggregation",
                "Tensiometer drift cross-checked against gravimetric core holdouts",
            ],
            stream_metrics={"baseline_ec_dsm": 3.45, "post_pulse_ec_dsm": 1.74},
            stream_attestation_hash="att-55b02d91e4f8a302",
            actionable_controls_for_tasker=[
                "Trigger Pulse 1 at 03:30 AM for 25 min whenever 30cm tensiometer reaches -42 kPa.",
                "Hold valves closed for 90 min so crystallized pore salt dissolves into the wetting front.",
                "Trigger Pulse 2 at 05:00 AM for 40 min. Verified outcome: root-zone EC drops 3.45 -> 1.74 dS/m while saving 31.5% water.",
            ],
            modality_preview_diagram=(
                "03:30 AM [25m Wetting Pulse] --> 90m Dissolve Pause --> 05:00 AM [40m Gravity Flush]\n"
                "   Root-Zone EC: 3.45 -> 1.74 dS/m | Water Saved: 31.5% [CAP-WATER-04 Verified]"
            ),
            blamed_actor=ActorRole.AGENT_SOLVER,
            reviewer_actor=ActorRole.AGENT_TASKER,
            blame_category=BlameCategory.LINEAGE_DEPENDENCY_ROUTING_GAP,
            friction_observed=(
                "CAP-WATER-04 reused the porous-media transport sub-module from CAP-FLOW-02, "
                "but v1.3 required manual lineage entry to split upstream royalties."
            ),
            counterfactual_root_cause=(
                "Ledger v1.3 lacked automatic DAG lineage traversal during ServiceAgreement settlement."
            ),
            latency_penalty_ms=195,
            proposed_skill_name="skill.v1_4.dag_lineage_auto_resolver",
            proposed_ledger_capability="automatic_dag_lineage_royalties",
            next_protocol_version="1.4",
            schema_diff_summary="Added automatic recursive lineage_parents DAG resolution for upstream capability royalty splits.",
            reward_pool_units=1000,
        ),
        RealWorldEventScenario(
            event_id="EVT-05",
            title="Polypharmacy Dosing Schedule Optimization to Prevent Morning Orthostatic Falls",
            domain="clinical_care_operations",
            media_headline="Pharmacovigilance Signal: Unexplained Morning Dizziness & Fall Hospitalizations in Seniors Prescribed Combined Beta-Blocker + SSRI Regimens",
            media_source_context="Community Clinic Pharmacovigilance Network & Federated Safety Alert (Oct 2026)",
            tasker_human_name="Dr. Hannah Lin (Community Geriatric Pharmacist)",
            tasker_human_role_desc="Reviews medication regimens for 600 home-dwelling seniors; prefers causal decision matrices with explicit safety gates.",
            tasker_modality=CognitiveModality.CAUSAL_DECISION_MATRIX,
            tasker_lived_problem=(
                "Patients taking both metoprolol and low-dose paroxetine at 08:00 breakfast are showing "
                "a 2.4x spike in mid-morning orthostatic blood-pressure drops, even at standard geriatric doses."
            ),
            tasker_feedback_prompt=(
                "Give me a clear causal decision matrix I can review with prescribing physicians showing "
                "whether staggering administration times eliminates the metabolic bottleneck without changing medications."
            ),
            available_state_vars=["cyp2d6_inhibition_auc", "stagger_window_hours", "baseline_map_mmhg"],
            target_guarantees=["adjusted_hazard_ratio < 1.10", "confidence_upper_95 < 1.22"],
            solver_human_name="Dr. Samuel Mensah (Clinical Pharmacokineticist & Causal Inference Specialist)",
            solver_human_role_desc="Models drug-clearance competition across federated privacy-preserving clinic cohorts.",
            solver_modality=CognitiveModality.CAUSAL_DECISION_MATRIX,
            solver_core_thesis=(
                "First-pass hepatic CYP2D6 enzyme saturation peaks 90 to 180 minutes after simultaneous oral dosing. "
                "Separating the two medications by a 12-hour window (evening vs. morning) prevents peak competitive "
                "inhibition, returning active beta-blocker clearance to baseline."
            ),
            solver_human_guidance=(
                "I'll lay out the clearance separation rules and renal precondition gates. Let my Solver Agent "
                "package the dosing decision model (CAP-CARE-05) and verify it across the 14-clinic federated summary stream."
            ),
            artifact_id="CAP-CARE-05",
            artifact_title="12-Hour Split-Dosing CYP2D6 Clearance & Fall-Prevention Decision Model",
            artifact_kind=ArtifactKind.CAUSAL_DIAGNOSTIC_MODEL,
            implementation_summary="Federated doubly-robust dosing stagger verifier with renal eGFR safety gating",
            input_schema={
                "cyp2d6_inhibition_auc": "float64",
                "stagger_window_hours": "float64",
                "baseline_map_mmhg": "float64",
            },
            output_schema={
                "adjusted_hazard_ratio": "float64",
                "confidence_upper_95": "float64",
            },
            units={
                "stagger_window_hours": "h",
                "baseline_map_mmhg": "mmHg",
                "adjusted_hazard_ratio": "ratio",
            },
            preconditions=[
                "stagger_window_hours >= 6.0",
                "egfr_ml_min >= 45.0",
            ],
            guarantees=[
                "adjusted_hazard_ratio < 1.10",
                "confidence_upper_95 < 1.22",
            ],
            test_vectors=[
                {"stagger_window_hours": 8.0, "adjusted_hazard_ratio": 1.03, "confidence_upper_95": 1.14},
                {"stagger_window_hours": 6.5, "adjusted_hazard_ratio": 1.07, "confidence_upper_95": 1.19},
            ],
            verifier_fn=_verify_cap_care_05,
            lineage_parents=["CAP-GRID-01", "CAP-TRUST-03"],
            stream_id="STREAM-PHARMA-FED-05",
            stream_title="Federated 14-Clinic Geriatric Orthostatic Vitals Stream (Zero-PHI)",
            stream_custodian="Federated Senior Care Co-op #02",
            stream_schema={
                "cyp2d6_inhibition_auc": "float64",
                "stagger_window_hours": "float64",
                "baseline_map_mmhg": "float64",
                "orthostatic_drop_mmhg": "float64",
            },
            stream_records=4200,
            stream_invariants=[
                "Differential privacy epsilon <= 0.5 per clinic shard",
                "Zero individual patient charts exported (sufficient statistics only)",
            ],
            stream_metrics={"simultaneous_hr": 2.41, "staggered_12h_hr": 1.03},
            stream_attestation_hash="att-77d81a63c902b44e",
            actionable_controls_for_tasker=[
                "Safety Gate Check: Confirm patient renal eGFR >= 45 mL/min before applying split-dosing schedule.",
                "Action: Shift SSRI administration to 20:00 and retain metoprolol at 08:00 (12-hour separation).",
                "Verified outcome: mid-morning orthostatic fall hazard ratio drops from 2.41 -> 1.03 (95% CI upper bound 1.14).",
            ],
            modality_preview_diagram=(
                "Decision Matrix: [Gate: eGFR >= 45] -> [Stagger 08:00 / 20:00 (12h)] -> [Fall Hazard Ratio: 2.41 -> 1.03]\n"
                "                 (CYP2D6 peak saturation avoided; CAP-CARE-05 verified across 4,200 federated records)"
            ),
            blamed_actor=ActorRole.AGENT_TASKER,
            reviewer_actor=ActorRole.AGENT_SOLVER,
            blame_category=BlameCategory.PRECONDITION_MODALITY_VISIBILITY_GAP,
            friction_observed=(
                "Initial modality rendering displayed the hazard ratio improvement before highlighting "
                "the mandatory renal eGFR >= 45 mL/min safety precondition gate."
            ),
            counterfactual_root_cause=(
                "ModalityBridge v1.4 listed preconditions in footnotes rather than compiling them into top-level safety gates."
            ),
            latency_penalty_ms=140,
            proposed_skill_name="skill.v2_0.precondition_safety_gate_compiler",
            proposed_ledger_capability="mandatory_precondition_modality_gate",
            next_protocol_version="2.0",
            schema_diff_summary="Upgraded ModalityBridge & Ledger to v2.0: InterfaceSpec.preconditions auto-compile into top-level human safety gates.",
            reward_pool_units=1000,
        ),
    ]
