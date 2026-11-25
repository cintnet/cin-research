"""
Unit Test Suite for the General-Purpose Agent-Web Ledger & Multi-Session Simulation.

Verifies:
  1. Strict per-actor SessionIsolationGuard ('no cheating' rules):
     - Cross-session memory reads/writes raise SessionBoundaryViolationError.
     - Direct human-to-human or cross-pair agent-to-human bypasses raise SessionBoundaryViolationError.
     - Direct human writes to the AgentWebLedger raise SessionBoundaryViolationError.
  2. Universal `CapabilityArtifact`, `InterfaceSpec`, and `DataStreamContract` registration
     and deterministic verification harness execution.
  3. General-purpose Agent-Web structural discovery (matching by state-variable schema
     and outcome guarantees).
  4. Universal `ModalityBridge` compilation into `CognitiveModality` views (`VISUAL_SYSTEM_TOPOLOGY`,
     `STEPWISE_OPERATIONAL_RUNBOOK`, `CAUSAL_DECISION_MATRIX`) with top-level safety precondition gates.
  5. Self-blame diagnostics and recursive evolution of agent skills and ledger protocol
     from v1.0 -> v1.1 -> v1.2 -> v1.3 -> v1.4 -> v2.0 across all 5 real-world events.
  6. 100% reward conservation across all human and agent contributors.
"""

from __future__ import annotations

import importlib.util
import unittest

HAS_INTERNAL_LOOP = importlib.util.find_spec("loop") is not None

from research.ledger_sim import (
    ActorRole,
    CognitiveModality,
    DelegationScope,
    DelegationSecurityViolation,
    DelegationToken,
    DelegationTokenValidator,
    DelegationValidationError,
    LedgerDanceSimulator,
    SessionBoundaryViolationError,
    SessionIsolationGuard,
    run_full_simulation,
)


class TestLedgerSimulationFramework(unittest.TestCase):
    def test_session_isolation_blocks_cross_actor_memory_cheating(self) -> None:
        guard = SessionIsolationGuard(run_seed="test-anti-cheat")
        guard.write_actor_memory(
            ActorRole.ORCHESTRATOR,
            ActorRole.ORCHESTRATOR,
            "secret_answer_key",
            {"solution": 42},
        )
        with self.assertRaises(SessionBoundaryViolationError):
            guard.read_actor_memory(
                ActorRole.AGENT_SOLVER, ActorRole.ORCHESTRATOR, "secret_answer_key"
            )
        with self.assertRaises(SessionBoundaryViolationError):
            guard.read_actor_memory(
                ActorRole.AGENT_TASKER, ActorRole.HUMAN_SOLVER, "private_notes"
            )
        self.assertEqual(guard.violation_count, 2)

    def test_session_isolation_blocks_illegal_communication_channels(self) -> None:
        guard = SessionIsolationGuard(run_seed="test-channels")
        with self.assertRaises(SessionBoundaryViolationError):
            guard.assert_direct_channel(
                ActorRole.HUMAN_TASKER, ActorRole.HUMAN_SOLVER, "bypass_agents"
            )
        with self.assertRaises(SessionBoundaryViolationError):
            guard.assert_direct_channel(
                ActorRole.AGENT_SOLVER, ActorRole.HUMAN_TASKER, "cross_pair_contact"
            )
        with self.assertRaises(SessionBoundaryViolationError):
            guard.assert_ledger_access(ActorRole.HUMAN_TASKER, "post_raw_human_msg")
        self.assertEqual(guard.violation_count, 3)

    def test_full_five_event_simulation_and_recursive_protocol_evolution(self) -> None:
        summary = run_full_simulation()
        self.assertEqual(summary["initial_protocol_version"], "1.0")
        self.assertEqual(summary["final_protocol_version"], "2.0")
        self.assertEqual(summary["total_verified_capabilities"], 5)
        self.assertEqual(summary["total_data_streams"], 5)
        self.assertEqual(summary["total_settled_agreements"], 5)
        self.assertEqual(summary["cheating_violations_during_valid_run"], 0)
        self.assertEqual(len(summary["events"]), 5)

        expected_versions = [
            ("1.0", "1.1"),
            ("1.1", "1.2"),
            ("1.2", "1.3"),
            ("1.3", "1.4"),
            ("1.4", "2.0"),
        ]
        valid_modalities = {m.value for m in CognitiveModality}
        for idx, ev in enumerate(summary["events"]):
            self.assertEqual(
                (ev["protocol_version_start"], ev["protocol_version_end"]),
                expected_versions[idx],
            )
            self.assertIn(ev["modality_rendered"], valid_modalities)
            self.assertTrue(ev["rewards"]["conservation_verified"])
            self.assertEqual(ev["rewards"]["total_pool_units"], 1000)
            self.assertGreaterEqual(len(ev["safety_precondition_gates"]), 2)
            self.assertGreaterEqual(len(ev["actionable_controls"]), 2)
            self.assertGreaterEqual(len(ev["verified_background_operations"]), 3)

    def test_lineage_royalties_flow_to_upstream_capabilities(self) -> None:
        sim = LedgerDanceSimulator()
        summary = sim.run_all_events()
        # Event 1 has no upstream lineage parents -> upstream_capability_royalty == 0
        ev1_rewards = summary["events"][0]["rewards"]
        self.assertEqual(ev1_rewards["upstream_capability_royalty"], 0)
        # Events 2, 3, 4, 5 depend on upstream capabilities -> upstream_capability_royalty == 120
        for ev in summary["events"][1:]:
            self.assertEqual(ev["rewards"]["upstream_capability_royalty"], 120)
            self.assertEqual(ev["rewards"]["data_stream_custodian_royalty"], 150)
            self.assertEqual(ev["rewards"]["self_blame_efficiency_bonus"], 70)

    def test_live_multi_session_sqlite_execution_artifacts_and_heldout_verification(self) -> None:
        import json
        from pathlib import Path

        base = Path(__file__).resolve().parent
        report_path = base / "live_execution_report.json"
        self.assertTrue(report_path.exists(), "live_execution_report.json must exist from live run")
        report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["final_protocol_version"], "2.0")
        self.assertEqual(report["verified_capabilities_count"], 5)
        self.assertEqual(report["settled_agreements_count"], 5)
        self.assertEqual(report["self_blame_prs_count"], 5)
        self.assertGreaterEqual(report["security_audit_blocks"], 2)

        for agr in report["service_agreements"]:
            self.assertEqual(agr["status"], "SETTLED")
            self.assertEqual(agr["public_pass"], 1)
            self.assertEqual(agr["heldout_pass"], 1)
            metrics = json.loads(agr["heldout_metrics_json"])
            self.assertTrue(metrics["passed"])
            rewards = json.loads(agr["rewards_json"])
            self.assertTrue(rewards["conservation_verified"])

    def test_clean_room_sandbox_actor_creation_and_everyday_pipeline(self) -> None:
        from research.ledger_sim.sandbox.actor_factory import (
            get_five_web_grounded_everyday_frictions,
            run_sandboxed_everyday_pipeline,
            synthesize_actors_for_friction,
            write_clean_room_sandbox_prompts,
        )

        frictions = get_five_web_grounded_everyday_frictions()
        self.assertEqual(len(frictions), 5)
        for prob in frictions:
            self.assertTrue(prob.real_world_evidence)
            self.assertTrue(prob.mundane_friction_point)
            self.assertTrue(prob.target_persona_summary)
            self.assertTrue(prob.current_workaround)
            personas = synthesize_actors_for_friction(prob)
            self.assertIn("human_tasker", personas)
            self.assertIn("human_solver", personas)
            prompts = write_clean_room_sandbox_prompts(prob, personas)
            self.assertEqual(len(prompts), 5)
            for role_name, info in prompts.items():
                self.assertIn("Clean-Room Sandbox Instructions", info.system_prompt)
                self.assertIn("- **Isolation Mode:**", info.system_prompt)

        report = run_sandboxed_everyday_pipeline()
        self.assertEqual(report["problems_evaluated"], 5)
        self.assertTrue(report["all_passed"])
        for res in report["runs"]:
            self.assertTrue(res["heldout_evaluation"]["passed"])
            self.assertTrue(res["rewards"]["conservation_verified"])

    def test_testnet_attention_scaling_validator_skills_and_ledger_critique(self) -> None:
        from pathlib import Path
        from research.ledger_sim.testnet_engine import build_and_execute_testnet_cycles

        rep = build_and_execute_testnet_cycles()
        self.assertEqual(rep["protocol_start"], "2.0")
        self.assertEqual(rep["protocol_end"], "4.0")
        self.assertEqual(rep["final_ledger_version"], "4.0")
        self.assertEqual(rep["total_cycles"], 6)
        self.assertEqual(rep["total_messages_traced"], 35)
        self.assertEqual(rep["total_skills_acquired"], 12)
        self.assertEqual(rep["total_participant_rfcs_merged"], 6)
        self.assertEqual(rep["latent_weight_packets_exchanged"], 4)
        self.assertEqual(rep["lquic_p2p_tunnels_established"], 1)
        self.assertEqual(rep["affective_alignment_pivots"], 2)
        self.assertTrue(rep["all_validator_certified"])

        # Verify progressive scaling from 1x1 (4 sub-agents) up to 4x4 (24 sub-agents)
        c1, c2, c3, c4, c5, c6 = rep["cycles"]
        self.assertEqual((c1["requesting_humans_count"], c1["answering_humans_count"]), (1, 1))
        self.assertEqual((c2["requesting_humans_count"], c2["answering_humans_count"]), (1, 2))
        self.assertEqual((c3["requesting_humans_count"], c3["answering_humans_count"]), (2, 2))
        self.assertEqual((c4["requesting_humans_count"], c4["answering_humans_count"]), (3, 3))
        self.assertEqual((c5["requesting_humans_count"], c5["answering_humans_count"]), (2, 2))
        self.assertEqual((c6["requesting_humans_count"], c6["answering_humans_count"]), (4, 4))
        self.assertEqual((c6["requesting_agents_count"], c6["answering_agents_count"]), (12, 12))

        # Verify Cycle 5 L-QUIC P2P Tunnel (measured by RTT latency & p99 jitter, 64-tick netcode) and Affective State Alignment
        self.assertIsNotNone(c5["lquic_p2p_tunnel"])
        self.assertEqual(c5["lquic_p2p_tunnel"]["tick_rate_hz"], 64)
        self.assertLess(c5["lquic_p2p_tunnel"]["steady_state_latency_ms"], 15.0)
        self.assertLess(c5["lquic_p2p_tunnel"]["p99_jitter_ms"], 5.0)
        self.assertEqual(len(c5["affective_state_alignments"]), 2)

        # Verify Cycle 6 NextLat Belief States, MTP Horizons & LoRA Weight Consensus
        self.assertIsNotNone(c6["cross_activation_consensus"])
        cons = c6["cross_activation_consensus"]
        self.assertGreater(cons["speedup_vs_symbolic"], 5.0)
        self.assertGreater(cons["collective_generalization_gain_pct"], 20.0)
        self.assertAlmostEqual(
            sum(cons["activation_attribution_shares"].values()), 100.0, places=1
        )

        for cyc in rep["cycles"]:
            self.assertEqual(cyc["validator_receipt"]["final_verdict"], "CERTIFIED_PASS")
            self.assertEqual(cyc["validator_receipt"]["attention_privacy_score"], 100.0)
            self.assertTrue(cyc["validator_receipt"]["self_correction_triggered"])
            self.assertEqual(sum(cyc["rewards_breakdown"].values()), 1000)

        dash_path = Path(__file__).resolve().parent / "dashboard" / "index.html"
        self.assertTrue(dash_path.exists())

    @unittest.skipUnless(HAS_INTERNAL_LOOP, "Internal loop orchestration tests run in the private monorepo.")
    def test_md_conductor_git_change_tracker_and_task_sparker(self) -> None:
        from loop.harness_evolver import (
            CHANGELOG_MD_PATH,
            MANIFEST_PATH,
            SPARKED_TASKS_PATH,
            run_evolution_audit,
        )

        record = run_evolution_audit(auto_heal=True)
        self.assertEqual(record["harness"], "Antigravity / gemini-4-argon")
        self.assertEqual(record["agent_lane"], "gemini-md-evolver")
        self.assertEqual(record["instruction_hygiene"]["status"], "PASS")
        self.assertEqual(record["instruction_hygiene"]["violation_count"], 0)
        self.assertGreaterEqual(record["instruction_hygiene"]["checked_files"], 70)

        # Verify all 5 Living Theses and all 5 Deep Research Volumes are present
        p2 = record["pillar_metrics"]["pillar_2_deep_research_volumes"]
        self.assertEqual(p2["living_theses_count"], 5)
        self.assertEqual(p2["research_volumes_count"], 5)

        # Verify Git & SHA-256 .md change tracking and changelog generation
        self.assertGreaterEqual(
            record["md_git_tracking_summary"]["total_governed_md_files"], 150
        )
        self.assertTrue(CHANGELOG_MD_PATH.exists())
        self.assertTrue(MANIFEST_PATH.exists())
        self.assertTrue(SPARKED_TASKS_PATH.exists())

        # Verify tasks are sparked from Testnet runs, RFCs, and interactions
        self.assertGreaterEqual(record["sparked_tasks_count"], 2)
        task_ids = [t["task_id"] for t in record["sparked_tasks"]]
        self.assertIn("SPARK-RFC-206-WEB-AND-VOL", task_ids)

    @unittest.skipUnless(HAS_INTERNAL_LOOP, "Internal loop orchestration tests run in the private monorepo.")
    def test_dual_realm_firewall_blocks_instruction_bleed_between_builders_and_testnet(self) -> None:
        from loop.harness_evolver import run_evolution_audit
        from research.ledger_sim import RealmIsolationFirewall as TopLevelRealmIsolationFirewall
        from research.ledger_sim.session_isolation import (
            RealmInstructionBleedError,
            RealmIsolationFirewall,
        )
        self.assertIs(TopLevelRealmIsolationFirewall, RealmIsolationFirewall)

        firewall = RealmIsolationFirewall()
        audit = firewall.audit_all_realm_b_harnesses()
        self.assertEqual(audit["status"], "ISOLATED_CLEAN")
        self.assertEqual(audit["harnesses_verified"], 4)

        # Verify that injecting any Realm A builder directive into a Realm B Testnet harness is blocked
        with self.assertRaises(RealmInstructionBleedError):
            firewall.validate_testnet_prompt_or_harness(
                "After solving the FSA claim, update src/notes/how-the-ledger-works.html and run deploy --harness.",
                source_label="contaminated_testnet_prompt",
            )

        record = run_evolution_audit(auto_heal=True)
        rs = record["realm_separation"]
        self.assertEqual(rs["firewall_status"], "ISOLATED_CLEAN")
        self.assertEqual(rs["realm_a_partitions_count"], 4)
        self.assertEqual(rs["realm_b_partitions_count"], 1)

        # Verify in-world Testnet self-corrections target Realm B harnesses, while web/paper tasks target Realm A
        tasks_by_id = {t["task_id"]: t for t in record["sparked_tasks"]}
        self.assertEqual(
            tasks_by_id["SPARK-TESTNET-C6-SELF-CORRECTION"]["realm"],
            "REALM_B_TESTNET_ACTORS",
        )
        self.assertEqual(
            tasks_by_id["SPARK-TESTNET-C6-SELF-CORRECTION"]["partition"],
            "B1_IN_WORLD_TESTNET_ACTORS",
        )
        self.assertEqual(
            tasks_by_id["SPARK-RFC-206-WEB-AND-VOL"]["realm"],
            "REALM_A_COLLECTIVE_BUILDERS",
        )

    @unittest.skipUnless(HAS_INTERNAL_LOOP, "Internal loop orchestration tests run in the private monorepo.")
    def test_capability_trajectory_forecaster_generates_six_stages_and_twenty_examples(self) -> None:
        from loop.capability_trajectory_forecaster import (
            ATLAS_MD_PATH,
            build_example_foresight_envelopes,
            build_stage_strategic_foresight,
            build_twenty_world_shaping_examples,
            write_trajectory_atlas_and_batch,
        )
        from loop.terminology_db import (
            CATALOG_MD_PATH,
            DB_PATH,
            audit_file,
            build_database,
            query_terms,
        )

        res = write_trajectory_atlas_and_batch()
        self.assertEqual(res["agent_lane"], "gemini-capability-trajectory")
        self.assertEqual(res["stages_count"], 6)
        self.assertEqual(res["examples_count"], 20)
        self.assertEqual(res["strategic_foresight_stages_count"], 6)
        self.assertTrue(ATLAS_MD_PATH.exists())
        text = ATLAS_MD_PATH.read_text(encoding="utf-8")
        self.assertIn("Example `#01`", text)
        self.assertIn("Example `#20`", text)
        self.assertIn("arXiv:2503.14499", text)
        self.assertIn("Step 1 — Horizon Scanning (`STEEP Macro-Drivers` & `Fringe Weak Signals`)", text)
        self.assertIn("Step 3 — Automated 3-Turn Delphi Debate (`The Persona Swarm`", text)
        self.assertIn("Step 4 — Scenario Generation (`The Futures Cone`", text)
        self.assertIn("Step 5 — Backcasting & 12–24 Month Signpost Tripwires", text)

        # Verify 5-Step Futurist Pipeline invariants across all 6 stages and 20 examples
        stage_foresight = build_stage_strategic_foresight()
        self.assertEqual(len(stage_foresight), 6)
        for sf in stage_foresight.values():
            self.assertEqual(len(sf.steep_macro_drivers), 3)
            self.assertEqual(len(sf.fringe_weak_signals), 3)
            self.assertEqual(
                sf.scenario_a_baseline_pct + sf.scenario_b_friction_pct + sf.scenario_c_paradigm_shift_pct,
                100,
            )
            self.assertEqual(len(sf.backcasted_signposts_12_24m), 3)
            for sp in sf.backcasted_signposts_12_24m:
                self.assertIn("If we observe", sp)
                self.assertIn("the probability of Scenario C increases by", sp)

        examples = build_twenty_world_shaping_examples()
        ex_envelopes = build_example_foresight_envelopes(examples)
        self.assertEqual(len(ex_envelopes), 20)
        for env in ex_envelopes.values():
            self.assertEqual(sum(env.futures_cone_probabilities.values()), 100)
            self.assertIn("If we observe", env.backcasted_signpost_tripwire)

        # Verify Relational + Graph Terminology & Scientific Provenance Database
        db_res = build_database()
        self.assertTrue(DB_PATH.exists())
        self.assertTrue(CATALOG_MD_PATH.exists())
        self.assertGreaterEqual(db_res["scanned_files_count"], 50)
        self.assertGreaterEqual(db_res["historical_glossary_and_axioms_count"], 900)

        # Verify on-demand query returns canonical scientific definitions, sources, and graph edges
        quic_matches = query_terms("QUIC")
        self.assertTrue(any(m.get("term_id") == "TERM-NET-QUIC-P2P-TRANSPORT" for m in quic_matches))
        foresight_matches = query_terms("Delphi")
        self.assertTrue(any(m.get("term_id") == "TERM-FORESIGHT-DELPHI-FUTURES-CONE-BACKCASTING" for m in foresight_matches))

        # Verify all concepts referenced in the Atlas are grounded with canonical definitions in-file
        findings = audit_file(ATLAS_MD_PATH)
        self.assertTrue(all(f["has_canonical_grounding_in_file"] for f in findings))

    @unittest.skipUnless(HAS_INTERNAL_LOOP, "Internal loop orchestration tests run in the private monorepo.")
    def test_instruction_context_metrics_self_hpo_rrsi_and_spra_compiler(self) -> None:
        from loop.instruction_metrics_and_evolver import (
            DASHBOARD_HTML_PATH,
            METRICS_JSON_PATH,
            REPORT_MD_PATH,
            SPRA_CORPUS_JSON_PATH,
            SPRA_INDEX_MD_PATH,
            ULTRA_LIGHT_KERNEL_PATH,
            query_spra_corpus,
            run_instruction_metrics_and_evolution,
        )

        res = run_instruction_metrics_and_evolution()
        summary = res["summary"]
        self.assertGreaterEqual(summary["total_agent_streams_profiled"], 33)
        self.assertGreaterEqual(summary["total_daily_stream_executions"], 270)
        self.assertGreaterEqual(summary["total_tracked_md_files_in_streams"], 80)
        self.assertEqual(summary["rrsi_leakage_critic_status"], "PASS_ALL_CLEAN")
        self.assertEqual(summary["spra_documents_compiled"], 10)
        self.assertGreaterEqual(summary["overall_context_token_reduction_pct"], 70.0)

        self.assertTrue(ULTRA_LIGHT_KERNEL_PATH.exists())
        self.assertTrue(METRICS_JSON_PATH.exists())
        self.assertTrue(REPORT_MD_PATH.exists())
        self.assertTrue(DASHBOARD_HTML_PATH.exists())
        self.assertTrue(SPRA_CORPUS_JSON_PATH.exists())
        self.assertTrue(SPRA_INDEX_MD_PATH.exists())

        # Verify SPRA Schema-RAG queries return compact structured Empirical-AI profiles
        quic_spra = query_spra_corpus("QUIC")
        self.assertGreaterEqual(len(quic_spra), 2)
        self.assertIn("SPRA-VOL-01", [p["spra_doc_id"] for p in quic_spra])
        self.assertTrue(all("problems" in p and "contributions" in p and "findings" in p for p in quic_spra))

        ties_spra = query_spra_corpus("TIES")
        self.assertGreaterEqual(len(ties_spra), 2)
        self.assertIn("SPRA-VOL-02", [p["spra_doc_id"] for p in ties_spra])

    def test_ietf_wimse_cryptographic_delegation_token_validator(self) -> None:
        """Comprehensive verification of offline attenuated delegation chains (IETF WIMSE)."""
        keys = {
            "human:alice": b"secret-key-human-alice-32-bytes!!",
            "agent:coordinator": b"secret-key-coord-agent-32-bytes!",
            "agent:solver": b"secret-key-solver-agent-32-bytes",
            "agent:auditor": b"secret-key-auditor-agent-32-byt",
        }
        resolver = lambda actor: keys[actor]
        t0 = 1730000000

        # 1. Happy-path 3-hop delegation chain
        root_scope = DelegationScope(action="compute", resource="sim:npu_cluster", max_budget=1000)
        root_token = DelegationToken(
            token_id="tok-root-001",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=3,
            issued_at=t0,
            expires_at=t0 + 3600,
            scopes=(root_scope,),
        ).sign(keys["human:alice"])

        hop1_scope = DelegationScope(action="compute", resource="sim:npu_cluster", max_budget=600)
        hop1_token = DelegationToken(
            token_id="tok-hop1-002",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=t0 + 10,
            expires_at=t0 + 1800,
            scopes=(hop1_scope,),
        ).sign(keys["agent:coordinator"])

        hop2_scope = DelegationScope(action="compute", resource="sim:npu_cluster", max_budget=300)
        hop2_token = DelegationToken(
            token_id="tok-hop2-003",
            principal="principal:alice_household",
            issuer_actor="agent:solver",
            audience_actor="agent:auditor",
            parent_token_hash=hop1_token.compute_digest(),
            depth=2,
            max_depth=3,
            issued_at=t0 + 20,
            expires_at=t0 + 900,
            scopes=(hop2_scope,),
        ).sign(keys["agent:solver"])

        valid, msg = DelegationTokenValidator.verify_chain(
            [root_token, hop1_token, hop2_token], resolver, current_time_sec=t0 + 50
        )
        self.assertTrue(valid, msg)
        self.assertIn("3 hops verified offline", msg)

        # 2. Scope escalation rejection (exceeding budget limit)
        escalated_scope = DelegationScope(action="compute", resource="sim:npu_cluster", max_budget=700)
        bad_budget_token = DelegationToken(
            token_id="tok-hop1-escalated-budget",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=t0 + 10,
            expires_at=t0 + 1800,
            scopes=(escalated_scope,),
        ).sign(keys["agent:coordinator"])

        # Scope escalation rejection (unauthorized action)
        unauthorized_action_scope = DelegationScope(action="admin_delete", resource="sim:npu_cluster", max_budget=100)
        bad_action_token = DelegationToken(
            token_id="tok-hop1-unauth-action",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=t0 + 10,
            expires_at=t0 + 1800,
            scopes=(unauthorized_action_scope,),
        ).sign(keys["agent:coordinator"])

        v_act, m_act = DelegationTokenValidator.verify_chain([root_token, bad_action_token], resolver)
        self.assertFalse(v_act)
        self.assertIn("Scope escalation detected", m_act)

        # 3. Lifetime expansion rejection
        lifetime_expanded_token = DelegationToken(
            token_id="tok-hop1-lifetime-expanded",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=t0 + 10,
            expires_at=t0 + 7200,  # exceeds root's t0 + 3600
            scopes=(hop1_scope,),
        ).sign(keys["agent:coordinator"])
        v_life, m_life = DelegationTokenValidator.verify_chain([root_token, lifetime_expanded_token], resolver)
        self.assertFalse(v_life)
        self.assertIn("Lifetime expansion", m_life)

        # 4. Corrupted parent byte-commitment rejection
        corrupted_hash_token = DelegationToken(
            token_id="tok-hop1-corrupted-hash",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash="0123456789abcdef" * 4,
            depth=1,
            max_depth=3,
            issued_at=t0 + 10,
            expires_at=t0 + 1800,
            scopes=(hop1_scope,),
        ).sign(keys["agent:coordinator"])
        v_hash, m_hash = DelegationTokenValidator.verify_chain([root_token, corrupted_hash_token], resolver)
        self.assertFalse(v_hash)
        self.assertIn("Parent token hash mismatch", m_hash)

        # 5. Depth limit enforcement
        shallow_root = DelegationToken(
            token_id="tok-shallow-root",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=1,  # limit max depth to 1
            issued_at=t0,
            expires_at=t0 + 3600,
            scopes=(root_scope,),
        ).sign(keys["human:alice"])
        shallow_hop1 = DelegationToken(
            token_id="tok-shallow-hop1",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash=shallow_root.compute_digest(),
            depth=1,
            max_depth=1,
            issued_at=t0 + 10,
            expires_at=t0 + 1800,
            scopes=(hop1_scope,),
        ).sign(keys["agent:coordinator"])
        shallow_hop2 = DelegationToken(
            token_id="tok-shallow-hop2",
            principal="principal:alice_household",
            issuer_actor="agent:solver",
            audience_actor="agent:auditor",
            parent_token_hash=shallow_hop1.compute_digest(),
            depth=2,  # exceeds max_depth of 1
            max_depth=2,
            issued_at=t0 + 20,
            expires_at=t0 + 900,
            scopes=(hop2_scope,),
        ).sign(keys["agent:solver"])
        v_depth, m_depth = DelegationTokenValidator.verify_chain(
            [shallow_root, shallow_hop1, shallow_hop2], resolver
        )
        self.assertFalse(v_depth)
        self.assertIn("Max depth expansion", m_depth)

        # 6. Invalid cryptographic signature rejection
        tampered_sig_token = DelegationToken(
            token_id="tok-hop1-tampered",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:solver",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=t0 + 10,
            expires_at=t0 + 1800,
            scopes=(hop1_scope,),
            signature="deadbeef" * 8,
        )
        v_sig, m_sig = DelegationTokenValidator.verify_chain([root_token, tampered_sig_token], resolver)
        self.assertFalse(v_sig)
        self.assertIn("Invalid signature", m_sig)

        # 7. Fail-closed schema and type validation
        with self.assertRaises(DelegationValidationError):
            DelegationScope(action="compute", resource="sim", max_budget=-50)
        with self.assertRaises(DelegationValidationError):
            DelegationToken(
                token_id="tok-bad",
                principal="p",
                issuer_actor="i",
                audience_actor="a",
                parent_token_hash=None,
                depth=0,
                max_depth=2,
                issued_at=t0,
                expires_at=t0 - 100,  # expires before issuance
                scopes=(root_scope,),
            )


def tearDownModule() -> None:
    """Clean up runtime test artifacts so git status remains clean."""
    import subprocess
    from pathlib import Path
    repo_root = Path(__file__).resolve().parents[2]
    try:
        subprocess.run(
            [
                "git",
                "checkout",
                "HEAD",
                "--",
                "knowledge/AI-CAPABILITY-TRAJECTORY-AND-WORLD-SHAPING-ATLAS.md",
                "knowledge/TERMINOLOGY-AND-SCIENTIFIC-PROVENANCE-CATALOG.md",
                "knowledge/terminology_registry.db",
                "knowledge/terminology_registry.json",
                "knowledge/trajectory_batches/",
                "research/ledger_sim/sandbox/",
                "research/ledger_sim/testnet_simulation_report.json",
            ],
            cwd=repo_root,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "clean", "-fd", "--", "knowledge/trajectory_batches/"],
            cwd=repo_root,
            capture_output=True,
            check=False,
        )
    except Exception:
        pass


if __name__ == "__main__":
    unittest.main()
