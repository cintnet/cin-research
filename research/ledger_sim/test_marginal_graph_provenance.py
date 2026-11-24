"""
Unit Tests for Marginal Graph Utility & Cryptographic Provenance Module
(research/ledger_sim/test_marginal_graph_provenance.py)

Tests:
  - W3C PROV-DM entity, activity, agent, and relation validation.
  - Causal integrity verification and cycle detection.
  - Proof-Carrying Code (Necula, 1997) predicate evaluation.
  - DyLAN Agent Importance Scoring (AIS) power iteration and node filtering.
  - AgentPrune graph sparsification and token efficiency calculation.
  - Standalone receipt verification.
  - Strict Steward Gate adherence (zero unapproved tokens or speculative dollar claims).
"""

import json
import unittest
from datetime import datetime, timezone

from research.ledger_sim.marginal_graph_provenance import (
    AgentNode,
    AgentPruneGraphOptimizer,
    AgentSlimmingGraphCompressor,
    AgentSlimmingResult,
    ContainmentPolicyViolation,
    DyLANImportanceScorer,
    GPTSwarmEdge,
    GPTSwarmExecutionReceipt,
    GPTSwarmGraphOptimizer,
    GPTSwarmNode,
    GPTSwarmOptimizableGraph,
    GraphEdge,
    ProvActivity,
    ProvAgent,
    ProvEntity,
    ProvRelation,
    W3CProvDocument,
    canonical_sha256,
    verify_w3c_prov_receipt,
)


class TestMarginalGraphProvenance(unittest.TestCase):

    def setUp(self):
        self.now_iso = datetime.now(timezone.utc).isoformat()
        self.dummy_digest = canonical_sha256({"test": "data"})

    def test_prov_entity_validation_fail_closed(self):
        """ProvEntity must enforce valid IDs and 64-char SHA-256 digests."""
        valid_entity = ProvEntity(
            entity_id="entity-test-1",
            entity_type="TaskObjective",
            content_digest=self.dummy_digest
        )
        valid_entity.validate()

        # Empty entity_id
        with self.assertRaises(ValueError):
            ProvEntity("", "TaskObjective", self.dummy_digest).validate()

        # Malformed entity_id
        with self.assertRaises(ValueError):
            ProvEntity("entity with spaces!", "TaskObjective", self.dummy_digest).validate()

        # Malformed digest (non-64 hex)
        with self.assertRaises(ValueError):
            ProvEntity("entity-1", "TaskObjective", "bad_digest").validate()

    def test_prov_activity_validation_temporal_order(self):
        """ProvActivity must enforce start_time <= end_time."""
        t_start = "2026-11-05T03:00:00+00:00"
        t_end = "2026-11-05T03:05:00+00:00"
        t_early = "2026-11-05T02:55:00+00:00"

        act_ok = ProvActivity(
            activity_id="act-1",
            activity_type="Optimization",
            start_time_iso=t_start,
            end_time_iso=t_end,
            parameters_digest=self.dummy_digest
        )
        act_ok.validate()

        # End time preceding start time must raise ValueError
        with self.assertRaises(ValueError):
            ProvActivity(
                activity_id="act-err",
                activity_type="Optimization",
                start_time_iso=t_start,
                end_time_iso=t_early,
                parameters_digest=self.dummy_digest
            ).validate()

    def test_w3c_prov_document_integrity_and_cycle_detection(self):
        """W3CProvDocument detects missing reference endpoints and causal cycles."""
        doc = W3CProvDocument("doc-trace-001")

        e1 = ProvEntity("e1", "InputData", self.dummy_digest)
        e2 = ProvEntity("e2", "OutputPlan", self.dummy_digest)
        doc.add_entity(e1)
        doc.add_entity(e2)

        act = ProvActivity("a1", "Processing", self.now_iso, self.now_iso, self.dummy_digest, ("e1",))
        doc.add_activity(act)

        ag = ProvAgent("ag1", "PersonalAgent", "device-owner")
        doc.add_agent(ag)

        doc.add_relation(ProvRelation("used", "a1", "e1"))
        doc.add_relation(ProvRelation("wasGeneratedBy", "e2", "a1"))
        doc.add_relation(ProvRelation("wasAssociatedWith", "a1", "ag1"))
        doc.add_relation(ProvRelation("wasDerivedFrom", "e2", "e1"))

        valid, errors = doc.verify_integrity()
        self.assertTrue(valid, f"Expected valid document but got errors: {errors}")
        self.assertEqual(len(errors), 0)

        # Introduce a causal cycle: e1 derived from e2
        doc.add_relation(ProvRelation("wasDerivedFrom", "e1", "e2"))
        valid_cycle, cycle_errors = doc.verify_integrity()
        self.assertFalse(valid_cycle)
        self.assertTrue(any("Causal cycle" in err for err in cycle_errors))

    def test_proof_carrying_code_verification(self):
        """Verifies Necula 1997 Proof-Carrying Code machine-checkable predicates."""
        doc = W3CProvDocument("doc-pcc-01")
        e1 = ProvEntity("e-data", "HealthRecordSummary", self.dummy_digest)
        act = ProvActivity("act-local", "Audit", self.now_iso, self.now_iso, self.dummy_digest, ("e-data",))
        ag = ProvAgent("ag-shield", "LocalAgent", "device-owner")

        doc.add_entity(e1)
        doc.add_activity(act)
        doc.add_agent(ag)
        doc.add_relation(ProvRelation("used", "act-local", "e-data"))
        doc.add_relation(ProvRelation("wasAssociatedWith", "act-local", "ag-shield"))

        # Safety predicate: strictly 0 network egress and local agent only
        def safety_predicate(doc_dict):
            agents = doc_dict.get("agents", {})
            return all(a.get("agent_type") == "LocalAgent" for a in agents.values())

        self.assertTrue(doc.verify_proof_carrying_code(safety_predicate))

        # Malicious predicate failure
        def failing_predicate(doc_dict):
            return "cloud-third-party" in doc_dict.get("agents", {})

        self.assertFalse(doc.verify_proof_carrying_code(failing_predicate))

    def test_dylan_agent_importance_scoring_and_subgraph_filtering(self):
        """DyLAN AIS dynamically scores agent contribution and filters active subgraphs."""
        nodes = [
            AgentNode("agent-1", "Shield (Local Privacy)", ("privacy", "filtering"), task_accuracy_score=0.9),
            AgentNode("agent-2", "Focus (Task Decomposition)", ("planning",), task_accuracy_score=0.85),
            AgentNode("agent-3", "Craft (Specialist Synthesis)", ("synthesis",), task_accuracy_score=0.8),
            AgentNode("agent-4", "Noisy Echo (Redundant)", ("chat",), task_accuracy_score=0.05),
        ]

        edges = [
            GraphEdge("agent-1", "agent-2", weight=0.9),
            GraphEdge("agent-2", "agent-3", weight=0.85),
            GraphEdge("agent-3", "agent-1", weight=0.4),
            GraphEdge("agent-4", "agent-2", weight=0.02),  # low utility edge
        ]

        scorer = DyLANImportanceScorer(damping_factor=0.85)
        scores = scorer.compute_agent_importance_scores(nodes, edges)

        self.assertEqual(len(scores), 4)
        self.assertGreater(scores["agent-1"], scores["agent-4"])
        self.assertGreater(scores["agent-2"], scores["agent-4"])
        self.assertGreater(scores["agent-3"], scores["agent-4"])

        # Filter active subgraph with threshold 0.15
        active = scorer.filter_active_subgraph(nodes, scores, min_importance_threshold=0.15)
        active_ids = {n.agent_id for n in active}
        self.assertNotIn("agent-4", active_ids)
        self.assertIn("agent-1", active_ids)
        self.assertIn("agent-2", active_ids)

    def test_agent_prune_sparsification_and_provenance_envelope(self):
        """AgentPrune systematically prunes redundant edges and generates W3C PROV-DM envelopes."""
        nodes = [
            AgentNode("a1", "Shield", ("privacy",)),
            AgentNode("a2", "Planner", ("planning",)),
            AgentNode("a3", "Executor", ("execution",)),
            AgentNode("a4", "Verifier", ("verification",)),
        ]

        # Fully connected 4x3 = 12 directed edges
        dense_edges = []
        for src in nodes:
            for tgt in nodes:
                if src.agent_id != tgt.agent_id:
                    # high weights along pipeline, low weights across others
                    w = 0.95 if (src.agent_id, tgt.agent_id) in [("a1", "a2"), ("a2", "a3"), ("a3", "a4"), ("a4", "a1")] else 0.1
                    dense_edges.append(GraphEdge(src.agent_id, tgt.agent_id, weight=w, token_cost=100))

        optimizer = AgentPruneGraphOptimizer(target_sparsity_pct=60.0)
        retained, stats = optimizer.sparsify_graph(nodes, dense_edges, "Secure P2P Coordination")

        self.assertLess(len(retained), len(dense_edges))
        self.assertGreater(stats["token_savings_pct"], 40.0)
        self.assertEqual(stats["original_edges"], 12)
        self.assertGreater(stats["pruned_edges"], 0)

        # Generate W3C PROV envelope
        prov_doc = optimizer.create_prov_envelope(
            task_id="task-42",
            task_description="Secure P2P Coordination without centralized platform lock-in",
            active_nodes=nodes,
            retained_edges=retained,
            stats=stats
        )

        valid, errors = prov_doc.verify_integrity()
        self.assertTrue(valid, f"PROV envelope failed integrity check: {errors}")

        doc_dict = prov_doc.to_dict()
        receipt_valid, receipt_errors = verify_w3c_prov_receipt(doc_dict)
        self.assertTrue(receipt_valid, f"Receipt failed standalone check: {receipt_errors}")

    def test_agent_slimming_hybrid_importance_rrf(self):
        """Verifies AgentSlimming Reciprocal Rank Fusion (RRF) hybrid importance ranking."""
        nodes = [
            AgentNode("a1", "Shield (Local Privacy)", ("privacy",), task_accuracy_score=0.95),
            AgentNode("a2", "Focus (Priority Decomposition)", ("planning",), task_accuracy_score=0.88),
            AgentNode("a3", "Craft (Execution Synthesis)", ("synthesis",), task_accuracy_score=0.82),
            AgentNode("a4", "Redundant Echo", ("chat",), task_accuracy_score=0.10),
        ]
        edges = [
            GraphEdge("a1", "a2", weight=0.9, message_count=5),
            GraphEdge("a2", "a3", weight=0.85, message_count=4),
            GraphEdge("a3", "a1", weight=0.7, message_count=3),
            GraphEdge("a4", "a1", weight=0.1, message_count=1),
        ]
        compressor = AgentSlimmingGraphCompressor(rrf_k=60, tolerance_epsilon=0.05)
        scores = compressor.compute_hybrid_importance(nodes, edges)

        self.assertEqual(len(scores), 4)
        self.assertAlmostEqual(sum(scores.values()), 1.0, places=2)
        # a1 (high topo + high func) must have the highest RRF score
        self.assertGreater(scores["a1"], scores["a4"])
        # a4 (low topo + low func) must have the lowest score
        self.assertLess(scores["a4"], scores["a2"])

    def test_agent_slimming_baseline_anchored_acceptance_and_compression(self):
        """Verifies baseline-anchored acceptance Q(G') >= (1 - eps) * Q(G) and token reduction."""
        nodes = [
            AgentNode("a1", "Core Shield", ("privacy",), input_token_cost=50, output_token_count=100, task_accuracy_score=0.95),
            AgentNode("a2", "Planner", ("planning",), input_token_cost=60, output_token_count=120, task_accuracy_score=0.90),
            AgentNode("a3", "Worker", ("execution",), input_token_cost=70, output_token_count=150, task_accuracy_score=0.88),
            AgentNode("a4", "Bloat Node 1", ("filler",), input_token_cost=80, output_token_count=200, task_accuracy_score=0.15),
            AgentNode("a5", "Bloat Node 2", ("filler",), input_token_cost=80, output_token_count=200, task_accuracy_score=0.12),
        ]
        edges = []
        for src in nodes:
            for tgt in nodes:
                if src.agent_id != tgt.agent_id:
                    edges.append(GraphEdge(src.agent_id, tgt.agent_id, weight=0.6, token_cost=50))

        compressor = AgentSlimmingGraphCompressor(rrf_k=60, tolerance_epsilon=0.05)
        result = compressor.compress_workflow(
            nodes=nodes,
            dense_edges=edges,
            task_objective="Optimize Medical Claim Billing Coordination",
            task_id="slimming-001",
            min_retained_nodes=3
        )

        self.assertIsInstance(result, AgentSlimmingResult)
        self.assertTrue(result.baseline_acceptance_passed)
        self.assertIn("a4", result.pruned_node_ids)
        self.assertIn("a5", result.pruned_node_ids)
        self.assertEqual(result.retained_nodes, 3)
        self.assertGreater(result.token_savings_pct, 40.0)
        self.assertGreater(result.pruned_edges, 0)
        self.assertIsNotNone(result.prov_envelope)

        valid, errors = result.prov_envelope.verify_integrity()
        self.assertTrue(valid, f"PROV envelope verification failed: {errors}")

    def test_agent_slimming_fail_closed_validation(self):
        """Validates fail-closed input bounds for AgentSlimmingGraphCompressor."""
        # Non-positive or non-int rrf_k
        with self.assertRaises(ValueError):
            AgentSlimmingGraphCompressor(rrf_k=0)
        with self.assertRaises(ValueError):
            AgentSlimmingGraphCompressor(rrf_k=-10)

        # Out-of-bounds tolerance_epsilon
        with self.assertRaises(ValueError):
            AgentSlimmingGraphCompressor(tolerance_epsilon=-0.01)
        with self.assertRaises(ValueError):
            AgentSlimmingGraphCompressor(tolerance_epsilon=0.55)

        # Empty nodes in compress_workflow
        compressor = AgentSlimmingGraphCompressor()
        with self.assertRaises(ValueError):
            compressor.compress_workflow(nodes=[], dense_edges=[], task_objective="test", task_id="t1")

    def test_steward_gate_compliance(self):
        """Enforces that serialized provenance documents never include unapproved token balances."""
        doc = W3CProvDocument("doc-steward-check")
        e = ProvEntity("e-test", "Artifact", self.dummy_digest)
        doc.add_entity(e)
        serialized = json.dumps(doc.to_dict())

        # Prohibited terms check
        self.assertNotIn("Contribution Tokens", serialized)
        self.assertNotIn("MMCT", serialized)
        self.assertNotIn("mmctBalance", serialized)
        self.assertNotIn("Somatic Witness", serialized)

    def test_gptswarm_node_validation_and_containment_fail_closed(self):
        """GPTSwarmNode must enforce valid IDs, declared operations, and token limits fail-closed."""
        node = GPTSwarmNode(
            node_id="analyst-1",
            role_name="MarketAnalyst",
            allowed_operations=("read_context", "analyze_rates"),
            max_input_tokens=100,
            max_output_tokens=100,
            accuracy_score=0.90,
        )
        node.validate()

        # Undeclared operation raises ContainmentPolicyViolation
        with self.assertRaises(ContainmentPolicyViolation):
            node.execute_operation("unauthorized_shell_exec", {"input": "test"})

        # Input payload exceeding max_input_tokens raises ContainmentPolicyViolation
        large_input = {"data": "x" * 600}  # ~150 tokens
        with self.assertRaises(ContainmentPolicyViolation):
            node.execute_operation("read_context", large_input)

        # Successful sandboxed execution
        res = node.execute_operation("read_context", {"data": "nominal"})
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["operation"], "read_context")

    def test_gptswarm_edge_validation_and_self_loops(self):
        """GPTSwarmEdge rejects self-loops, negative costs, and out-of-range weights."""
        valid_edge = GPTSwarmEdge("node-a", "node-b", weight=0.75, token_cost=100)
        valid_edge.validate()

        # Self loop rejected
        with self.assertRaises(ValueError):
            GPTSwarmEdge("node-a", "node-a").validate()

        # Invalid weight
        with self.assertRaises(ValueError):
            GPTSwarmEdge("node-a", "node-b", weight=1.5).validate()

        # Negative token cost
        with self.assertRaises(ValueError):
            GPTSwarmEdge("node-a", "node-b", token_cost=-10).validate()

    def test_gptswarm_dag_cycle_detection_and_topological_execution(self):
        """GPTSwarmOptimizableGraph detects cycles and executes DAG in strict topological order."""
        graph = GPTSwarmOptimizableGraph("swarm-dag-1", "Audit Healthcare Pricing")
        n1 = GPTSwarmNode("ingest", "DataIngest", ("read_context",), accuracy_score=0.92)
        n2 = GPTSwarmNode("auditor", "PriceAuditor", ("infer",), accuracy_score=0.88)
        n3 = GPTSwarmNode("verifier", "AuditVerifier", ("verify",), accuracy_score=0.95)

        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_node(n3)

        graph.add_edge(GPTSwarmEdge("ingest", "auditor"))
        graph.add_edge(GPTSwarmEdge("auditor", "verifier"))

        order = graph.get_topological_order()
        self.assertEqual(order, ["ingest", "auditor", "verifier"])

        exec_res = graph.execute_graph({"initial": "pricing_table"})
        self.assertEqual(exec_res["order"], ["ingest", "auditor", "verifier"])
        self.assertIn("ingest", exec_res["outputs"])
        self.assertIn("auditor", exec_res["outputs"])
        self.assertIn("verifier", exec_res["outputs"])

        # Add cycle edge verifier -> ingest
        graph.add_edge(GPTSwarmEdge("verifier", "ingest"))
        with self.assertRaises(ValueError):
            graph.get_topological_order()

    def test_gptswarm_graph_optimizer_and_prov_envelope(self):
        """GPTSwarmGraphOptimizer prunes redundant edges and generates W3C PROV-DM cryptographic receipts."""
        graph = GPTSwarmOptimizableGraph("swarm-opt-1", "Synthesize Community GPO")
        n1 = GPTSwarmNode("coordinator", "Coordinator", ("read_context",), accuracy_score=0.90)
        n2 = GPTSwarmNode("buyer_a", "BuyerAgent", ("infer",), accuracy_score=0.85)
        n3 = GPTSwarmNode("buyer_b", "BuyerAgent", ("infer",), accuracy_score=0.85)
        n4 = GPTSwarmNode("summarizer", "Summarizer", ("verify",), accuracy_score=0.92)

        for n in [n1, n2, n3, n4]:
            graph.add_node(n)

        # Dense connectivity
        graph.add_edge(GPTSwarmEdge("coordinator", "buyer_a", weight=0.9, token_cost=200))
        graph.add_edge(GPTSwarmEdge("coordinator", "buyer_b", weight=0.9, token_cost=200))
        graph.add_edge(GPTSwarmEdge("buyer_a", "summarizer", weight=0.85, token_cost=200))
        graph.add_edge(GPTSwarmEdge("buyer_b", "summarizer", weight=0.85, token_cost=200))
        # Redundant low-weight shortcut edge
        graph.add_edge(GPTSwarmEdge("coordinator", "summarizer", weight=0.1, token_cost=200))

        optimizer = GPTSwarmGraphOptimizer(accuracy_threshold=0.80)
        receipt = optimizer.optimize_topology(graph, max_edge_prunes=2)

        self.assertIsInstance(receipt, GPTSwarmExecutionReceipt)
        self.assertEqual(receipt.topology_type, "gptswarm_optimizable_graph")
        self.assertTrue(receipt.token_savings_pct >= 0.0)
        self.assertTrue(receipt.quality_score >= 0.80)
        self.assertEqual(len(receipt.prov_envelope_digest), 64)

        # Verify receipt with standalone W3C PROV-DM verifier
        valid, errs = verify_w3c_prov_receipt(receipt.prov_document)
        self.assertTrue(valid, f"Receipt validation errors: {errs}")

        # Steward Gate compliance on receipt
        receipt_json = json.dumps(receipt.prov_document)
        self.assertNotIn("Contribution Tokens", receipt_json)
        self.assertNotIn("MMCT", receipt_json)
        self.assertNotIn("mmctBalance", receipt_json)
        self.assertNotIn("+$", receipt_json)


if __name__ == "__main__":
    unittest.main()
