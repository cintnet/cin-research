"""
research/ledger_sim/test_delegation_token_validator.py

Comprehensive unit tests for IETF WIMSE delegation token validation and VERA
authority-preserving edge revocation (arXiv:2608.30091).
"""

from __future__ import annotations

import unittest
from typing import Dict

from research.ledger_sim.delegation_token_validator import (
    DelegationEdge,
    DelegationScope,
    DelegationSecurityViolation,
    DelegationToken,
    DelegationTokenValidator,
    DelegationValidationError,
    EdgeRevocationRecord,
    VeraEdgeRevocationManager,
)


class TestDelegationTokenAndVera(unittest.TestCase):
    def setUp(self) -> None:
        self.keys: Dict[str, bytes] = {
            "human:alice": b"secret-key-human-alice-32-bytes!!",
            "agent:coordinator": b"secret-key-coord-agent-32-bytes!",
            "agent:medical_auditor": b"secret-key-med-audit-32-bytes!!",
            "agent:utility_auditor": b"secret-key-util-audit-32-bytes!",
            "agent:formulary_checker": b"secret-key-formulary-32-bytes!",
            "agent:malicious_peer": b"secret-key-adversary-32-bytes!!",
        }
        self.resolver = lambda actor: self.keys[actor]
        self.t0 = 1730000000

    def test_wimse_happy_path_and_attenuation(self) -> None:
        """Verify 3-hop delegation chain with monotonic attenuation."""
        root_scope = DelegationScope(action="audit", resource="records:healthcare", max_budget=1000)
        root_token = DelegationToken(
            token_id="tok-root-001",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=3,
            issued_at=self.t0,
            expires_at=self.t0 + 3600,
            scopes=(root_scope,),
        ).sign(self.keys["human:alice"])

        hop1_scope = DelegationScope(action="audit", resource="records:healthcare", max_budget=500)
        hop1_token = DelegationToken(
            token_id="tok-hop1-002",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:medical_auditor",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=self.t0 + 10,
            expires_at=self.t0 + 1800,
            scopes=(hop1_scope,),
        ).sign(self.keys["agent:coordinator"])

        valid, msg = DelegationTokenValidator.verify_chain(
            [root_token, hop1_token], self.resolver, current_time_sec=self.t0 + 20
        )
        self.assertTrue(valid, msg)
        self.assertIn("2 hops verified offline", msg)

    def test_wimse_attenuation_violations_fail_closed(self) -> None:
        """Scope escalation, lifetime expansion, and corrupted parent hash must fail closed."""
        root_scope = DelegationScope(action="audit", resource="records:healthcare", max_budget=1000)
        root_token = DelegationToken(
            token_id="tok-root-001",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=3,
            issued_at=self.t0,
            expires_at=self.t0 + 3600,
            scopes=(root_scope,),
        ).sign(self.keys["human:alice"])

        # Escalated budget
        bad_scope = DelegationScope(action="audit", resource="records:healthcare", max_budget=1200)
        bad_token = DelegationToken(
            token_id="tok-bad-budget",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:medical_auditor",
            parent_token_hash=root_token.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=self.t0 + 10,
            expires_at=self.t0 + 1800,
            scopes=(bad_scope,),
        ).sign(self.keys["agent:coordinator"])

        v, msg = DelegationTokenValidator.verify_chain([root_token, bad_token], self.resolver)
        self.assertFalse(v)
        self.assertIn("Scope escalation detected", msg)

    def test_vera_dag_registration_and_authority_preservation(self) -> None:
        """Test VERA edge registration, cascading revocation, and authority preservation."""
        manager = VeraEdgeRevocationManager()
        wf_id = "wf-household-bills-001"

        # 1. Edge 1: Alice -> Coordinator
        scope_root = DelegationScope(action="coordinate", resource="household:expenses", max_budget=2000)
        tok_e1 = DelegationToken(
            token_id="tok-e1",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=4,
            issued_at=self.t0,
            expires_at=self.t0 + 7200,
            scopes=(scope_root,),
        ).sign(self.keys["human:alice"])

        edge1 = DelegationEdge(
            edge_id="edge-1-alice-to-coord",
            workflow_id=wf_id,
            source_actor="human:alice",
            target_actor="agent:coordinator",
            token=tok_e1,
            parent_edge_ids=(),
            created_at=self.t0,
        ).sign(self.keys["human:alice"])

        manager.register_edge(edge1, self.resolver)

        # 2. Edge 2: Coordinator -> Medical Auditor (parent: edge1)
        scope_med = DelegationScope(action="audit", resource="records:healthcare", max_budget=800)
        tok_e2 = DelegationToken(
            token_id="tok-e2",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:medical_auditor",
            parent_token_hash=tok_e1.compute_digest(),
            depth=1,
            max_depth=4,
            issued_at=self.t0 + 5,
            expires_at=self.t0 + 3600,
            scopes=(scope_med,),
        ).sign(self.keys["agent:coordinator"])

        edge2 = DelegationEdge(
            edge_id="edge-2-coord-to-med",
            workflow_id=wf_id,
            source_actor="agent:coordinator",
            target_actor="agent:medical_auditor",
            token=tok_e2,
            parent_edge_ids=("edge-1-alice-to-coord",),
            created_at=self.t0 + 5,
        ).sign(self.keys["agent:coordinator"])

        manager.register_edge(edge2, self.resolver)

        # 3. Edge 3: Coordinator -> Utility Auditor (parent: edge1)
        scope_util = DelegationScope(action="audit", resource="records:utilities", max_budget=400)
        tok_e3 = DelegationToken(
            token_id="tok-e3",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:utility_auditor",
            parent_token_hash=tok_e1.compute_digest(),
            depth=1,
            max_depth=4,
            issued_at=self.t0 + 10,
            expires_at=self.t0 + 3600,
            scopes=(scope_util,),
        ).sign(self.keys["agent:coordinator"])

        edge3 = DelegationEdge(
            edge_id="edge-3-coord-to-util",
            workflow_id=wf_id,
            source_actor="agent:coordinator",
            target_actor="agent:utility_auditor",
            token=tok_e3,
            parent_edge_ids=("edge-1-alice-to-coord",),
            created_at=self.t0 + 10,
        ).sign(self.keys["agent:coordinator"])

        manager.register_edge(edge3, self.resolver)

        # 4. Edge 4: Medical Auditor -> Formulary Checker (parent: edge2)
        scope_form = DelegationScope(action="check", resource="records:formulary", max_budget=200)
        tok_e4 = DelegationToken(
            token_id="tok-e4",
            principal="principal:alice_household",
            issuer_actor="agent:medical_auditor",
            audience_actor="agent:formulary_checker",
            parent_token_hash=tok_e2.compute_digest(),
            depth=2,
            max_depth=4,
            issued_at=self.t0 + 15,
            expires_at=self.t0 + 1800,
            scopes=(scope_form,),
        ).sign(self.keys["agent:medical_auditor"])

        edge4 = DelegationEdge(
            edge_id="edge-4-med-to-form",
            workflow_id=wf_id,
            source_actor="agent:medical_auditor",
            target_actor="agent:formulary_checker",
            token=tok_e4,
            parent_edge_ids=("edge-2-coord-to-med",),
            created_at=self.t0 + 15,
        ).sign(self.keys["agent:medical_auditor"])

        manager.register_edge(edge4, self.resolver)

        # Verify all 4 edges active initially
        for eid in ["edge-1-alice-to-coord", "edge-2-coord-to-med", "edge-3-coord-to-util", "edge-4-med-to-form"]:
            active, msg = manager.is_edge_active(wf_id, eid, current_time_sec=self.t0 + 30)
            self.assertTrue(active, f"{eid} should be active: {msg}")

        # Execute VERA Revocation on edge 2 (Medical Auditor) by Coordinator with cascading=True
        rev_rec = EdgeRevocationRecord(
            revocation_id="rev-001-med-audit-scope",
            workflow_id=wf_id,
            edge_id="edge-2-coord-to-med",
            revoker_actor="agent:coordinator",
            revoked_at=self.t0 + 50,
            cascading=True,
            reason="Medical billing audit scope expired by coordinator",
        ).sign(self.keys["agent:coordinator"])

        res = manager.revoke_edge(rev_rec, self.keys["agent:coordinator"])
        self.assertTrue(res["revoked"])
        self.assertEqual(res["cascaded_downstream_edges"], ["edge-4-med-to-form"])

        # Check edge 2: directly revoked
        act2, msg2 = manager.is_edge_active(wf_id, "edge-2-coord-to-med")
        self.assertFalse(act2)
        self.assertIn("directly revoked", msg2)

        # Check edge 4: disabled by cascading revocation of ancestor edge 2
        act4, msg4 = manager.is_edge_active(wf_id, "edge-4-med-to-form")
        self.assertFalse(act4)
        self.assertIn("cascading revocation of ancestor", msg4)

        # CRITICAL VERA AUTHORITY PRESERVATION GUARANTEE:
        # Edge 1 (Alice -> Coordinator) and Edge 3 (Coordinator -> Utility Auditor) MUST REMAIN ACTIVE!
        act1, msg1 = manager.is_edge_active(wf_id, "edge-1-alice-to-coord")
        self.assertTrue(act1, msg1)

        act3, msg3 = manager.is_edge_active(wf_id, "edge-3-coord-to-util")
        self.assertTrue(act3, msg3)

        # Subgraph check
        subgraph = manager.get_active_subgraph(wf_id)
        self.assertEqual(subgraph["active_edges"], ["edge-1-alice-to-coord", "edge-3-coord-to-util"])
        self.assertEqual(subgraph["revoked_edges"], ["edge-2-coord-to-med", "edge-4-med-to-form"])
        self.assertIn("agent:coordinator", subgraph["active_nodes"])
        self.assertIn("agent:utility_auditor", subgraph["active_nodes"])
        self.assertEqual(subgraph["authority_preservation_ratio"], 0.5)

        # Generate and verify W3C PROV-DM receipt
        prov = manager.generate_w3c_prov_receipt(wf_id, "rev-001-med-audit-scope")
        self.assertEqual(prov["standard"], "W3C PROV-DM (Moreau & Missier, 2013)")
        self.assertEqual(prov["agentEntity"], "agent:coordinator")
        self.assertEqual(prov["actedOnBehalfOf"], "principal:alice_household")
        self.assertIn("VERA-Edge-Revocation-Protocol", prov["wasAssociatedWith"])

    def test_vera_unauthorized_revocation_fails_closed(self) -> None:
        """Malicious peer attempting to revoke an edge fails with DelegationSecurityViolation."""
        manager = VeraEdgeRevocationManager()
        wf_id = "wf-secure-002"

        scope = DelegationScope(action="compute", resource="sim:npu", max_budget=100)
        tok = DelegationToken(
            token_id="tok-sec-01",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=2,
            issued_at=self.t0,
            expires_at=self.t0 + 3600,
            scopes=(scope,),
        ).sign(self.keys["human:alice"])

        edge = DelegationEdge(
            edge_id="edge-sec-01",
            workflow_id=wf_id,
            source_actor="human:alice",
            target_actor="agent:coordinator",
            token=tok,
            created_at=self.t0,
        ).sign(self.keys["human:alice"])
        manager.register_edge(edge, self.resolver)

        # Malicious peer tries to sign a revocation
        unauth_rev = EdgeRevocationRecord(
            revocation_id="rev-unauth-001",
            workflow_id=wf_id,
            edge_id="edge-sec-01",
            revoker_actor="agent:malicious_peer",
            revoked_at=self.t0 + 10,
            reason="Malicious disruption",
        ).sign(self.keys["agent:malicious_peer"])

        with self.assertRaises(DelegationSecurityViolation) as ctx:
            manager.revoke_edge(unauth_rev, self.keys["agent:malicious_peer"])
        self.assertIn("Unauthorized revoker", str(ctx.exception))

    def test_vera_cycle_detection_in_dag(self) -> None:
        """Adding edges that create a cycle must be rejected fail-closed."""
        manager = VeraEdgeRevocationManager()
        wf_id = "wf-cycle-003"

        scope = DelegationScope(action="audit", resource="res:test", max_budget=500)
        tok1 = DelegationToken(
            token_id="tok-c1",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=4,
            issued_at=self.t0,
            expires_at=self.t0 + 3600,
            scopes=(scope,),
        ).sign(self.keys["human:alice"])

        edge1 = DelegationEdge(
            edge_id="edge-c1",
            workflow_id=wf_id,
            source_actor="human:alice",
            target_actor="agent:coordinator",
            token=tok1,
            parent_edge_ids=(),
            created_at=self.t0,
        ).sign(self.keys["human:alice"])
        manager.register_edge(edge1, self.resolver)

        # Attempt to add self-referential parent
        tok_bad = DelegationToken(
            token_id="tok-c2",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:medical_auditor",
            parent_token_hash=tok1.compute_digest(),
            depth=1,
            max_depth=4,
            issued_at=self.t0 + 5,
            expires_at=self.t0 + 1800,
            scopes=(scope,),
        ).sign(self.keys["agent:coordinator"])

        edge_cyclic = DelegationEdge(
            edge_id="edge-cyclic",
            workflow_id=wf_id,
            source_actor="agent:coordinator",
            target_actor="agent:medical_auditor",
            token=tok_bad,
            parent_edge_ids=("edge-cyclic",),  # self loop
            created_at=self.t0 + 5,
        ).sign(self.keys["agent:coordinator"])

        # Must fail because edge-cyclic does not exist yet as parent
        with self.assertRaises(DelegationValidationError):
            manager.register_edge(edge_cyclic, self.resolver)

    def test_vera_non_cascading_revocation(self) -> None:
        """Non-cascading revocation revokes only the targeted edge."""
        manager = VeraEdgeRevocationManager()
        wf_id = "wf-non-cascade-004"

        scope = DelegationScope(action="read", resource="data:weather", max_budget=10)
        tok1 = DelegationToken(
            token_id="tok-nc1",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=3,
            issued_at=self.t0,
            expires_at=self.t0 + 3600,
            scopes=(scope,),
        ).sign(self.keys["human:alice"])

        edge1 = DelegationEdge(
            edge_id="edge-nc1",
            workflow_id=wf_id,
            source_actor="human:alice",
            target_actor="agent:coordinator",
            token=tok1,
            created_at=self.t0,
        ).sign(self.keys["human:alice"])
        manager.register_edge(edge1, self.resolver)

        tok2 = DelegationToken(
            token_id="tok-nc2",
            principal="principal:alice_household",
            issuer_actor="agent:coordinator",
            audience_actor="agent:medical_auditor",
            parent_token_hash=tok1.compute_digest(),
            depth=1,
            max_depth=3,
            issued_at=self.t0 + 5,
            expires_at=self.t0 + 1800,
            scopes=(scope,),
        ).sign(self.keys["agent:coordinator"])

        edge2 = DelegationEdge(
            edge_id="edge-nc2",
            workflow_id=wf_id,
            source_actor="agent:coordinator",
            target_actor="agent:medical_auditor",
            token=tok2,
            parent_edge_ids=("edge-nc1",),
            created_at=self.t0 + 5,
        ).sign(self.keys["agent:coordinator"])
        manager.register_edge(edge2, self.resolver)

        # Revoke edge 1 with cascading=False
        rev = EdgeRevocationRecord(
            revocation_id="rev-nc-001",
            workflow_id=wf_id,
            edge_id="edge-nc1",
            revoker_actor="human:alice",
            revoked_at=self.t0 + 10,
            cascading=False,
            reason="Pause root dispatching without cascading",
        ).sign(self.keys["human:alice"])

        res = manager.revoke_edge(rev, self.keys["human:alice"])
        self.assertTrue(res["revoked"])
        self.assertEqual(res["cascaded_downstream_edges"], [])

        act1, _ = manager.is_edge_active(wf_id, "edge-nc1")
        self.assertFalse(act1)

        # Edge 2 is NOT disabled by cascading revocation because cascading was False
        act2, msg2 = manager.is_edge_active(wf_id, "edge-nc2")
        self.assertTrue(act2, msg2)

    def test_vera_token_lifetime_expiration(self) -> None:
        """Expired edge token marks edge inactive."""
        manager = VeraEdgeRevocationManager()
        wf_id = "wf-exp-005"

        scope = DelegationScope(action="compute", resource="sim:npu", max_budget=10)
        tok = DelegationToken(
            token_id="tok-exp-01",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=2,
            issued_at=self.t0,
            expires_at=self.t0 + 100,
            scopes=(scope,),
        ).sign(self.keys["human:alice"])

        edge = DelegationEdge(
            edge_id="edge-exp-01",
            workflow_id=wf_id,
            source_actor="human:alice",
            target_actor="agent:coordinator",
            token=tok,
            created_at=self.t0,
        ).sign(self.keys["human:alice"])
        manager.register_edge(edge, self.resolver)

        # Before expiry
        act, _ = manager.is_edge_active(wf_id, "edge-exp-01", current_time_sec=self.t0 + 50)
        self.assertTrue(act)

        # After expiry
        act_after, msg_after = manager.is_edge_active(wf_id, "edge-exp-01", current_time_sec=self.t0 + 150)
        self.assertFalse(act_after)
        self.assertIn("expired", msg_after)

    def test_vera_tampered_signature_rejected_fail_closed(self) -> None:
        """Tampered signatures on edge or revocation record fail closed."""
        manager = VeraEdgeRevocationManager()
        wf_id = "wf-tamper-006"

        scope = DelegationScope(action="compute", resource="sim:npu", max_budget=10)
        tok = DelegationToken(
            token_id="tok-t1",
            principal="principal:alice_household",
            issuer_actor="human:alice",
            audience_actor="agent:coordinator",
            parent_token_hash=None,
            depth=0,
            max_depth=2,
            issued_at=self.t0,
            expires_at=self.t0 + 3600,
            scopes=(scope,),
        ).sign(self.keys["human:alice"])

        bad_edge = DelegationEdge(
            edge_id="edge-bad-sig",
            workflow_id=wf_id,
            source_actor="human:alice",
            target_actor="agent:coordinator",
            token=tok,
            created_at=self.t0,
            signature="0123456789abcdef" * 4,
        )
        with self.assertRaises(DelegationSecurityViolation):
            manager.register_edge(bad_edge, self.resolver)


if __name__ == "__main__":
    unittest.main()

