"""
Unit Test Suite for Multi-Party Capability Attenuation & Session Isolation Audit.

Grounded in:
- Jack B. Dennis & Earl C. Van Horn (1966): Programming Semantics for Multiprogrammed Computations
  [Object-Capability Security & Zero Ambient Authority].
- Mark S. Miller, Chip Morningstar, Bill Frantz (2003): Capability Myths Demolished
  [Dynamic Revocation & Monotonic Attenuation].
- Layered Delegation Chains & Privilege Attenuation (arXiv:2611.07050, Nov 2026).
- Sub-Agent Session Isolation & Laundering Prevention (arXiv:2610.16005, Oct 2026).
- Signed, Sealed, Leaked: Trust Beyond Signature for MCP Toolchains (arXiv:2611.06585, Nov 2026).

Verifies:
1. Monotonic authority attenuation across multi-hop agent delegations (scopes, lifetime, depth).
2. Clean session boundary teardown: wiping isolated ephemeral memory with zero ambient root privileges retained.
3. Fail-closed defense against scope escalation, lifetime expansion, and cross-session memory tampering.
4. Cascading recursive teardown across descendant sub-agent session trees.
5. W3C PROV-DM cryptographic receipts with SHA-256 digests.
6. Strict Steward Gate compliance (zero unapproved tokens or speculative monetary claims).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Ensure repo root is on sys.path for direct module discovery
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from research.ledger_sim.session_isolation import (
    ActorRole,
    CapabilityAttenuationError,
    SessionBoundaryViolationError,
    SessionIsolationGuard,
    StewardGateViolationError,
    SubAgentSession,
    SubAgentSessionManager,
)


class TestCapabilityAttenuationSessionIsolation(unittest.TestCase):
    """Test suite validating sub-agent session isolation and monotonic capability attenuation."""

    def setUp(self) -> None:
        self.session_guard = SessionIsolationGuard(run_seed="test-attenuation-seed-2026")
        self.mgr = SubAgentSessionManager(
            session_guard=self.session_guard, run_seed="test-attenuation-seed-2026"
        )

        # Seed parent vault with private baseline state
        token = self.session_guard.get_token(ActorRole.AGENT_TASKER)
        vault = self.session_guard._vaults[ActorRole.AGENT_TASKER]
        vault.write_private(token, "public_calendar", {"slots": ["09:00", "14:00"]})
        vault.write_private(token, "dispute_records", {"claim_ref": "CLM-4401", "status": "pending"})
        vault.write_private(token, "root_signing_key", "K-MASTER-SEC-9921")
        vault.write_private(token, "financial_credentials", "SEC-VAULT-BANK-77")

    def test_multi_hop_delegation_monotonic_attenuation(self) -> None:
        """
        Verify multi-hop delegation chain (Root -> Hop1 -> Hop2 -> Hop3)
        strictly enforces monotonic capability attenuation across scopes, lifetimes, and depth.
        """
        # Root Session (depth 0)
        root_scopes = {"public_calendar", "dispute_records", "utility_audit"}
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes=root_scopes,
            lifetime_seconds=3600.0,
            max_depth=4,
        )
        self.assertEqual(root.depth, 0)
        self.assertEqual(root.max_depth, 4)
        self.assertEqual(root.delegated_scopes, root_scopes)
        self.assertTrue(root.is_active)

        # Hop 1 Subagent (Coordinator, depth 1)
        hop1_scopes = {"public_calendar", "dispute_records"}
        hop1 = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="coordinator",
            requested_scopes=hop1_scopes,
            lifetime_seconds=1800.0,
        )
        self.assertEqual(hop1.depth, 1)
        self.assertEqual(hop1.parent_session_id, root.session_id)
        self.assertEqual(hop1.delegated_scopes, hop1_scopes)
        self.assertLessEqual(hop1.expires_at, root.expires_at)
        self.assertTrue(hop1.is_active)

        # Hop 2 Subagent (Dispute Specialist, depth 2)
        hop2_scopes = {"dispute_records"}
        hop2 = self.mgr.spawn_child_session(
            parent_session_id=hop1.session_id,
            caller_token=hop1.session_token,
            subagent_id="dispute_specialist",
            requested_scopes=hop2_scopes,
            lifetime_seconds=900.0,
        )
        self.assertEqual(hop2.depth, 2)
        self.assertEqual(hop2.parent_session_id, hop1.session_id)
        self.assertEqual(hop2.delegated_scopes, hop2_scopes)
        self.assertLessEqual(hop2.expires_at, hop1.expires_at)
        self.assertTrue(hop2.is_active)

        # Hop 3 Subagent (Leaf Formatter, depth 3)
        hop3_scopes = {"dispute_records"}
        hop3 = self.mgr.spawn_child_session(
            parent_session_id=hop2.session_id,
            caller_token=hop2.session_token,
            subagent_id="leaf_formatter",
            requested_scopes=hop3_scopes,
            lifetime_seconds=300.0,
        )
        self.assertEqual(hop3.depth, 3)
        self.assertEqual(hop3.parent_session_id, hop2.session_id)
        self.assertEqual(hop3.delegated_scopes, hop3_scopes)
        self.assertLessEqual(hop3.expires_at, hop2.expires_at)
        self.assertTrue(hop3.is_active)

    def test_scope_escalation_rejected_fail_closed(self) -> None:
        """
        Attempting to request a scope not held by the parent session must fail closed
        with CapabilityAttenuationError (arXiv:2610.16005).
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=3600.0,
        )

        initial_violations = self.mgr.violation_count
        with self.assertRaises(CapabilityAttenuationError) as ctx:
            self.mgr.spawn_child_session(
                parent_session_id=root.session_id,
                caller_token=root.session_token,
                subagent_id="unauthorized_subagent",
                requested_scopes={"public_calendar", "root_signing_key"},  # Escalation!
                lifetime_seconds=600.0,
            )

        self.assertIn("Scope escalation detected", str(ctx.exception))
        self.assertIn("root_signing_key", str(ctx.exception))
        self.assertEqual(self.mgr.violation_count, initial_violations + 1)

    def test_lifetime_expansion_rejected_fail_closed(self) -> None:
        """
        Attempting to extend lifetime beyond parent session's expiration must fail closed
        with CapabilityAttenuationError.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=100.0,
        )

        with self.assertRaises(CapabilityAttenuationError) as ctx:
            self.mgr.spawn_child_session(
                parent_session_id=root.session_id,
                caller_token=root.session_token,
                subagent_id="greedy_timer",
                requested_scopes={"public_calendar"},
                lifetime_seconds=500.0,  # Exceeds parent lifetime!
            )

        self.assertIn("Lifetime expansion detected", str(ctx.exception))

    def test_depth_limit_exceeded_rejected_fail_closed(self) -> None:
        """
        Sub-agent delegations exceeding parent max_depth must fail closed.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=3600.0,
            max_depth=2,  # Root is depth 0; allowed: depth 1, depth 2
        )

        child1 = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="child1",
            requested_scopes={"public_calendar"},
            lifetime_seconds=1800.0,
        )
        self.assertEqual(child1.depth, 1)

        child2 = self.mgr.spawn_child_session(
            parent_session_id=child1.session_id,
            caller_token=child1.session_token,
            subagent_id="child2",
            requested_scopes={"public_calendar"},
            lifetime_seconds=900.0,
        )
        self.assertEqual(child2.depth, 2)

        # Attempting depth 3 when max_depth == 2 must fail closed
        with self.assertRaises(CapabilityAttenuationError) as ctx:
            self.mgr.spawn_child_session(
                parent_session_id=child2.session_id,
                caller_token=child2.session_token,
                subagent_id="child3_illegal",
                requested_scopes={"public_calendar"},
                lifetime_seconds=300.0,
            )

        self.assertIn("Delegation depth limit reached", str(ctx.exception))

    def test_max_depth_expansion_rejected_fail_closed(self) -> None:
        """
        Child sub-agent cannot declare a max_depth greater than its parent.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=3600.0,
            max_depth=3,
        )

        with self.assertRaises(CapabilityAttenuationError) as ctx:
            self.mgr.spawn_child_session(
                parent_session_id=root.session_id,
                caller_token=root.session_token,
                subagent_id="expansive_child",
                requested_scopes={"public_calendar"},
                lifetime_seconds=1800.0,
                max_depth=5,  # Exceeds parent max_depth of 3!
            )

        self.assertIn("Max depth expansion", str(ctx.exception))

    def test_child_session_ephemeral_memory_quarantine(self) -> None:
        """
        Verifies child sessions only receive delegated keys and have zero access
        to parent private store or unauthorized root credentials.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=3600.0,
        )

        child = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="calendar_worker",
            requested_scopes={"public_calendar"},
            lifetime_seconds=1800.0,
        )

        # Authorized scope read works
        cal = child.read_ephemeral(child.session_token, "public_calendar")
        self.assertIn("slots", cal)

        # Unauthorized scope read fails closed
        with self.assertRaises(CapabilityAttenuationError) as ctx:
            child.read_ephemeral(child.session_token, "root_signing_key")
        self.assertIn("Scope violation", str(ctx.exception))

        # Attenuation prevents writing outside scope
        with self.assertRaises(CapabilityAttenuationError):
            child.write_ephemeral(child.session_token, "financial_credentials", "TAMPERED")

        # Wrong caller token fails closed
        with self.assertRaises(SessionBoundaryViolationError):
            child.read_ephemeral("forged-token-abc", "public_calendar")

    def test_clean_teardown_zeroizes_ephemeral_memory_and_removes_root_privileges(self) -> None:
        """
        Verifies clean teardown of child sessions:
        1. Ephemeral memory is completely wiped clean.
        2. Session token is invalidated.
        3. Zero ambient root privileges persist.
        4. Parent vault digest is verified pristine.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"dispute_records"},
            lifetime_seconds=3600.0,
        )
        child = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="dispute_worker",
            requested_scopes={"dispute_records"},
            lifetime_seconds=1800.0,
            initial_ephemeral={"dispute_records": {"case_id": "99", "state": "draft"}},
        )

        # Verify child session is active and holding ephemeral memory
        self.assertTrue(child.is_active)
        self.assertEqual(len(child.ephemeral_store), 1)

        # Execute teardown
        res = self.mgr.teardown_session(child.session_id, caller_token=root.session_token)
        self.assertEqual(res["event"], "session_teardown_clean")
        self.assertTrue(res["ephemeral_zeroized"])
        self.assertFalse(res["ambient_root_privileges_retained"])
        self.assertTrue(res["parent_digest_preserved"])

        # Invariants after teardown:
        # 1. Ephemeral store is empty
        self.assertEqual(len(child.ephemeral_store), 0)
        # 2. Session is inactive
        self.assertFalse(child.is_active)
        # 3. Read/write fails closed
        with self.assertRaises(SessionBoundaryViolationError):
            child.read_ephemeral(child.session_token, "dispute_records")
        with self.assertRaises(SessionBoundaryViolationError):
            child.write_ephemeral(child.session_token, "dispute_records", {"test": 1})
        # 4. Executing task on terminated session fails closed
        with self.assertRaises(SessionBoundaryViolationError):
            self.mgr.execute_subagent_task(
                session_id=child.session_id,
                caller_token=child.session_token,
                task_name="dummy_task",
                task_callable=lambda store, inp: None,
                input_payload={},
            )

    def test_cascading_teardown_cleans_all_descendant_subagents(self) -> None:
        """
        Tearing down an intermediate sub-agent session recursively tears down all
        its descendant sub-agent sessions, wiping ephemeral memory across the tree.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar", "dispute_records"},
            lifetime_seconds=3600.0,
            max_depth=4,
        )
        hop1 = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="coordinator",
            requested_scopes={"public_calendar", "dispute_records"},
            lifetime_seconds=1800.0,
        )
        hop2 = self.mgr.spawn_child_session(
            parent_session_id=hop1.session_id,
            caller_token=hop1.session_token,
            subagent_id="specialist",
            requested_scopes={"dispute_records"},
            lifetime_seconds=900.0,
            initial_ephemeral={"dispute_records": {"doc": "evidence"}},
        )
        hop3 = self.mgr.spawn_child_session(
            parent_session_id=hop2.session_id,
            caller_token=hop2.session_token,
            subagent_id="leaf",
            requested_scopes={"dispute_records"},
            lifetime_seconds=300.0,
            initial_ephemeral={"dispute_records": {"doc": "evidence_leaf"}},
        )

        self.assertTrue(hop1.is_active)
        self.assertTrue(hop2.is_active)
        self.assertTrue(hop3.is_active)

        # Teardown hop1: should cascade to hop2 and hop3
        summary = self.mgr.teardown_session(hop1.session_id, caller_token=root.session_token)
        self.assertEqual(summary["cascaded_children_count"], 1)

        self.assertFalse(hop1.is_active)
        self.assertFalse(hop2.is_active)
        self.assertFalse(hop3.is_active)
        self.assertEqual(len(hop1.ephemeral_store), 0)
        self.assertEqual(len(hop2.ephemeral_store), 0)
        self.assertEqual(len(hop3.ephemeral_store), 0)

        # Root remains untouched and active
        self.assertTrue(root.is_active)

    def test_subagent_task_execution_within_scope(self) -> None:
        """
        Sub-agent task execution operates cleanly within isolated ephemeral scope.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"dispute_records"},
            lifetime_seconds=3600.0,
        )
        child = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="parser",
            requested_scopes={"dispute_records"},
            lifetime_seconds=1800.0,
            initial_ephemeral={"dispute_records": {"items": [10, 20, 30]}},
        )

        def sum_items(store: dict, inp: dict) -> dict:
            items = store["dispute_records"]["items"]
            multiplier = inp.get("factor", 1)
            return {"total": sum(items) * multiplier}

        res = self.mgr.execute_subagent_task(
            session_id=child.session_id,
            caller_token=child.session_token,
            task_name="calculate_sum",
            task_callable=sum_items,
            input_payload={"factor": 2},
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["result"]["total"], 120)

    def test_w3c_prov_receipt_generation_and_integrity(self) -> None:
        """
        Verifies W3C PROV-DM receipt conforms to schema, contains SHA-256 digest,
        and cites primary sources arXiv:2611.07050 and arXiv:2610.16005.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=3600.0,
        )
        child = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="worker",
            requested_scopes={"public_calendar"},
            lifetime_seconds=1800.0,
        )

        receipt = self.mgr.generate_prov_receipt(child)
        self.assertIn("@context", receipt)
        self.assertEqual(receipt["@type"], "prov:Activity")
        self.assertIn("cin:receiptDigest", receipt)
        self.assertEqual(len(receipt["cin:receiptDigest"]), 64)
        sources = receipt["prov:generated"]["cin:primarySources"]
        self.assertIn("arXiv:2611.07050", sources)
        self.assertIn("arXiv:2610.16005", sources)
        self.assertTrue(receipt["prov:generated"]["cin:stewardGateCompliant"])

    def test_steward_gate_invariants_strictly_enforced(self) -> None:
        """
        Steward Gate compliance fail-closed: forbidden speculative tokens or claims
        must raise StewardGateViolationError during session operations.
        """
        root = self.mgr.spawn_root_session(
            actor_role=ActorRole.AGENT_TASKER,
            initial_scopes={"public_calendar"},
            lifetime_seconds=3600.0,
        )

        # Attempting forbidden term in subagent scope
        with self.assertRaises(StewardGateViolationError):
            self.mgr.spawn_child_session(
                parent_session_id=root.session_id,
                caller_token=root.session_token,
                subagent_id="bad_scope_agent",
                requested_scopes={"mmct"},
                lifetime_seconds=600.0,
            )

        child = self.mgr.spawn_child_session(
            parent_session_id=root.session_id,
            caller_token=root.session_token,
            subagent_id="good_child",
            requested_scopes={"public_calendar"},
            lifetime_seconds=600.0,
        )

        # Writing forbidden term into ephemeral store
        with self.assertRaises(StewardGateViolationError):
            child.write_ephemeral(child.session_token, "public_calendar", {"promise": "+$5000/yr"})

        # Executing task with forbidden term in name or input
        with self.assertRaises(StewardGateViolationError):
            self.mgr.execute_subagent_task(
                session_id=child.session_id,
                caller_token=child.session_token,
                task_name="mmct_balance_update",
                task_callable=lambda store, inp: None,
                input_payload={},
            )


if __name__ == "__main__":
    unittest.main()
