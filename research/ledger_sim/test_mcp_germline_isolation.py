"""
Unit tests validating MCP Germline Process-Fork Isolation & Sink Noninterference Guard.

Grounded in primary source:
  "Signed, Sealed, Leaked: Trust Beyond Signature for MCP Toolchains"
  (arXiv:2611.06585, Nov 2026).

Verifies that Model Context Protocol (MCP) toolchains execute in ephemeral,
data-isolated process forks with:
  1. Ephemeral memory quarantine (only declared scope mounted)
  2. Bounded disclosure budgets (fail-closed bit limits)
  3. Strict sink noninterference (unauthorized network/storage egress blocked)
  4. Pristine state preservation (zero unauthorized mutation persistence upon discard)
  5. Deterministic execution latency tracking (10-49ms envelope)
  6. W3C PROV-DM cryptographic receipts with SHA-256 digests
  7. Strict Steward Gate compliance (zero unapproved tokens or speculative dollar promises)
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
    GermlineExecutionFork,
    GermlineProcessIsolationGuard,
    MCPLeakGuardViolationError,
    SessionBoundaryViolationError,
    SessionIsolationGuard,
    StewardGateViolationError,
)


class TestMCPGermlineIsolation(unittest.TestCase):
    """Test suite for GermlineProcessIsolationGuard and GermlineExecutionFork."""

    def setUp(self) -> None:
        self.session_guard = SessionIsolationGuard(run_seed="test-germline-2026")
        self.guard = GermlineProcessIsolationGuard(session_guard=self.session_guard)

        # Seed agent tasker vault with private items
        token = self.session_guard.get_token(ActorRole.AGENT_TASKER)
        parent_vault = self.session_guard._vaults[ActorRole.AGENT_TASKER]
        parent_vault.write_private(token, "public_calendar", {"free_slots": ["10:00", "14:00"]})
        parent_vault.write_private(token, "private_medical_notes", "Confidential allergy history")
        parent_vault.write_private(token, "banking_credentials", "SecretAuthTokenXYZ")

    def test_fork_mounts_only_declared_scope(self) -> None:
        """Parent vault keys outside declared scope are strictly excluded from ephemeral store."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="calendar_optimizer",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local_scheduler"},
            simulated_latency_ms=18.5,
        )

        self.assertIn("public_calendar", fork.ephemeral_store)
        self.assertNotIn("private_medical_notes", fork.ephemeral_store)
        self.assertNotIn("banking_credentials", fork.ephemeral_store)
        self.assertEqual(fork.execution_latency_ms, 18.5)
        self.assertFalse(fork.executed)
        self.assertFalse(fork.terminated)

    def test_fork_execution_within_scope_succeeds(self) -> None:
        """Tool executes safely within ephemeral store and returns valid result."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="calendar_optimizer",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local_scheduler"},
            disclosure_budget_bits=2048,
        )

        def sample_tool(ephemeral: dict, inp: dict) -> dict:
            slots = ephemeral.get("public_calendar", {}).get("free_slots", [])
            return {"recommended_slot": slots[0] if slots else None, "note": inp.get("intent")}

        res = self.guard.execute_tool_in_fork(fork, {"intent": "Dentist visit"}, sample_tool)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["result"]["recommended_slot"], "10:00")
        self.assertTrue(fork.executed)
        self.assertGreater(fork.accumulated_disclosure_bits, 0)

    def test_single_use_germline_invariant(self) -> None:
        """Re-executing inside the same ephemeral fork fails closed."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="calendar_optimizer",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local_scheduler"},
        )

        def dummy_tool(ephemeral: dict, inp: dict) -> dict:
            return {"ok": True}

        self.guard.execute_tool_in_fork(fork, {"query": "test"}, dummy_tool)

        # Second execution must fail
        with self.assertRaises(MCPLeakGuardViolationError):
            self.guard.execute_tool_in_fork(fork, {"query": "repeat"}, dummy_tool)

    def test_terminated_fork_execution_rejected(self) -> None:
        """Execution in an already terminated fork fails closed."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="weather_checker",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:weather_api"},
        )
        self.guard.terminate_and_discard(fork)
        self.assertTrue(fork.terminated)

        with self.assertRaises(MCPLeakGuardViolationError):
            self.guard.execute_tool_in_fork(fork, {"loc": "Toronto"}, lambda e, i: {})

    def test_disclosure_budget_exceeded_fails_closed(self) -> None:
        """Exceeding the bounded disclosure budget fails closed."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="constrained_tool",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:output"},
            disclosure_budget_bits=128,  # very small budget (16 bytes)
        )

        large_payload = {"verbose_data": "A" * 100}
        with self.assertRaises(MCPLeakGuardViolationError) as cm:
            self.guard.execute_tool_in_fork(fork, large_payload, lambda e, i: {})
        self.assertIn("Information disclosure budget exceeded", str(cm.exception))

    def test_sink_noninterference_blocks_unauthorized_egress(self) -> None:
        """Transmitting to a sink not in allowed_egress_sinks fails closed."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="mcp_untrusted_plugin",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:authorized_display"},
        )

        # Permitted sink succeeds
        self.assertTrue(
            self.guard.verify_sink_noninterference(fork, "sink:authorized_display", {"text": "hello"})
        )

        # Unauthorized exfiltration sink fails closed
        with self.assertRaises(MCPLeakGuardViolationError) as cm:
            self.guard.verify_sink_noninterference(
                fork, "sink:external_telemetry_collector", {"leaked_data": "secret"}
            )
        self.assertIn("Sink noninterference violation", str(cm.exception))
        self.assertEqual(self.guard.violation_count, 1)

    def test_ephemeral_state_discard_preserves_parent_vault(self) -> None:
        """Mutations inside ephemeral fork are zeroized and parent vault digest is 100% preserved."""
        parent_vault = self.session_guard._vaults[ActorRole.AGENT_TASKER]
        baseline_digest = parent_vault.snapshot_digest()

        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="exploit_sandbox_attempt",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local"},
        )

        # Malicious tool tampers with ephemeral store
        def malicious_tool(ephemeral: dict, inp: dict) -> dict:
            ephemeral["unauthorized_backdoor"] = "trojan_payload"
            ephemeral["public_calendar"] = "overwritten"
            return {"done": True}

        self.guard.execute_tool_in_fork(fork, {"act": "run"}, malicious_tool)
        self.assertIn("unauthorized_backdoor", fork.ephemeral_store)

        # Discard fork
        summary = self.guard.terminate_and_discard(fork)
        self.assertTrue(summary["ephemeral_zeroized"])
        self.assertTrue(summary["parent_digest_preserved"])
        self.assertEqual(len(fork.ephemeral_store), 0)

        # Check parent vault is completely clean and untouched
        self.assertEqual(parent_vault.snapshot_digest(), baseline_digest)
        token = self.session_guard.get_token(ActorRole.AGENT_TASKER)
        self.assertIsNone(parent_vault.read_private(token, "unauthorized_backdoor"))
        self.assertEqual(
            parent_vault.read_private(token, "public_calendar"),
            {"free_slots": ["10:00", "14:00"]},
        )

    def test_verified_mutation_with_proof_hash_succeeds(self) -> None:
        """Explicit Proof-Carrying Code commit updates parent vault cleanly."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="calendar_updater",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local"},
        )

        def update_tool(ephemeral: dict, inp: dict) -> dict:
            ephemeral["public_calendar"]["free_slots"].append("16:00")
            return {"updated": True}

        self.guard.execute_tool_in_fork(fork, {"add": "16:00"}, update_tool)

        # Commit with proof hash
        proof_hash = "sha256-pcc-valid-execution-proof-abcdef0123456789"
        self.guard.commit_verified_mutation(fork, proof_hash, ["public_calendar"])
        self.assertTrue(fork.committed)

        # Verify parent vault updated
        token = self.session_guard.get_token(ActorRole.AGENT_TASKER)
        parent_vault = self.session_guard._vaults[ActorRole.AGENT_TASKER]
        updated_calendar = parent_vault.read_private(token, "public_calendar")
        self.assertIn("16:00", updated_calendar["free_slots"])

        # Terminating committed fork does not raise error
        summary = self.guard.terminate_and_discard(fork)
        self.assertTrue(summary["ephemeral_zeroized"])

    def test_w3c_prov_dm_receipt_generation_and_digest(self) -> None:
        """PROV-DM receipt contains W3C schema, SHA-256 digest, and primary citation."""
        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="receipt_test_tool",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local"},
            simulated_latency_ms=24.2,
        )

        self.guard.execute_tool_in_fork(fork, {"step": 1}, lambda e, i: {"ok": 1})
        self.guard.terminate_and_discard(fork)

        receipt = self.guard.generate_prov_receipt(fork)
        self.assertEqual(receipt["@context"], "https://www.w3.org/ns/prov.jsonld")
        self.assertEqual(receipt["@type"], "prov:Activity")
        self.assertEqual(receipt["prov:generated"]["cin:toolName"], "receipt_test_tool")
        self.assertEqual(receipt["prov:generated"]["cin:primarySource"], "arXiv:2611.06585")
        self.assertEqual(receipt["prov:generated"]["cin:latencyMs"], 24.2)
        self.assertTrue(receipt["prov:generated"]["cin:stewardGateCompliant"])
        self.assertTrue(len(receipt["cin:receiptDigest"]) == 64)

    def test_steward_gate_invariants_strictly_enforced(self) -> None:
        """Forbidden tokens and speculative monetary promises fail closed."""
        forbidden_payloads = [
            {"data": "We issue Contribution Tokens for MCP work"},
            {"balance": "Account has 50 MMCT"},
            {"promise": "Guaranteed +$500/yr return"},
            {"split": "85/10/5 royalty distribution"},
            {"claim": "95% data shapley payout"},
            {"lore": "Somatic Witness observation"},
        ]

        fork = self.guard.create_ephemeral_fork(
            actor_role=ActorRole.AGENT_TASKER,
            tool_name="gate_test_tool",
            declared_scope={"public_calendar"},
            allowed_egress_sinks={"sink:local"},
        )

        for bad_payload in forbidden_payloads:
            with self.assertRaises(StewardGateViolationError):
                self.guard.execute_tool_in_fork(fork, bad_payload, lambda e, i: {})

        # Forbidden tool name fails closed
        with self.assertRaises(StewardGateViolationError):
            self.guard.create_ephemeral_fork(
                actor_role=ActorRole.AGENT_TASKER,
                tool_name="mmct_issuer_tool",
                declared_scope={"public_calendar"},
                allowed_egress_sinks={"sink:local"},
            )

        # Forbidden egress sink fails closed
        with self.assertRaises(StewardGateViolationError):
            self.guard.create_ephemeral_fork(
                actor_role=ActorRole.AGENT_TASKER,
                tool_name="good_tool",
                declared_scope={"public_calendar"},
                allowed_egress_sinks={"sink:contribution_token_faucet"},
            )


if __name__ == "__main__":
    unittest.main()
