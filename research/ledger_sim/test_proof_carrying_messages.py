"""Unit tests for Proof-Carrying Messages (PCM) and Merkle Inclusion Verification.

Validates fail-closed input verification, tamper detection across audit paths,
cryptographic root and signature verification, caveat enforcement, and simulation suites.
"""

from __future__ import annotations

import unittest
import sys
from pathlib import Path

# Ensure worktree root and research/ledger_sim directory are in sys.path
_DIR = Path(__file__).resolve().parent
_ROOT = _DIR.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

try:
    from research.ledger_sim.proof_carrying_messages import (
        MerkleInclusionProof,
        MerkleLog,
        PCMCaveat,
        PCMValidationError,
        PCMVerifier,
        ProofCarryingMessage,
        canonical_json_bytes,
        hash_leaf,
    )
    from research.ledger_sim.pcm_merkle_agent_verification_sim import (
        run_single_pcm_simulation,
        run_pcm_experiment_suite,
    )
except ModuleNotFoundError:
    from proof_carrying_messages import (
        MerkleInclusionProof,
        MerkleLog,
        PCMCaveat,
        PCMValidationError,
        PCMVerifier,
        ProofCarryingMessage,
        canonical_json_bytes,
        hash_leaf,
    )
    from pcm_merkle_agent_verification_sim import (
        run_single_pcm_simulation,
        run_pcm_experiment_suite,
    )


class TestProofCarryingMessages(unittest.TestCase):
    def setUp(self) -> None:
        self.signing_key = b"witness-signing-key-test-00123"
        self.log = MerkleLog("witness-log-1", self.signing_key)
        self.entry0 = {"tx": "refund_001", "amount_cents": 2500, "user": "alice"}
        self.entry1 = {"tx": "refund_002", "amount_cents": 5000, "user": "bob"}
        self.entry2 = {"tx": "refund_003", "amount_cents": 7500, "user": "carol"}

        self.idx0, self.h0 = self.log.append(self.entry0)
        self.idx1, self.h1 = self.log.append(self.entry1)
        self.idx2, self.h2 = self.log.append(self.entry2)

        self.root = self.log.root_hash()
        self.signature = self.log.sign_root(self.root)
        self.verifier = PCMVerifier({"witness-log-1": self.signing_key})

    def test_merkle_inclusion_nominal(self) -> None:
        """Nominal honest inclusion proof must verify cleanly."""
        proof0 = self.log.get_inclusion_proof(0)
        pcm0 = ProofCarryingMessage(
            message_id="msg-001",
            sender_id="twin-agent-1",
            recipient_id="broker-twin-2",
            claim_type="REFUND_AUTHORIZATION",
            claim_payload=self.entry0,
            attestation_log_id="witness-log-1",
            attestation_root=self.root,
            inclusion_proof=proof0,
            attestor_signature=self.signature,
        )
        res = self.verifier.verify(pcm0)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.failure_code, None)
        self.assertEqual(res.computed_root, self.root)

    def test_tampered_leaf_payload_rejected(self) -> None:
        """Altering claim payload without re-signing fails root comparison."""
        proof0 = self.log.get_inclusion_proof(0)
        tampered_entry = dict(self.entry0)
        tampered_entry["amount_cents"] = 999999  # Privilege escalation attempt

        pcm = ProofCarryingMessage(
            message_id="msg-002",
            sender_id="attacker-agent",
            recipient_id="broker-twin-2",
            claim_type="REFUND_AUTHORIZATION",
            claim_payload=tampered_entry,
            attestation_log_id="witness-log-1",
            attestation_root=self.root,
            inclusion_proof=proof0,
            attestor_signature=self.signature,
        )
        res = self.verifier.verify(pcm)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.failure_code, "ROOT_MISMATCH")

    def test_corrupted_audit_path_rejected(self) -> None:
        """Corrupting sibling hash in audit path fails root comparison."""
        proof0 = self.log.get_inclusion_proof(0)
        corrupted_path = list(proof0.audit_path)
        direction, _ = corrupted_path[0]
        corrupted_path[0] = (direction, "abcd" * 16)

        bad_proof = MerkleInclusionProof(
            leaf_index=proof0.leaf_index,
            tree_size=proof0.tree_size,
            audit_path=tuple(corrupted_path),
        )

        pcm = ProofCarryingMessage(
            message_id="msg-003",
            sender_id="attacker-agent",
            recipient_id="broker-twin-2",
            claim_type="REFUND_AUTHORIZATION",
            claim_payload=self.entry0,
            attestation_log_id="witness-log-1",
            attestation_root=self.root,
            inclusion_proof=bad_proof,
            attestor_signature=self.signature,
        )
        res = self.verifier.verify(pcm)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.failure_code, "ROOT_MISMATCH")

    def test_untrusted_attestor_log_rejected(self) -> None:
        """Unknown or untrusted log IDs are rejected fail-closed."""
        proof0 = self.log.get_inclusion_proof(0)
        pcm = ProofCarryingMessage(
            message_id="msg-004",
            sender_id="twin-agent-1",
            recipient_id="broker-twin-2",
            claim_type="REFUND_AUTHORIZATION",
            claim_payload=self.entry0,
            attestation_log_id="rogue-witness-log",
            attestation_root=self.root,
            inclusion_proof=proof0,
            attestor_signature=self.signature,
        )
        res = self.verifier.verify(pcm)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.failure_code, "UNTRUSTED_ATTESTOR")

    def test_invalid_signature_rejected(self) -> None:
        """Forged or altered attestor signature fails verification."""
        proof0 = self.log.get_inclusion_proof(0)
        pcm = ProofCarryingMessage(
            message_id="msg-005",
            sender_id="twin-agent-1",
            recipient_id="broker-twin-2",
            claim_type="REFUND_AUTHORIZATION",
            claim_payload=self.entry0,
            attestation_log_id="witness-log-1",
            attestation_root=self.root,
            inclusion_proof=proof0,
            attestor_signature="00" * 32,
        )
        res = self.verifier.verify(pcm)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.failure_code, "INVALID_ROOT_SIGNATURE")

    def test_caveat_expiration_and_budget_bounds(self) -> None:
        """Caveats enforce expiration epoch and maximum monetary amount."""
        proof0 = self.log.get_inclusion_proof(0)
        pcm = ProofCarryingMessage(
            message_id="msg-006",
            sender_id="twin-agent-1",
            recipient_id="broker-twin-2",
            claim_type="REFUND_AUTHORIZATION",
            claim_payload=self.entry0,
            attestation_log_id="witness-log-1",
            attestation_root=self.root,
            inclusion_proof=proof0,
            attestor_signature=self.signature,
            caveats=(
                PCMCaveat("valid_until_epoch", 1000),
                PCMCaveat("max_amount_cents", 5000),
                PCMCaveat("allowed_tool", "execute_refund"),
            ),
        )

        # 1. Valid context
        res_ok = self.verifier.verify(
            pcm, current_epoch=999, context_constraints={"amount_cents": 2500, "tool_name": "execute_refund"}
        )
        self.assertTrue(res_ok.is_valid)

        # 2. Expired epoch
        res_exp = self.verifier.verify(
            pcm, current_epoch=1001, context_constraints={"amount_cents": 2500, "tool_name": "execute_refund"}
        )
        self.assertFalse(res_exp.is_valid)
        self.assertEqual(res_exp.failure_code, "CAVEAT_EXPIRED")

        # 3. Exceeded amount
        res_over = self.verifier.verify(
            pcm, current_epoch=999, context_constraints={"amount_cents": 5001, "tool_name": "execute_refund"}
        )
        self.assertFalse(res_over.is_valid)
        self.assertEqual(res_over.failure_code, "CAVEAT_BUDGET_EXCEEDED")

        # 4. Tool mismatch
        res_tool = self.verifier.verify(
            pcm, current_epoch=999, context_constraints={"amount_cents": 2500, "tool_name": "wipe_database"}
        )
        self.assertFalse(res_tool.is_valid)
        self.assertEqual(res_tool.failure_code, "CAVEAT_TOOL_MISMATCH")

    def test_fail_closed_validation_errors(self) -> None:
        """Constructor and data structures reject malformed types and values fail-closed."""
        # Null bytes in message identifiers
        proof0 = self.log.get_inclusion_proof(0)
        with self.assertRaises(PCMValidationError):
            ProofCarryingMessage(
                message_id="msg\x00evil",
                sender_id="twin",
                recipient_id="broker",
                claim_type="TEST",
                claim_payload={"a": 1},
                attestation_log_id="witness-log-1",
                attestation_root=self.root,
                inclusion_proof=proof0,
                attestor_signature=self.signature,
            )

        # Path traversal characters in identifiers
        with self.assertRaises(PCMValidationError):
            ProofCarryingMessage(
                message_id="../../etc/passwd",
                sender_id="twin",
                recipient_id="broker",
                claim_type="TEST",
                claim_payload={"a": 1},
                attestation_log_id="witness-log-1",
                attestation_root=self.root,
                inclusion_proof=proof0,
                attestor_signature=self.signature,
            )

        # Boolean in integer fields
        with self.assertRaises(PCMValidationError):
            PCMCaveat("max_amount_cents", True)

        with self.assertRaises(PCMValidationError):
            MerkleInclusionProof(leaf_index=True, tree_size=10, audit_path=())

        with self.assertRaises(PCMValidationError):
            self.log.get_inclusion_proof(False)  # type: ignore

    def test_simulation_experiment_suite(self) -> None:
        """Simulation experiment must run cleanly across 10 seeds with 100% tamper detection."""
        metrics = run_pcm_experiment_suite(num_seeds=10)
        self.assertEqual(len(metrics), 10)
        for m in metrics:
            self.assertEqual(m.total_workflows, 100)
            self.assertEqual(m.honest_workflows, 50)
            self.assertEqual(m.adversarial_workflows, 50)
            self.assertEqual(m.tamper_detected_count, 50)
            self.assertEqual(m.honest_passed_count, 50)
            self.assertEqual(m.tamper_detection_rate, 100.0)
            self.assertEqual(m.false_positive_rate, 0.0)
            self.assertEqual(m.verifier_agreement_rate, 100.0)
            self.assertLess(m.avg_latency_ms, 2.0)


if __name__ == "__main__":
    unittest.main()
