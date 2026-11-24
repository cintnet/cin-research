"""
research/ledger_sim/test_provable_inference_verifier.py

Comprehensive Unit Tests for Provable Inference Verifier on Agent-Web Ledger.
Verifies FlashProve zero-knowledge zkSNARK proof-of-inference, model-swapping detection,
in-flight tampering prevention, W3C PROV-DM provenance export, and strict Steward Gate compliance.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

try:
    from research.ledger_sim.provable_inference_verifier import (
        InferenceTamperingDetected,
        InferenceVerificationError,
        InferenceTaskSpec,
        ProofSystemKind,
        ProvableInferenceReceipt,
        ProvableInferenceVerifier,
        VerificationStatus,
        WeightCommitment,
        canonical_sha256,
        zkSNARKInferenceProof,
    )
except ImportError:
    from provable_inference_verifier import (
        InferenceTamperingDetected,
        InferenceVerificationError,
        InferenceTaskSpec,
        ProofSystemKind,
        ProvableInferenceReceipt,
        ProvableInferenceVerifier,
        VerificationStatus,
        WeightCommitment,
        canonical_sha256,
        zkSNARKInferenceProof,
    )


class TestProvableInferenceVerifier(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = ProvableInferenceVerifier()
        self.model_id = "model:llama-4-maverick-400b-4bit"
        self.commitment_digest = canonical_sha256("DUMMY_QUANTIZED_MODEL_WEIGHTS_SHARDS_V1")
        self.commitment = WeightCommitment(
            commitment_id="comm:llama-4-maverick:20261102",
            model_id=self.model_id,
            architecture="MoE-400B-4bit",
            quantization_format="INT4_AWQ",
            tensor_shard_count=64,
            commitment_digest=self.commitment_digest,
            context_window_limit=1024,
            created_at=datetime.now(timezone.utc).isoformat(),
            formal_soundness_ref="Lean4:FlashProve.Soundness.Theorem_4_1",
            metadata={"source": "Anthropic FlashProve Research Prototype", "benchmark": "Greedy-Inference-Eval"},
        )
        self.verifier.register_weight_commitment(self.commitment)

        self.prompt = "Analyze Medicare CPT code 99214 outpatient visit complexity guidelines."
        self.prompt_digest = canonical_sha256(self.prompt)
        self.task = InferenceTaskSpec(
            task_id="task:inference:001",
            model_id=self.model_id,
            caller_agent_id="agent:personal-twin:4401",
            prompt_tokens_digest=self.prompt_digest,
            decoding_params={"temperature": 0.0, "max_tokens": 512, "greedy": True},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.response_text = "CPT 99214 represents Level 4 office or outpatient evaluation requiring moderate medical decision making."

    def test_weight_commitment_registration_and_retrieval(self) -> None:
        """Weight commitments must be registered and retrieved faithfully."""
        comm = self.verifier.get_weight_commitment(self.model_id)
        self.assertIsNotNone(comm)
        self.assertEqual(comm.commitment_digest, self.commitment_digest)
        self.assertEqual(comm.architecture, "MoE-400B-4bit")
        self.assertEqual(comm.tensor_shard_count, 64)

    def test_duplicate_registration_conflicting_commitment_fails_closed(self) -> None:
        """Registering a conflicting weight commitment for the same model ID must raise InferenceTamperingDetected."""
        tampered_comm = WeightCommitment(
            commitment_id="comm:llama-4-maverick:tampered",
            model_id=self.model_id,
            architecture="MoE-400B-4bit",
            quantization_format="INT4_AWQ",
            tensor_shard_count=64,
            commitment_digest=canonical_sha256("TAMPERED_WEIGHT_SHARDS"),
            context_window_limit=1024,
            created_at=datetime.now(timezone.utc).isoformat(),
            formal_soundness_ref="Lean4:FlashProve.Soundness.Theorem_4_1",
        )
        with self.assertRaises(InferenceTamperingDetected):
            self.verifier.register_weight_commitment(tampered_comm)

    def test_successful_end_to_end_verification(self) -> None:
        """Valid zkSNARK proof matching registered weights must verify with VERIFIED status."""
        proof = self.verifier.create_simulated_proof(
            task=self.task,
            response_text=self.response_text,
            tokens_generated=64,
            proof_system=ProofSystemKind.FLASHPROVE_GROTH16,
        )
        receipt = self.verifier.verify_proof(
            task=self.task,
            response_text=self.response_text,
            proof=proof,
        )
        self.assertEqual(receipt.status, VerificationStatus.VERIFIED)
        self.assertTrue(receipt.weight_commitment_verified)
        self.assertTrue(receipt.cryptographic_soundness_verified)
        self.assertTrue(receipt.zk_zero_knowledge_verified)
        self.assertIn("receipt:task:inference:001:", receipt.receipt_id)
        self.assertGreater(receipt.verification_latency_ms, 0.0)

    def test_model_swapping_attack_detection(self) -> None:
        """If a provider secretly runs a cheaper model with different weights, verification fails closed."""
        fake_weights = canonical_sha256("CHEAP_QUANTIZED_1B_MODEL_WEIGHTS")
        fake_inputs_digest = self.verifier.compute_public_inputs_digest(
            model_id=self.model_id,
            commitment_digest=fake_weights,
            prompt_digest=self.task.prompt_tokens_digest,
            response_digest=canonical_sha256(self.response_text),
            decoding_params=self.task.decoding_params,
        )
        tampered_proof = zkSNARKInferenceProof(
            proof_id="proof:swapped:001",
            task_id=self.task.task_id,
            model_id=self.model_id,
            commitment_digest=fake_weights,
            prompt_digest=self.task.prompt_tokens_digest,
            response_digest=canonical_sha256(self.response_text),
            proof_system=ProofSystemKind.FLASHPROVE_GROTH16.value,
            formal_soundness_ref="Lean4:FlashProve.Soundness.Theorem_4_1",
            public_inputs_digest=fake_inputs_digest,
            proof_wire_digest=canonical_sha256(b"WIRE_BYTES"),
            proof_size_bytes=2048,
            proving_duration_ms=120.0,
            tokens_generated=64,
        )
        receipt = self.verifier.verify_proof(
            task=self.task,
            response_text=self.response_text,
            proof=tampered_proof,
        )
        self.assertEqual(receipt.status, VerificationStatus.TAMPERED_WEIGHT_COMMITMENT)
        self.assertFalse(receipt.weight_commitment_verified)
        self.assertIn("Weight commitment mismatch", receipt.details["error"])

    def test_response_mutation_tampering_detection(self) -> None:
        """If an intermediate proxy mutates the response tokens in flight, verification detects tampering."""
        proof = self.verifier.create_simulated_proof(
            task=self.task,
            response_text=self.response_text,
            tokens_generated=64,
        )
        # Proxy maliciously alters output
        mutated_text = self.response_text + " [INJECTED ADVERSARIAL TOKEN]"
        receipt = self.verifier.verify_proof(
            task=self.task,
            response_text=mutated_text,
            proof=proof,
        )
        self.assertEqual(receipt.status, VerificationStatus.TAMPERED_RESPONSE)
        self.assertFalse(receipt.cryptographic_soundness_verified)
        self.assertIn("Response digest mismatch", receipt.details["error"])

    def test_prompt_or_decoding_parameter_tampering_detection(self) -> None:
        """If decoding parameters or prompt digest do not match public inputs, proof is REJECTED."""
        proof = self.verifier.create_simulated_proof(
            task=self.task,
            response_text=self.response_text,
            tokens_generated=64,
        )
        # Caller task altered temperature
        tampered_task = InferenceTaskSpec(
            task_id=self.task.task_id,
            model_id=self.task.model_id,
            caller_agent_id=self.task.caller_agent_id,
            prompt_tokens_digest=self.task.prompt_tokens_digest,
            decoding_params={"temperature": 0.7, "max_tokens": 512, "greedy": False},
            timestamp=self.task.timestamp,
        )
        receipt = self.verifier.verify_proof(
            task=tampered_task,
            response_text=self.response_text,
            proof=proof,
        )
        self.assertEqual(receipt.status, VerificationStatus.REJECTED)
        self.assertIn("Public inputs digest mismatch", receipt.details["error"])

    def test_context_window_limit_exceeded(self) -> None:
        """Proofs generating tokens beyond the model's context limit are rejected fail-closed."""
        # Commitment limit is 1024
        proof = self.verifier.create_simulated_proof(
            task=self.task,
            response_text=self.response_text,
            tokens_generated=2048,
        )
        receipt = self.verifier.verify_proof(
            task=self.task,
            response_text=self.response_text,
            proof=proof,
        )
        self.assertEqual(receipt.status, VerificationStatus.CONTEXT_WINDOW_EXCEEDED)
        self.assertIn("exceeds context window limit", receipt.details["error"])

    def test_unrecognized_proof_system_fails_closed(self) -> None:
        """Proofs claiming unverified or arbitrary proof systems fail closed."""
        valid_proof = self.verifier.create_simulated_proof(
            task=self.task,
            response_text=self.response_text,
            tokens_generated=64,
        )
        unrecognized_proof = zkSNARKInferenceProof(
            proof_id=valid_proof.proof_id,
            task_id=valid_proof.task_id,
            model_id=valid_proof.model_id,
            commitment_digest=valid_proof.commitment_digest,
            prompt_digest=valid_proof.prompt_digest,
            response_digest=valid_proof.response_digest,
            proof_system="CustomUnverifiedCryptoSystem-v0",
            formal_soundness_ref=valid_proof.formal_soundness_ref,
            public_inputs_digest=valid_proof.public_inputs_digest,
            proof_wire_digest=valid_proof.proof_wire_digest,
            proof_size_bytes=valid_proof.proof_size_bytes,
            proving_duration_ms=valid_proof.proving_duration_ms,
            tokens_generated=valid_proof.tokens_generated,
        )
        receipt = self.verifier.verify_proof(
            task=self.task,
            response_text=self.response_text,
            proof=unrecognized_proof,
        )
        self.assertEqual(receipt.status, VerificationStatus.UNSOUND_PROOF_SYSTEM)
        self.assertIn("Unrecognized proof system", receipt.details["error"])

    def test_w3c_prov_bundle_generation(self) -> None:
        """W3C PROV-DM bundle must conform to standard JSON-LD provenance structure."""
        proof = self.verifier.create_simulated_proof(
            task=self.task,
            response_text=self.response_text,
            tokens_generated=64,
        )
        receipt = self.verifier.verify_proof(
            task=self.task,
            response_text=self.response_text,
            proof=proof,
        )
        bundle = self.verifier.export_w3c_prov_bundle(
            receipt=receipt,
            task=self.task,
            proof=proof,
        )
        self.assertIn("@context", bundle)
        self.assertIn("entity", bundle)
        self.assertIn("activity", bundle)
        self.assertIn("wasGeneratedBy", bundle)
        self.assertIn("used", bundle)
        self.assertIn("wasDerivedFrom", bundle)

    def test_schema_validation_and_bounds_fail_closed(self) -> None:
        """Invalid types, out-of-range bounds, and malformed digests must raise InferenceVerificationError."""
        # Non-hex digest
        with self.assertRaises(InferenceVerificationError):
            WeightCommitment(
                commitment_id="comm:test",
                model_id=self.model_id,
                architecture="Test",
                quantization_format="INT4",
                tensor_shard_count=1,
                commitment_digest="not-a-valid-sha256-hex",
                context_window_limit=1024,
                created_at="2026-11-05T00:00:00Z",
                formal_soundness_ref="Lean4:Test",
            )

        # Invalid temperature (< 0.0 or > 2.0)
        with self.assertRaises(InferenceVerificationError):
            InferenceTaskSpec(
                task_id="task:err",
                model_id=self.model_id,
                caller_agent_id="agent:01",
                prompt_tokens_digest=self.prompt_digest,
                decoding_params={"temperature": -1.0},
                timestamp="2026-11-05T00:00:00Z",
            )

        # Proof size too small
        with self.assertRaises(InferenceVerificationError):
            zkSNARKInferenceProof(
                proof_id="proof:tiny",
                task_id="task:01",
                model_id=self.model_id,
                commitment_digest=self.commitment_digest,
                prompt_digest=self.prompt_digest,
                response_digest=canonical_sha256("resp"),
                proof_system=ProofSystemKind.FLASHPROVE_GROTH16.value,
                formal_soundness_ref="Lean4:Soundness",
                public_inputs_digest=canonical_sha256("inputs"),
                proof_wire_digest=canonical_sha256("wire"),
                proof_size_bytes=10,  # Below 1024 bytes
                proving_duration_ms=10.0,
                tokens_generated=10,
            )

    def test_steward_gate_invariants(self) -> None:
        """Receipts and commitments must reject unapproved token or dollar promises."""
        with self.assertRaises(InferenceVerificationError):
            WeightCommitment(
                commitment_id="comm:illegal",
                model_id=self.model_id,
                architecture="Test",
                quantization_format="INT4",
                tensor_shard_count=1,
                commitment_digest=self.commitment_digest,
                context_window_limit=1024,
                created_at="2026-11-05T00:00:00Z",
                formal_soundness_ref="Lean4:Test",
                metadata={"reward": "50 Contribution Tokens"},
            )


if __name__ == "__main__":
    unittest.main()
