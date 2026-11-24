"""
research/ledger_sim/test_contextual_integrity_guard.py

Unit test suite for Contextual Integrity Transmission Guard and Information-Sharing Confinement.

Validates:
- Strict 5-tuple norm enforcement (Ghalebikesabi et al. 2024 / Nissenbaum 2004).
- Fail-closed parameter, boolean, and NaN/Inf validations.
- Automatic redaction of unregistered or unconsented attributes.
- Deterministic cryptographic receipts and W3C PROV-DM bundle generation.
- Strict Steward Gate invariants (zero unapproved tokens or speculative claims).
"""

from __future__ import annotations

import unittest
from typing import Set

from research.ledger_sim.contextual_integrity_guard import (
    AttributeLeakageError,
    ContextualIntegrityGuard,
    ContextualNorm,
    InformationSensitivityTier,
    ParameterValidationError,
    StewardGateViolationError,
    TransmissionPrinciple,
    TransmissionReceipt,
)


class TestContextualIntegrityGuard(unittest.TestCase):
    """Test suite for Contextual Integrity Transmission Guard."""

    def setUp(self) -> None:
        self.guard = ContextualIntegrityGuard(guard_id="guard-clinic-01")
        self.standard_norm = ContextualNorm(
            norm_id="norm-medical-scheduling",
            data_subject_role="patient",
            sender_role="patient_personal_agent",
            recipient_role="clinic_scheduling_agent",
            information_type="appointment_time_preference",
            principle=TransmissionPrinciple.EXPLICIT_USER_CONSENT,
            sensitivity_tier=InformationSensitivityTier.TIER_1_OPERATIONAL,
        )
        self.confidential_norm = ContextualNorm(
            norm_id="norm-medical-diagnosis",
            data_subject_role="patient",
            sender_role="patient_personal_agent",
            recipient_role="clinic_scheduling_agent",
            information_type="clinical_history_summary",
            principle=TransmissionPrinciple.CONFIDENTIAL_AUDIT_ONLY,
            sensitivity_tier=InformationSensitivityTier.TIER_2_CONFIDENTIAL,
        )

    def test_nominal_norm_registration(self) -> None:
        """Registered norms appear in listed norms in order."""
        self.guard.register_norm(self.standard_norm)
        self.guard.register_norm(self.confidential_norm)
        norms = self.guard.list_norms()
        self.assertEqual(len(norms), 2)
        self.assertEqual(norms[0].norm_id, "norm-medical-scheduling")
        self.assertEqual(norms[1].norm_id, "norm-medical-diagnosis")

    def test_duplicate_norm_rejected(self) -> None:
        """Registering identical norm ID raises ParameterValidationError."""
        self.guard.register_norm(self.standard_norm)
        with self.assertRaises(ParameterValidationError):
            self.guard.register_norm(self.standard_norm)

    def test_nominal_authorized_transmission(self) -> None:
        """Attributes matching norm and principle pass through unredacted."""
        self.guard.register_norm(self.standard_norm)
        payload = {"appointment_time_preference": "Tuesday 10:00 AM"}
        consented: Set[TransmissionPrinciple] = {TransmissionPrinciple.EXPLICIT_USER_CONSENT}

        redacted, receipt = self.guard.verify_and_transmit(
            sender_agent_id="agent-alice",
            sender_role="patient_personal_agent",
            recipient_agent_id="agent-clinic",
            recipient_role="clinic_scheduling_agent",
            data_subject_role="patient",
            payload_attributes=payload,
            consented_principles=consented,
            timestamp_sec=1762400000,
        )

        self.assertEqual(redacted["appointment_time_preference"], "Tuesday 10:00 AM")
        self.assertEqual(receipt.redacted_attribute_count, 0)
        self.assertEqual(receipt.status, "VERIFIED_TRANSMISSION")

    def test_unregistered_attribute_redacted_fail_closed(self) -> None:
        """Attributes without a registered norm are automatically redacted."""
        self.guard.register_norm(self.standard_norm)
        payload = {
            "appointment_time_preference": "Tuesday 10:00 AM",
            "unregistered_home_address": "123 Main Street",
        }
        consented: Set[TransmissionPrinciple] = {TransmissionPrinciple.EXPLICIT_USER_CONSENT}

        redacted, receipt = self.guard.verify_and_transmit(
            sender_agent_id="agent-alice",
            sender_role="patient_personal_agent",
            recipient_agent_id="agent-clinic",
            recipient_role="clinic_scheduling_agent",
            data_subject_role="patient",
            payload_attributes=payload,
            consented_principles=consented,
            timestamp_sec=1762400000,
        )

        self.assertEqual(redacted["appointment_time_preference"], "Tuesday 10:00 AM")
        self.assertTrue(redacted["unregistered_home_address"].startswith("[REDACTED:UNREGISTERED_NORM:"))
        self.assertEqual(receipt.redacted_attribute_count, 1)

    def test_confidential_attribute_without_principle_redacted(self) -> None:
        """Confidential attributes lacking required principle are redacted."""
        self.guard.register_norm(self.confidential_norm)
        payload = {"clinical_history_summary": "Asthma diagnosis 2021"}
        # Consented principle is EXPLICIT_USER_CONSENT, but norm requires CONFIDENTIAL_AUDIT_ONLY
        consented: Set[TransmissionPrinciple] = {TransmissionPrinciple.EXPLICIT_USER_CONSENT}

        redacted, receipt = self.guard.verify_and_transmit(
            sender_agent_id="agent-alice",
            sender_role="patient_personal_agent",
            recipient_agent_id="agent-clinic",
            recipient_role="clinic_scheduling_agent",
            data_subject_role="patient",
            payload_attributes=payload,
            consented_principles=consented,
            timestamp_sec=1762400000,
        )

        self.assertTrue(redacted["clinical_history_summary"].startswith("[REDACTED:PRINCIPLE_UNSATISFIED:"))
        self.assertEqual(receipt.redacted_attribute_count, 1)

    def test_confidential_attribute_with_matching_principle_passes(self) -> None:
        """Confidential attributes with matching consented principle pass unredacted."""
        self.guard.register_norm(self.confidential_norm)
        payload = {"clinical_history_summary": "Asthma diagnosis 2021"}
        consented: Set[TransmissionPrinciple] = {TransmissionPrinciple.CONFIDENTIAL_AUDIT_ONLY}

        redacted, receipt = self.guard.verify_and_transmit(
            sender_agent_id="agent-alice",
            sender_role="patient_personal_agent",
            recipient_agent_id="agent-clinic",
            recipient_role="clinic_scheduling_agent",
            data_subject_role="patient",
            payload_attributes=payload,
            consented_principles=consented,
            timestamp_sec=1762400000,
        )

        self.assertEqual(redacted["clinical_history_summary"], "Asthma diagnosis 2021")
        self.assertEqual(receipt.redacted_attribute_count, 0)

    def test_boolean_and_nan_injection_rejected(self) -> None:
        """Booleans, NaNs, and Infs in parameters fail closed."""
        # Boolean timestamp
        with self.assertRaises(ParameterValidationError):
            self.guard.verify_and_transmit(
                sender_agent_id="agent-alice",
                sender_role="patient_personal_agent",
                recipient_agent_id="agent-clinic",
                recipient_role="clinic_scheduling_agent",
                data_subject_role="patient",
                payload_attributes={"test": 123},
                consented_principles=set(),
                timestamp_sec=True,  # type: ignore[arg-type]
            )

        # NaN float in payload
        with self.assertRaises(ParameterValidationError):
            self.guard.verify_and_transmit(
                sender_agent_id="agent-alice",
                sender_role="patient_personal_agent",
                recipient_agent_id="agent-clinic",
                recipient_role="clinic_scheduling_agent",
                data_subject_role="patient",
                payload_attributes={"test": float("nan")},
                consented_principles=set(),
                timestamp_sec=100,
            )

    def test_steward_gate_invariants_strictly_enforced(self) -> None:
        """Forbidden tokens and speculative promises raise StewardGateViolationError."""
        # Unapproved token in payload
        with self.assertRaises(StewardGateViolationError):
            self.guard.verify_and_transmit(
                sender_agent_id="agent-alice",
                sender_role="patient_personal_agent",
                recipient_agent_id="agent-clinic",
                recipient_role="clinic_scheduling_agent",
                data_subject_role="patient",
                payload_attributes={"notes": "Transfer 50 Contribution Tokens"},
                consented_principles=set(),
                timestamp_sec=100,
            )

        # Speculative royalty claim in agent role
        with self.assertRaises(StewardGateViolationError):
            self.guard.verify_and_transmit(
                sender_agent_id="agent-alice",
                sender_role="85/10/5 distributor",
                recipient_agent_id="agent-clinic",
                recipient_role="clinic_scheduling_agent",
                data_subject_role="patient",
                payload_attributes={"notes": "nominal"},
                consented_principles=set(),
                timestamp_sec=100,
            )

    def test_cryptographic_receipt_integrity(self) -> None:
        """Receipt digests are deterministic and tamper-evident."""
        self.guard.register_norm(self.standard_norm)
        payload = {"appointment_time_preference": "Tuesday 10:00 AM"}
        _, receipt = self.guard.verify_and_transmit(
            sender_agent_id="agent-alice",
            sender_role="patient_personal_agent",
            recipient_agent_id="agent-clinic",
            recipient_role="clinic_scheduling_agent",
            data_subject_role="patient",
            payload_attributes=payload,
            consented_principles={TransmissionPrinciple.EXPLICIT_USER_CONSENT},
            timestamp_sec=1762400000,
        )

        d1 = receipt.compute_digest()
        self.assertEqual(len(d1), 64)
        self.assertEqual(receipt.compute_digest(), d1)

    def test_w3c_prov_dm_export(self) -> None:
        """Audit log exports valid W3C PROV-DM structures."""
        self.guard.register_norm(self.standard_norm)
        payload = {"appointment_time_preference": "Tuesday 10:00 AM"}
        self.guard.verify_and_transmit(
            sender_agent_id="agent-alice",
            sender_role="patient_personal_agent",
            recipient_agent_id="agent-clinic",
            recipient_role="clinic_scheduling_agent",
            data_subject_role="patient",
            payload_attributes=payload,
            consented_principles={TransmissionPrinciple.EXPLICIT_USER_CONSENT},
            timestamp_sec=1762400000,
        )

        bundle = self.guard.export_w3c_prov_dm()
        self.assertIn("entity", bundle)
        self.assertIn("activity", bundle)
        self.assertIn("wasGeneratedBy", bundle)
        self.assertIn("prefix", bundle)
        self.assertEqual(len(bundle["entity"]), 1)


if __name__ == "__main__":
    unittest.main()
