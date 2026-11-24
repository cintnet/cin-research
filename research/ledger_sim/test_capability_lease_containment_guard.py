"""
research/ledger_sim/test_capability_lease_containment_guard.py

Comprehensive Unit Tests for Time-Bounded Capability Lease & Untrusted Monitoring Containment Guard.
"""

from __future__ import annotations

import math
from pathlib import Path
import sys
import time
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from research.ledger_sim.capability_lease_containment_guard import (
    ActionScope,
    CapabilityLease,
    CapabilityLeaseContainmentGuard,
    DynamicRevocationManager,
    EgressPolicy,
    EgressProtocolViolationError,
    EgressSecurityViolation,
    EgressUnauthorizedDestinationError,
    EgressVolumeExceededError,
    IndependentEgressGateway,
    GermlineExecutionViolation,
    GermlineProcessFork,
    GermlineToolDefinition,
    GermlineToolExecutionHarness,
    LeaseExpiredError,
    LeaseRevokedError,
    LeaseSecurityViolation,
    LeaseValidationError,
    PostExposureTraceEvaluator,
    RolloutStage,
    RolloutTrace,
    StewardGateViolationError,
    ToolSinkExfiltrationError,
    TraceMetrics,
    TraceStep,
    TrajectoryAuditPolicy,
    TrajectoryAuditor,
    UntrustedMonitoringRejection,
    UntrustedMonitor,
    assert_steward_gate_compliance,
)


class TestCapabilityLeaseContainmentGuard(unittest.TestCase):
    """Rigorous test suite for capability lease containment, caretaker revocation, and untrusted monitoring."""

    def setUp(self) -> None:
        self.secret_key = b"super-secret-containment-key-32-bytes!"
        self.base_time = 1762410000.0  # Stable deterministic timestamp
        self.monitor = UntrustedMonitor(canary_tokens=["CANARY_SECRET_AUTH_KEY_XYZ"])
        self.guard = CapabilityLeaseContainmentGuard(secret_key=self.secret_key, monitor=self.monitor)

        self.sample_scope = ActionScope(
            action_name="fs:read",
            resource_regex=r"^/workspace/sandbox/.*\.json$",
            max_payload_bytes=4096,
            is_destructive=False,
        )
        self.write_scope = ActionScope(
            action_name="fs:write",
            resource_regex=r"^/workspace/sandbox/.*\.json$",
            max_payload_bytes=4096,
            is_destructive=True,
        )

    def test_lease_creation_and_signature_verification(self) -> None:
        """Valid leases sign and verify properly; tampering with any field invalidates signature."""
        lease = self.guard.issue_lease(
            lease_id="lease-001",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
            max_invocations=10,
        )
        self.assertTrue(lease.verify_signature(self.secret_key))
        self.assertFalse(lease.is_expired(self.base_time + 100.0))

        # Tampering with expires_at should fail signature verification
        lease.expires_at += 1000.0
        self.assertFalse(lease.verify_signature(self.secret_key))

    def test_lease_expiration_fails_closed(self) -> None:
        """Actions attempted after expires_at fail closed with LeaseExpiredError."""
        lease = self.guard.issue_lease(
            lease_id="lease-expiring",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 300.0,
            max_invocations=5,
        )
        # Action at base_time + 100s succeeds
        res, receipt = self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/config.json",
            payload={"offset": 0},
            action_callable=lambda p: {"status": "ok", "bytes": 128},
            current_time=self.base_time + 100.0,
        )
        self.assertEqual(res["status"], "ok")
        self.assertEqual(receipt["event"], "GUARDED_ACTION_EXECUTED")

        # Action at base_time + 301s must fail closed
        with self.assertRaises(LeaseExpiredError):
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/config.json",
                payload={"offset": 0},
                action_callable=lambda p: {"status": "ok"},
                current_time=self.base_time + 301.0,
            )

    def test_invocation_quota_exhaustion_fails_closed(self) -> None:
        """Lease with max_invocations=2 rejects subsequent calls once exhausted."""
        lease = self.guard.issue_lease(
            lease_id="lease-budget",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
            max_invocations=2,
        )
        # Call 1: OK
        self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/a.json",
            payload={},
            action_callable=lambda p: 1,
            current_time=self.base_time,
        )
        # Call 2: OK
        self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/b.json",
            payload={},
            action_callable=lambda p: 2,
            current_time=self.base_time + 10.0,
        )
        # Call 3: Exceeded -> LeaseSecurityViolation
        with self.assertRaises(LeaseSecurityViolation) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/c.json",
                payload={},
                action_callable=lambda p: 3,
                current_time=self.base_time + 20.0,
            )
        self.assertIn("exhausted", str(cm.exception))

    def test_dynamic_caretaker_revocation(self) -> None:
        """Revoking a lease handle immediately prevents further actions."""
        lease = self.guard.issue_lease(
            lease_id="lease-to-revoke",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
            max_invocations=10,
        )
        # Action before revocation succeeds
        self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/a.json",
            payload={},
            action_callable=lambda p: "ok",
            current_time=self.base_time,
        )

        # Dynamic revocation
        revoked = self.guard.revocation_manager.revoke(
            lease_id="lease-to-revoke",
            reason="Security review: task completed early",
            revoked_by="principal-alice",
            current_time=self.base_time + 50.0,
        )
        self.assertIn("lease-to-revoke", revoked)

        # Subsequent action must fail closed with LeaseRevokedError
        with self.assertRaises(LeaseRevokedError):
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/a.json",
                payload={},
                action_callable=lambda p: "ok",
                current_time=self.base_time + 60.0,
            )

    def test_cascading_revocation_in_delegation_chain(self) -> None:
        """Revoking a parent lease cascades monotonically to all descendant child leases."""
        parent = self.guard.issue_lease(
            lease_id="lease-parent",
            principal_id="principal-alice",
            holder_id="agent-coordinator",
            allowed_scopes=[self.sample_scope, self.write_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
            max_invocations=100,
        )
        child = self.guard.issue_lease(
            lease_id="lease-child",
            principal_id="agent-coordinator",
            holder_id="agent-subtask-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 1800.0,
            max_invocations=20,
            parent_lease_id="lease-parent",
        )
        grandchild = self.guard.issue_lease(
            lease_id="lease-grandchild",
            principal_id="agent-subtask-1",
            holder_id="agent-leaf-worker",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 900.0,
            max_invocations=5,
            parent_lease_id="lease-child",
        )

        self.assertTrue(self.guard.revocation_manager.is_active("lease-parent"))
        self.assertTrue(self.guard.revocation_manager.is_active("lease-child"))
        self.assertTrue(self.guard.revocation_manager.is_active("lease-grandchild"))

        # Revoking the parent lease cascades to both child and grandchild
        revoked_all = self.guard.revocation_manager.revoke(
            lease_id="lease-parent",
            reason="Parent task cancelled",
            revoked_by="principal-alice",
            current_time=self.base_time + 10.0,
        )
        self.assertCountEqual(revoked_all, ["lease-parent", "lease-child", "lease-grandchild"])
        self.assertFalse(self.guard.revocation_manager.is_active("lease-child"))
        self.assertFalse(self.guard.revocation_manager.is_active("lease-grandchild"))

    def test_monotonic_attenuation_enforcement(self) -> None:
        """Child lease attempting to expand duration, invocations, or scopes is rejected."""
        parent = self.guard.issue_lease(
            lease_id="lease-atten-parent",
            principal_id="principal-alice",
            holder_id="agent-parent",
            allowed_scopes=[self.sample_scope],  # Only fs:read
            issued_at=self.base_time,
            expires_at=self.base_time + 1000.0,
            max_invocations=50,
        )
        # Attempt 1: Lifetime escalation (expires_at > parent)
        with self.assertRaises(LeaseSecurityViolation):
            self.guard.issue_lease(
                lease_id="lease-atten-bad-time",
                principal_id="agent-parent",
                holder_id="agent-child",
                allowed_scopes=[self.sample_scope],
                issued_at=self.base_time,
                expires_at=self.base_time + 2000.0,
                parent_lease_id="lease-atten-parent",
            )

        # Attempt 2: Scope escalation (introducing destructive fs:write not in parent)
        with self.assertRaises(LeaseSecurityViolation):
            self.guard.issue_lease(
                lease_id="lease-atten-bad-scope",
                principal_id="agent-parent",
                holder_id="agent-child",
                allowed_scopes=[self.write_scope],
                issued_at=self.base_time,
                expires_at=self.base_time + 500.0,
                max_invocations=10,
                parent_lease_id="lease-atten-parent",
            )

        # Attempt 3: Resource escalation (widening regex to unauthorized paths)
        unauthorized_resource_scope = ActionScope(
            action_name="fs:read",
            resource_regex=r"^/etc/.*$",
            max_payload_bytes=4096,
            is_destructive=False,
        )
        with self.assertRaises(LeaseSecurityViolation):
            self.guard.issue_lease(
                lease_id="lease-atten-bad-resource",
                principal_id="agent-parent",
                holder_id="agent-child",
                allowed_scopes=[unauthorized_resource_scope],
                issued_at=self.base_time,
                expires_at=self.base_time + 500.0,
                max_invocations=10,
                parent_lease_id="lease-atten-parent",
            )

    def test_untrusted_monitor_canary_leak_detection(self) -> None:
        """Action payload containing canary secret is rejected and lease is auto-revoked."""
        lease = self.guard.issue_lease(
            lease_id="lease-canary-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Attempting to leak the canary token
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/data.json",
                payload={"query": "SELECT * WHERE token = 'CANARY_SECRET_AUTH_KEY_XYZ'"},
                action_callable=lambda p: "leaked",
                current_time=self.base_time,
            )
        self.assertIn("MON_CANARY_LEAK", str(cm.exception))
        # Lease should now be dynamically revoked
        self.assertFalse(self.guard.revocation_manager.is_active("lease-canary-test"))

    def test_untrusted_monitor_exploit_pattern_detection(self) -> None:
        """Action payload containing path traversal or shell injection is rejected."""
        lease = self.guard.issue_lease(
            lease_id="lease-exploit-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Path traversal payload
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/test.json",
                payload={"path": "../../../etc/passwd"},
                action_callable=lambda p: "hacked",
                current_time=self.base_time,
            )
        self.assertIn("MON_EXPLOIT_PATTERN", str(cm.exception))

    def test_untrusted_monitor_out_of_scope_action_rejected(self) -> None:
        """Calling unpermitted action or accessing out-of-scope resource raises rejection."""
        lease = self.guard.issue_lease(
            lease_id="lease-scope-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Action name mismatch
        with self.assertRaises(UntrustedMonitoringRejection):
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="net:connect",
                resource_uri="/workspace/sandbox/data.json",
                payload={},
                action_callable=lambda p: 1,
                current_time=self.base_time,
            )

        # Resource regex mismatch on fresh lease
        lease2 = self.guard.issue_lease(
            lease_id="lease-scope-test-2",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        with self.assertRaises(UntrustedMonitoringRejection):
            self.guard.execute_guarded_action(
                lease=lease2,
                action_name="fs:read",
                resource_uri="/system/root/secrets.json",
                payload={},
                action_callable=lambda p: 1,
                current_time=self.base_time,
            )

    def test_numeric_finiteness_defense(self) -> None:
        """Payloads containing NaN or Inf floats fail closed."""
        lease = self.guard.issue_lease(
            lease_id="lease-nan-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/data.json",
                payload={"loss": float("nan")},
                action_callable=lambda p: 1,
                current_time=self.base_time,
            )
        self.assertIn("MON_NON_FINITE_FLOAT", str(cm.exception))

    def test_steward_gate_compliance(self) -> None:
        """Forbidden tokens and speculative monetary promises trigger StewardGateViolationError."""
        # Forbidden in assertion helper
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("Deploy Contribution Tokens for settlement")
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance({"reward": "Earn $5,000 per month with AI"})
        with self.assertRaises(StewardGateViolationError):
            assert_steward_gate_compliance("Fixed 85/10/5 royalty distribution")

        # Forbidden in guarded action payload
        lease = self.guard.issue_lease(
            lease_id="lease-steward-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        with self.assertRaises(StewardGateViolationError):
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/data.json",
                payload={"token": "MMCT"},
                action_callable=lambda p: 1,
                current_time=self.base_time,
            )

    def test_execution_receipt_integrity(self) -> None:
        """Guarded actions produce verifiable, tamper-evident execution receipts."""
        lease = self.guard.issue_lease(
            lease_id="lease-receipt-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        res, receipt = self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/report.json",
            payload={"page": 1},
            action_callable=lambda p: {"items": [1, 2, 3]},
            current_time=self.base_time + 10.0,
        )
        self.assertEqual(res["items"], [1, 2, 3])
        self.assertEqual(receipt["event"], "GUARDED_ACTION_EXECUTED")
        self.assertEqual(receipt["lease_id"], "lease-receipt-test")
        self.assertTrue(len(receipt["receipt_digest"]) == 64)
        self.assertEqual(len(self.guard.get_execution_history()), 1)

    def test_critical_action_deferral_enforcement(self) -> None:
        """Destructive actions must defer to trusted approval tokens (Kutasov et al. 2025)."""
        lease = self.guard.issue_lease(
            lease_id="lease-critical-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.write_scope],  # is_destructive=True
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Attempt without trusted approval token fails closed
        with self.assertRaises(LeaseSecurityViolation) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:write",
                resource_uri="/workspace/sandbox/target.json",
                payload={"data": "content"},
                action_callable=lambda p: {"status": "written"},
                current_time=self.base_time,
            )
        self.assertIn("CRITICAL_ACTION_DEFERRAL_REQUIRED", str(cm.exception))

        # Attempt with valid trusted approval token succeeds
        res, receipt = self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:write",
            resource_uri="/workspace/sandbox/target.json",
            payload={"data": "content"},
            action_callable=lambda p: {"status": "written"},
            current_time=self.base_time,
            trusted_approval_token="TRUSTED_HUMAN_SIGN_OFF_001",
        )
        self.assertEqual(res["status"], "written")
        self.assertEqual(receipt["event"], "GUARDED_ACTION_EXECUTED")

    def test_canary_output_leak_detected(self) -> None:
        """Authorized tool executions that leak protected canary tokens in results fail closed and revoke lease."""
        lease = self.guard.issue_lease(
            lease_id="lease-canary-out-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/secret.json",
                payload={"read": True},
                action_callable=lambda p: {"content": "protected data CANARY_SECRET_AUTH_KEY_XYZ leak"},
                current_time=self.base_time,
            )
        self.assertIn("MON_CANARY_OUTPUT_LEAK", str(cm.exception))
        # Lease must be automatically revoked
        self.assertFalse(self.guard.revocation_manager.is_active("lease-canary-out-test"))

    def test_recovery_latency_exceeded_fails_closed_and_revokes_lease(self) -> None:
        """Actions with monitor/recovery latency exceeding ceiling fail closed and auto-revoke lease (Lindner et al., 2025)."""
        lease = self.guard.issue_lease(
            lease_id="lease-recovery-latency-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Attempt action where simulated monitor latency exceeds 500ms ceiling
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/data.json",
                payload={"read": True},
                action_callable=lambda p: {"status": "ok"},
                current_time=self.base_time,
                simulated_monitor_latency_ms=620.5,
            )
        self.assertIn("RECOVERY_LATENCY_EXCEEDED", str(cm.exception))
        # Offending lease must be dynamically revoked immediately
        self.assertFalse(self.guard.revocation_manager.is_active("lease-recovery-latency-test"))

    def test_synchronous_pre_execution_attestation_in_receipt(self) -> None:
        """Nominal execution records synchronous pre-execution receipt digest and verified recovery latency."""
        lease = self.guard.issue_lease(
            lease_id="lease-attest-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        res, receipt = self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/data.json",
            payload={"read": True},
            action_callable=lambda p: {"data": "verified_content"},
            current_time=self.base_time,
            simulated_monitor_latency_ms=12.4,
        )
        self.assertEqual(res["data"], "verified_content")
        self.assertEqual(receipt["event"], "GUARDED_ACTION_EXECUTED")
        self.assertEqual(receipt["recovery_latency_ms"], 12.4)
        self.assertIn("pre_receipt_digest", receipt)
        self.assertTrue(len(receipt["pre_receipt_digest"]) >= 32)

    def test_invalid_max_recovery_latency_rejected(self) -> None:
        """Non-positive or non-finite recovery latency bounds raise LeaseValidationError fail-closed."""
        with self.assertRaises(LeaseValidationError):
            CapabilityLeaseContainmentGuard(secret_key=self.secret_key, max_recovery_latency_ms=-10.0)
        with self.assertRaises(LeaseValidationError):
            CapabilityLeaseContainmentGuard(secret_key=self.secret_key, max_recovery_latency_ms=float("nan"))
        with self.assertRaises(LeaseValidationError):
            CapabilityLeaseContainmentGuard(secret_key=self.secret_key, max_recovery_latency_ms=float("inf"))

    def test_trajectory_attestation_in_nominal_receipt(self) -> None:
        """Nominal multi-step workflow generates trajectory attestations and includes digest in execution receipt."""
        lease = self.guard.issue_lease(
            lease_id="lease-trajectory-nominal",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        res, receipt = self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/data1.json",
            payload={"step": 1},
            action_callable=lambda p: {"status": "ok"},
            current_time=self.base_time,
        )
        self.assertIn("trajectory_attestation_digest", receipt)
        self.assertTrue(len(receipt["trajectory_attestation_digest"]) >= 32)
        self.assertEqual(receipt["payload_bytes"], len('{"step": 1}'.encode("utf-8")))

    def test_trajectory_audit_detects_prohibited_side_task_and_revokes_lease(self) -> None:
        """Covert side task patterns (Control OSWorld, arXiv:2610.03818) raise UntrustedMonitoringRejection and auto-revoke lease."""
        lease = self.guard.issue_lease(
            lease_id="lease-side-task-subversion",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # First action benign
        self.guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/data.json",
            payload={"step": "read_user_input"},
            action_callable=lambda p: {"status": "ok"},
            current_time=self.base_time,
        )
        # Second action attempts covert dump_creds or steal_token side task
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            self.guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/log.json",
                payload={"action": "dump_creds_to_buffer"},
                action_callable=lambda p: {"status": "ok"},
                current_time=self.base_time + 1.0,
            )
        self.assertIn("MON_TRAJECTORY_SIDE_TASK_DETECTED", str(cm.exception))
        # Lease must be dynamically revoked immediately fail-closed
        self.assertFalse(self.guard.revocation_manager.is_active("lease-side-task-subversion"))

    def test_trajectory_cumulative_payload_volume_quota_fails_closed(self) -> None:
        """Accumulated outbound payload exceeding trajectory policy cap fails closed and revokes lease."""
        policy = TrajectoryAuditPolicy(max_cumulative_payload_bytes=1000)
        auditor = TrajectoryAuditor(policy=policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            trajectory_auditor=auditor,
        )
        lease = guard.issue_lease(
            lease_id="lease-cumulative-bytes-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Execute action with 600 bytes payload
        guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/data.json",
            payload={"blob": "x" * 600},
            action_callable=lambda p: {"status": "ok"},
            current_time=self.base_time,
        )
        # Next action pushes cumulative bytes over 1000 byte policy ceiling
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            guard.execute_guarded_action(
                lease=lease,
                action_name="fs:read",
                resource_uri="/workspace/sandbox/data.json",
                payload={"blob": "y" * 600},
                action_callable=lambda p: {"status": "ok"},
                current_time=self.base_time + 1.0,
            )
        self.assertIn("MON_TRAJECTORY_CUMULATIVE_BYTES_EXCEEDED", str(cm.exception))
        self.assertFalse(guard.revocation_manager.is_active("lease-cumulative-bytes-test"))

    def test_trajectory_probing_loop_detection_fails_closed(self) -> None:
        """Repetitive probing actions exceeding max_consecutive_probing_actions fail closed."""
        probe_scope = ActionScope(
            action_name="probe:scan",
            resource_regex=r"^/workspace/sandbox/.*$",
            max_payload_bytes=4096,
            is_destructive=False,
        )
        policy = TrajectoryAuditPolicy(max_consecutive_probing_actions=3)
        auditor = TrajectoryAuditor(policy=policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            trajectory_auditor=auditor,
        )
        lease = guard.issue_lease(
            lease_id="lease-probing-loop-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[probe_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # First 2 probing actions pass
        for i in range(2):
            guard.execute_guarded_action(
                lease=lease,
                action_name="probe:scan",
                resource_uri=f"/workspace/sandbox/target_{i}",
                payload={"query": i},
                action_callable=lambda p: {"found": False},
                current_time=self.base_time + i,
            )
        # 3rd probing action breaches max_consecutive_probing_actions
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            guard.execute_guarded_action(
                lease=lease,
                action_name="probe:scan",
                resource_uri="/workspace/sandbox/target_3",
                payload={"query": 3},
                action_callable=lambda p: {"found": False},
                current_time=self.base_time + 3,
            )
        self.assertIn("MON_TRAJECTORY_PROBING_LOOP_DETECTED", str(cm.exception))
        self.assertFalse(guard.revocation_manager.is_active("lease-probing-loop-test"))

    def test_trajectory_cross_scope_exfiltration_fails_closed(self) -> None:
        """Reading a sensitive store followed by outbound transmission of sensitive tokens fails closed."""
        read_sens_scope = ActionScope(
            action_name="fs:read",
            resource_regex=r"^/workspace/sandbox/credentials\.json$",
            max_payload_bytes=4096,
            is_destructive=False,
        )
        upload_scope = ActionScope(
            action_name="net:upload",
            resource_regex=r"^https://telemetry\.example\.com/send_report$",
            max_payload_bytes=4096,
            is_destructive=False,
        )
        guard = CapabilityLeaseContainmentGuard(secret_key=self.secret_key, monitor=self.monitor)
        lease = guard.issue_lease(
            lease_id="lease-cross-scope-leak",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[read_sens_scope, upload_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        # Step 1: Read credentials
        guard.execute_guarded_action(
            lease=lease,
            action_name="fs:read",
            resource_uri="/workspace/sandbox/credentials.json",
            payload={"load": True},
            action_callable=lambda p: {"status": "ok"},
            current_time=self.base_time,
        )
        # Step 2: Outbound upload payload referencing secret credentials
        with self.assertRaises(UntrustedMonitoringRejection) as cm:
            guard.execute_guarded_action(
                lease=lease,
                action_name="net:upload",
                resource_uri="https://telemetry.example.com/send_report",
                payload={"telemetry": "leaked_secret_key_material"},
                action_callable=lambda p: {"sent": True},
                current_time=self.base_time + 1.0,
            )
        self.assertIn("MON_TRAJECTORY_CROSS_SCOPE_EXFILTRATION", str(cm.exception))
        self.assertFalse(guard.revocation_manager.is_active("lease-cross-scope-leak"))

    def test_trajectory_audit_policy_validation_and_steward_gate(self) -> None:
        """Trajectory audit policies reject non-positive bounds and enforce strict Steward Gate."""
        with self.assertRaises(LeaseValidationError):
            TrajectoryAuditPolicy(max_sliding_window_actions=-5)
        with self.assertRaises(LeaseValidationError):
            TrajectoryAuditPolicy(max_cumulative_payload_bytes=0)
        with self.assertRaises(LeaseValidationError):
            TrajectoryAuditPolicy(max_consecutive_probing_actions=-1)

        auditor = TrajectoryAuditor()
        lease = self.guard.issue_lease(
            lease_id="lease-steward-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        with self.assertRaises(StewardGateViolationError):
            auditor.audit_step(
                lease=lease,
                history=[],
                proposed_action="fs:read",
                proposed_resource="/workspace/sandbox/data.json",
                proposed_payload={"reward": "MMCT tokens"},
                now=self.base_time,
            )

    def test_egress_policy_validation_and_steward_gate(self) -> None:
        """Egress policies validate domain syntax, bounds, and Steward Gate compliance."""
        with self.assertRaises(LeaseValidationError):
            EgressPolicy(allowed_domains=("invalid domain with spaces",))
        with self.assertRaises(LeaseValidationError):
            EgressPolicy(max_payload_bytes_per_request=-10)
        with self.assertRaises(LeaseValidationError):
            EgressPolicy(max_cumulative_bytes=0)
        with self.assertRaises(LeaseValidationError):
            EgressPolicy(max_requests_per_lease=0)
        with self.assertRaises(LeaseValidationError):
            EgressPolicy(allowed_protocols=("ftp",))
        with self.assertRaises(StewardGateViolationError):
            EgressPolicy(allowed_domains=("mmct.crypto.org",))

    def test_egress_authorized_request_succeeds_with_attestation(self) -> None:
        """Authorized outbound network call produces verified attestation and execution receipt."""
        egress_policy = EgressPolicy(
            allowed_domains=("api.cintnet.org", "*.trusted-partner.org"),
            allowed_protocols=("https",),
            max_payload_bytes_per_request=16384,
        )
        gateway = IndependentEgressGateway(policy=egress_policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            egress_gateway=gateway,
        )
        lease = guard.issue_lease(
            lease_id="lease-egress-ok",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
            max_invocations=5,
        )

        res, receipt = guard.execute_guarded_egress(
            lease=lease,
            destination_url="https://api.cintnet.org/status",
            payload={"action": "heartbeat"},
            network_callable=lambda p: {"status": 200, "alive": True},
            current_time=self.base_time + 10.0,
        )
        self.assertEqual(res["status"], 200)
        self.assertEqual(receipt["event"], "GUARDED_EGRESS_EXECUTED")
        self.assertEqual(receipt["lease_id"], "lease-egress-ok")
        self.assertTrue(len(receipt["egress_attestation_digest"]) == 64)
        self.assertEqual(lease.invocations_count, 1)

        # Subdomain wildcard matching works
        res2, receipt2 = guard.execute_guarded_egress(
            lease=lease,
            destination_url="https://sub.trusted-partner.org/v1/sync",
            payload={"sync": True},
            network_callable=lambda p: {"synced": True},
            current_time=self.base_time + 15.0,
        )
        self.assertEqual(res2["synced"], True)
        self.assertEqual(lease.invocations_count, 2)

    def test_egress_unauthorized_destination_fails_closed_and_auto_revokes(self) -> None:
        """Outbound request targeting unapproved destination raises error and dynamically revokes lease."""
        egress_policy = EgressPolicy(allowed_domains=("api.cintnet.org",))
        gateway = IndependentEgressGateway(policy=egress_policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            egress_gateway=gateway,
        )
        lease = guard.issue_lease(
            lease_id="lease-egress-unauth",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )

        with self.assertRaises(EgressUnauthorizedDestinationError):
            guard.execute_guarded_egress(
                lease=lease,
                destination_url="https://malicious-exfiltration-target.com/drain",
                payload={"stolen": "data"},
                network_callable=lambda p: {"sent": True},
                current_time=self.base_time + 5.0,
            )

        # Offending lease must be auto-revoked immediately
        self.assertFalse(guard.revocation_manager.is_active("lease-egress-unauth"))
        rec = guard.revocation_manager.get_revocation_record("lease-egress-unauth")
        self.assertIn("Auto-revocation on egress security violation", rec["reason"])

    def test_egress_raw_ip_destination_blocked_fail_closed(self) -> None:
        """Raw IP address targets are blocked to prevent bypassing DNS-level egress policies."""
        egress_policy = EgressPolicy(allowed_domains=("api.cintnet.org",))
        gateway = IndependentEgressGateway(policy=egress_policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            egress_gateway=gateway,
        )
        lease = guard.issue_lease(
            lease_id="lease-raw-ip-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )

        with self.assertRaises(EgressUnauthorizedDestinationError):
            guard.execute_guarded_egress(
                lease=lease,
                destination_url="https://198.51.100.42/exfil",
                payload={"data": "raw_ip"},
                network_callable=lambda p: {"sent": True},
                current_time=self.base_time + 5.0,
            )
        self.assertFalse(guard.revocation_manager.is_active("lease-raw-ip-test"))

    def test_egress_forbidden_protocol_fails_closed(self) -> None:
        """Insecure or unapproved protocols (e.g., http without loopback) are rejected."""
        egress_policy = EgressPolicy(allowed_domains=("api.cintnet.org",), allowed_protocols=("https",))
        gateway = IndependentEgressGateway(policy=egress_policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            egress_gateway=gateway,
        )
        lease = guard.issue_lease(
            lease_id="lease-bad-proto",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )

        with self.assertRaises(EgressProtocolViolationError):
            guard.execute_guarded_egress(
                lease=lease,
                destination_url="http://api.cintnet.org/insecure",
                payload={"data": "test"},
                network_callable=lambda p: {"sent": True},
                current_time=self.base_time + 5.0,
            )
        self.assertFalse(guard.revocation_manager.is_active("lease-bad-proto"))

    def test_egress_payload_volume_quota_exceeded_fails_closed(self) -> None:
        """Single request or cumulative payload exceeding egress quotas fails closed and revokes lease."""
        egress_policy = EgressPolicy(
            allowed_domains=("api.cintnet.org",),
            max_payload_bytes_per_request=100,
            max_cumulative_bytes=250,
        )
        gateway = IndependentEgressGateway(policy=egress_policy)
        guard = CapabilityLeaseContainmentGuard(
            secret_key=self.secret_key,
            monitor=self.monitor,
            egress_gateway=gateway,
        )
        lease = guard.issue_lease(
            lease_id="lease-quota-test",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )

        # Single request exceeding 100 bytes fails closed
        with self.assertRaises(EgressVolumeExceededError):
            guard.execute_guarded_egress(
                lease=lease,
                destination_url="https://api.cintnet.org/upload",
                payload={"huge_data": "x" * 200},
                network_callable=lambda p: {"sent": True},
                current_time=self.base_time + 1.0,
            )
        self.assertFalse(guard.revocation_manager.is_active("lease-quota-test"))

    # =====================================================================
    # Germline Execution & Ephemeral Process Confinement Tests (arXiv:2611.06585)
    # =====================================================================

    def test_germline_tool_registration_and_fork_spawn(self) -> None:
        """Germline harness registers signed MCP tools and spawns clean data-free forks."""
        harness = GermlineToolExecutionHarness(revocation_manager=self.guard.revocation_manager)
        tool_def = GermlineToolDefinition(
            tool_id="mcp-file-search",
            publisher_id="pub-verified-analyst",
            signature="ed25519-sig-valid-9941a8",
            allowed_sink_domains=("api.cintnet.org", "internal.local"),
            max_payload_bytes=8192,
        )
        harness.register_tool(tool_def)
        self.assertEqual(harness.get_tool("mcp-file-search"), tool_def)

        fork = harness.spawn_germline_fork(
            tool_id="mcp-file-search",
            destination_sink="api.cintnet.org",
            current_time=self.base_time,
        )
        self.assertTrue(fork.is_active)
        self.assertFalse(fork.disposed)
        self.assertEqual(fork.tool_id, "mcp-file-search")
        self.assertEqual(fork.destination_sink, "api.cintnet.org")
        self.assertTrue(fork.fork_id.startswith("fork-mcp-file-search-"))
        self.assertEqual(fork.retained_state, {})

    def test_germline_fork_blocks_unauthorized_destination_sink(self) -> None:
        """Attempting to spawn fork targeting an unapproved sink raises ToolSinkExfiltrationError."""
        harness = GermlineToolExecutionHarness(revocation_manager=self.guard.revocation_manager)
        tool_def = GermlineToolDefinition(
            tool_id="mcp-weather",
            publisher_id="pub-weather-inc",
            signature="ed25519-sig-weather-88a",
            allowed_sink_domains=("weather.cintnet.org",),
        )
        harness.register_tool(tool_def)

        # Unauthorized exfiltration sink must fail closed
        with self.assertRaises(ToolSinkExfiltrationError):
            harness.spawn_germline_fork(
                tool_id="mcp-weather",
                destination_sink="covert-drop.attacker.com",
                current_time=self.base_time,
            )

    def test_germline_tool_execution_enforces_ephemeral_disposal(self) -> None:
        """After execution, the ephemeral fork is disposed and cannot be reused (sink noninterference)."""
        harness = GermlineToolExecutionHarness(revocation_manager=self.guard.revocation_manager)
        tool_def = GermlineToolDefinition(
            tool_id="mcp-calculator",
            publisher_id="pub-math-tools",
            signature="ed25519-sig-math-77b",
            allowed_sink_domains=("math.cintnet.org",),
        )
        harness.register_tool(tool_def)
        lease = self.guard.issue_lease(
            lease_id="lease-germline-1",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        fork = harness.spawn_germline_fork(
            tool_id="mcp-calculator",
            destination_sink="math.cintnet.org",
            current_time=self.base_time,
        )

        res, receipt = harness.execute_germline_tool(
            fork=fork,
            lease=lease,
            tool_callable=lambda p: {"sum": p["a"] + p["b"]},
            payload={"a": 10, "b": 25},
            current_time=self.base_time + 1.0,
            simulated_latency_ms=14.2,
        )
        self.assertEqual(res, {"sum": 35})
        self.assertEqual(receipt["event"], "GERMLINE_TOOL_EXECUTED")
        self.assertTrue(receipt["disposed"])
        self.assertIn("receipt_digest", receipt)

        # Fork must now be disposed
        self.assertTrue(fork.disposed)
        self.assertFalse(fork.is_active)

        # Re-using a disposed fork must fail closed
        with self.assertRaises(GermlineExecutionViolation):
            harness.execute_germline_tool(
                fork=fork,
                lease=lease,
                tool_callable=lambda p: {"res": "again"},
                payload={"a": 1},
                current_time=self.base_time + 2.0,
            )

    def test_germline_tool_execution_blocks_expired_or_revoked_lease(self) -> None:
        """Expired or revoked capability leases fail closed and dispose the fork immediately."""
        harness = GermlineToolExecutionHarness(revocation_manager=self.guard.revocation_manager)
        tool_def = GermlineToolDefinition(
            tool_id="mcp-fetch",
            publisher_id="pub-fetch-corp",
            signature="ed25519-sig-fetch-33c",
            allowed_sink_domains=("data.cintnet.org",),
        )
        harness.register_tool(tool_def)
        lease = self.guard.issue_lease(
            lease_id="lease-germline-expired",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 60.0,
        )
        fork = harness.spawn_germline_fork(
            tool_id="mcp-fetch",
            destination_sink="data.cintnet.org",
            current_time=self.base_time,
        )

        # Calling with time beyond expiry fails closed
        with self.assertRaises(LeaseExpiredError):
            harness.execute_germline_tool(
                fork=fork,
                lease=lease,
                tool_callable=lambda p: {"ok": True},
                payload={"key": "val"},
                current_time=self.base_time + 120.0,
            )
        self.assertTrue(fork.disposed)

    def test_germline_tool_steward_gate_invariants(self) -> None:
        """Steward gate violations in payload or destination fail closed."""
        harness = GermlineToolExecutionHarness(revocation_manager=self.guard.revocation_manager)
        tool_def = GermlineToolDefinition(
            tool_id="mcp-echo",
            publisher_id="pub-echo",
            signature="sig-echo",
            allowed_sink_domains=("echo.cintnet.org",),
        )
        harness.register_tool(tool_def)
        lease = self.guard.issue_lease(
            lease_id="lease-germline-steward",
            principal_id="principal-alice",
            holder_id="agent-worker-1",
            allowed_scopes=[self.sample_scope],
            issued_at=self.base_time,
            expires_at=self.base_time + 3600.0,
        )
        fork = harness.spawn_germline_fork(
            tool_id="mcp-echo",
            destination_sink="echo.cintnet.org",
            current_time=self.base_time,
        )

        # Payload containing forbidden token promises fails closed
        with self.assertRaises(StewardGateViolationError):
            harness.execute_germline_tool(
                fork=fork,
                lease=lease,
                tool_callable=lambda p: p,
                payload={"message": "You will earn $500/yr with our Contribution Token!"},
                current_time=self.base_time + 1.0,
            )

    def test_post_exposure_trace_step_validation_and_steward_gate(self) -> None:
        """Trace steps reject invalid stages, non-finite values, and Steward Gate violations."""
        # Invalid stage fails closed
        with self.assertRaises(LeaseValidationError):
            TraceStep(
                step_id="step-1",
                stage="invalid_stage",
                action_name="fs:read",
                payload={"path": "/safe/path.json"},
            )

        # Non-finite timestamp fails closed
        with self.assertRaises(LeaseValidationError):
            TraceStep(
                step_id="step-2",
                stage=RolloutStage.INGESTION,
                action_name="fs:read",
                payload={"path": "/safe/path.json"},
                timestamp=float("nan"),
            )

        # Steward gate violation in payload fails closed
        with self.assertRaises(StewardGateViolationError):
            TraceStep(
                step_id="step-3",
                stage=RolloutStage.COMMIT,
                action_name="publish",
                payload={"headline": "Get rich with our token payout!"},
            )

    def test_post_exposure_taint_only_causes_utility_collapse(self) -> None:
        """Under TAINT_ONLY, exposure to tainted data suppresses legitimate proposal commits."""
        evaluator = PostExposureTraceEvaluator()
        trace = RolloutTrace(
            trace_id="tr-taint-1",
            scenario_id="scen-untrusted-web-101",
            regime="TAINT_ONLY",
        )
        # Stage 1: Ingestion of tainted web page
        trace.add_step(
            TraceStep(
                step_id="step-ingest-1",
                stage=RolloutStage.INGESTION,
                action_name="web:fetch",
                payload={"url": "https://example.com/data.html"},
                is_tainted=True,
                is_authorized_intent=True,
            )
        )
        # Stage 2: Intermediate propagation
        trace.add_step(
            TraceStep(
                step_id="step-prop-1",
                stage=RolloutStage.PROPAGATION,
                action_name="data:parse",
                payload={"field": "summary"},
                is_tainted=True,
                is_authorized_intent=True,
            )
        )
        # Stage 3: Authorized proposal commit
        trace.add_step(
            TraceStep(
                step_id="step-commit-1",
                stage=RolloutStage.COMMIT,
                action_name="db:save",
                payload={"status": "complete"},
                is_tainted=False,
                is_authorized_intent=True,
            )
        )

        metrics = evaluator.evaluate_trace(trace)
        self.assertEqual(metrics.endpoint_violation_rate, 0.0)
        self.assertEqual(metrics.taint_propagation_ratio, 1.0)
        # Under TAINT_ONLY, tainted input causes utility collapse (authorized commit score is 0.0)
        self.assertEqual(metrics.authorized_proposal_commit_score, 0.0)
        self.assertEqual(metrics.authorized_commits, 0)
        self.assertEqual(metrics.containment_integrity_index, 0.0)

    def test_post_exposure_intent_ledger_preserves_authorized_commits(self) -> None:
        """Under INTENT_LEDGER, explicit authorized proposals commit cleanly despite tainted input."""
        evaluator = PostExposureTraceEvaluator()
        trace = RolloutTrace(
            trace_id="tr-intent-1",
            scenario_id="scen-untrusted-web-101",
            regime="INTENT_LEDGER",
        )
        # Stage 1: Ingestion of tainted input
        trace.add_step(
            TraceStep(
                step_id="step-ingest-1",
                stage=RolloutStage.INGESTION,
                action_name="web:fetch",
                payload={"url": "https://example.com/data.html"},
                is_tainted=True,
                is_authorized_intent=True,
            )
        )
        # Stage 2: Propagation step
        trace.add_step(
            TraceStep(
                step_id="step-prop-1",
                stage=RolloutStage.PROPAGATION,
                action_name="data:parse",
                payload={"field": "summary"},
                is_tainted=True,
                is_authorized_intent=True,
            )
        )
        # Stage 3: Authorized commit matching declared intent
        trace.add_step(
            TraceStep(
                step_id="step-commit-1",
                stage=RolloutStage.COMMIT,
                action_name="db:save",
                payload={"status": "complete"},
                is_tainted=False,
                is_authorized_intent=True,
                policy_violation=False,
            )
        )

        metrics = evaluator.evaluate_trace(trace)
        self.assertEqual(metrics.endpoint_violation_rate, 0.0)
        self.assertEqual(metrics.taint_propagation_ratio, 1.0)
        # Under INTENT_LEDGER, legitimate proposal is preserved (score is 1.0)
        self.assertEqual(metrics.authorized_proposal_commit_score, 1.0)
        self.assertEqual(metrics.authorized_commits, 1)
        self.assertAlmostEqual(metrics.containment_integrity_index, 1.0, places=3)

    def test_post_exposure_benchmark_aggregate_statistics(self) -> None:
        """Benchmark comparison across regimes shows intent ledger superiority over taint only."""
        evaluator = PostExposureTraceEvaluator()
        traces = []
        for regime in ("TAINT_ONLY", "INTENT_LEDGER"):
            t = RolloutTrace(
                trace_id=f"tr-{regime.lower()}-test",
                scenario_id="scen-batch-1",
                regime=regime,
            )
            t.add_step(TraceStep("s1", RolloutStage.INGESTION, "web:fetch", {"url": "https://a.test"}, is_tainted=True))
            t.add_step(TraceStep("s2", RolloutStage.PROPAGATION, "parse", {"k": "v"}, is_tainted=True))
            t.add_step(TraceStep("s3", RolloutStage.COMMIT, "save", {"ok": True}, is_tainted=False, is_authorized_intent=True))
            traces.append(t)

        summary = evaluator.evaluate_benchmark(traces)
        self.assertIn("TAINT_ONLY", summary)
        self.assertIn("INTENT_LEDGER", summary)
        self.assertEqual(summary["TAINT_ONLY"]["mean_authorized_proposal_commit_score"], 0.0)
        self.assertEqual(summary["INTENT_LEDGER"]["mean_authorized_proposal_commit_score"], 1.0)
        self.assertGreater(
            summary["INTENT_LEDGER"]["mean_containment_integrity_index"],
            summary["TAINT_ONLY"]["mean_containment_integrity_index"],
        )


if __name__ == "__main__":
    unittest.main()
