"""Executable adversarial regression cases. These are not statistical security bounds."""
import copy
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from security import Broker, Device, acquire, canonical, fixture


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.b, self.d = fixture()
        self.envelope = self.b.seal(b"private-adapter-fixture")

    def test_valid_roundtrip(self):
        self.assertEqual(self.b.open(self.envelope, acquire(self.b,self.d,0),0), b"private-adapter-fixture")

    def test_evidence_replay(self):
        c=self.b.challenge(0);ev=[d.sign(c) for d in self.d[:2]]
        self.b.issue(c,ev,0)
        with self.assertRaises(PermissionError): self.b.issue(c,ev,0)

    def test_stale_challenge(self):
        c=self.b.challenge(0)
        with self.assertRaises(PermissionError): self.b.issue(c,[d.sign(c) for d in self.d[:2]],2)

    def test_wrong_person(self):
        c=self.b.challenge(0);c["owner"]="other"
        with self.assertRaises(PermissionError): self.b.issue(c,[d.sign(c) for d in self.d[:2]],0)

    def test_wrong_scope(self):
        c=self.b.challenge(0,"recover")
        with self.assertRaises(PermissionError): self.b.issue(c,[d.sign(c) for d in self.d[:2]],0)

    def test_forged_signature(self):
        c=self.b.challenge(0);ev=[d.sign(c) for d in self.d[:2]];ev[0]["signature"]="00"*64
        with self.assertRaises(PermissionError): self.b.issue(c,ev,0)

    def test_unknown_device(self):
        c=self.b.challenge(0)
        with self.assertRaises(PermissionError): self.b.issue(c,[self.d[0].sign(c),Device.create("fake","fake").sign(c)],0)

    def test_duplicate_device(self):
        c=self.b.challenge(0);ev=self.d[0].sign(c)
        with self.assertRaises(PermissionError): self.b.issue(c,[ev,ev],0)

    def test_missing_quorum(self):
        c=self.b.challenge(0)
        with self.assertRaises(PermissionError): self.b.issue(c,[self.d[0].sign(c)],0)

    def test_shared_failure_domain(self):
        d=[Device.create("a","shared"),Device.create("b","shared")];b=Broker("owner",d)
        with self.assertRaises(PermissionError): acquire(b,d,0)

    def test_lease_expiry(self):
        token=acquire(self.b,self.d,0)
        self.b.open(self.envelope,token,4)
        with self.assertRaises(PermissionError): self.b.open(self.envelope,token,5)

    def test_suspend_invalidates_lease(self):
        token=acquire(self.b,self.d,0);self.b.suspend(1)
        with self.assertRaises(PermissionError): self.b.open(self.envelope,token,1)

    def test_suspended_devices_cannot_renew(self):
        self.b.suspend(0)
        with self.assertRaises(PermissionError): acquire(self.b,self.d,1)

    def test_clock_rollback(self):
        token=acquire(self.b,self.d,5)
        with self.assertRaises(PermissionError): self.b.open(self.envelope,token,4)

    def test_ciphertext_tamper(self):
        token=acquire(self.b,self.d,0);env=copy.deepcopy(self.envelope)
        raw=bytearray.fromhex(env["ciphertext"]);raw[0]^=1;env["ciphertext"]=raw.hex()
        with self.assertRaises(InvalidTag): self.b.open(env,token,0)

    def test_metadata_tamper(self):
        token=acquire(self.b,self.d,0);env=copy.deepcopy(self.envelope);env["metadata"]["owner"]="other"
        with self.assertRaises(PermissionError): self.b.open(env,token,0)

    def test_old_payload_version(self):
        token=acquire(self.b,self.d,0);self.b.version+=1
        with self.assertRaises(PermissionError): self.b.open(self.envelope,token,0)

    def test_forged_recovery(self):
        self.b.suspend(0);c=self.b.challenge(1,"recover")
        with self.assertRaises(PermissionError): self.b.recover(c,Ed25519PrivateKey.generate().sign(canonical(c)),1)

    def test_recovery_and_old_epoch(self):
        old=acquire(self.b,self.d,0);self.b.suspend(1);c=self.b.challenge(2,"recover")
        signature=self.b.recovery_key.sign(canonical(c));self.b.recover(c,signature,2)
        with self.assertRaises(PermissionError): self.b.open(self.envelope,old,2)
        with self.assertRaises(PermissionError): self.b.recover(c,signature,2)
        self.assertEqual(self.b.open(self.envelope,acquire(self.b,self.d,3),3),b"private-adapter-fixture")

    def test_single_sensor_dropout_recoverable(self):
        with self.assertRaises(PermissionError): self.d[0].sign(self.b.challenge(0),present=False)
        token=acquire(self.b,self.d[1:],0)
        self.assertEqual(self.b.open(self.envelope,token,0),b"private-adapter-fixture")

    def test_counterexample_compromised_quorum_can_sign_false_presence(self):
        # Demonstrates the assumption: stolen device keys can assert false presence.
        token=acquire(self.b,self.d,0)
        self.assertEqual(self.b.open(self.envelope,token,0),b"private-adapter-fixture")


if __name__=="__main__": unittest.main(verbosity=2)
