"""Software reference broker. No claim of hardware/process isolation or RAM erasure."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass
class Device:
    name: str
    domain: str
    key: Ed25519PrivateKey

    @classmethod
    def create(cls, name: str, domain: str) -> "Device":
        return cls(name, domain, Ed25519PrivateKey.generate())

    def sign(self, challenge: dict, present: bool = True) -> dict:
        if not present:
            raise PermissionError("emulated presence absent")
        message = {**challenge, "device": self.name}
        return {"message": message, "signature": self.key.sign(canonical(message)).hex()}


class Broker:
    """Caller-provided time emulates a trusted monotonic clock. Broker state is trusted."""

    def __init__(self, owner: str, devices: list[Device], quorum: int = 2,
                 domains: int = 2, lease_ticks: int = 5):
        if len({d.name for d in devices}) != len(devices):
            raise ValueError("duplicate enrollment")
        if not 1 <= domains <= quorum <= len(devices) or lease_ticks <= 0:
            raise ValueError("invalid quorum or lease")
        self.owner, self.contract = owner, "personal-state-v1"
        self.devices = {d.name: (d.key.public_key(), d.domain) for d in devices}
        self.quorum, self.domains, self.lease_ticks = quorum, domains, lease_ticks
        self.epoch, self.suspended, self.version = 0, False, 1
        self.data_key = AESGCM.generate_key(bit_length=256)
        self.recovery_key = Ed25519PrivateKey.generate()
        self.recovery_public = self.recovery_key.public_key()
        self.pending: dict[str, dict] = {}
        self.leases: dict[str, dict] = {}
        self.last_time = -1

    def clock(self, now: int):
        if type(now) is not int or now < self.last_time:
            raise PermissionError("invalid or rolled-back trusted clock")
        self.last_time = now

    def challenge(self, now: int, scope: str = "infer") -> dict:
        self.clock(now)
        if scope not in {"infer", "recover"}:
            raise PermissionError("unknown scope")
        c = {"owner": self.owner, "contract": self.contract, "epoch": self.epoch,
             "nonce": secrets.token_hex(16), "expires": now + 2, "scope": scope}
        self.pending[c["nonce"]] = c.copy()
        return c

    def _fresh(self, c: dict, now: int, scope: str):
        self.clock(now)
        if (self.pending.get(c.get("nonce")) != c or c.get("owner") != self.owner
                or c.get("contract") != self.contract or c.get("epoch") != self.epoch
                or c.get("scope") != scope or now >= c.get("expires", -1)):
            raise PermissionError("unrecognized, stale or out-of-scope challenge")

    def issue(self, c: dict, evidence: list[dict], now: int) -> str:
        self._fresh(c, now, "infer")
        if self.suspended:
            raise PermissionError("suspended")
        seen, domains = set(), set()
        for item in evidence:
            msg = item.get("message", {})
            name = msg.get("device")
            if name not in self.devices or name in seen or msg != {**c, "device": name}:
                raise PermissionError("invalid or duplicate device evidence")
            pub, domain = self.devices[name]
            try:
                pub.verify(bytes.fromhex(item["signature"]), canonical(msg))
            except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
                raise PermissionError("invalid signature") from exc
            seen.add(name)
            domains.add(domain)
        if len(seen) < self.quorum or len(domains) < self.domains:
            raise PermissionError("insufficient independent evidence")
        del self.pending[c["nonce"]]
        token = secrets.token_hex(24)
        self.leases[token] = {"epoch": self.epoch, "expires": now + self.lease_ticks}
        return token

    def seal(self, payload: bytes) -> dict:
        metadata = {"owner": self.owner, "contract": self.contract, "version": self.version}
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self.data_key).encrypt(nonce, payload, canonical(metadata))
        return {"metadata": metadata, "nonce": nonce.hex(), "ciphertext": encrypted.hex()}

    def open(self, envelope: dict, lease: str, now: int) -> bytes:
        self.clock(now)
        grant = self.leases.get(lease)
        if (self.suspended or not grant or grant["epoch"] != self.epoch
                or now >= grant["expires"]):
            raise PermissionError("no current lease")
        expected = {"owner": self.owner, "contract": self.contract, "version": self.version}
        if envelope["metadata"] != expected:
            raise PermissionError("payload context mismatch")
        return AESGCM(self.data_key).decrypt(bytes.fromhex(envelope["nonce"]),
                 bytes.fromhex(envelope["ciphertext"]), canonical(envelope["metadata"]))

    def suspend(self, now: int):
        self.clock(now)
        self.suspended = True
        self.epoch += 1
        self.leases.clear()
        self.pending.clear()

    def recover(self, c: dict, signature: bytes, now: int):
        self._fresh(c, now, "recover")
        try:
            self.recovery_public.verify(signature, canonical(c))
        except InvalidSignature as exc:
            raise PermissionError("invalid recovery approval") from exc
        self.epoch += 1
        self.suspended = False
        self.pending.clear()
        self.leases.clear()


def fixture(owner="person-0"):
    devices = [Device.create("wrist", "wrist"), Device.create("ring", "ring"),
               Device.create("phone", "phone")]
    return Broker(owner, devices), devices


def acquire(broker: Broker, devices: list[Device], now: int) -> str:
    c = broker.challenge(now)
    return broker.issue(c, [d.sign(c) for d in devices[:broker.quorum]], now)
