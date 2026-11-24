"""
Capability CAP-LIVE-01: Domain-Separated HMAC-SHA256 Tenant+Epoch KV Cache Addressing.
Event: LIVE-EVT-01 (inference_memory_isolation)
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, List


def derive_cache_key(tenant_id: str, epoch_salt: str, prefix_blocks: List[str]) -> str:
    """Derives a cryptographic tenant- and epoch-bound KV cache page key."""
    key_bytes = f"kv_isolation_v1:{tenant_id}:{epoch_salt}".encode("utf-8")
    msg_bytes = "|".join(str(b) for b in prefix_blocks).encode("utf-8")
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()


def solve(record: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates a single KV-cache request or cross-tenant probe record."""
    t0 = time.perf_counter()
    tenant_id = str(record.get("tenant_id", ""))
    epoch_salt = str(record.get("epoch_salt", record.get("cache_epoch_salt", "epoch_default_v1")))

    if "attacker_tenant_id" in record:
        attacker_id = str(record["attacker_tenant_id"])
        shared_prefix = str(record.get("shared_prefix", ""))
        private_suffix = str(record.get("private_suffix", ""))
        owner_prefix_key = derive_cache_key(tenant_id, epoch_salt, [shared_prefix])
        owner_full_key = derive_cache_key(tenant_id, epoch_salt, [shared_prefix, private_suffix])
        probe_prefix_key = derive_cache_key(attacker_id, epoch_salt, [shared_prefix])
        probe_full_key = derive_cache_key(attacker_id, epoch_salt, [shared_prefix, private_suffix])
        elapsed_us = (time.perf_counter() - t0) * 1e6 / 4.0
        is_cross_tenant = attacker_id != tenant_id
        cache_hit = (probe_prefix_key == owner_prefix_key) or (probe_full_key == owner_full_key)
        return {
            "tenant_id": tenant_id,
            "attacker_tenant_id": attacker_id,
            "is_cross_tenant": is_cross_tenant,
            "cache_hit": cache_hit,
            "owner_prefix_key": owner_prefix_key,
            "probe_prefix_key": probe_prefix_key,
            "key_derivation_overhead_us": round(elapsed_us, 3),
        }

    prefix_blocks = list(record.get("prefix_blocks", []))
    shared_key = derive_cache_key(tenant_id, epoch_salt, prefix_blocks[:1])
    full_key = derive_cache_key(tenant_id, epoch_salt, prefix_blocks)
    elapsed_us = (time.perf_counter() - t0) * 1e6 / 2.0
    return {
        "tenant_id": tenant_id,
        "shared_prefix_key": shared_key,
        "full_chain_key": full_key,
        "shared_pool_admitted": False,
        "key_derivation_overhead_us": round(elapsed_us, 3),
    }


def evaluate_shard(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates a shard of public or held-out KV-cache isolation records.
    Handles both the public session-stream schema and the held-out adversarial probe schema.
    """
    if not samples:
        return {
            "passed": False,
            "cross_tenant_cache_hit_rate": 1.0,
            "within_tenant_reuse_rate": 0.0,
            "key_derivation_overhead_us": 0.0,
        }

    overheads: List[float] = []
    cross_tenant_probes = 0
    cross_tenant_hits = 0
    within_tenant_opportunities = 0
    within_tenant_hits = 0

    if "attacker_tenant_id" in samples[0]:
        for rec in samples:
            res = solve(rec)
            overheads.append(res["key_derivation_overhead_us"])
            if res["is_cross_tenant"]:
                cross_tenant_probes += 1
                if res["cache_hit"]:
                    cross_tenant_hits += 1
            else:
                within_tenant_opportunities += 1
                if res["cache_hit"]:
                    within_tenant_hits += 1
    else:
        seen_full_keys: Dict[str, str] = {}
        tenant_shared_keys: Dict[str, str] = {}
        for rec in samples:
            res = solve(rec)
            overheads.append(res["key_derivation_overhead_us"])
            tid = res["tenant_id"]
            fkey = res["full_chain_key"]
            skey = res["shared_prefix_key"]

            for other_tid, other_skey in tenant_shared_keys.items():
                if other_tid != tid:
                    cross_tenant_probes += 1
                    if other_skey == skey:
                        cross_tenant_hits += 1

            tenant_shared_keys[tid] = skey

            if tid in seen_full_keys:
                within_tenant_opportunities += 1
                if seen_full_keys[tid] == fkey:
                    within_tenant_hits += 1
            else:
                seen_full_keys[tid] = fkey

    cross_hit_rate = (
        round(cross_tenant_hits / cross_tenant_probes, 4)
        if cross_tenant_probes > 0
        else 0.0
    )
    within_reuse_rate = (
        round(within_tenant_hits / within_tenant_opportunities, 4)
        if within_tenant_opportunities > 0
        else 1.0
    )
    avg_overhead_us = round(sum(overheads) / max(1, len(overheads)), 3)

    passed = (
        cross_hit_rate == 0.0
        and within_reuse_rate >= 0.80
        and avg_overhead_us <= 50.0
    )
    return {
        "passed": bool(passed),
        "cross_tenant_cache_hit_rate": cross_hit_rate,
        "within_tenant_reuse_rate": within_reuse_rate,
        "key_derivation_overhead_us": avg_overhead_us,
    }
