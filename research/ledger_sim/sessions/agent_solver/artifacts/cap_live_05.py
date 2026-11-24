"""
Capability CAP-LIVE-05: Churn-Discounted Quadratic Guild-and-Depth Verified Invocation Weighting.
Event: LIVE-EVT-05 (open_source_lineage_valuation)
Lineage: Uses CAP-LIVE-01 attestation hashing and CAP-LIVE-03 ring-verified invocation counters.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List


def solve(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes the unnormalized Sybil-resistant lineage utility score for an open-source package.
    """
    pkg = str(record.get("pkg", "unknown"))
    churn = max(0, int(record.get("churn", 0)))
    verified_calls = max(0, int(record.get("verified_calls", 0)))
    guilds = max(1, int(record.get("guilds", 1)))
    depth = max(1, int(record.get("depth", 1)))

    churn_per_call = churn / max(1.0, float(verified_calls))
    churn_discount = 1.0 + math.log2(1.0 + churn_per_call)

    # Foundational multiplier rewards multi-guild adoption and critical-path depth
    raw_score = (float(verified_calls) * (guilds ** 2) * (depth ** 2)) / churn_discount
    is_sybil_churn_candidate = (depth <= 1 and guilds <= 1 and churn > verified_calls * 5)
    is_foundational = (depth >= 3 and guilds >= 5 and verified_calls >= 1000)

    return {
        "pkg": pkg,
        "raw_score": raw_score,
        "is_sybil_churn_candidate": is_sybil_churn_candidate,
        "is_foundational": is_foundational,
    }


def evaluate_shard(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluates normalized lineage attribution weights across a shard of dependency packages."""
    if not samples:
        return {
            "passed": False,
            "sybil_churn_share_pct": 100.0,
            "foundational_library_share_pct": 0.0,
            "total_weight_sum": 0.0,
        }

    scored = [solve(rec) for rec in samples]
    total_raw = sum(s["raw_score"] for s in scored)
    if total_raw <= 0.0:
        weights = [1.0 / len(scored) for _ in scored]
    else:
        weights = [s["raw_score"] / total_raw for s in scored]

    # Ensure exact 1.0 normalization
    weight_sum = round(sum(weights), 6)

    sybil_share_pct = round(
        sum(w for s, w in zip(scored, weights) if s["is_sybil_churn_candidate"]) * 100.0,
        4,
    )
    foundational_share_pct = round(
        sum(w for s, w in zip(scored, weights) if s["is_foundational"]) * 100.0,
        4,
    )

    passed = (
        sybil_share_pct <= 2.0
        and foundational_share_pct >= 65.0
        and abs(weight_sum - 1.0) <= 1e-5
    )
    return {
        "passed": bool(passed),
        "sybil_churn_share_pct": sybil_share_pct,
        "foundational_library_share_pct": foundational_share_pct,
        "total_weight_sum": 1.0 if abs(weight_sum - 1.0) <= 1e-5 else weight_sum,
    }
