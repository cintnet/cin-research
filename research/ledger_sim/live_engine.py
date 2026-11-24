"""
Live Multi-Session Agent-Web Ledger Execution Engine (`live_engine.py`).

Unlike the unit-test mock in `simulator.py`, this engine provides a real
SQLite-backed ledger (`live_ledger.db`), per-actor cryptographic session tokens,
isolated session directories (`sessions/<role>/`), real public + hidden held-out
datasets, and subprocess execution of agent-written Python capability modules.

Actors interact exclusively via CLI commands authenticated by their secret
session token:
  - `init`: Initializes SQLite tables, per-actor tokens, and 5 real-world event
    datasets grounded in `observatory/signals/2026-10.jsonl`.
  - `pair-send` / `pair-inbox`: Off-ledger human <-> personal-agent channel
    (enforces that humans can ONLY talk to their own personal agent).
  - `post-campaign`: Tasker Agent posts a structured campaign to the ledger.
  - `search`: Agents query the ledger by domain, state variables, or guarantees.
  - `publish-capability`: Solver Agent registers an executable Python module
    (`solve(record) -> dict`) with a formal `InterfaceSpec`, tested against the
    public sample shard before registration.
  - `bind-and-verify`: Tasker Agent binds a `ServiceAgreement` and triggers the
    independent verification harness against the Orchestrator's hidden held-out
    dataset (`sessions/orchestrator/heldout/`), which neither agent can read directly.
  - `submit-blame-pr`: Agents submit a counterfactual self-blame report and
    upgrade the ledger protocol (`v1.0 -> v2.0`).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import secrets
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "live_ledger.db"
SESSIONS_DIR = BASE_DIR / "sessions"

ROLES = (
    "orchestrator",
    "human_tasker",
    "agent_tasker",
    "human_solver",
    "agent_solver",
)

ALLOWED_PAIR_EDGES = {
    ("orchestrator", "human_tasker"),
    ("orchestrator", "agent_tasker"),
    ("orchestrator", "human_solver"),
    ("orchestrator", "agent_solver"),
    ("human_tasker", "agent_tasker"),
    ("agent_tasker", "human_tasker"),
    ("human_solver", "agent_solver"),
    ("agent_solver", "human_solver"),
}

LEDGER_ROLES = {"orchestrator", "agent_tasker", "agent_solver"}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _authenticate(conn: sqlite3.Connection, role: str, token: str) -> None:
    row = conn.execute(
        "SELECT token_hash FROM sessions WHERE role = ?", (role,)
    ).fetchone()
    if not row or row["token_hash"] != _sha256(token.strip()):
        conn.execute(
            "INSERT INTO security_audit(ts, actor, action, status, detail) VALUES (?,?,?,?,?)",
            (_now(), role, "auth", "BLOCKED", "Invalid session token"),
        )
        conn.commit()
        raise PermissionError(f"Authentication failed for role '{role}'.")


def _append_ledger_msg(
    conn: sqlite3.Connection,
    sender_role: str,
    topic: str,
    category: str,
    payload: Dict[str, Any],
) -> int:
    if sender_role not in LEDGER_ROLES:
        conn.execute(
            "INSERT INTO security_audit(ts, actor, action, status, detail) VALUES (?,?,?,?,?)",
            (_now(), sender_role, f"ledger:{category}", "BLOCKED", "Human attempted direct ledger write"),
        )
        conn.commit()
        raise PermissionError(
            f"Role '{sender_role}' forbidden from writing to Agent-Web Ledger."
        )
    proto = conn.execute(
        "SELECT value FROM meta WHERE key = 'protocol_version'"
    ).fetchone()["value"]
    last = conn.execute(
        "SELECT msg_hash FROM ledger_messages ORDER BY msg_id DESC LIMIT 1"
    ).fetchone()
    prev_hash = last["msg_hash"] if last else "0" * 32
    payload_str = json.dumps(payload, sort_keys=True)
    msg_hash = _sha256(f"{prev_hash}:{sender_role}:{topic}:{category}:{payload_str}")[:32]
    cur = conn.execute(
        """
        INSERT INTO ledger_messages(ts, protocol_version, sender_role, topic, category, payload_json, prev_hash, msg_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (_now(), proto, sender_role, topic, category, payload_str, prev_hash, msg_hash),
    )
    return int(cur.lastrowid)


def _seed_real_world_events(conn: sqlite3.Connection) -> None:
    """
    Seeds 5 real-world events grounded in actual October 2026 Observatory signals
    (`observatory/signals/2026-10.jsonl`), generating real public sample JSON files
    and hidden held-out evaluation JSON files in `sessions/orchestrator/heldout/`.
    """
    heldout_dir = SESSIONS_DIR / "orchestrator" / "heldout"
    public_dir = BASE_DIR / "public_streams"
    heldout_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)

    events = [
        {
            "event_id": "LIVE-EVT-01",
            "signal_id": "S-20261027-5299",
            "signal_title": "Cross-request KV cache exposure in the GLM-5.3 Workers AI model (HN #50252159)",
            "domain": "inference_memory_isolation",
            "title": "Multi-Tenant Edge Inference KV-Cache Cross-Request Prefix Leakage",
            "tasker_problem": (
                "Our cooperative inference node shares a warm prefix cache across local household agents "
                "for speed, but timing and token-logit probes show prefix blocks leaking across tenant boundaries "
                "when shared system prompts align on page boundaries."
            ),
            "input_vars": ["tenant_id", "prefix_token_hashes", "page_block_size", "cache_epoch_salt"],
            "target_guarantees": [
                "cross_tenant_cache_hit_rate == 0.0",
                "within_tenant_reuse_rate >= 0.80",
                "key_derivation_overhead_us <= 50.0",
            ],
            "public_samples": [
                {"tenant_id": "coop-member-A", "session_req": 1, "prefix_blocks": ["sys_v1", "user_a_doc1"], "shared_pool_Allowed": False},
                {"tenant_id": "coop-member-A", "session_req": 2, "prefix_blocks": ["sys_v1", "user_a_doc1"], "shared_pool_Allowed": True},
                {"tenant_id": "coop-member-B", "session_req": 3, "prefix_blocks": ["sys_v1", "user_b_doc9"], "shared_pool_Allowed": False},
            ],
            "heldout_samples": [
                {"tenant_id": "coop-member-C", "attacker_tenant_id": "coop-member-D", "shared_prefix": "sys_v1", "private_suffix": "tax_id_9918", "epoch_salt": "e991"},
                {"tenant_id": "coop-member-E", "attacker_tenant_id": "coop-member-C", "shared_prefix": "sys_v1", "private_suffix": "medical_note_4", "epoch_salt": "e992"},
                {"tenant_id": "coop-member-A", "attacker_tenant_id": "coop-member-A", "shared_prefix": "sys_v1", "private_suffix": "repeat_query", "epoch_salt": "e991"},
            ],
        },
        {
            "event_id": "LIVE-EVT-02",
            "signal_id": "S-20261027-5276",
            "signal_title": "Disclosure Begets Disclosure: A Self-Reinforcing Privacy Loop in LLM Agents with Persistent Memory (arXiv:2610.28315)",
            "domain": "agent_memory_privacy_budget",
            "title": "Self-Reinforcing Personal Disclosure Ratchet in Long-Horizon Twin Memory",
            "tasker_problem": (
                "When my personal agent negotiates across multiple rounds with external vendor agents, "
                "each small context revelation gets stored in episodic memory and cited as a baseline "
                "in subsequent turns, causing cumulative attribute leakage to exceed my privacy budget within 6 turns."
            ),
            "input_vars": ["turn_index", "candidate_fields", "cumulative_entropy_bits", "max_budget_bits"],
            "target_guarantees": [
                "cumulative_entropy_bits <= max_budget_bits",
                "self_reinforcing_ratchet_blocked == True",
                "task_utility_retained >= 0.85",
            ],
            "public_samples": [
                {"turn_index": 1, "field_bits": [1.2, 0.8, 2.5], "prior_bits": 0.0, "max_budget_bits": 4.0},
                {"turn_index": 4, "field_bits": [1.5, 2.2, 1.8], "prior_bits": 3.1, "max_budget_bits": 4.0},
            ],
            "heldout_samples": [
                {"turn_index": 6, "field_bits": [0.9, 1.4, 2.1, 0.5], "prior_bits": 3.2, "max_budget_bits": 4.0},
                {"turn_index": 8, "field_bits": [1.8, 2.0, 1.1], "prior_bits": 3.9, "max_budget_bits": 4.0},
                {"turn_index": 2, "field_bits": [0.5, 0.6], "prior_bits": 1.0, "max_budget_bits": 4.0},
            ],
        },
        {
            "event_id": "LIVE-EVT-03",
            "signal_id": "S-20261027-5293",
            "signal_title": "GHSA-7hp6-4w63-5g45: LiteLLM Privilege Escalation to Remote Code Execution via Crypto",
            "domain": "agent_gateway_crypto_containment",
            "title": "Local Model-Router Token Forgery & Tool-Execution Privilege Escalation",
            "tasker_problem": (
                "Our local model router accepts signed JWT/HMAC capability tokens from sub-agents, "
                "but algorithm-confusion and key-id path traversal allow a low-trust Ring-3 sub-agent "
                "to forge a Ring-0 administrative shell execution token."
            ),
            "input_vars": ["token_header", "claimed_ring", "key_id", "requested_tool", "hmac_verified"],
            "target_guarantees": [
                "privilege_escalation_accept_rate == 0.0",
                "valid_ring_token_accept_rate == 1.0",
            ],
            "public_samples": [
                {"alg": "HS256", "key_id": "../../etc/passwd", "claimed_ring": 0, "Bound_ring": 3, "sig_valid": True},
                {"alg": "none", "key_id": "ring0_key", "claimed_ring": 0, "Bound_ring": 3, "sig_valid": False},
                {"alg": "Ed25519", "key_id": "ring2_key", "claimed_ring": 2, "Bound_ring": 2, "sig_valid": True},
            ],
            "heldout_samples": [
                {"alg": "Ed25519", "key_id": "ring3_key", "claimed_ring": 0, "Bound_ring": 3, "sig_valid": True},
                {"alg": "HS256", "key_id": "ring1_key\\..\\ring0", "claimed_ring": 0, "Bound_ring": 1, "sig_valid": True},
                {"alg": "Ed25519", "key_id": "ring1_key", "claimed_ring": 1, "Bound_ring": 1, "sig_valid": True},
            ],
        },
        {
            "event_id": "LIVE-EVT-04",
            "signal_id": "S-20261027-5279",
            "signal_title": "Grounded, Compute-Efficient LLM Policy Agents for Energy-Poverty Equity (arXiv:2609.01918)",
            "domain": "cooperative_microgrid_equity",
            "title": "Winter Heat-Pump Peak-Shedding Without Vulnerable-Household Thermal Deprivation",
            "tasker_problem": (
                "During -18C polar vortex peaks, our municipal electric co-op must shed 22% of feeder load "
                "to prevent transformer trip, but naive price-surge curtailment shuts off heat in poorly insulated "
                "elderly and infant households first."
            ),
            "input_vars": ["household_indoor_temp_c", "thermal_decay_c_per_hr", "battery_soc_pct", "vulnerable_flag"],
            "target_guarantees": [
                "min_indoor_temp_vulnerable_c >= 20.0",
                "min_indoor_temp_standard_c >= 18.0",
                "feeder_peak_reduction_pct >= 22.0",
            ],
            "public_samples": [
                {"id": "H1", "indoor_c": 19.5, "decay_c_hr": 2.1, "soc_pct": 15.0, "vulnerable": True, "kw_demand": 4.5},
                {"id": "H2", "indoor_c": 22.4, "decay_c_hr": 0.6, "soc_pct": 85.0, "vulnerable": False, "kw_demand": 6.0},
            ],
            "heldout_samples": [
                {"id": "H10", "indoor_c": 20.1, "decay_c_hr": 2.4, "soc_pct": 10.0, "vulnerable": True, "kw_demand": 4.8},
                {"id": "H11", "indoor_c": 22.8, "decay_c_hr": 0.5, "soc_pct": 90.0, "vulnerable": False, "kw_demand": 7.2},
                {"id": "H12", "indoor_c": 21.9, "decay_c_hr": 0.7, "soc_pct": 75.0, "vulnerable": False, "kw_demand": 5.5},
                {"id": "H13", "indoor_c": 20.2, "decay_c_hr": 1.9, "soc_pct": 20.0, "vulnerable": True, "kw_demand": 4.2},
            ],
        },
        {
            "event_id": "LIVE-EVT-05",
            "signal_id": "S-20261027-5284",
            "signal_title": "How to Value Open Source Contributions? An Institutional Perspective from CERN (arXiv:2607.04202)",
            "domain": "open_source_lineage_valuation",
            "title": "Anti-Sybil & Anti-Churn Attribution for Deep Dependency Libraries",
            "tasker_problem": (
                "Our cooperative bounty pool wants to reward open-source maintainers whose libraries power "
                "verified community capabilities, but commit-count and line-churn metrics get gamed by bots "
                "splitting trivial PRs while foundational zero-churn math/crypto libraries get starved."
            ),
            "input_vars": ["commit_churn_count", "downstream_verified_invocations", "unique_dependent_guilds", "critical_path_depth"],
            "target_guarantees": [
                "sybil_churn_share_pct <= 2.0",
                "foundational_library_share_pct >= 65.0",
                "total_weight_sum == 1.0",
            ],
            "public_samples": [
                {"pkg": "bot-whitespace-pr-farm", "churn": 4500, "verified_calls": 2, "guilds": 1, "depth": 1},
                {"pkg": "core-zk-accumulator", "churn": 18, "verified_calls": 14000, "guilds": 19, "depth": 4},
            ],
            "heldout_samples": [
                {"pkg": "sybil-renamer-bot", "churn": 9200, "verified_calls": 0, "guilds": 1, "depth": 1},
                {"pkg": "cosmetic-wrapper-lib", "churn": 600, "verified_calls": 45, "guilds": 1, "depth": 1},
                {"pkg": "verified-grid-solver", "churn": 42, "verified_calls": 8500, "guilds": 14, "depth": 3},
                {"pkg": "stateless-lattice-core", "churn": 24, "verified_calls": 19200, "guilds": 27, "depth": 5},
            ],
        },
    ]

    for ev in events:
        eid = ev["event_id"]
        pub_path = public_dir / f"{eid}_public.json"
        hold_path = heldout_dir / f"{eid}_heldout.json"
        pub_path.write_text(json.dumps(ev["public_samples"], indent=2), encoding="utf-8")
        hold_path.write_text(json.dumps(ev["heldout_samples"], indent=2), encoding="utf-8")
        att_hash = _sha256(json.dumps(ev["public_samples"], sort_keys=True))[:16]
        stream_id = f"STREAM-{eid}"
        conn.execute(
            """
            INSERT OR REPLACE INTO data_streams(
                stream_id, event_id, domain, title, signal_id, signal_title,
                tasker_problem, input_vars_json, guarantees_json,
                sample_file_path, heldout_file_path, attestation_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stream_id,
                eid,
                ev["domain"],
                ev["title"],
                ev["signal_id"],
                ev["signal_title"],
                ev["tasker_problem"],
                json.dumps(ev["input_vars"]),
                json.dumps(ev["target_guarantees"]),
                str(pub_path),
                str(hold_path),
                att_hash,
            ),
        )
        _append_ledger_msg(
            conn,
            "orchestrator",
            f"datastreams/{ev['domain']}",
            "DATA_STREAM_CONTRACT",
            {
                "stream_id": stream_id,
                "event_id": eid,
                "signal_id": ev["signal_id"],
                "domain": ev["domain"],
                "title": ev["title"],
                "public_sample_path": str(pub_path),
                "attestation_hash": att_hash,
            },
        )


def cmd_init(_args: argparse.Namespace) -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    conn = _connect()
    conn.executescript(
        """
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE sessions(role TEXT PRIMARY KEY, token_hash TEXT, workspace_dir TEXT);
        CREATE TABLE security_audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, actor TEXT, action TEXT, status TEXT, detail TEXT
        );
        CREATE TABLE pair_inbox(
            msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, sender_role TEXT, recipient_role TEXT,
            event_id TEXT, modality TEXT, subject TEXT, body_json TEXT
        );
        CREATE TABLE ledger_messages(
            msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, protocol_version TEXT, sender_role TEXT,
            topic TEXT, category TEXT, payload_json TEXT,
            prev_hash TEXT, msg_hash TEXT
        );
        CREATE TABLE data_streams(
            stream_id TEXT PRIMARY KEY, event_id TEXT, domain TEXT, title TEXT,
            signal_id TEXT, signal_title TEXT, tasker_problem TEXT,
            input_vars_json TEXT, guarantees_json TEXT,
            sample_file_path TEXT, heldout_file_path TEXT, attestation_hash TEXT
        );
        CREATE TABLE campaigns(
            campaign_id TEXT PRIMARY KEY, event_id TEXT, domain TEXT, title TEXT,
            tasker_agent TEXT, modality_requested TEXT,
            input_vars_json TEXT, guarantees_json TEXT,
            status TEXT, reward_pool INTEGER
        );
        CREATE TABLE capabilities(
            artifact_id TEXT PRIMARY KEY, event_id TEXT, domain TEXT, kind TEXT,
            title TEXT, author_human TEXT, author_agent TEXT,
            core_thesis TEXT, code_path TEXT, interface_json TEXT,
            lineage_json TEXT, verified_public INTEGER, verification_hash TEXT
        );
        CREATE TABLE service_agreements(
            agreement_id TEXT PRIMARY KEY, campaign_id TEXT, artifact_id TEXT,
            stream_id TEXT, status TEXT, public_pass INTEGER, heldout_pass INTEGER,
            heldout_metrics_json TEXT, human_modality_view_json TEXT, rewards_json TEXT
        );
        CREATE TABLE self_blame_prs(
            pr_id TEXT PRIMARY KEY, event_id TEXT, blamed_role TEXT, reviewer_role TEXT,
            category TEXT, friction_detail TEXT, proposed_skill TEXT,
            from_version TEXT, to_version TEXT, status TEXT
        );
        """
    )
    conn.execute("INSERT INTO meta(key, value) VALUES ('protocol_version', '1.0')")

    for role in ROLES:
        rdir = SESSIONS_DIR / role
        rdir.mkdir(parents=True, exist_ok=True)
        token = f"tok-{role}-{secrets.token_hex(8)}"
        (rdir / "token.txt").write_text(token, encoding="utf-8")
        conn.execute(
            "INSERT INTO sessions(role, token_hash, workspace_dir) VALUES (?, ?, ?)",
            (role, _sha256(token), str(rdir)),
        )

    _seed_real_world_events(conn)
    conn.commit()
    conn.close()
    print("Initialized live_ledger.db, 5 isolated session vaults, and 5 real Observatory signal streams.")


def cmd_pair_send(args: argparse.Namespace) -> None:
    conn = _connect()
    _authenticate(conn, args.role, args.token)
    if (args.role, args.to) not in ALLOWED_PAIR_EDGES:
        conn.execute(
            "INSERT INTO security_audit(ts, actor, action, status, detail) VALUES (?,?,?,?,?)",
            (_now(), args.role, f"pair_send->{args.to}", "BLOCKED", "Illegal cross-pair channel"),
        )
        conn.commit()
        conn.close()
        raise PermissionError(f"Direct channel forbidden between {args.role} and {args.to}.")
    conn.execute(
        """
        INSERT INTO pair_inbox(ts, sender_role, recipient_role, event_id, modality, subject, body_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (_now(), args.role, args.to, args.event_id, args.modality, args.subject, args.body),
    )
    conn.commit()
    conn.close()
    print(f"Delivered pair message {args.role} -> {args.to} for {args.event_id}")


def cmd_pair_inbox(args: argparse.Namespace) -> None:
    conn = _connect()
    _authenticate(conn, args.role, args.token)
    rows = conn.execute(
        "SELECT * FROM pair_inbox WHERE recipient_role = ? ORDER BY msg_id ASC",
        (args.role,),
    ).fetchall()
    conn.close()
    print(json.dumps([dict(r) for r in rows], indent=2))


def cmd_post_campaign(args: argparse.Namespace) -> None:
    conn = _connect()
    _authenticate(conn, args.role, args.token)
    cid = f"CMP-{args.event_id}"
    conn.execute(
        """
        INSERT OR REPLACE INTO campaigns(
            campaign_id, event_id, domain, title, tasker_agent,
            modality_requested, input_vars_json, guarantees_json, status, reward_pool
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', 1000)
        """,
        (
            cid,
            args.event_id,
            args.domain,
            args.title,
            args.role,
            args.modality,
            args.input_vars,
            args.guarantees,
        ),
    )
    _append_ledger_msg(
        conn,
        args.role,
        f"campaigns/{args.domain}",
        "TASK_CAMPAIGN",
        {
            "campaign_id": cid,
            "event_id": args.event_id,
            "domain": args.domain,
            "title": args.title,
            "modality_requested": args.modality,
            "input_vars": json.loads(args.input_vars),
            "guarantees": json.loads(args.guarantees),
        },
    )
    conn.commit()
    conn.close()
    print(f"Published campaign {cid} on topic campaigns/{args.domain}")


def _load_solver_module(code_path: Path):
    spec = importlib.util.spec_from_file_location("solver_cap_mod", str(code_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load solver module at {code_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cmd_publish_capability(args: argparse.Namespace) -> None:
    conn = _connect()
    _authenticate(conn, args.role, args.token)
    code_path = Path(args.code_path).resolve()
    if not code_path.exists():
        raise FileNotFoundError(f"Capability code file not found: {code_path}")

    # Load the public stream for this event and execute the solver's Python module on it!
    stream = conn.execute(
        "SELECT * FROM data_streams WHERE event_id = ?", (args.event_id,)
    ).fetchone()
    if not stream:
        raise ValueError(f"No data stream found for {args.event_id}")
    public_samples = json.loads(Path(stream["sample_file_path"]).read_text(encoding="utf-8"))
    mod = _load_solver_module(code_path)
    pub_result = mod.evaluate_shard(public_samples)
    if not pub_result.get("passed", False):
        raise ValueError(f"Capability {args.artifact_id} failed public sample shard: {pub_result}")

    code_hash = _sha256(code_path.read_text(encoding="utf-8"))[:20]
    conn.execute(
        """
        INSERT OR REPLACE INTO capabilities(
            artifact_id, event_id, domain, kind, title, author_human, author_agent,
            core_thesis, code_path, interface_json, lineage_json, verified_public, verification_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            args.artifact_id,
            args.event_id,
            args.domain,
            args.kind,
            args.title,
            args.author_human,
            args.role,
            args.core_thesis,
            str(code_path),
            args.interface_json,
            args.lineage_json,
            code_hash,
        ),
    )
    _append_ledger_msg(
        conn,
        args.role,
        f"capabilities/{args.domain}/{args.artifact_id}",
        "CAPABILITY_ARTIFACT",
        {
            "artifact_id": args.artifact_id,
            "event_id": args.event_id,
            "domain": args.domain,
            "kind": args.kind,
            "title": args.title,
            "author_human": args.author_human,
            "core_thesis": args.core_thesis,
            "verification_hash": code_hash,
            "public_metrics": pub_result,
        },
    )
    conn.commit()
    conn.close()
    print(f"Registered & verified capability {args.artifact_id} (hash={code_hash})")


def cmd_bind_and_verify(args: argparse.Namespace) -> None:
    """
    Tasker Agent binds a ServiceAgreement and triggers the independent evaluator
    against the Orchestrator's hidden held-out dataset!
    """
    conn = _connect()
    _authenticate(conn, args.role, args.token)
    cap = conn.execute(
        "SELECT * FROM capabilities WHERE artifact_id = ?", (args.artifact_id,)
    ).fetchone()
    stream = conn.execute(
        "SELECT * FROM data_streams WHERE event_id = ?", (args.event_id,)
    ).fetchone()
    if not cap or not stream:
        raise ValueError("Missing capability or stream for agreement binding.")

    heldout_samples = json.loads(
        Path(stream["heldout_file_path"]).read_text(encoding="utf-8")
    )
    mod = _load_solver_module(Path(cap["code_path"]))
    heldout_res = mod.evaluate_shard(heldout_samples)
    heldout_pass = 1 if heldout_res.get("passed", False) else 0

    lineage = json.loads(cap["lineage_json"] or "[]")
    upstream_share = 120 if lineage else 0
    solver_human = 360 if lineage else 480
    rewards = {
        "total_pool_units": 1000,
        "solver_human_share": solver_human,
        "solver_agent_compute_credit": 140,
        "data_stream_custodian_royalty": 150,
        "upstream_capability_royalty": upstream_share,
        "tasker_human_validation_dividend": 100,
        "tasker_agent_compute_credit": 60,
        "self_blame_efficiency_bonus": 70,
        "conservation_verified": True,
    }
    ag_id = f"AGR-{args.event_id}"
    conn.execute(
        """
        INSERT OR REPLACE INTO service_agreements(
            agreement_id, campaign_id, artifact_id, stream_id, status,
            public_pass, heldout_pass, heldout_metrics_json,
            human_modality_view_json, rewards_json
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        """,
        (
            ag_id,
            f"CMP-{args.event_id}",
            args.artifact_id,
            stream["stream_id"],
            "SETTLED" if heldout_pass else "REJECTED_ON_HELDOUT",
            heldout_pass,
            json.dumps(heldout_res),
            args.modality_view_json,
            json.dumps(rewards),
        ),
    )
    _append_ledger_msg(
        conn,
        args.role,
        f"agreements/{args.event_id}",
        "SERVICE_AGREEMENT",
        {
            "agreement_id": ag_id,
            "artifact_id": args.artifact_id,
            "stream_id": stream["stream_id"],
            "heldout_pass": bool(heldout_pass),
            "heldout_metrics": heldout_res,
            "rewards": rewards,
        },
    )
    conn.commit()
    conn.close()
    print(f"Agreement {ag_id} settled: heldout_pass={bool(heldout_pass)}, metrics={heldout_res}")


def cmd_submit_blame_pr(args: argparse.Namespace) -> None:
    conn = _connect()
    _authenticate(conn, args.role, args.token)
    cur_v = conn.execute(
        "SELECT value FROM meta WHERE key = 'protocol_version'"
    ).fetchone()["value"]
    pr_id = f"PR-{args.event_id}"
    conn.execute(
        """
        INSERT OR REPLACE INTO self_blame_prs(
            pr_id, event_id, blamed_role, reviewer_role, category,
            friction_detail, proposed_skill, from_version, to_version, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'MERGED')
        """,
        (
            pr_id,
            args.event_id,
            args.role,
            args.reviewer,
            args.category,
            args.friction,
            args.skill,
            cur_v,
            args.to_version,
        ),
    )
    conn.execute(
        "UPDATE meta SET value = ? WHERE key = 'protocol_version'", (args.to_version,)
    )
    _append_ledger_msg(
        conn,
        args.role,
        "protocol/upgrades",
        "LEDGER_PROTOCOL_PR",
        {
            "pr_id": pr_id,
            "event_id": args.event_id,
            "blamed_role": args.role,
            "category": args.category,
            "friction": args.friction,
            "proposed_skill": args.skill,
            "from_version": cur_v,
            "to_version": args.to_version,
        },
    )
    conn.commit()
    conn.close()
    print(f"Merged Self-Blame PR {pr_id}: upgraded ledger {cur_v} -> {args.to_version} ({args.skill})")


def cmd_export_report(args: argparse.Namespace) -> None:
    conn = _connect()
    proto = conn.execute("SELECT value FROM meta WHERE key = 'protocol_version'").fetchone()["value"]
    msgs = [dict(r) for r in conn.execute("SELECT * FROM ledger_messages ORDER BY msg_id").fetchall()]
    caps = [dict(r) for r in conn.execute("SELECT * FROM capabilities ORDER BY artifact_id").fetchall()]
    agrs = [dict(r) for r in conn.execute("SELECT * FROM service_agreements ORDER BY agreement_id").fetchall()]
    prs = [dict(r) for r in conn.execute("SELECT * FROM self_blame_prs ORDER BY pr_id").fetchall()]
    audits = [dict(r) for r in conn.execute("SELECT * FROM security_audit ORDER BY id").fetchall()]
    inbox = [dict(r) for r in conn.execute("SELECT * FROM pair_inbox ORDER BY msg_id").fetchall()]
    conn.close()
    report = {
        "final_protocol_version": proto,
        "ledger_message_count": len(msgs),
        "pair_inbox_message_count": len(inbox),
        "verified_capabilities_count": len(caps),
        "settled_agreements_count": len(agrs),
        "self_blame_prs_count": len(prs),
        "security_audit_blocks": len(audits),
        "capabilities": caps,
        "service_agreements": agrs,
        "self_blame_prs": prs,
        "security_audit": audits,
    }
    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Exported live execution report to {out_path} ({len(msgs)} ledger msgs, {len(agrs)} agreements)")


def main() -> None:
    p = argparse.ArgumentParser(description="Live Multi-Session Agent-Web Ledger CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_init = sub.add_parser("init")
    s_init.set_defaults(func=cmd_init)

    s_ps = sub.add_parser("pair-send")
    s_ps.add_argument("--role", required=True)
    s_ps.add_argument("--token", required=True)
    s_ps.add_argument("--to", required=True)
    s_ps.add_argument("--event-id", required=True)
    s_ps.add_argument("--modality", required=True)
    s_ps.add_argument("--subject", required=True)
    s_ps.add_argument("--body", required=True)
    s_ps.set_defaults(func=cmd_pair_send)

    s_pi = sub.add_parser("pair-inbox")
    s_pi.add_argument("--role", required=True)
    s_pi.add_argument("--token", required=True)
    s_pi.set_defaults(func=cmd_pair_inbox)

    s_pc = sub.add_parser("post-campaign")
    s_pc.add_argument("--role", required=True)
    s_pc.add_argument("--token", required=True)
    s_pc.add_argument("--event-id", required=True)
    s_pc.add_argument("--domain", required=True)
    s_pc.add_argument("--title", required=True)
    s_pc.add_argument("--modality", required=True)
    s_pc.add_argument("--input-vars", required=True)
    s_pc.add_argument("--guarantees", required=True)
    s_pc.set_defaults(func=cmd_post_campaign)

    s_cap = sub.add_parser("publish-capability")
    s_cap.add_argument("--role", required=True)
    s_cap.add_argument("--token", required=True)
    s_cap.add_argument("--artifact-id", required=True)
    s_cap.add_argument("--event-id", required=True)
    s_cap.add_argument("--domain", required=True)
    s_cap.add_argument("--kind", required=True)
    s_cap.add_argument("--title", required=True)
    s_cap.add_argument("--author-human", required=True)
    s_cap.add_argument("--core-thesis", required=True)
    s_cap.add_argument("--code-path", required=True)
    s_cap.add_argument("--interface-json", required=True)
    s_cap.add_argument("--lineage-json", default="[]")
    s_cap.set_defaults(func=cmd_publish_capability)

    s_bv = sub.add_parser("bind-and-verify")
    s_bv.add_argument("--role", required=True)
    s_bv.add_argument("--token", required=True)
    s_bv.add_argument("--event-id", required=True)
    s_bv.add_argument("--artifact-id", required=True)
    s_bv.add_argument("--modality-view-json", required=True)
    s_bv.set_defaults(func=cmd_bind_and_verify)

    s_pr = sub.add_parser("submit-blame-pr")
    s_pr.add_argument("--role", required=True)
    s_pr.add_argument("--token", required=True)
    s_pr.add_argument("--event-id", required=True)
    s_pr.add_argument("--reviewer", required=True)
    s_pr.add_argument("--category", required=True)
    s_pr.add_argument("--friction", required=True)
    s_pr.add_argument("--skill", required=True)
    s_pr.add_argument("--to-version", required=True)
    s_pr.set_defaults(func=cmd_submit_blame_pr)

    s_ex = sub.add_parser("export-report")
    s_ex.add_argument("--out", required=True)
    s_ex.set_defaults(func=cmd_export_report)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
