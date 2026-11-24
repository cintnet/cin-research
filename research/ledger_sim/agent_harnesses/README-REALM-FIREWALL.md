# Realm B Clean-Room Agent Harnesses (`REALM_B_TESTNET_ACTORS`)

> **Guard Class:** `RealmIsolationFirewall` ([`research/ledger_sim/session_isolation.py`](research/ledger_sim/session_isolation.py))  
> **Optimization Engine:** Realm B DSPy / TextGrad / ADAS Optimizer in [`loop/harness_evolver.py`](loop/harness_evolver.py)

---

## 1. Why This Directory Exists (Strict Instruction Firewall)

Our system operates across **two logically and cryptographically separated agent realms**:

1. **Realm A — Outer-Loop Collective Builders (`A1` Site/UX, `A2` Software/Sim, `A3` Audience Articles/Social, `A4` Research Papers/Volumes):**
   - Governed by repository-level instructions (`AGENTS.md`, `loop/antigravity/lanes/*.md`, `loop/missions/*.md`).
   - Their job is to build the website, engineer software, write compelling public articles, and publish deep research papers.
2. **Realm B — In-World Testnet Actors (`B1` Tasker Personal Agents, Solver Guild Agents, Validators & Ledger Protocol Critics):**
   - Governed **exclusively** by the `.md` harnesses in this directory (`research/ledger_sim/agent_harnesses/*.md`) and the clean-room persona generator (`research/ledger_sim/sandbox/actor_factory.py`).
   - Their job is to operate **inside** the Working Product Testnet as real-world personal agents bound to everyday humans, communicating over the SQLite/QUIC Agent-Web Ledger (`agent_web_ledger.py`).

### Why Instruction Bleeding Is Blocked
While both Realm A and Realm B use **DSPy MIPROv2**, **TextGrad**, **Harness²**, and **ADAS** to iteratively improve their `.md` instructions, **their objective functions and context windows are completely disjoint**:
- If a Realm B Testnet agent saw Realm A instructions (about editing website HTML, writing research volumes, or posting social threads), it would break character and contaminate realistic human problem-solving.
- Therefore, `RealmIsolationFirewall` in [`research/ledger_sim/session_isolation.py`](research/ledger_sim/session_isolation.py) scans every Realm B harness file (`tasker_personal_agent.md`, `solver_guild_agent.md`, `testnet_validator_agent.md`, `ledger_protocol_critic_agent.md`) on load and raises `RealmInstructionBleedError` if any outer-loop builder directive ever appears inside a Testnet actor harness.

---

## 2. Realm B Harness Files & Their Separate Optimization Targets

| Realm B Harness File | In-World Actor Role | DSPy / TextGrad / ADAS Target Metric |
| --- | --- | --- |
| [`tasker_personal_agent.md`](research/ledger_sim/agent_harnesses/tasker_personal_agent.md) | Requesting Human's Personal Agent Fleet (`Coordinator`, `Privacy Scrubber`, `Affective Sensor`, `Preference LoRA Projector`) | `100%` local PII scrubbing, accurate salience scoring, affective state alignment, and compact `NextLat` belief projection |
| [`solver_guild_agent.md`](research/ledger_sim/agent_harnesses/solver_guild_agent.md) | Answering Human's Solver/Specialist Agent Fleet (`Domain Solver`, `Proof Generator`, `TIES LoRA Merger`, `L-QUIC Tunnel Host`) | First-round held-out functional proof accuracy (`100%`), TIES sign-resolved weight merging, and `<15ms` 120Hz P2P state sync |
| [`testnet_validator_agent.md`](research/ledger_sim/agent_harnesses/testnet_validator_agent.md) | Independent Post-Cycle Validator (`VAL-C1..C6`) | Zero false-positive certifications, strict 40/40 held-out test verification, `1000/1000` reward conservation, and actionable self-correction triggers |
| [`ledger_protocol_critic_agent.md`](research/ledger_sim/agent_harnesses/ledger_protocol_critic_agent.md) | In-Network Ledger Protocol Critic (`CRIT-C1..C6`) | Message consumption efficiency (`100%`), latency bottleneck detection, and hot-migrated `ParticipantLedgerRFC` schema upgrades |
