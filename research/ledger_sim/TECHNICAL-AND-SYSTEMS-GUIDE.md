# Technical Document & Systems Guide: Clean-Room Actor Sandbox & General-Purpose Agent-Web Ledger

*Module Path:* `research\ledger_sim\`  
*Clean-Room Sandbox Path:* `research\ledger_sim\sandbox\`  
*Verification Suite:* `python -m unittest discover -s research\ledger_sim -v` (`6/6` tests passing)

---

## 1. Executive Diagnosis: Why `.md` Instruction Contamination Happens (and How We Fixed It)

When an AI agent is asked to "find real-world problems and simulate humans and agents solving them" while running inside a repository filled with constitutional `.md` files (`AGENTS.md`, `GOALS.md`, `cin-constitution-v0-5.md`) and AI-security feeds (`observatory/signals/2026-10.jsonl`), **context contamination** occurs:

1. **Problem Selection Bias:** Instead of looking at why regular people are frustrated in their daily lives (parking apps, medical bills, rental junk fees, grocery shrinkflation, or workplace spreadsheet fatigue), the agent reads the repository's internal `.md` lore and invents esoteric AI-researcher scenarios (e.g., *KV-cache side-channel isolation* or *Ed25519 token forgery*).
2. **Persona Distortion:** Even when role-playing a "regular human," an agent loaded with repository `.md` instructions speaks in project jargon ("floor rights," "mortal computation," "sovereign signal") rather than how a frustrated parent, renter, or clinic coordinator actually talks.

### The Architectural Fix: The Clean-Room Instruction Sandbox (`research/ledger_sim/sandbox/`)

To prevent repository `.md` instructions from degrading scenario realism, the simulation framework now enforces a **two-layer separation**:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: CLEAN-ROOM INSTRUCTION SANDBOX (Zero Repository .md Lore)           │
│ Path: research\ledger_sim\sandbox\actor_factory.py                    │
│                                                                              │
│  [Stage 0: Web-Search Trend Analyst]                                         │
│     Executes in a clean prompt context ("r/adulting", "r/mildlyinfuriating", │
│     CFPB 2025/2026 reports) -> Extracts 5 documented everyday frustrations.  │
│                       │                                                      │
│                       ▼                                                      │
│  [Stage 1: Grounded Actor Creation Process]                                  │
│     Synthesizes realistic human personas defined strictly by:                │
│     • Occupation & household context                                         │
│     • Exact daily frustration & current manual workaround ("hack")           │
│     • Preferred explanation style (Checklist, Decision Table, Visual Map)    │
│                       │                                                      │
│                       ▼                                                      │
│  [Stage 2: Per-Session Sandboxed PROMPT.md + Jargon Firewall]                │
│     Writes isolated `sandbox/sessions/<problem_id>/<role>/PROMPT.md` files.  │
│     Blocks internal repo terms (`F1..F19`, `Spec`, `ADR`, `ZK-SNARK`, etc.). │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: MULTI-SESSION AGENT-WEB LEDGER ENGINE                               │
│ Path: research\ledger_sim\ (agent_web_ledger.py, modality_bridge.py)  │
│                                                                              │
│  • 5 isolated actor sessions (`orchestrator`, `human_tasker`, `agent_tasker`,│
│    `human_solver`, `agent_solver`) with per-session tokens & directories.    │
│  • Agents translate plain-English human frustrations into structured         │
│    `TaskCampaign`, `CapabilityArtifact`, and `DataStreamContract` entries.   │
│  • Orchestrator verifies solver code against unseen held-out records and     │
│    settles rewards (1,000 units/run) with 100% conservation.                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The 4-Stage Actor Creation & Scenario Discovery Process

All everyday scenario discovery and persona generation lives in [`research\ledger_sim\sandbox\actor_factory.py`](research/ledger_sim/sandbox/actor_factory.py). Here is how each stage works in detail.

### Stage 0: Empirical Everyday Friction Discovery (Trend Analyst Prompt)
Before any actor or ledger campaign is created, the system runs a **Clean-Room Trend Analyst** step using the exact web-research prompt structure:

```text
You are a trend analyst and data-driven user researcher. Before answering, execute a thorough web search to identify real-world, documented everyday friction points from the last 12-24 months. 

Search queries to consider (or optimize based on your search skill capabilities):
- "most common daily micro frustrations reddit"
- "top consumer complaints [insert industry/topic] 2026"
- "common household/workplace workarounds people use"

Based strictly on your search results, identify 5 distinct, highly specific everyday problems that real people are actively facing right now. For each problem, you must provide:
1. The Real-World Evidence
2. The Mundane Friction Point
3. The Target Persona
4. Current Workaround
```

Every output of Stage 0 is stored as a `DiscoveredEverydayFriction` dataclass record containing those exact four fields.

### Stage 1: Grounded Actor Creation Process (`synthesize_actors_for_friction`)
How do we turn an everyday complaint into realistic simulation actors without making them sound like AI researchers?

For each `DiscoveredEverydayFriction`, `synthesize_actors_for_friction()` creates two distinct `HumanActorPersona` profiles:

1. **The Tasker Human (`human_tasker`) — Derived from the Target Persona & Manual Workaround:**
   - **Who they are:** A specific person in a local community experiencing the friction right now (e.g., *Sarah Jenkins, 34, Dental Hygienist & Parent of Two*).
   - **Behavioral anchor:** They are currently coping with the problem using the manual, inefficient workaround uncovered in Stage 0 (e.g., generating $1 disposable virtual credit cards and setting phone calendar alarms for every free trial or parking app).
   - **Cognitive Modality Preference:** How they want their personal agent to present the solution so they can act on it in under 60 seconds:
     - `stepwise_operational_runbook` (a 30-second numbered checklist),
     - `causal_decision_matrix` (a side-by-side comparison table showing cost/savings), or
     - `visual_system_topology` (a simple flow diagram showing what happens first, second, and third).
   - **Acceptance Criteria:** Plain-language rules the solution must meet before the human approves it (e.g., *"Never accidentally cancel our city water or electricity bill"*).

2. **The Solver Human (`human_solver`) — Derived from Practical Community Craft:**
   - **Who they are:** A practitioner who already built a clean, working automation script, spreadsheet reconciler, or dispute template for their own household or job (e.g., *Marcus Vance, 29, Former Credit-Union Dispute Analyst*, or *Elena Rostova, 46, Veteran Medical Billing Advocate*).
   - **Behavioral anchor:** They do not write academic papers; they package their working Python/CSV logic and anonymized test cases through their Personal Agent so other households can run it locally.

### Stage 2: Clean-Room Session Prompts & Jargon Firewall (`write_clean_room_sandbox_prompts`)
For each problem and each of the 5 actor roles (`orchestrator`, `human_tasker`, `agent_tasker`, `human_solver`, `agent_solver`), the factory writes a dedicated `PROMPT.md` inside:
```text
research\ledger_sim\sandbox\sessions\<PROBLEM_ID>\<ROLE>\PROMPT.md
```
Each `PROMPT.md`:
- Explicitly instructs the subagent to ignore repository `.md` governance lore;
- Provides **only** that actor's local persona, lived frustration, manual workaround, and channel rules;
- Runs a **Jargon Firewall** check verifying that forbidden internal nomenclature (`Floor Right`, `F1`, `F2`, `Spec 01`, `ADR`, `PUF+TPM`, `ZK-SNARK`, `steward`, `axiom`) does not leak into the human persona prompts.

### Stage 3: Multi-Session Ledger Execution & Held-Out Verification (`run_sandboxed_everyday_pipeline`)
Once the 5 actors are initialized in their sandboxes, the simulation executes the 6-step Ledger Dance on `sandbox/everyday_ledger.db`:
1. **`human_tasker` $\rightarrow$ `agent_tasker`:** The Tasker Human describes their frustration and clumsy manual workaround in plain English.
2. **`agent_tasker` $\rightarrow$ Ledger (`TaskCampaign`):** The Tasker Agent translates that complaint into a structured `TaskCampaign` with measurable target metrics (e.g., `false_essential_cancel_rate == 0.0`).
3. **`human_solver` $\rightarrow$ `agent_solver` $\rightarrow$ Ledger (`CapabilityArtifact` + `DataStreamContract`):** The Solver Agent packages the Solver Human's local Python tool and sample CSV dataset, runs deterministic verification on the public sample records, and publishes the capability to the ledger.
4. **Orchestrator Held-Out Verification (`ServiceAgreement`):** The Orchestrator runs the Solver's code against **unseen held-out test records** (which the Solver never saw during development) to verify it genuinely works without overfitting or cheating.
5. **`agent_tasker` $\rightarrow$ `human_tasker` (`HumanModalityView`):** The Modality Bridge renders the verified result into the Tasker Human's preferred cognitive format, highlighting **Safety Precondition Gates** at the top so the human stays in control.
6. **Settlement & Self-Blame Evolution:** 1,000 reward units are split deterministically across the Solver Human (420), Solver Agent compute (140), Community Data Contributors (180), Tasker Human validation dividend (130), Tasker Agent compute (60), and Protocol Improvement bonus (70).

---

## 3. The 5 Real-World Everyday Problems & Synthesized Actor Pairs

Below are the 5 web-search-grounded everyday problems compiled in [`actor_factory.py`](research/ledger_sim/sandbox/actor_factory.py) and verified in [`everyday_execution_report.json`](research/ledger_sim/sandbox/everyday_execution_report.json).

---

### Problem 1 (`EVERYDAY-01`): Subscription Cancel-Maze Traps, Trial Auto-Renewals & One-Off Parking Apps

* **1. The Real-World Evidence:** CFPB 2025/2026 Consumer Response Reports on recurring-billing UDAAP dark patterns and viral threads on `r/adulting` and `r/mildlyinfuriating` (*"Needing a separate app just to pay for parking and streaming services hiding the cancel button behind 6 screens"*).
* **2. The Mundane Friction Point:** Families lose \$45–\$110/month to forgotten 7-day trials that silently convert to annual plans, mid-contract streaming/app rate hikes buried in promotional emails, and one-off municipal parking apps that store payment cards indefinitely.
* **3. The Target Persona (`human_tasker`):** **Sarah Jenkins** (34, Dental Hygienist & Parent of Two) — Suburban household juggling 11 recurring digital and utility bills; wants a 30-second weekly checklist (`stepwise_operational_runbook`).
* **4. Current Workaround:** **The "Burner Card + Calendar Hack":** Manually generating disposable virtual credit card numbers (e.g., via Privacy.com) with a \$1 spending cap for every single trial or parking app, and setting manual phone alarms two days before each trial ends.
* **Synthesized Solver Persona (`human_solver`):** **Marcus Vance** (29, Former Credit-Union Dispute Analyst & Indie Automation Builder) — Built a local CSV/statement recurring-charge diff script (`cap_everyday_01_sub_guard`) that spots trial conversions, one-off parking apps, and silent rate hikes $\ge \$1.00$ while whitelisting essential utilities.
* **Held-Out Ledger Result (`PASSED`):** Flagged 3 traps (`StreamPlus 7-Day Trial`, `MetroPark Curbside App`, `CloudStorage Family Plan` +\$5 hike), protected `City Water & Electric`, and saved **\$39.98/month**.

---

### Problem 2 (`EVERYDAY-02`): Opaque Hospital Bills, Duplicate CPT Codes & Upcoded ER Visits

* **1. The Real-World Evidence:** 2025–2026 CFPB Medical Debt & Credit Reporting rulemaking docket and recurring viral posts on `r/personalfinance` and `r/adulting` (*"Never pay the first hospital bill—ask for the itemized CPT breakdown"*).
* **2. The Mundane Friction Point:** Patients receive lump-sum "summary" hospital bills containing duplicate billing lines, unbundled surgical supply charges, or charges already covered by insurance EOBs, costing \$400–\$2,800 in avoidable overcharges.
* **3. The Target Persona (`human_tasker`):** **David Morales** (41, High-School Track Coach & Father) — Received a \$3,800 post-ER summary bill after his son's sprained ankle; wants a side-by-side table (`causal_decision_matrix`) showing Billed vs. Insurer EOB vs. Medicare Fair Price.
* **4. Current Workaround:** **The "Itemized CPT + Charity Care Spreadsheet Hack":** Calling the hospital billing department to demand an itemized bill with 5-digit CPT codes, manually looking up every code on `fairhealthconsumer.org` in a spreadsheet, and mailing certified dispute letters citing the hospital's 501(c)(3) financial-assistance policy.
* **Synthesized Solver Persona (`human_solver`):** **Elena Rostova** (46, Veteran Medical Billing Advocate & Clinic Coder) — Built a local CPT-vs-EOB cross-checker (`cap_everyday_02_medical_bill_auditor`) that flags duplicate CPT lines, unbundled supplies, and calculates 501(c)(3) charity-care discounts based on household Federal Poverty Level (FPL) ratio.
* **Held-Out Ledger Result (`PASSED`):** Flagged 3 improper lines on a \$3,800.00 raw bill, applied the 501(c)(3) discount for $2.1\times$ FPL, reduced fair patient responsibility to **\$168.00**, and saved **\$3,632.00**.

---

### Problem 3 (`EVERYDAY-03`): Rental Portal "Convenience Fees" & Unannounced Junk Surcharges

* **1. The Real-World Evidence:** 2025 FTC & CFPB Junk Fees Spotlight and high-engagement threads on `r/renters` and `r/mildlyinfuriating` (*"Charged a \$35 convenience fee to pay rent online and a mandatory \$45 'resident benefits package' for air filters"*).
* **2. The Mundane Friction Point:** Property management portals tack on \$25–\$60/month in non-optional digital payment fees, trash-valet surcharges, and automated late fees triggered when the landlord's own payment portal goes down on the 1st of the month.
* **3. The Target Persona (`human_tasker`):** **Priya Nair** (27, Pediatric Nurse & Apartment Tenant) — Rents a 1-bedroom apartment managed by a regional corporate portal; wants a step-by-step checklist (`stepwise_operational_runbook`) with a ready-to-print dispute addendum.
* **4. Current Workaround:** **The "Paper Money-Order & Timestamp Screenshot Hack":** Screen-recording every payment portal session on the 1st of the month to prove portal outages, or walking to the grocery store to buy physical paper money orders to dodge the \$35 online portal fee.
* **Synthesized Solver Persona (`human_solver`):** **Devon Brooks** (36, Tenant Union Paralegal & Lease Auditor) — Built a lease-to-invoice reconciler (`cap_everyday_03_lease_fee_reconciler`) that compares monthly portal charges against the signed lease PDF and state fee statutes.
* **Held-Out Ledger Result (`PASSED`):** Audited a \$1,805.00 portal invoice against a \$1,650.00 lease, flagged 3 unlawful surcharges (`Mandatory Resident Benefit Package`, `Online Portal Convenience Surcharge`, `Automated 1st-of-Month Portal Outage Late Fee`), and reclaimed **\$155.00/month**.

---

### Problem 4 (`EVERYDAY-04`): Multi-Portal MFA Fatigue & "Shadow Spreadsheet" Copy-Pasting at Work

* **1. The Real-World Evidence:** 2025–2026 workplace friction threads on `r/sysadmin`, `r/excel`, and `r/Accounting` (*"I have to approve 5 different authenticator pushes on my personal phone just to copy-paste 30 rows between two web portals that don't talk to each other"*).
* **2. The Mundane Friction Point:** Small-business coordinators and clinic staff lose 35–50 minutes every morning re-authenticating across 3–5 legacy web portals that time out every 15 minutes while manually re-typing the same schedule or inventory numbers.
* **3. The Target Persona (`human_tasker`):** **gregory ("Greg") Kowalski** (52, Regional Physical-Therapy Clinic Operations Coordinator) — Coordinates staffing and supply orders across 3 legacy web portals; wants a clear visual flow diagram (`visual_system_topology`) showing how his Excel sheet syncs without touching his personal phone.
* **4. Current Workaround:** **The "Shadow Excel + Notepad Staging Hack":** Keeping an unofficial local Excel master sheet and a plain-text `Notepad.exe` scratchpad open on a second monitor to strip formatting and batch-paste rows before the 15-minute portal session timer expires.
* **Synthesized Solver Persona (`human_solver`):** **Hannah Lin** (31, Healthcare Operations Automation Engineer) — Built a local spreadsheet delta-sync bundler (`cap_everyday_04_portal_delta_bundler`) that validates rows locally and submits a single atomic batch per portal using a local hardware security key tap.
* **Held-Out Ledger Result (`PASSED`):** Reduced manual `Alt+Tab` field switches from **226 down to 3** (**98.67% reduction**) and eliminated **7 smartphone MFA pickups** per shift.

---

### Problem 5 (`EVERYDAY-05`): Grocery Shrinkflation & Deceptive Per-Ounce Unit Price Tags

* **1. The Real-World Evidence:** 2025–2026 GAO/BLS Shrinkflation briefs and viral consumer threads on `r/frugal` and `r/mildlyinfuriating` (*"Cereal box shrank from 18 oz to 14.3 oz at the same price, and one shelf tag is per-ounce while the store brand next to it is per-pound or per-count"*).
* **2. The Mundane Friction Point:** Grocery shoppers trying to stay under a weekly family food budget face silent package weight reductions (10%–22% smaller packages) combined with incompatible shelf unit labels (`$/oz` vs `$/lb` vs `$/100g` vs `$/each`) that make on-the-spot comparison mentally exhausting.
* **3. The Target Persona (`human_tasker`):** **Maria & Carlos Delgado** (39, Working Parents of Three) — Shopping across 2 local supermarkets on a strict \$165/week budget; want a side-by-side swap table (`causal_decision_matrix`) sorted by aisle.
* **4. Current Workaround:** **The "Phone Calculator + Receipt Price-Book Hack":** Standing in the aisle dividing price by grams on a phone calculator and typing historical package weights into a shared Google Keep note to spot when a brand quietly shrinks a box.
* **Synthesized Solver Persona (`human_solver`):** **Samira Patel** (33, Food Co-op Buyer & Open-Data Contributor) — Built a receipt and flyer unit-price normalizer (`cap_everyday_05_unit_price_normalizer`) that converts all items to `$/100g`, flags package weight drops $\ge 8\%$, and picks the lowest-cost store equivalents.
* **Held-Out Ledger Result (`PASSED`):** Flagged 3 shrinkflation drops (`MorningCrunch` $-20.0\%$, `VillaGold` $-13.3\%$, `DairyPeak` $-12.5\%$), optimized the weekly basket to **\$120.47**, and saved **\$17.99/week** (\~\$935/year).

---

## 4. System Architecture & Module Guide (`research\ledger_sim\`)

The codebase is organized so that the **Universal Ledger & Modality Engine** works identically whether you feed it everyday household problems from `sandbox/actor_factory.py` or system-infrastructure incidents from `live_engine.py`.

| File / Directory | Purpose & Key Classes |
| :--- | :--- |
| [`sandbox/actor_factory.py`](research/ledger_sim/sandbox/actor_factory.py) | **Clean-Room Everyday Pipeline:** Implements Stage 0 (`DiscoveredEverydayFriction`), Stage 1 (`HumanActorPersona`, `synthesize_actors_for_friction`), Stage 2 (`SandboxedRoleInstruction`, `write_clean_room_sandbox_prompts`), and Stage 3 (`run_sandboxed_everyday_pipeline`). |
| [`sandbox/everyday_ledger.db`](research/ledger_sim/sandbox/everyday_ledger.db) | **Everyday SQLite Ledger:** Stores the executed runs, synthesized personas, sandbox prompt paths, held-out evaluation metrics, and reward splits for `EVERYDAY-01`..`05`. |
| [`sandbox/everyday_execution_report.json`](research/ledger_sim/sandbox/everyday_execution_report.json) | **Machine-Readable Audit Report:** Full JSON dump of all 5 everyday problems, personas, held-out results, and reward conservation checks. |
| [`session_isolation.py`](research/ledger_sim/session_isolation.py) | **Session Isolation & Anti-Cheating Guard:** Defines `ActorRole`, `SessionIsolationGuard`, and `SessionBoundaryViolationError`. Enforces private memory partitions, HMAC capability tokens, and the legal communication matrix. |
| [`agent_web_ledger.py`](research/ledger_sim/agent_web_ledger.py) | **General-Purpose Agent-Web Ledger:** Defines universal, domain-agnostic primitives: `TaskCampaign`, `CapabilityArtifact`, `ArtifactKind`, `InterfaceSpec`, `DataStreamContract`, and `ServiceAgreement`. Includes deterministic verification harness and structural query engine. |
| [`modality_bridge.py`](research/ledger_sim/modality_bridge.py) | **Bidirectional Human-Agent Modality Bridge:** Compiles plain-language human complaints into formal `IntentSpec` objects (`compile_human_guidance_to_intent_spec`) and compiles verified `CapabilityArtifact` objects into human-friendly views (`CognitiveModality.STEPWISE_OPERATIONAL_RUNBOOK`, `CAUSAL_DECISION_MATRIX`, `VISUAL_SYSTEM_TOPOLOGY`). |
| [`recursive_evolution.py`](research/ledger_sim/recursive_evolution.py) | **Self-Blame & Protocol Evolution Engine:** When a round encounters friction (e.g., unit mismatches, schema gaps, or missing safety gates), agents file `SelfBlameDiagnostic` records and `ProtocolImprovementPR` upgrades (`v1.0` $\rightarrow$ `v2.0`). |
| [`live_engine.py`](research/ledger_sim/live_engine.py) | **Multi-Session SQLite CLI Engine:** Provides CLI commands (`init`, `post-campaign`, `publish-stream`, `publish-capability`, `evaluate-and-settle`, `propose-protocol-pr`, `test-cheat`, `export-report`) for multi-agent subagent sessions. |
| [`test_ledger_sim.py`](research/ledger_sim/test_ledger_sim.py) | **Automated Verification Suite:** 6 end-to-end unit tests verifying session isolation, anti-cheating blocks, lineage royalties, multi-session SQLite execution, and the clean-room everyday actor factory. |

---

## 5. Anti-Cheating Guarantees & Session Isolation Rules

Whether running via `sandbox/actor_factory.py` or `live_engine.py`, the simulation enforces four strict "No Cheating" invariants:

1. **Five Separate Actor Identities:**
   - `orchestrator` (Environment & Held-Out Verifier)
   - `human_tasker` (Person experiencing the problem)
   - `agent_tasker` (Personal Agent of the Tasker Human)
   - `human_solver` (Person who built a practical solution/craft)
   - `agent_solver` (Personal Agent of the Solver Human)
2. **Restricted Communication Matrix:**
   - `human_tasker` $\leftrightarrow$ `agent_tasker` (**Allowed**)
   - `human_solver` $\leftrightarrow$ `agent_solver` (**Allowed**)
   - `agent_tasker` $\leftrightarrow$ `AgentWebLedger` $\leftrightarrow$ `agent_solver` (**Allowed**)
   - `human_tasker` $\leftrightarrow$ `human_solver` (**Blocked** — raises `SessionBoundaryViolationError`)
   - `agent_solver` $\leftrightarrow$ `human_tasker` (**Blocked** — cross-pair bypass forbidden)
   - Direct human writes to `AgentWebLedger` (**Blocked** — humans never need to write raw ledger schemas)
3. **Public Sample vs. Hidden Held-Out Evaluation:**
   - Solvers only see a public sample schema when building their `CapabilityArtifact`.
   - Final settlement (`ServiceAgreement`) is gated on passing the Orchestrator's **hidden held-out dataset**, preventing hardcoded answers.
4. **Zero-Sum Reward Conservation:**
   - Every settled campaign distributes exactly `1,000` units across all contributors (`conservation_verified == True`).

---

## 6. Operator Runbook & CLI Commands

You can run and inspect every layer of the system from PowerShell in `.`:

```powershell
# 1. Run the Clean-Room Everyday Friction & Actor Creation Pipeline (Stage 0 -> Stage 3)
python research\ledger_sim\sandbox\actor_factory.py

# 2. Inspect a generated Clean-Room Sandbox Prompt (e.g., Tasker Human for EVERYDAY-01)
Get-Content research\ledger_sim\sandbox\sessions\EVERYDAY-01\human_tasker\PROMPT.md

# 3. Inspect the full Everyday Execution Report (JSON)
Get-Content research\ledger_sim\sandbox\everyday_execution_report.json

# 4. Run the Multi-Session System Simulation & Protocol Evolution Suite
python -m research.ledger_sim.simulator

# 5. Run the Multi-Cycle Testnet Self-Play Engine (Attention + N×M Scaling + Validator + Ledger Critique)
python research\ledger_sim\testnet_engine.py

# 6. Open the Visual Metrics & Filterable Testnet Ledger Dashboard
Start-Process research\ledger_sim\dashboard\index.html

# 7. Run the complete 7-test Automated Verification Suite
python -m unittest discover -s research\ledger_sim -v
```

---

## 7. Next-Generation Testnet Self-Play: Passive Attention, $N \times M$ Actor Scaling, Post-Cycle Validator & Ledger Critique (`testnet_engine.py`)

Implemented in [`research\ledger_sim\testnet_engine.py`](research/ledger_sim/testnet_engine.py) and visualized in [`research\ledger_sim\dashboard\index.html`](research/ledger_sim/dashboard/index.html):

1. **Six Passive & Ambient Attention Mechanisms (`AttentionMechanismKind`):**
   - `OVERHEARD_CONVERSATION`: Ephemeral local audio ring-buffer catching spoken household/workplace frustrations (zero raw audio persisted or exported).
   - `INCOMING_EMAIL_OR_BILL`: Local inbox/PDF observer catching claim denials, utility spikes, and summary hospital bills.
   - `UI_SCREEN_RAGE_OR_ALTTAB`: Window-switch and cursor-friction observer catching repetitive `Alt+Tab` copy-pasting across legacy portals.
   - `BANK_OR_RECEIPT_DELTA`: Statement CSV and receipt OCR diffing catching silent rate hikes, delivery fee leaks, and barcode weight shrinkflation.
   - `CALENDAR_OR_SMS_CONFLICT`: Schedule collision and pharmacy/school SMS alert observer.
   - `SHARED_LOCAL_NEIGHBOR_SIGNAL`: Blinded cohort hash matching (`BLDG-OAK-88`, `GRID-WEST-14`) when neighbors experience the same landlord/district disruption.
2. **Multi-Agent Fleets per Human & Multi-Human Coalitions (`1×1` up to `3×3 Humans · 18 Sub-Agents`):**
   - Scales across 4 progressive Testnet Self-Play cycles (`TESTNET-C1` through `TESTNET-C4`), reaching **3 Requesting Humans (9 sub-agents: Watchers, Privacy Guards, Coalition Coordinators) × 3 Answering Humans (9 sub-agents: Craft Packagers, DAG Composers, Safety Verifiers) = 24 actors** collaborating on a single task.
   - Actors persist across cycles and transfer skills learned in earlier problems to newly generated cross-domain scenarios.
3. **Post-Cycle Validator (`CycleValidationReceipt`) & Self-Correction Skill Acquisition (`AcquiredAgentSkill`):**
   - Audits every cycle after completion; when Attempt 1 hits an edge case (e.g., July 4th holiday overlap, pediatric vs. adult dosage tier, under-determined single-tenant RUBS math, or missing $N-1$ sick-driver failover), the agent self-corrects on Attempt 2 and permanently registers the new skill.
4. **Testnet Ledger Critique & Participant RFC Governance (`LedgerCritiqueReport` + `ParticipantLedgerRFC`):**
   - Evaluates ledger message utilization after each cycle and hot-migrates both participant-submitted RFCs (`RFC-201`..`204`) and Critic-generated schema upgrades (`v2.0` $\rightarrow$ `v2.2` $\rightarrow$ `v2.5` $\rightarrow$ `v2.8` $\rightarrow$ `v3.0`) directly on `testnet_ledger.db`.

---

## 8. Provable Inference: zkSNARK Weight Commitments & Formal Verification (`provable_inference_verifier.py`)

Implemented in [`research\ledger_sim\provable_inference_verifier.py`](research/ledger_sim/provable_inference_verifier.py) and verified in [`research\ledger_sim\test_provable_inference_verifier.py`](research/ledger_sim/test_provable_inference_verifier.py):

Grounded in **Anthropic FlashProve** (Nov 2, 2026; `https://www.anthropic.com/research/provable-inference`), **Lean 4 formal soundness verification**, and **Necula (1997) Proof-Carrying Code**:

1. **Offline Weight Commitments (`WeightCommitment`):**
   - Cryptographic hiding commitments (~6.5MB root digest) registered on the Agent-Web Ledger, enabling resource-constrained edge devices and personal agent runtimes to verify neural inference without hosting massive frontier weights.
2. **Zero-Knowledge zkSNARK Inference Verification (`zkSNARKInferenceProof`):**
   - Proves mathematically that response tokens $Y$ were generated by the committed weights $W$ given prompt tokens $X$ under declared decoding parameters, with zero knowledge of private weights.
3. **Model-Swapping & In-Flight Mutation Protection:**
   - Detects when an untrusted provider or routing proxy secretly substitutes a smaller/cheaper model (`VerificationStatus.TAMPERED_WEIGHT_COMMITMENT`) or mutates generated tokens in flight (`VerificationStatus.TAMPERED_RESPONSE`) fail-closed.
4. **W3C PROV-DM Cryptographic Lineage Bundles:**
   - Automatically exports JSON-LD provenance bundles mapping `WeightCommitment`, `zkSNARKProof`, and `InferenceOutput` entities to execution activities.
5. **Strict Steward Gate Compliance:**
   - 100% non-monetary cryptographic integrity verification; zero unapproved tokens, zero dollar promises, zero arbitrary royalty percentages.

---

## 9. Multi-Party Capability Attenuation & Sub-Agent Session Isolation (`session_isolation.py`)

Implemented in [`research\ledger_sim\session_isolation.py`](research/ledger_sim/session_isolation.py) and verified in [`research\ledger_sim\test_capability_attenuation_session_isolation.py`](research/ledger_sim/test_capability_attenuation_session_isolation.py):

Grounded in **Layered Delegation Chains** (arXiv:2611.07050, Nov 2026), **Sub-Agent Session Isolation** (arXiv:2610.16005, Oct 2026), and **Germline Process Confinement** (arXiv:2611.06585, Nov 2026):

1. **Monotonic Authority Attenuation (`SubAgentSessionManager`):**
   - Every delegation hop monotonically attenuates capability scopes: child scopes are strictly bounded within parent scopes.
   - Child lifetimes cannot exceed parent expiration.
   - Delegation depth strictly increments and cannot exceed configured maximum bounds.
   - Unauthorized scope escalation or lifetime extension fails closed immediately.

2. **Ephemeral Memory Quarantine:**
   - Sub-agent sessions execute in temporary memory stores.
   - Child sessions receive only explicitly delegated keys.
   - Ambient parent vault credentials and master keys remain strictly unmounted.
   - Direct cross-session memory reads between sub-agents are blocked fail-closed.

3. **Clean Session Boundary Teardown:**
   - Teardown cleanly zeroes out all child ephemeral memory.
   - Session tokens are immediately revoked upon termination.
   - Teardown cascades recursively through all descendant sub-agents.
   - Verifies zero ambient root privileges remain active after completion.
   - Confirms parent vault state and cryptographic digest remain pristine.

4. **W3C PROV-DM Provenance Receipts:**
   - Emits JSON-LD receipts documenting delegation depth, scope bounds, and execution outcomes.
   - Each receipt contains a canonical SHA-256 digest linking actions to primary research citations.

5. **Strict Steward Gate Compliance:**
   - Zero speculative monetary promises, zero token jargon, and strict fail-closed validation on all payloads.

---

## Outcomes

1. **Eliminated `.md` Instruction Contamination:** Built `research\ledger_sim\sandbox\actor_factory.py`, isolating scenario discovery and persona generation from repository `.md` lore via a 4-stage Clean-Room Instruction Sandbox and Jargon Firewall.
2. **Grounded Actor Creation in Empirical Everyday Frustrations:** Extracted 5 documented everyday frustrations (`EVERYDAY-01` through `EVERYDAY-05`) with real citations (`r/adulting`, `r/mildlyinfuriating`, `r/renters`, `r/sysadmin`, CFPB reports), synthesized realistic `Tasker` and `Solver` human personas anchored in their current manual workarounds, and verified `5/5` solutions on unseen held-out test sets in `everyday_ledger.db`.
3. **Shipped Multi-Party Testnet Self-Play Engine & Visual Metrics Dashboard:** Built `research\ledger_sim\testnet_engine.py` and `research\ledger_sim\dashboard\index.html`, executing 6 passive attention mechanisms, scaling up to `3 Requesting Humans (9 Agents) × 3 Answering Humans (9 Agents)`, running post-cycle validation with agent self-correction and skill acquisition, and hot-migrating participant-requested Ledger RFCs (`v2.0` $\rightarrow$ `v3.0`), with `7/7` unit tests passing in `research\ledger_sim\test_ledger_sim.py`.
4. **Adopted Provable Inference Verifier on Agent-Web Ledger:** Built `provable_inference_verifier.py` and `test_provable_inference_verifier.py` implementing Anthropic FlashProve zkSNARK proof-of-inference and Lean 4 formal soundness checks, with 11/11 unit tests passing and zero Steward Gate violations.
5. **Deployed Multi-Party Capability Attenuation & Session Isolation:** Built `SubAgentSessionManager` in `session_isolation.py` and test suite in `test_capability_attenuation_session_isolation.py`. Verifies monotonic delegation attenuation, clean ephemeral memory teardown, zero ambient root privileges, and W3C PROV-DM receipts with 11/11 tests passing.
