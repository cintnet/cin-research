# Canonical base thesis: functional deliverable of the Collective Intelligence Network

**Status:** Canonical Architectural & Editorial Reference  
**Updated:** 2026-11-15  
**Companion Foundations:** [`01-CYBERNETIC-AGENCY-EXTENDED-MIND-AND-DYADIC-ALIGNMENT.md`](knowledge/foundations/01-CYBERNETIC-AGENCY-EXTENDED-MIND-AND-DYADIC-ALIGNMENT.md), [`02-MULTIMODAL-PERCEPTUAL-SENSORIUM-ATTESTATION-AND-RED-TEAMING.md`](knowledge/foundations/02-MULTIMODAL-PERCEPTUAL-SENSORIUM-ATTESTATION-AND-RED-TEAMING.md)  
**Strategic Backlog Anchor:** [`STEWARD-TODO.md`](STEWARD-TODO.md) (`[TODO-01]`)

The Collective Intelligence Network (CIN) specifies, simulates, and builds open sociotechnical infrastructure that keeps biological humans sovereign as capable AI systems scale. CIN is neither a policy think tank without a technical artifact nor a closed consumer subscription vendor. Instead, it develops a concrete five-part functional deliverable: a **Multimodal Egocentric & Ambient Perceptual Sensorium**, a **Cryptographically Sealed Episodic Memory Vault**, a **Monogamous Principal-Bound Personal Cognitive Model**, **Bifurcated Provenance Ledgers across the Personal Markov Blanket**, and a **Polycentric Collective Coordination Substrate**. Together, these five coupled primitives allow an individual and a loyal personal model to perceive physical reality with calibrated humility, preserve private autobiographical memory, transact across untrusted agent networks through minimal cryptographic proofs, and coordinate shared economic and civic life from the bottom up.

## Why human sovereignty requires a grounded functional stack

Human agency erodes when intelligence, memory, and verification sit inside multi-tenant cloud platforms controlled by external vendors or central bureaucracies. Current frontier models operate predominantly as ungrounded statistical predictors trained on scraped text, detached from authenticated physical observation and bound to their corporate operators' engagement or compliance objectives. When software agents negotiate at machine speed over human-facing web channels, ordinary people lose the ability to verify what an agent observed, which principal authorized its action, or whether shared institutions are being quietly gamed.

Resolving this asymmetry requires anchoring machine cognition to one biological person at the hardware capture boundary before any network coordination begins. Each person needs calibrated local sensing, exclusive custody over raw personal history, a cognitive model legally and architecturally bound to their sole welfare, a statistical firewall separating internal life from external proof, and an open ledger substrate for voluntary collective action.

## The five functional primitives of the CIN deliverable

### 1. Multimodal Egocentric & Ambient Perceptual Sensorium

*(Sensor systems and perceptual grounding)*

Physical grounding begins with wearable egocentric devices and trusted-environment heterogeneous sensor arrays. These arrays combine visual RGB and monocular SLAM cameras, depth and ranging sensors, millimeter-wave radar, high-rate inertial measurement units (IMUs), spatial and bone-conducted contact acoustics, and ambient environmental transducers (cf. Meta Project Aria, Engel, Somasundaram et al. 2023; Grauman et al. *Ego4D* 2022 and *Ego-Exo4D* 2024). Instead of streaming raw feeds to remote servers, local edge inference fuses imperfect, complementary modalities where each sensor covers the failure modes of the others.

All streams align to a unified hardware capture clock (`Device Time` and sub-millisecond multi-device time codes) rather than host arrival timestamps distorted by bus latency or operating-system scheduling jitter. Every observation carries self-assessed sensor health and confidence metadata, forming a perception architecture that knows when its own optics, acoustics, or ranging channels are degraded or blind (cf. [`the-seeing-world.md`](the-seeing-world.md)). At the silicon root, Physical Unclonable Functions (`PUF`), Trusted Computing Group Device Identifier Composition Engine (`TCG DICE`) key hierarchies, Distributed Management Task Force Security Protocol and Data Model (`DMTF SPDM`) bus sessions, and IETF Remote ATtestation procedureS (`IETF RATS`, `RFC 9334`) bind observations to attested peripheral firmware. Where embodied machines or local relays meet physical force, optical data diodes and `IEC 61508` hardware dead-man switches isolate frontier models from direct motor actuation so power drops to a safe state unless local human permission actively renews.

### 2. Cryptographically Sealed Episodic Memory Vault

*(Extended mind and post-transduction provenance)*

Raw observations and personal interactions flow into a local, append-only autobiographical event store that satisfies Andy Clark and David Chalmers's (1998) parity criteria for the Extended Mind while honoring Endel Tulving's (1972, 2002) separation between spatiotemporally indexed episodic memory and distilled semantic knowledge. Events are cryptographically signed at hardware capture using Coalition for Content Provenance and Authenticity (`C2PA`) manifests and Merkle hash chains, then encrypted under keys held by the human principal. Exclusively the biological person and their bound personal cognitive model can decrypt and traverse raw autobiographical records; external labs, advertisers, employers, and peer nodes never gain read access to the vault.

CIN enforces strict **analog-to-digital transduction realism (*Signed Is Not True*)** across this vault (cf. [`who-audits-the-oracle.md`](who-audits-the-oracle.md); Fu & Xu 2018). Hardware attestation proves post-transduction silicon chain of custody, clock integrity, and attested firmware configuration after physical energy crosses the analog-to-digital converter. Cryptographic signatures never prove unspoofed physical ground truth across the analog hole prior to signal conversion, where acoustic, optical, thermal, or electromagnetic injection can deceive an intact transducer.

### 3. Monogamous Principal-Bound Personal Cognitive Model

*(Cybernetic self-model and dyadic exocortex)*

Above the sealed vault sits a specialized personal cognitive model grounded in Joscha Bach's cognitive architecture (*Principles of Synthetic Intelligence* 2009; *MicroPsi 2* 2012; cybernetic self-models, perceptual grounding, teleonomic motivation, and personal exocortex), Karl Friston's *Markov Blanket* formalism (2013, 2019), and Jack Balkin's *Information Fiduciary* legal standard (2016). Unlike multi-tenant cloud assistants shared across millions of accounts, this model is trained and continually adapted to co-exist in a `1:1` dyad with one single biological person.

Its objective hierarchy and fiduciary duty bind it strictly to respect the wishes, agency, privacy, and long-term flourishing of that single human principal. It is never subordinated to aggregate collective utility, state orthodoxy, or corporate vendor retention targets. Reasoning jointly over live perceptual streams, episodic vault memories, direct conversation with its person, and verified peer or agent feedback, it acts as a calibrated second mind. Following Lisanne Bainbridge's (1983) findings on automation-induced skill atrophy, the model deliberately tapers its scaffolding during routine practice so its human principal retains sharp unassisted judgment.

### 4. Bifurcated Provenance Ledgers across the Personal Markov Blanket

*(Internal homeostatic memory versus external boundary proofs)*

Carrying hardware-attested provenance forward from the vault, the personal cognitive model serves as the statistical Markov Blanket boundary around the human-exocortex dyad. It evaluates context, consent, and risk to decide which signed events remain internal and which cross the boundary as verifiable external claims:

- **The Private Autobiographical Ledger** records internal homeostatic states: health and physiological baselines, personal learning trajectories, private deliberations, household routines, and unshared reflections. Only the personal cognitive model and biological principal read these states, using them to improve personal wellbeing, skill, and foresight.
- **The Public Attestation & Escrow Ledger** governs active and sensory boundary states exchanged over dedicated machine transport lanes (`MCP` and `A2A` over `IETF QUIC`, `RFC 9000`). When transacting with secondary, lower-trust external agents, the personal model reveals minimal facts via selective zero-knowledge proofs, `IETF SCITT` transparency receipts, and expiring Object-Capability Security leases (Dennis & Van Horn 1966; Necula 1997). Consequential external claims require Byzantine fault-tolerant corroboration across observer classes independent in ownership, manufacturer, and software (`k >= 3f + 1`; Lamport, Shostak & Pease 1982).

### 5. Polycentric Collective Coordination Substrate

*(Emergent self-rule, post-fiat clearing, and active lab engagement)*

Bidirectional coupling between sovereign `Person + Personal Model + Public Ledger` dyads and the **Wide Network Ledger** expands individual cognitive light cones (Michael Levin 2019), allowing consenting people to coordinate at municipal, bioregional, and planetary scales without dissolving individual autonomy. Through this substrate, communities provision collective Universal Basic Services, route voluntary merit-bonded tasks that repair or improve shared commons, and settle real productive capacity through transparent reciprocal mutual credit clearing and statutory Rudolf Meidner cooperative equity conversion beyond fiat-only opacity and rentier extraction.

To prevent covert capture, the substrate audits collusive Sybil and shadow-cartel rings using subgraph density tests (`e`-means and `k`-truss) paired with physical load and conservation checks. Externally, CIN uses this architecture to engage roughly 40 frontier AI laboratories and 50 AI safety institutes through concrete convergence and deviation overlays. Internally, governance rules emerge bottom-up from consenting people and their personal agents under Elinor Ostrom's (1990, 2010) polycentric design principles rather than top-down CIN decrees.

Crucially, coupling the **Personal Markov Blanket** to the **Wide Network Ledger** enforces **risk-scaled asymmetric transparency** that brings actors wielding concentrated power to relinquish unilateral black-box control to the collective without violent coercion:
- **Low societal risk (ordinary personal life):** Actions confined to one household's wellbeing carry negligible systemic externality, so raw records remain strictly encrypted inside the person's local vault with zero public disclosure.
- **High societal risk (concentrated institutional or autonomous power):** Whenever a frontier lab, corporation, insurer, or public ministry takes or deploys agents to take actions estimated to carry significant risk to society, **the network demands proportional cryptographic transparency, independent audit proofs, capability-lease bounds, and multi-stakeholder collective sign-off in return for network interoperability, procurement access, and legitimacy**. When diverse individuals and groups who share a concrete interest (households, frontline unions and cooperatives, open-source builders, safety researchers, public officials, and conscientious lab teams) interlock these ledger requirements together, keeping high-risk systems secret becomes operationally unviable compared to sharing governance with the collective.

## End-to-end dataflow and constitutional realism limits

Information flows forward from physical transduction in the **Perceptual Sensorium** into append-only local custody inside the **Sealed Episodic Memory Vault** and grounded inference inside the **Monogamous Personal Cognitive Model**. From there, approved claims cross the **Personal Markov Blanket** onto the **Public Attestation & Escrow Ledger** and reach the **Wide Network Ledger** of the **Polycentric Collective Coordination Substrate**. In the reverse direction, verified environmental conditions, open civic tasks, mutual credit balances, and peer warnings flow back from the Wide Network Ledger through the Public Attestation boundary so the personal model can advise its human principal without exposing private autobiographical state.

Four constitutional realism rules constrain every stage of this loop:

1. **Post-transduction humility:** Silicon signatures authenticate device configuration and post-conversion custody, never uncontested physical truth across the analog hole.
2. **No hardware plutocracy:** Certified sensors never confer superior civic standing or define reality unilaterally; consequential facts rest on independent observer classes and scored calibration track records.
3. **System-borne uncertainty and human contestability:** Coverage gaps and demographic calibration drift (Sjoding et al. 2020; Crawford 2013) widen system uncertainty bars rather than penalizing under-sensed people. Sensor anomalies trigger human-contestable review, never automatic punishment.
4. **Zero speculative financialization:** Under the Steward Gate, CIN never issues speculative tokens, promises personal dollar savings, or prescribes unapproved royalty splits.

## Anti-leakage register translation table for `cintnet.org`

Internal architectural identifiers and research shorthand must never leak bare into public `everyday` prose on `cintnet.org`. Agents writing public pages, blog essays, and audience guides must translate technical primitives into kitchen-table English (`specs/org/voice.md`), placing formal citations inside `<aside class="for-researchers">` or footnotes:

| Canonical functional primitive (technical / internal) | Frontier lab, standards & civic bridge (`constitutional` / `research`) | Kitchen-table English for `cintnet.org` body copy (`everyday`) |
| :--- | :--- | :--- |
| Multimodal Egocentric & Ambient Perceptual Sensorium | Calibrated multi-sensor edge fusion, `Device Time` sync, `DMTF SPDM` / `IETF RATS` peripheral attestation & `IEC 61508` safety relays | **cameras, microphones, and motion sensors on your glasses or in your room that check each other, flag when their view is blocked, and wire physical dead-man switches into machines** |
| Cryptographically Sealed Episodic Memory Vault | Local-first encrypted event store, `C2PA` capture provenance & analog-hole transduction realism (*Signed Is Not True*) | **a private digital diary locked on your own hardware so only you and your personal assistant can read it, with tamper-evident receipts that still allow human challenge when sensors misread** |
| Monogamous Principal-Bound Personal Cognitive Model | `1:1` principal-aligned cognitive architecture (Bach exocortex) & statutory information fiduciary duty of loyalty (Balkin) | **a personal assistant trained to work exclusively for one person, legally bound to your side, that steps back so your own skills stay sharp** |
| Bifurcated Provenance Ledgers across the Personal Markov Blanket | Friston Markov blanket boundary, Private Autobiographical Ledger vs. Public `IETF SCITT` / ZK / Object-Capability Escrow Ledger | **a strict privacy boundary that keeps your raw life history at home while sharing only minimal, expiring proofs when your assistant deals with outside software** |
| Polycentric Collective Coordination Substrate | Wide Network Ledger, Ostrom polycentric governance, Universal Basic Services, reciprocal mutual credit & Meidner cooperative equity | **an open coordination network where neighbours and their assistants team up on shared services, settle real local work fairly without hidden junk fees, and set their own community rules** |

Never write alphanumeric layer codes, brand shorthand for sensor suites, the bare phrase `Base Thesis`, or unexplained terms such as `Markov Blanket` or `Exocortex` in `everyday` body paragraphs.

## How every active CIN surface connects to this deliverable

1. **ORG Website (`cintnet.org` -> `site\`):** Explains the lived human stakes, honest engineering limits, and practical adoption steps of the five primitives in plain `everyday` prose, backed by primary-source researcher disclosures and interactive browser benches under `/labs/`.
2. **Shared Horizon & Institutional Registry (`research\paths\` & `research\institutions\`):** Turns the deliverable into verified action cards and branching timeline encounters across six actor classes, paired with structural alignment overlays for ~40 frontier AI labs, ~50 safety institutes, public agencies, and cooperatives.
3. **Agent-Web Testnet & Simulations (`research\ledger_sim\`):** Stress-tests sensorium red-team threat vectors, Markov-blanket selective disclosure, expiring capability leases, mutual credit conservation, and collusive cartel detection under deterministic RNG seeds.
4. **Observatory & Knowledge Broker (`observatory\`, `knowledge\`, `loop\context_broker.py`):** Tracks empirical capability signposts, maintains verified scientific provenance (`terminology_registry.db`), and serves `< 300`-token on-demand context contracts across scheduled agent lanes.
