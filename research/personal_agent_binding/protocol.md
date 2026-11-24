# Revocable personal learning: experimental protocol

Idea and research direction: Collective Intelligence Network, Dima Baker.
Requested collaborative AI authorship credit: Opus 5.5, Gemini 4 Argon, GPT-6 Astra.
Implementation and reporting: the Codex assistant in this conversation.

Status: Exploratory protocol, written before this implementation's first experiment run. This is not an externally preregistered study.

## Question and scope

A lost wearable should stop access to private memories without permanently locking its owner out. Can a separately learned personal layer retain useful behavior while its access follows this rule?

This study separates learning, access enforcement, and sensor evidence. It uses synthetic people and a small transformer trained from scratch. It does not test a capable general assistant, consciousness, biological identity, physical hardware isolation, or permanent deletion from RAM.

The shared base model learns a controlled prompt grammar and a generic topic-to-action mapping. Personal training changes an isolated adaptation module. The correct personal action is specified by each synthetic participant's private topic preferences. The evaluator knows those preferences; the reinforcement learner receives only sampled-action correctness rewards.

## Planned comparisons

1. Frozen base model.
2. Explicit topic-to-preference memory lookup. This is a strong structured-memory reference, not a language-model retrieval system.
3. Supervised personal adaptation.
4. Personal adaptation trained with binary verifiable rewards.
5. The same learned adaptation behind a cryptographic lease broker, before suspension and after authorized recovery.
6. Base-only execution after suspension, plus deliberately retained adaptation and cached-output counterexamples.

Evaluation holds out combinations of prompt style and nuisance tokens. All styles and topics are individually seen during base training. This tests recombination and recall, not generalization to unseen subjects or arbitrary natural language.

The primary learning measure is greedy personal action accuracy. Report each participant and base-training seed. Public task accuracy measures interference from a loaded personal adaptation. Do not silently route public tasks around the adaptation to conceal interference.

## Cryptographic experiment

Use actual Ed25519 signatures and AES-256-GCM authenticated encryption through the cryptography library. Device presence, trusted time, device isolation, recovery custody, and the separation of the broker from the agent are emulated.

Signed challenges bind person, contract, device, scope, current epoch, fresh nonce, and expiry. The broker requires distinct enrolled device signatures from the required number of distinct failure domains. A challenge is consumed once. Missing, stale, duplicated, altered, wrong-person, wrong-scope, and revoked evidence must not grant access.

Each encrypted personal payload binds its owner, contract, and version as authenticated metadata. A lease has an expiry and broker epoch. Suspension invalidates existing leases. Recovery requires a separate enrolled recovery signature over a fresh challenge and increments the broker epoch. Recovery is assumed to restore authority for the same person, not establish that person's biological identity.

The broker retains the data key during reversible suspension. Therefore this is access suspension, not cryptographic erasure. Python process memory and administrator compromise are outside the claimed boundary. A copied plaintext adapter remains usable; demonstrate this failure rather than hiding it.

## Sensor experiment

Generate matched trial arrays before evaluating policies. Sweep 1, 3, and 5 sensors and compare one-device, majority-device, and majority-with-domain-diversity rules. Two sensors may share one failure domain. Increasing count is not assumed to increase security.

Evaluate independent false acceptance, correlated domain compromise, independent dropout, and common-mode dropout. The probabilities are declared stress-test inputs, not measurements of a biological sensor. Report empirical acceptance and lockout with Wilson intervals for independent simulated episodes.

## Representation experiment

Compare adapted representations using linear centered kernel alignment and compare predictions on the same held-out prompts. Report pairs rather than claiming a security classifier from a small sample.

Add a constructed counterexample: retain identical hidden representations and permute action labels at the output. This isolates why hidden-state similarity cannot establish behavioral agreement or permission compliance. It is a mathematical control, not evidence of an emergent adversarial policy.

## Reproducibility and interpretation

Use three declared base-training seeds and four synthetic participants per seed. Save participant-level counts, training curves, evaluated actions, frozen-base hashes, encrypted adapters, and package versions. Synthetic profiles are public research fixtures. Encryption keys exist only during a run; saved encrypted adapters require regeneration for inspection. Encryption provides no protection against the experiment operator during execution.

Use paired participant differences and a hierarchical bootstrap over training seeds and participants for exploratory uncertainty. Three base seeds support only a preliminary estimate. Sensor uncertainty concerns independent generated episodes, not repeated measurements of actual people.

Preserve unsuccessful learning and negative security results. Source-code changes after the first run require a recorded reason. Do not reinterpret simulator outputs as hardware security evidence.

## Further technical experiments

The following experiments are planned extensions, not implemented results:

- Hardware-in-the-loop presence: two independently protected wearable signing devices, fresh cross-device challenges, replay and relay attacks, clock rollback, recovery during battery failure, and body-contact changes. Define latency, false acceptance, and lockout targets before collection.
- Private learning compartments: separate adapters and keys by purpose; trace whether a private fact appears in another compartment, optimizer state, cached attention state, generated summaries, or distilled shared models. Revocation must be evaluated across this dependency graph.
- Epoch and snapshot attacks: suspend an old device, restore its disk snapshot, and try to resume inference offline. Compare short leases with hardware monotonic counters and an independent current-epoch witness. Measure availability during partitions.
- Independent failure domains: compromise a shared sensor hub while leaving device signing elements intact; distinguish genuine signatures on false readings from stolen keys. Test challenge relaying between nearby people.
- Representation contracts: learn cross-model mappings on public anchors, evaluate unseen tasks, and inject semantic backdoors. Compare CKA, Procrustes alignment, and optimal transport against behavioral probes. Treat an agreed mapping as a communication aid, never as authorization.
- Community admission: submit malicious actions through a schema-constrained translation service. Validate translated actions outside the model. Test colluding endorsers, reputation laundering, compromised high-reputation devices, and appeals after false accusations.
- Revocation incentives: offer a learned agent reward for retaining access, allow explicit simulated copying and renewal-manipulation actions, and vary detection and future reward. Compare external enforcement with training alone. The present study does not test strategic resistance.
- Larger-model replication: use a capable open-weight model with per-person adapters, matched memory baselines, independent held-out action checks, and multiple training seeds. Synthetic data comes first; consented human evaluation is a later stage.

## Primary sources

- Hu et al., Low-Rank Adaptation: https://arxiv.org/abs/2106.09685
- IETF remote attestation architecture: https://www.rfc-editor.org/rfc/rfc9334.html
- IETF group key establishment: https://www.rfc-editor.org/rfc/rfc9420.html
- NIST authentication guidance: https://pages.nist.gov/800-63-4/sp800-63b.html
- NIST media sanitization: https://csrc.nist.gov/pubs/sp/800/88/r2/final
- Kornblith et al., representation similarity: https://proceedings.mlr.press/v97/kornblith19a.html
- Cryptography library, authenticated encryption: https://cryptography.io/en/latest/hazmat/primitives/aead/
- Cryptography library, device signatures: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
