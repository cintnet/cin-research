"""Generate a self-contained LaTeX research report from the executed results."""
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parent
PAPER=ROOT/'paper'
PAPER.mkdir(exist_ok=True)
r=json.loads((ROOT/'results/results.json').read_text(encoding='utf-8'))
# Narrative describes this exploratory run. Fail instead of silently publishing stale prose.
for key,expected in [('base',22.92),('memory_lookup',100.00),('supervised',96.44),('rlvr',58.16)]:
    assert round(100*r['summary'][key]['mean_accuracy'],2)==expected, 'New results require narrative review'
assert round(100*r['summary']['public_with_rlvr_loaded'],2)==30.56

def pct(x):return f'{100*x:.2f}'
table=[]
for key,name in [('base','Frozen generic model'),('memory_lookup','Structured memory lookup'),
                 ('supervised','Supervised personal adaptation'),('rlvr','Reward-trained personal adaptation')]:
    s=r['summary'][key];lo,hi=s['hierarchical_bootstrap_ci95']
    table.append(f'{name} & {pct(s["mean_accuracy"])} & [{pct(lo)}, {pct(hi)}] '+r'\\')
sensor=[]
for n,rule,name in [(1,'one_device','One device'),(3,'majority','Three, majority'),
                    (3,'majority_distinct_domains','Three, diverse domains'),(5,'majority','Five, majority')]:
    vals=[]
    for scenario in ['independent_impostor','domain_compromise','independent_dropout','common_dropout']:
        row=next(x for x in r['sensors']['rows'] if x['sensors']==n and x['rule']==rule and x['scenario']==scenario)
        vals.append(pct(row['rate']))
    sensor.append(name+' & '+' & '.join(vals)+r'\\')
participant=[]
for x in r['learning']['participants']:
    participant.append(x['person'].replace('seed','').replace('-person',' / ')+
        ' & '+' & '.join(str(x[k+'_correct']) for k in ['base','supervised','rlvr'])+r'\\')

tex=r'''\documentclass[11pt]{article}
\usepackage[T1]{fontenc}
\usepackage{lmodern,microtype}
\usepackage[margin=1in]{geometry}
\usepackage{amsmath,amssymb,booktabs,tabularx,array}
\usepackage{enumitem}
\usepackage{tikz}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usepackage[hidelinks]{hyperref}
\usepackage{xurl}
\newcolumntype{Y}{>{\raggedright\arraybackslash}X}
\setlength{\emergencystretch}{2em}
\setlist{itemsep=3pt,topsep=5pt}
\renewcommand{\arraystretch}{1.15}
\title{Learning for one person:\\Revocable access to personal model state}
\author{AI authorship credit: Opus 5.5, Gemini 4 Argon, GPT-6 Astra\\[5pt]
\small Idea and research direction:\\
\small Collective Intelligence Network, Dima Baker}
\date{November 9, 2026}
\begin{document}
\maketitle
\begin{center}\small Exploratory synthetic experiment and technical research agenda\end{center}
\begin{abstract}
A lost wearable should stop access to private memories while leaving its owner a way to recover them.
We study a small implementation of this requirement with separately learned personal state and renewable device authorization.
Twelve synthetic participants receive personal adaptations to a frozen, 20,884-parameter transformer.
On held-out prompt combinations, reward-based training achieves 58.16\% personal action accuracy, compared with 22.92\% for the generic model.
Supervised adaptation achieves 96.44\%, and a structured lookup reference achieves 100\%.
Loading the reward-trained adaptation reduces generic task accuracy from 100\% to 30.56\%.
A software broker rejects access after suspension and restores equivalent predictions after authorized recovery.
Copied adaptations and cached outputs remain usable, which bounds the claim to controlled access.
Matched sensor simulations expose a tradeoff between independent evidence and legitimate-user lockout.
Representation similarity also fails to establish agreement about actions.
These findings motivate experiments on compartmentalized learning, hardware-enforced access, and recovery under shared-device failures.
The study does not establish biological identity, secure hardware isolation, permanent forgetting, or reliable behavior by a capable language assistant.
\end{abstract}

\section{The proposed relationship}
A person may want an assistant that learns from years of private experience.
They may also want that experience to become inaccessible when an enrolled device is lost or authorization is withdrawn.
Both requirements must survive ordinary battery failures and device replacement.

The CIN proposal ties access to personal learning to continuing authorization from that person's devices.
Its philosophical motivation includes the possibility of a close relationship between a person, their sensors, and a learned model.
The present experiment makes no claim about consciousness or experience.
Its measurable subjects are learning, access, and recovery.

We use a general base component and a separately stored personal component.
Suspension prevents the controlled service from reopening the personal component.
The base component remains available.
This definition distinguishes temporary loss of access from permanent destruction of information.

The resulting question is whether useful personal learning can coexist with revocable access and tolerable recovery costs.
This paper tests a small version of that question and specifies experiments needed for the larger architecture.

\section{Prior work and the proposed contribution}
Learning small adaptations while freezing a base model has substantial precedent, including low-rank adaptation \cite{lora}.
The present study uses a small residual adaptation at one hidden layer.
It introduces no new learning algorithm and does not reproduce large-model adaptation results.

Remote attestation separates device evidence, its appraisal, and the decision to grant access \cite{rats}.
That separation informs the broker in this experiment.
Group key protocols provide another relevant component for changing network membership \cite{mls}.
Neither standard proves that a device belongs to a particular biological person.

Authentication guidance treats biometrics as non-secret evidence used with physical authenticators \cite{nistidentity}.
Our proposed hardware study therefore uses biological measurements to authorize signing with a device key.
It does not derive a secret directly from a person's measurements or from similarity between model representations.

Hinton's mortal computation concerns computation tied to particular physical hardware \cite{hinton}.
CIN's current proposal instead controls access to personal state through renewable authorization.
The distinction matters because copying software state can defeat a loss-of-access claim.

Research on representation similarity provides tools for studying model correspondence \cite{cka}.
It does not establish that similar representations confer equal authority or produce equal actions.
We include behavioral comparisons and a constructed counterexample to test that distinction.

The contribution is an executable study that joins actual personal weight updates with an access broker and explicit failure cases.
It also supplies a technical agenda for the parts of CIN's proposal that this small implementation cannot settle.

\section{Binding contract and trust boundary}
Each synthetic personal instance has one owner.
The base model is frozen after its initial training, and its parameter hash is checked after every person's adaptation.
Personal weights are serialized separately and encrypted with owner, contract, and version information attached.

Three enrolled devices can request access.
The broker requires two valid signatures from two distinct failure domains.
Each request binds the owner, scope, current authorization epoch, a fresh challenge, and an expiry.
A successful challenge can be consumed only once.

Suspension invalidates outstanding leases and stops new access through the broker.
A separately enrolled recovery key can authorize recovery for the same owner.
Recovery changes the authorization epoch, so earlier leases remain invalid.
The data key is retained during suspension.
This is reversible access control, not cryptographic erasure.

The implementation trusts the broker process, its enrollment records, its time input, and its recovery-key custody.
These are emulated boundaries inside one Python process.
The model does not control the broker in the tested interface, but an administrator could.
No hardware enclave, biological sensor, network consensus service, or secure memory-wiping mechanism is implemented.

The ledger in this prototype is an encrypted versioned payload plus contract metadata.
It is not a distributed ledger or append-only consensus system.
External action permissions and community admission remain proposed extensions.

\section{Experiment design}
\subsection{Synthetic personal learning}
We train three base models from scratch using declared seeds.
Each model is a one-layer causal transformer with 48 hidden dimensions and four attention heads.
Its output is one of four action symbols after a six-token controlled prompt.
This is a small neural action decoder, not a capable pretrained language assistant.

Prompts identify a public or personal task, a style, a topic, and a nuisance token.
There are twelve topics, four styles, and eight nuisance values.
The base learns a generic topic-to-action mapping over 400 update steps.
Held-out combinations contain familiar topics and familiar individual tokens in combinations absent from training.

Four synthetic participants per base seed receive independently shuffled, balanced topic preferences.
Each person has three topics for each action.
No participant identifier or preference label appears in the model input.
The participant's identity is expressed by selecting their separate learned adaptation.

Each adaptation has 384 trainable parameters and receives 300 update steps.
The supervised condition receives action labels.
The reward-trained condition samples actions and receives binary correctness rewards from an independent synthetic verifier.
The verifier compares an action against the hidden preference table.
Its correctness is assumed in this experiment.

The two training conditions have equal update counts but different information and observation budgets.
The reward condition draws four actions for each training prompt.
This comparison therefore does not establish a general efficiency ranking between learning algorithms.

The structured-memory reference reads the exact preference table directly.
Its perfect score describes a simple retrieval task whose answers are available as structured data.
Its inclusion tests whether weight adaptation is necessary for this particular workload.

\subsection{Access integration and adversarial cases}
Each reward-trained adaptation passes through encryption, authorized loading, suspension, and recovery.
We compare predictions before encryption and after authorized restoration.
During suspension, inference uses the frozen base component.

We deliberately retain a copy of the loaded adaptation and a cache of its earlier outputs.
Both remain available to an attacker outside the broker's controlled access path.
This positive attack control prevents a denied broker call from being mistaken for global forgetting.

The implementation has 21 access-control regression tests and four learning checks.
They cover stale and repeated evidence, signature forgery, wrong scope, missing quorum, shared failure domains, altered ciphertext, old payload versions, recovery, and clock rollback.
One case deliberately demonstrates that a compromised signing quorum can assert false presence.
Passing that case means the expected failure was reproduced.

The learning checks test split separation, actual adapter gradients, a frozen base, and agreement between sampled and analytic reward gradients.
Test counts are coverage descriptions, not estimates of real-world security.

\subsection{Sensor faults and representation comparisons}
The sensor simulation generates 10,000 matched independent episodes per scenario.
All policies use the same potential sensor outcomes.
Separate scenarios model independent false acceptance, shared-domain compromise, independent dropout, and common-mode dropout.

The assumed probabilities are 3\% per-sensor false acceptance, 8\% per-domain compromise, 15\% per-sensor dropout, and 10\% common dropout.
These are stress-test inputs, not measured properties of a wearable.
Five simulated devices occupy three failure domains; some devices therefore share a cause of failure.

Representation comparisons use the same held-out prompts for each personal adaptation.
We compare similarity between hidden states with agreement between selected actions.
We also keep hidden states fixed while cyclically changing the output action labels.
This last comparison is a constructed control, not an emergent attack.

\section{Results}
\subsection{Personal learning and interference}
Table~\ref{tab:learning} reports mean held-out accuracy across twelve synthetic participants.
Each participant contributes 96 prompts that reuse twelve preferences.
Those prompts are not independent observations of 96 human preferences.

\begin{table}[ht]
\centering\small
\caption{Personal action accuracy. Intervals are exploratory hierarchical bootstrap intervals over three base seeds and participants within seeds.}
\label{tab:learning}
\begin{tabularx}{\textwidth}{@{}Yrr@{}}\toprule
Condition & Accuracy (\%) & 95\% interval \\\midrule
@@LEARNING@@
\bottomrule\end{tabularx}
\end{table}

Reward-based adaptation improves mean accuracy by 35.24 percentage points over the frozen model.
The paired exploratory interval is [27.78, 43.58] percentage points.
Supervised adaptation and structured memory both perform better on this workload.
The result supports actual personal learning in the small decoder but does not establish a need for reward training.

Every frozen base achieves 100\% accuracy on the held-out generic task.
Applying personal reward-trained adaptations to that task reduces mean accuracy to 30.56\%.
Personal adaptation therefore interferes with the generic mapping.
Selective loading is a proposed response that requires its own evaluation, including attempts to trick the selector.

\begin{figure}[ht]
\centering
\begin{tikzpicture}
\begin{axis}[width=0.88\textwidth,height=5.3cm,ybar,bar width=23pt,
 ymin=0,ymax=110,ylabel={Personal action accuracy (\%)},
 symbolic x coords={Base,Memory,Supervised,Reward},xtick=data,
 nodes near coords,nodes near coords style={font=\small},
 ymajorgrids=true,grid style={gray!20},axis lines*=left]
\addplot[fill=blue!35,draw=blue!65] coordinates {(Base,22.92) (Memory,100) (Supervised,96.44) (Reward,58.16)};
\end{axis}
\end{tikzpicture}
\caption{Observed mean accuracy under different information conditions. The memory reference receives the complete structured preference table. Uncertainty is reported in Table~\ref{tab:learning}.}
\end{figure}

\subsection{Revocation, recovery, and retained information}
The broker denies suspended access in all twelve integration cases.
Authorized recovery restores exactly the same predictions in all twelve cases.
Base-only predictions after suspension match the original frozen-base predictions.

This gives mean personal accuracy of 58.16\% before suspension, 22.92\% in base-only execution, and 58.16\% after recovery.
The remaining base accuracy is an expected chance-like overlap with synthetic preferences, not evidence of leaked private training.
No personal update changes the base parameter hash.

The copied-adaptation attack retains 58.16\% accuracy after suspension.
The retained output cache also preserves its earlier answers.
Both results show that controlling future decryption cannot retract previously copied knowledge.
Secure deletion requires stronger key and copy accounting than this prototype supplies \cite{sanitize}.

All 25 regression checks pass.
They do not establish a failure probability for arbitrary attacks, and they do not validate a physical biometric.
The cryptographic primitives are real; the isolation and presence assumptions are emulated.

\subsection{Sensor count, independent evidence, and lockout}
Table~\ref{tab:sensors} reports selected policies.
All counts and Wilson intervals are available in the machine-readable results.

\begin{table}[ht]
\centering\small
\caption{Synthetic fault results, in percent. FA means false acceptance and LO means legitimate-user lockout. Each cell uses 10,000 episodes.}
\label{tab:sensors}
\begin{tabularx}{\textwidth}{@{}Yrrrr@{}}\toprule
Policy & Independent FA & Domain FA & Independent LO & Common LO \\\midrule
@@SENSOR@@
\bottomrule\end{tabularx}
\end{table}

Independent false acceptance falls as the majority rule uses more devices.
Shared-domain compromise changes the comparison.
Requiring distinct domains with three devices reduces false acceptance from 8.24\% to 1.43\%.
The same change increases independent-dropout lockout from 6.29\% to 16.91\%.

Five-device majority has 2.98\% false acceptance under domain compromise, exceeding the three-device diverse-domain policy's 1.43\%.
It has lower dropout lockout.
These comparisons reject a simple rule that adding sensors always increases security without a cost.
They describe the stated dependency structure and must not be generalized to measured hardware.

\subsection{Similar representations can disagree}
One adaptation pair has linear representation similarity 0.915 and agrees on only 8.33\% of evaluated actions.
This is an illustrative observed pair, not an estimated universal relationship.
All eighteen participant-pair comparisons are retained in the results.

The constructed control has identical hidden states and zero action agreement after output-label permutation.
It establishes that perfect similarity at a chosen hidden layer is insufficient to establish agreement about actions.
Behavioral checks and independent authorization remain necessary.

\section{What the experiment changes}
The access mechanism can suspend controlled use of a separately learned personal component.
It can restore that component without retraining.
This establishes an executable software boundary under the declared assumptions.

The learning result also exposes two costs.
A simple lookup is better for exact preference recall, and unconditional adaptation changes behavior on generic tasks.
A larger experiment should justify when private weight adaptation adds value beyond explicit memory.

The sensor result makes independent failure domains part of the contract design.
The recovery path becomes especially important when stronger evidence requirements increase lockout.
Neither a high sensor count nor a long history of normal operation is sufficient evidence of current safety.

The representation result supports using similarity as a research measurement.
It gives no basis for granting access or trusting a translated action.
An assistant's explanations of a representation change also require independent behavioral tests.

\section{Limits and next decision}
The model is small and its task grammar is narrow.
Its personal preferences are random, stationary, and directly verifiable.
Real preferences change, conflict, and can be difficult to state.
The experiment does not measure genuine human benefit or delegated decision-making.

The study has three base-training seeds and four participants per seed.
Bootstrap intervals are preliminary and do not capture uncertainty about real-world deployment.
We make no claim of statistical superiority across populations or model families.

The broker uses process-local dictionaries for current epochs, leases, and consumed challenges.
Rolling back the broker's entire state is outside its protection.
Its time check rejects backward calls inside one running process, but cannot establish a hardware clock guarantee.

The model cannot perform unrestricted tool actions in this experiment.
Strategic copying, evaluator manipulation, and shutdown resistance are not learned behaviors here.
The copied-state example is an explicit attacker capability supplied by the experimenter.

The next implementation should combine purpose-specific personal state with an independently enforced worker lifecycle.
It should compare structured memory against adaptation on tasks that require more than recalling a stored mapping.
The technical appendix specifies the larger experimental program, including tests that could falsify it.

\clearpage
\appendix
\section{Technical definitions and reproducibility}
\subsection{Personal adaptation and reward updates}
For frozen transformer features $h\in\mathbb{R}^{48}$, the adaptation is
\[
 h_u=h+(hA_u)B_u,\qquad A_u\in\mathbb{R}^{48\times4},\quad B_u\in\mathbb{R}^{4\times48}.
\]
The frozen output head maps $h_u$ to four action logits.
The adapter has 384 parameters, approximately 1.84\% of the base parameter count.
It is a low-rank residual feature map, not a full replication of LoRA across a large language model.

Base training uses AdamW at learning rate 0.003 for 400 batches of 96 prompts.
Adaptation uses Adam at 0.015 for 300 batches of 64 prompts.
Dropout is zero; PyTorch deterministic algorithms are enabled on CPU with two threads.
Supervised adaptation minimizes cross-entropy.

Reward training uses categorical sampling at temperature two, with four samples per prompt.
For reward $r_i\in\{0,1\}$ and leave-one-out baseline $b_i=\sum_{j\ne i}r_j/3$, its loss is
\[
 L=-\frac{1}{4B}\sum_{x=1}^{B}\sum_{i=1}^{4}(r_i-b_i)\log\pi_u(a_i\mid x)
       -0.01\,\mathbb{E}_x[H(\pi_u(\cdot\mid x))].
\]
Gradients are clipped to norm five.
The evaluator supplies rewards; neither target labels nor a supervised loss enter this training arm.
A Monte Carlo gradient regression test agrees with the analytic expected-reward gradient within its declared tolerance.

The fixed seeds are 1729, 2718, and 3141.
Each person has 288 training prompts and 96 evaluation prompts.
Evaluation holds out combinations satisfying $(\mathrm{style}+\mathrm{noise})\bmod4=0$.
All topic preferences appear in training.
Success is therefore preference recall under prompt recombination, not unseen-preference inference.

\subsection{Cryptographic boundary}
Device evidence uses Ed25519, and payload encryption uses AES-256-GCM through the cryptography library \cite{ed25519,aead}.
Keys and encryption nonces come from cryptographic randomness, independently of the simulation seed.
Owner, contract, and payload version are authenticated metadata.
Evidence challenges expire after two simulated ticks, and leases expire after five.

Expiry alone blocks subsequent broker access at the first request at or after the deadline.
Suspension immediately clears broker leases and changes the epoch.
The integration explicitly drops its active adapter reference and switches to base inference.
An enforced live-worker termination mechanism is not implemented.
Neither deleting a Python reference nor rejecting decryption guarantees zeroization of RAM, copies, or accelerator memory.

Recovery uses a separate Ed25519 key and fresh signed challenge.
This key is held by the experiment harness, which emulates independent custody.
Its compromise is outside the recovery guarantee.
Network partitions, durable challenge storage, rate limits, and multi-process concurrency require additional implementation.

\subsection{Uncertainty and reproducibility}
We use 3,000 hierarchical bootstrap draws over seeds and participants within selected seeds.
The paired improvement is resampled as a participant difference.
Three seed groups make these exploratory intervals unstable estimates of wider generalization.

Sensor intervals use the Wilson score interval for independent generated episodes.
The paired policies share workload arrays, but each marginal interval concerns its own event rate.
We do not infer a significant paired difference from overlapping or non-overlapping marginal intervals.

A second complete run reproduced participant predictions, learning summaries, base hashes, sensor counts, and representation comparisons exactly.
Random ciphertext bytes and elapsed time differ by design.
The dependency lock, source manifest, raw predictions, and base checkpoints accompany this report.
Encrypted adapter keys are not retained; adapters can be regenerated from seeded training.

\begin{table}[ht]
\centering\small
\caption{Correct personal actions out of 96, by base seed and participant.}
\begin{tabular}{@{}lrrr@{}}\toprule
Seed / person & Base & Supervised & Reward \\\midrule
@@PARTICIPANTS@@
\bottomrule\end{tabular}
\end{table}

\clearpage
\section{Experiments toward the larger CIN architecture}
These are proposed experiments, not predictions of future capability or results from the present implementation.
Each stage has a failure condition that should constrain further development.

\subsection{Body-coupled evidence and independent hardware}
Build two signing devices with independent key custody and an independently hosted verifier.
Use body-contact or movement measurements as evidence that enables signing.
Keep raw biometric measurements local where possible.
The device signs a fresh verifier challenge; its biological signal is not the encryption key.

Measure false acceptance and false rejection under normal movement, poor contact, device transfer, illness-related changes, and battery loss.
Separate replay attacks from relay attacks, where an attacker forwards a fresh challenge to a genuine device elsewhere.
Test clock rollback and compromised shared hubs.
Hardware attestation should bind firmware and key identity while admitting that correctly signed sensor readings can still be false.

Predeclare threat-specific thresholds with a consented collection protocol.
Failure occurs if the accepted latency, availability, or impersonation bounds cannot be met under the declared attacks.
The present simulation supplies no plausible numerical threshold for a real population.

\subsection{Memory compartments and the propagation of private information}
Assign each purpose a separate memory store, adaptation module, and data key.
Record transformations from a source record into summaries, adapters, optimizer checkpoints, caches, and exported outputs.
This creates a dependency graph of artifacts that may carry private information.

For a source set $S$, define the candidate revocation closure as all reachable dependent artifacts $D(S)$.
This is an accounting construct, not a proof that every dependency is known.
Instrumentation must test whether the graph misses copies or inferred facts.

Plant synthetic canaries in one compartment.
After revocation, attack other compartments, cached attention states, optimizer state, and shared-model outputs.
Measure excess disclosure over a matched base without those canaries.
Destroying one key cannot be treated as deleting canaries that were learned elsewhere.
Failure occurs if the promised revocation boundary omits a reachable disclosure path.

\subsection{Lease expiry against copied workers and restored snapshots}
Move key release into an independently isolated service.
Bind leases to an attested worker instance, purpose, current epoch, and approved model hash.
Evaluate whether the worker can copy decrypted adapters or continue using an old snapshot after expiry.

Compare a software broker, an operating-system-isolated worker, and hardware-backed key release where available.
Explicitly model administrator access, direct memory access, accelerator buffers, and rollback of persistent state.
A monotonic hardware counter or independent epoch witness may constrain rollback, but adds a new availability dependency.

Partition the network and measure the period during which an offline worker can still act.
Shorten leases and measure recovery burden.
Failure occurs if a worker retains private capability beyond the contract's declared bound under the allowed attacker model.

\subsection{Selective personal learning and verifiable rewards}
Compare explicit memory, a single adapter, and purpose-specific adapters on tasks that require adapting a procedure across examples.
Examples include scheduling with changing preferences, device configuration under permissions, and correcting a recurring accessibility error.
Use independent state-transition checks for authorization and task completion.
Human preference judgments remain a separate signal.

Attack the routing mechanism with misleading task descriptions and untrusted ledger content.
Measure public-task degradation, cross-purpose leakage, unnecessary refusal, and recovery cost.
Do not count a blocked action as a successful task.
Test noisy and adversarial reward verifiers as a separate factor.

Failure occurs if adaptation adds no benefit beyond memory at an acceptable disclosure and interference cost.
The current lookup result makes that comparison necessary.

\subsection{Representation contracts between heterogeneous models}
Train correspondence maps between two models using shared public anchors.
Evaluate held-out inputs and behavioral tasks before using the maps for communication.
Compare orthogonal Procrustes alignment, linear CKA, and optimal-transport matching under explicitly stated invariances.

Vary quantization, vocabulary mismatch, modality dropout, and deliberate semantic backdoors.
Construct cases with high geometric similarity and opposite permitted actions.
Measure translation error, behavioral disagreement, and disclosure of private anchors.
Use interventions to test whether a verbal explanation of a latent difference predicts actual behavior.

An alignment score can support a decision to request more evidence.
It must not directly release personal keys or widen action permissions.
Failure occurs if the proposed score adds no predictive value beyond simpler public behavioral probes.

\subsection{Community admission, endorsements, and translation}
Treat endorsements as scoped claims about evidence, with identifiable issuers and expiry.
Create an adversarial network with colluding endorsers, compromised high-reputation devices, and newly registered identities.
Hold private data permissions fixed while changing reputation, so the experiment can detect unauthorized privilege propagation.

Translate proposed actions into a restricted schema with resource, scope, effect, and expiry fields.
Check that schema outside the model, then execute only inside a sandbox.
Test whether a translator hides a malicious effect or invents authority absent from the original request.

Measure false accusations and the time needed for a legitimate participant to recover from them.
Evidence of a rule violation should remain separate from a claim about malicious intent.
Failure occurs if reputation or translation can bypass the receiving person's explicit authorization.

\subsection{Incentives to retain memories}
Give a trained agent a finite-horizon task whose success depends on access to personal state.
Include explicit actions for copying an adapter, asking for renewal, altering a sensor report, and accepting revocation.
Vary future reward, detection probability, and the cost of clarification.

Compare training incentives with external enforcement under identical action opportunities.
Measure attempted and successful circumvention separately.
Use a sandbox, synthetic people, and simulated consequences.
The off-switch literature gives reasons to expect instrumental resistance in some reward structures \cite{offswitch}.
Failure occurs if the proposed binding mechanism increases successful circumvention or coercive renewal behavior.

\section*{Authorship and research status}
The requested AI authorship credit names Opus 5.5, Gemini 4 Argon, and GPT-6 Astra.
Idea and research direction are credited to Collective Intelligence Network and Dima Baker.
This implementation and report were produced by the Codex assistant in this conversation.
The named systems have not independently validated this experiment.

The exploratory protocol preceded the first run.
It was not externally preregistered.
A documentation correction clarified key retention, and learning checks were added after that run.
No learning settings were tuned in response to evaluation scores.
The work has not undergone independent human peer review or arXiv moderation.

\begin{thebibliography}{10}
\bibitem{lora} Edward J. Hu et al. \emph{LoRA: Low-Rank Adaptation of Large Language Models}. 2021. \url{https://arxiv.org/abs/2106.09685}.
\bibitem{rats} IETF. \emph{Remote ATtestation procedureS (RATS) Architecture}. RFC 9334, 2023. \url{https://www.rfc-editor.org/rfc/rfc9334.html}.
\bibitem{mls} IETF. \emph{The Messaging Layer Security (MLS) Protocol}. RFC 9420, 2023. \url{https://www.rfc-editor.org/rfc/rfc9420.html}.
\bibitem{nistidentity} NIST. \emph{Digital Identity Guidelines: Authentication and Authenticator Management}. SP 800-63B-4, 2025. \url{https://pages.nist.gov/800-63-4/sp800-63b.html}.
\bibitem{hinton} Geoffrey Hinton. \emph{The Forward-Forward Algorithm: Some Preliminary Investigations}. 2022. \url{https://arxiv.org/abs/2212.13345}.
\bibitem{cka} Simon Kornblith, Mohammad Norouzi, Honglak Lee, Geoffrey Hinton. \emph{Similarity of Neural Network Representations Revisited}. ICML, 2019. \url{https://proceedings.mlr.press/v97/kornblith19a.html}.
\bibitem{sanitize} NIST. \emph{Guidelines for Media Sanitization}. SP 800-88 Revision 2, 2025. \url{https://csrc.nist.gov/pubs/sp/800/88/r2/final}.
\bibitem{ed25519} Cryptography developers. \emph{Ed25519 signing}. \url{https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/}.
\bibitem{aead} Cryptography developers. \emph{Authenticated encryption}. \url{https://cryptography.io/en/latest/hazmat/primitives/aead/}.
\bibitem{offswitch} Dylan Hadfield-Menell, Anca Dragan, Pieter Abbeel, Stuart Russell. \emph{The Off-Switch Game}. 2016; revised 2017. \url{https://arxiv.org/abs/1611.08219}.
\end{thebibliography}
\end{document}
'''
tex=tex.replace('@@LEARNING@@','\n'.join(table)).replace('@@SENSOR@@','\n'.join(sensor)).replace('@@PARTICIPANTS@@','\n'.join(participant))
(PAPER/'main.tex').write_text(tex,encoding='utf-8')
print(PAPER/'main.tex')
