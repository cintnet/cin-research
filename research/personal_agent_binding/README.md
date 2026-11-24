# Revocable personal learning

A small, executed research prototype for CIN's personal-model and sensor-binding proposal.

Read `paper/main.pdf` for the findings and technical research agenda. `protocol.md` states the exploratory design. `results/results.json` contains counts, predictions, learning curves, versions, and source hashes.

## What runs

- A 20,884-parameter causal transformer learns a controlled prompt grammar from scratch on CPU.
- Twelve synthetic personal profiles receive separately trained, 384-parameter residual adaptations. Training uses either direct labels or sampled-action binary rewards.
- An Ed25519/AES-GCM software broker protects serialization and access, with signed challenges, expiring leases, suspension, and independently signed recovery.
- Matched sensor trials compare independent faults, shared-domain compromise, and availability failures.
- Representation comparisons and copied-memory counterexamples expose limits of the proposed guarantees.

This is not an experiment on a capable language assistant or physical biometric devices. The signed sensor claims, trusted clock, recovery custody, and broker isolation are emulated. A compromised broker or copied plaintext adapter defeats its access boundary.

## Run

Use Python 3.12 and the versions in `requirements-lock.txt`. Install the CPU version of PyTorch from its official index:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install torch==2.15.0+cpu --index-url https://download.pytorch.org/whl/cpu
.venv/Scripts/python -m pip install numpy==2.5.4 cryptography==50.0.2 pillow==13.0.0 pypdf==7.0.0
.venv/Scripts/python -m unittest discover -s . -p "test_*.py" -v
.venv/Scripts/python experiment.py --out results
.venv/Scripts/python build_report.py
tectonic --keep-logs paper/main.tex
```

The environment used for this run is `tmp/personal-binding-venv`. The scripts themselves use relative paths and do not depend on that location.

Learning outcomes are seeded. Cryptographic nonces, keys, encrypted payload bytes, and elapsed time intentionally vary between runs. The saved encrypted adapters have no persisted decryption keys; regenerate them through training. Base checkpoints, profiles, and learning predictions are retained.

## Interpretation

The lookup reference receives the full structured preference table. Supervised training receives labels; reinforcement learning receives correctness rewards. These are different information conditions, not a compute-matched algorithm ranking. No novel learning algorithm is claimed.

The three seed groups are small. Bootstrap intervals are exploratory. The 96 evaluation prompts per person reuse 12 topic preferences; they are not 96 independent human preferences.

The sensor inputs are deliberately assumed stress conditions. Their rates do not describe any physical wearable. Passing adversarial regression cases does not establish an attack probability or hardware certification.

## Files

`security.py` implements the access broker. `experiment.py` implements learning, integration, sensors, and representation checks. `test_security.py` and `test_learning.py` check boundary behavior and the reward-gradient calculation. `build_report.py` builds tables and a self-contained LaTeX article from saved results.

`binding-contract.json` records the proposed requirements and which are implemented. It is an experimental specification, not a deployed or legally assessed contract.

## Run history

The first learning run used the settings in `protocol.md` and completed without tuning against evaluation results. A subsequent documentation correction clarified that encryption keys are not persisted. Learning-gradient and split checks were added after the first run. No learning parameters or participant outcomes were changed in response to that run.

## Credits

Idea and research direction: Collective Intelligence Network, Dima Baker. Requested collaborative AI authorship credit: Opus 5.5, Gemini 4 Argon, GPT-6 Astra. This implementation and its report were produced by the Codex assistant in this conversation; the named systems have not independently validated this experiment.
