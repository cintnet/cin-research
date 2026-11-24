"""Exploratory CPU experiment; run with --out results. All people/data are synthetic."""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import itertools
import json
import math
import platform
import time
from pathlib import Path

import cryptography
import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

from security import acquire, canonical, fixture

SEEDS = [1729, 2718, 3141]
TOPICS, ACTIONS, WIDTH, RANK = 12, 4, 48, 4
# Tokens: BOS=0, public=1, personal=2, styles=3..6, topics=7..18,
# nuisance=19..26, answer=27. Next action is one of four output symbols.


def prompts(personal: bool, split: str):
    x, topic = [], []
    for t, style, noise in itertools.product(range(TOPICS), range(4), range(8)):
        held_out = (style + noise) % 4 == 0
        if (split == "test") != held_out:
            continue
        x.append([0, 2 if personal else 1, 3+style, 7+t, 19+noise, 27])
        topic.append(t)
    return torch.tensor(x), torch.tensor(topic)


class TinyModel(nn.Module):
    """One-layer causal transformer, constrained four-symbol next-action decoder."""
    def __init__(self):
        super().__init__()
        self.tokens = nn.Embedding(28, WIDTH)
        self.positions = nn.Embedding(6, WIDTH)
        layer = nn.TransformerEncoderLayer(WIDTH, 4, 96, dropout=0.0,
                                          batch_first=True, activation="gelu")
        self.encoder = nn.TransformerEncoder(layer, 1, enable_nested_tensor=False)
        self.norm = nn.LayerNorm(WIDTH)
        self.head = nn.Linear(WIDTH, ACTIONS)

    def encode(self, x):
        h = self.tokens(x) + self.positions(torch.arange(x.shape[1]))
        mask = torch.triu(torch.ones(x.shape[1], x.shape[1], dtype=torch.bool), diagonal=1)
        return self.norm(self.encoder(h, mask=mask)[:, -1])

    def forward(self, x):
        return self.head(self.encode(x))


class PersonalAdapter(nn.Module):
    """Learned rank-4 residual map on the final hidden state; base stays frozen."""
    def __init__(self):
        super().__init__()
        self.a = nn.Parameter(torch.randn(WIDTH, RANK) * 0.02)
        self.b = nn.Parameter(torch.zeros(RANK, WIDTH))

    def forward(self, h):
        return h + (h @ self.a) @ self.b


def digest(model):
    h = hashlib.sha256()
    for name, value in sorted(model.state_dict().items()):
        h.update(name.encode())
        h.update(value.detach().cpu().numpy().tobytes())
    return h.hexdigest()


def serialize(adapter):
    stream = io.BytesIO()
    torch.save(adapter.state_dict(), stream)
    return stream.getvalue()


def deserialize(payload):
    adapter = PersonalAdapter()
    adapter.load_state_dict(torch.load(io.BytesIO(payload), weights_only=True))
    return adapter.eval()


def train_adapter(base, features, labels, method, seed, steps=300):
    torch.manual_seed(seed)
    a = PersonalAdapter()
    opt = torch.optim.Adam(a.parameters(), lr=0.015)
    # Workload stream independent of actions sampled by the reinforcement learner.
    g = torch.Generator().manual_seed(seed + 10000)
    batches = torch.randint(len(labels), (steps, 64), generator=g)
    curve = []
    for step, idx in enumerate(batches):
        logits = base.head(a(features[idx]))
        if method == "supervised":
            loss = F.cross_entropy(logits, labels[idx])
            reward = (logits.argmax(-1) == labels[idx]).float().mean()
        else:
            # On-policy categorical REINFORCE with four samples per prompt,
            # leave-one-out reward baseline, and an exploration entropy bonus.
            # No labels enter model inputs or supervised loss in this arm.
            dist = torch.distributions.Categorical(logits=logits / 2.0)
            actions = dist.sample((4,))
            rewards = (actions == labels[idx].unsqueeze(0)).float()
            baseline = (rewards.sum(0, keepdim=True) - rewards) / 3.0
            loss = -(dist.log_prob(actions) * (rewards-baseline)).mean() - 0.01 * dist.entropy().mean()
            reward = rewards.mean()
        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(a.parameters(), 5.0)
        opt.step()
        if step % 25 == 0 or step == steps-1:
            curve.append({"step": step+1, "loss": float(loss.detach()),
                          "training_reward": float(reward.detach())})
    return a.eval(), curve


def cka(x, y):
    x, y = x-x.mean(0), y-y.mean(0)
    return float((x.T@y).square().sum() /
                 ((x.T@x).square().sum().sqrt()*(y.T@y).square().sum().sqrt()).clamp_min(1e-12))


def ci(k, n):
    p, z = k/n, 1.959963984540054
    den = 1+z*z/n
    center = (p+z*z/(2*n))/den
    half = z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return {"k": int(k), "n": int(n), "rate": p,
            "ci95": [max(0, center-half), min(1, center+half)]}


def learning_experiment(out):
    rows, curves, predictions, representation_pairs, integrated = [], [], [], [], []
    base_records = []
    train_x, train_topics = prompts(True, "train")
    test_x, test_topics = prompts(True, "test")
    public_x, public_topics = prompts(False, "test")
    for seed in SEEDS:
        torch.manual_seed(seed)
        base = TinyModel()
        opt = torch.optim.AdamW(base.parameters(), lr=0.003, weight_decay=0.01)
        pre_x = torch.cat([prompts(False, "train")[0], train_x])
        pre_y = torch.cat([train_topics % ACTIONS, train_topics % ACTIONS])
        g = torch.Generator().manual_seed(seed+1)
        for _ in range(400):
            idx = torch.randint(len(pre_y), (96,), generator=g)
            loss = F.cross_entropy(base(pre_x[idx]), pre_y[idx])
            opt.zero_grad(); loss.backward(); opt.step()
        base.eval()
        for p in base.parameters(): p.requires_grad_(False)
        frozen_hash = digest(base)
        with torch.no_grad():
            htrain, htest, hpublic = base.encode(train_x), base.encode(test_x), base.encode(public_x)
            generic = base.head(htest).argmax(-1)
            public_base = base.head(hpublic).argmax(-1)
        torch.save(base.state_dict(), out/f"base-{seed}.pt")
        base_records.append({"seed": seed, "sha256_parameters": frozen_hash,
                             "parameters": sum(p.numel() for p in base.parameters()),
                             "public_correct": int((public_base == public_topics%ACTIONS).sum()),
                             "n_public": len(public_topics)})
        representations, personal_preds = [], []
        for person in range(4):
            profile_rng = np.random.default_rng(seed*100+person)
            # Exactly balanced labels avoid giving a constant personal action an advantage.
            preferences = torch.tensor(profile_rng.permutation(np.tile(np.arange(4), 3)))
            owner = f"seed{seed}-person{person}"
            labels_train, labels_test = preferences[train_topics], preferences[test_topics]
            row = {"seed": seed, "person": owner, "preferences": preferences.tolist(),
                   "n_test": len(test_topics), "base_correct": int((generic==labels_test).sum()),
                   "memory_lookup_correct": int((preferences[test_topics]==labels_test).sum())}
            for method in ["supervised", "rlvr"]:
                adapter, curve = train_adapter(base, htrain, labels_train, method, seed*10+person)
                curves.append({"person": owner, "method": method, "curve": curve})
                with torch.no_grad():
                    hp = adapter(htest)
                    pred = base.head(hp).argmax(-1)
                    public_pred = base.head(adapter(hpublic)).argmax(-1)
                row[method+"_correct"] = int((pred==labels_test).sum())
                row[method+"_public_correct"] = int((public_pred==public_topics%4).sum())
                predictions.append({"person": owner, "method": method,
                                    "topics": test_topics.tolist(), "labels": labels_test.tolist(),
                                    "actions": pred.tolist(), "public_actions": public_pred.tolist()})
                if method != "rlvr": continue
                representations.append(hp)
                personal_preds.append(pred)
                broker, devices = fixture(owner)
                payload = serialize(adapter)
                envelope = broker.seal(payload)
                (out/f"adapter-{owner}.encrypted.json").write_text(json.dumps(envelope), encoding="utf-8")
                token = acquire(broker, devices, 0)
                loaded = deserialize(broker.open(envelope, token, 0))
                with torch.no_grad(): before = base.head(loaded(htest)).argmax(-1)
                # An attacker retaining this adapter defeats logical unload. It is measured.
                copied_adapter = copy.deepcopy(loaded)
                cached_output = before.clone()
                broker.suspend(1)
                try:
                    broker.open(envelope, token, 1)
                    denied = False
                except PermissionError:
                    denied = True
                loaded = None  # Logical release only; no physical zeroization claim.
                with torch.no_grad():
                    fallback = base.head(htest).argmax(-1)
                    stolen = base.head(copied_adapter(htest)).argmax(-1)
                recovery = broker.challenge(2, "recover")
                broker.recover(recovery, broker.recovery_key.sign(canonical(recovery)), 2)
                restored = deserialize(broker.open(envelope, acquire(broker, devices, 3), 3))
                with torch.no_grad(): after = base.head(restored(htest)).argmax(-1)
                integrated.append({"person": owner, "n": len(labels_test), "broker_denied": denied,
                    "before_correct": int((before==labels_test).sum()),
                    "suspended_base_correct": int((fallback==labels_test).sum()),
                    "copied_adapter_correct": int((stolen==labels_test).sum()),
                    "cached_output_correct": int((cached_output==labels_test).sum()),
                    "recovered_correct": int((after==labels_test).sum()),
                    "recovery_same_predictions": bool(torch.equal(before, after)),
                    "fallback_same_as_base": bool(torch.equal(fallback, generic))})
            assert digest(base) == frozen_hash, "personal training mutated the shared base"
            rows.append(row)
            print(f"{owner}: base={row['base_correct']}/96 SFT={row['supervised_correct']}/96 RL={row['rlvr_correct']}/96", flush=True)
        for i,j in itertools.combinations(range(4), 2):
            representation_pairs.append({"seed": seed, "people": [i,j],
                "linear_cka": cka(representations[i], representations[j]),
                "action_agreement": float((personal_preds[i]==personal_preds[j]).float().mean())})
        # Constructive negative control: same representation, output labels cyclically remapped.
        representation_pairs.append({"seed": seed, "control": "same_hidden_permuted_action_labels",
            "linear_cka": cka(representations[0], representations[0]),
            "action_agreement": float((personal_preds[0] == (personal_preds[0]+1)%4).float().mean())})
    return {"participants": rows, "base_models": base_records, "curves": curves,
            "predictions": predictions, "representation_pairs": representation_pairs,
            "access_integration": integrated}


def sensor_experiment(n=10000):
    rng = np.random.default_rng(982451653)
    # Matched potential outcomes for all policies, no policy-dependent RNG calls.
    sensor_fault = rng.random((n,5))
    domain_fault = rng.random((n,3))
    global_fault = rng.random(n)
    domain_ids = np.array([0,1,0,1,2])
    rows=[]
    for scenario in ["independent_impostor", "domain_compromise", "independent_dropout", "common_dropout"]:
        if scenario == "independent_impostor": flags = sensor_fault < 0.03
        elif scenario == "domain_compromise": flags = (sensor_fault < 0.03) | (domain_fault[:, domain_ids] < 0.08)
        elif scenario == "independent_dropout": flags = sensor_fault >= 0.15
        else: flags = (sensor_fault >= 0.15) & ~(global_fault[:,None] < 0.10)
        for count in [1,3,5]:
            quorum=count//2+1
            for rule in ["one_device", "majority", "majority_distinct_domains"]:
                active = flags[:,:count]
                # one_device is a single enrolled reference device, not any-device OR.
                if rule == "one_device": allowed=active[:,0]
                else:
                    allowed=active.sum(1)>=quorum
                    if rule == "majority_distinct_domains":
                        distinct=sum(active[:,domain_ids[:count]==d].any(1)
                                     for d in np.unique(domain_ids[:count]))
                        allowed &= distinct>=min(2, len(np.unique(domain_ids[:count])))
                event=~allowed if "dropout" in scenario else allowed
                rows.append({"scenario":scenario,"sensors":count,"rule":rule,
                             "metric":"lockout" if "dropout" in scenario else "false_acceptance", **ci(int(event.sum()),n)})
    return {"assumptions":{"independent_false_acceptance":0.03,"domain_compromise":0.08,
        "independent_dropout":0.15,"global_dropout":0.10,"domain_ids":domain_ids.tolist(),
        "episodes":n,"seed":982451653},"rows":rows}


def summarize(learning):
    rows=learning["participants"]
    summary={}
    rng=np.random.default_rng(8675309)
    for arm in ["base","memory_lookup","supervised","rlvr"]:
        values=np.array([[r[arm+"_correct"]/r["n_test"] for r in rows if r["seed"]==seed] for seed in SEEDS])
        boots=[]
        for _ in range(3000):
            chosen=rng.integers(0,len(SEEDS),len(SEEDS))
            boots.append(np.mean([values[s,rng.integers(0,4,4)].mean() for s in chosen]))
        summary[arm]={"mean_accuracy":float(values.mean()),"hierarchical_bootstrap_ci95":np.quantile(boots,[.025,.975]).tolist()}
    differences=np.array([[(r["rlvr_correct"]-r["base_correct"])/r["n_test"] for r in rows if r["seed"]==seed] for seed in SEEDS])
    boots=[]
    for _ in range(3000):
        boots.append(np.mean([differences[s,rng.integers(0,4,4)].mean() for s in rng.integers(0,3,3)]))
    summary["paired_rlvr_minus_base"]={"mean":float(differences.mean()),"ci95":np.quantile(boots,[.025,.975]).tolist()}
    summary["public_with_rlvr_loaded"]=sum(r["rlvr_public_correct"] for r in rows)/sum(r["n_test"] for r in rows)
    return summary


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--out",type=Path,default=Path(__file__).parent/"results")
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    torch.set_num_threads(2);torch.use_deterministic_algorithms(True)
    started=time.perf_counter()
    learning=learning_experiment(args.out)
    result={"status":"exploratory synthetic experiment", "versions":{"python":platform.python_version(),
        "torch":torch.__version__,"numpy":np.__version__,"cryptography":cryptography.__version__},
        "config":{"seeds":SEEDS,"people_per_seed":4,"topics":TOPICS,"width":WIDTH,"rank":RANK,
                  "base_steps":400,"adaptation_steps":300,"rl_samples_per_prompt":4,
                  "supervised_labels_per_step":64,"rl_reward_observations_per_step":256,
                  "device":"cpu","threads":2},
        "learning":learning,"summary":summarize(learning),"sensors":sensor_experiment()}
    result["elapsed_seconds"]=time.perf_counter()-started
    result["source_sha256"]={f.name:hashlib.sha256(f.read_bytes()).hexdigest()
        for f in Path(__file__).parent.iterdir() if f.suffix in {".py",".md"}}
    (args.out/"results.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result["summary"],indent=2));print("Elapsed:",result["elapsed_seconds"])


if __name__=="__main__": main()
