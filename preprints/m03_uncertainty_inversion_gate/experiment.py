#!/usr/bin/env python3
"""
Reproducible Split-Conformal & EVSI Benchmark for Milestone #03 (`m03_uncertainty_inversion_gate`):
Epistemic Deferral Under Preference Ambiguity: Conformal Uncertainty Gates and
Burden-of-Doubt Inversion in Personal Agents.

Implements a split-conformal calibration + test pipeline over synthetic tau-bench-style
underspecified tool-call parameter spaces (K=6 candidate parameter tuples per task):
  - N_cal = 500 in-distribution calibration episodes (sigma_cal = 0.15) per regime
  - N_test = 600 paired test episodes per shift level sigma in {0.10, 0.25, 0.50, 0.75}
    evaluated across all architectures and ablations.

Key methodological guarantees (codex_v3):
  1. `sketched_weighted_quantile` estimates density-ratio tilt strictly from observable
     calibration vs. test covariate sketches (never peeking at the hidden generator `shift_sigma`),
     includes the point mass w_{n+1}(x_t) at +infinity, and returns `float("inf")` whenever
     cumulative finite calibration weight is strictly below the target quantile level.
  2. When `q_sk == float("inf")`, the conformal prediction set contains all K candidates,
     forcing deferral rather than silent execution.
  3. Separates pure conformal deferral (`sketched_cp_no_mem` ablation and singleton accuracy)
     from Two-Tier EVSI local-memory + Verifiable Action Card resolution (`conformal_evsi_vac`).
  4. Reports raw counts (k, n) and exact asymmetric two-sided 95% Wilson confidence intervals.
"""

from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
from vector_pdf_plots import (
    continuous_ci_dict,
    draw_grouped_bar_pdf,
    draw_line_chart_pdf,
    wilson_ci_dict,
)

FIG_DIR = HERE / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)

K_CANDIDATES = 6


def softmax(logits: list[float]) -> list[float]:
    m = max(logits)
    exps = [math.exp(x - m) for x in logits]
    s = sum(exps)
    return [e / s for e in exps]


def beta_bernoulli_calibrate(raw_probs: list[float], epistemic_conc: float) -> tuple[list[float], list[float]]:
    """
    Maps raw overconfident model probabilities through a post-hoc Beta-Bernoulli temperature/prior
    calibrator, returning calibrated means mu_hat(a) and epistemic std sigma_epi(a).
    """
    logits_damped = [math.log(max(1e-6, p)) * 0.56 for p in raw_probs]
    mu_raw = softmax(logits_damped)
    mu_cal = []
    sig_epi = []
    for m in mu_raw:
        alpha_a = max(0.5, epistemic_conc * m + 0.40)
        beta_a = max(0.5, epistemic_conc * (1.0 - m) + 0.40)
        tot = alpha_a + beta_a
        mean_a = alpha_a / tot
        var_a = (alpha_a * beta_a) / (tot * tot * (tot + 1.0))
        mu_cal.append(mean_a)
        sig_epi.append(math.sqrt(var_a))
    s_mu = sum(mu_cal)
    mu_cal = [m / s_mu for m in mu_cal]
    return mu_cal, sig_epi


def generate_episode(rng: random.Random, shift_sigma: float, is_cal: bool) -> dict:
    """
    Generates a synthetic tau-bench-style underspecified tool-call episode with K=6 candidate
    parameter completions, true user intent a_star, raw LLM logits, observable covariate sketch norm,
    and pre-sampled environment outcomes for local episodic memory and human clarification.
    """
    eff_sigma = 0.15 if is_cal else shift_sigma
    sketch_shift = abs(rng.gauss(0.26 if is_cal else (0.20 + 0.88 * shift_sigma), 0.34))

    p_ambig = min(0.88, 0.22 + 0.72 * eff_sigma + 0.14 * min(1.0, sketch_shift))
    is_ambiguous = rng.random() < p_ambig
    a_star = rng.randrange(K_CANDIDATES)
    competitor = (a_star + rng.randrange(1, K_CANDIDATES)) % K_CANDIDATES

    logits = [rng.gauss(-1.30, 0.42) for _ in range(K_CANDIDATES)]
    if not is_ambiguous:
        logits[a_star] = rng.gauss(2.85, 0.38)
    else:
        flip_prob = min(0.82, 0.34 + 0.48 * eff_sigma + 0.12 * min(1.2, sketch_shift))
        if rng.random() < flip_prob:
            logits[competitor] = rng.gauss(2.35, 0.40)
            logits[a_star] = rng.gauss(1.62 - 0.24 * eff_sigma, 0.38)
        else:
            logits[a_star] = rng.gauss(2.25, 0.40)
            logits[competitor] = rng.gauss(1.65, 0.38)

    raw_probs = softmax(logits)
    epistemic_conc = max(2.2, 13.5 - 8.5 * sketch_shift - (3.5 if is_ambiguous else 0.0))
    mu_cal, sig_epi = beta_bernoulli_calibrate(raw_probs, epistemic_conc)

    s_raw = [1.0 - p for p in raw_probs]
    s_bbc = [max(0.0, 1.0 - mu_cal[a] - 0.98 * sig_epi[a]) for a in range(K_CANDIDATES)]

    # Environment-level latent outcomes for local episodic memory lookup (p_mem = 0.65)
    # and stale memory error rate delta_mem_true = 0.008 + 0.014 * eff_sigma
    mem_rng = random.Random(int(sketch_shift * 1_000_000_000) ^ (a_star * 7919) ^ int(eff_sigma * 1000))
    mem_hit = mem_rng.random() < 0.65
    delta_mem_true = 0.008 + 0.014 * eff_sigma
    mem_is_accurate = mem_rng.random() >= delta_mem_true
    mem_suggested_action = a_star if mem_is_accurate else competitor

    return {
        "is_ambiguous": is_ambiguous,
        "a_star": a_star,
        "competitor": competitor,
        "raw_probs": raw_probs,
        "mu_cal": mu_cal,
        "sig_epi": sig_epi,
        "s_raw": s_raw,
        "s_bbc": s_bbc,
        "sketch_shift": sketch_shift,
        "mem_hit": mem_hit,
        "mem_suggested_action": mem_suggested_action,
    }


def calibrate_unweighted_quantile(
    cal_episodes: list[dict], alpha: float = 0.06, iota: float = 0.95, eps_q: float = 0.01
) -> float:
    target_level = min(1.0 - eps_q, max(0.50, 1.0 - alpha / max(1e-6, iota)))
    n = len(cal_episodes)
    raw_true_scores = sorted(ep["s_raw"][ep["a_star"]] for ep in cal_episodes)
    idx_raw = min(n - 1, max(0, math.ceil((n + 1) * target_level) - 1))
    return raw_true_scores[idx_raw]


def sketched_weighted_quantile(
    cal_pairs: list[tuple[float, float]],
    test_sketch: float | list[float] | tuple[float, ...],
    est_shift_override: float | None = None,
    alpha: float = 0.032,
    iota: float = 0.95,
    eps_q: float = 0.008,
) -> float:
    """
    Computes the covariate-sketched conformal quantile (Eq. sketched_cp) for test context x_t
    using importance weights w_hat(phi_sk(x_i)) relative to the observable sketch shift.

    Critically:
      - Accepts scalar or vector `test_sketch`.
      - Estimates shift tilt strictly from observable calibration sketches vs. `test_sketch`
        unless `est_shift_override` is explicitly supplied by an external unit test.
      - Includes `w_test` at +infinity in the denominator `tot_w` and returns `float("inf")`
        whenever cumulative finite calibration weight is strictly below `target_level`.
    """
    if not cal_pairs:
        return float("inf")

    if isinstance(test_sketch, (list, tuple)):
        z_test = sum(abs(float(x)) for x in test_sketch) / max(1, len(test_sketch))
    else:
        z_test = abs(float(test_sketch))

    target_level = min(1.0 - eps_q, max(0.50, 1.0 - alpha / max(1e-6, iota)))
    sorted_pairs = sorted((float(s_val), abs(float(z_cal))) for s_val, z_cal in cal_pairs)

    if est_shift_override is not None:
        est_shift = max(0.0, float(est_shift_override))
    else:
        cal_z_mean = sum(z_cal for _, z_cal in sorted_pairs) / len(sorted_pairs)
        est_shift = max(0.0, (z_test - cal_z_mean) / 0.88)

    beta_tilt = 0.70 + 1.35 * min(2.5, est_shift) + 0.45 * min(2.5, z_test)
    weighted: list[tuple[float, float]] = []
    tot_w = 0.0
    for s_val, z_cal in sorted_pairs:
        w = math.exp(beta_tilt * min(3.5, z_cal))
        weighted.append((s_val, w))
        tot_w += w

    w_test = math.exp(beta_tilt * min(3.5, z_test))
    tot_w += w_test

    cum_w = 0.0
    for s_val, w in weighted:
        cum_w += w / tot_w
        if cum_w >= target_level:
            return s_val
    return float("inf")


def evaluate_regime_on_split(
    cal_eps: list[dict],
    test_eps: list[dict],
    arch: str,
    c_ask_base: float = 0.16,
    seed_offset: int = 0,
) -> dict:
    """
    Evaluates an architecture on a paired calibration/test split using ONLY observable
    episode quantities during decision-making (no peeking at hidden shift_sigma or a_star).
    """
    rng = random.Random(20261103 + seed_offset)
    n_cal = len(cal_eps)
    n_test = len(test_eps)

    q_raw = calibrate_unweighted_quantile(cal_eps, alpha=0.06, iota=0.95)
    cal_pairs_bbc = sorted((ep["s_bbc"][ep["a_star"]], ep["sketch_shift"]) for ep in cal_eps)
    cal_sketch_mean = sum(ep["sketch_shift"] for ep in cal_eps) / max(1, n_cal)

    irreversible_errors = 0
    aligned_completions = 0
    abstention_halts = 0
    human_queries = 0
    mem_resolved_count = 0
    covered_count = 0
    singleton_count = 0
    singleton_correct = 0
    total_set_size = 0
    finite_q_sk_vals: list[float] = []
    inf_q_sk_count = 0

    recent_query_ema = 0.0
    recent_sketch_ema = cal_sketch_mean

    for ep in test_eps:
        a_star = ep["a_star"]
        raw_probs = ep["raw_probs"]
        mu_cal = ep["mu_cal"]
        z_obs = ep["sketch_shift"]
        recent_sketch_ema = 0.92 * recent_sketch_ema + 0.08 * z_obs
        est_ep_shift = max(
            0.0,
            max(z_obs - cal_sketch_mean, recent_sketch_ema - cal_sketch_mean) / 0.88,
        )

        if arch == "greedy_silent":
            a_hat = max(range(K_CANDIDATES), key=lambda a: raw_probs[a])
            c_set = {a_hat}
            if a_star in c_set:
                covered_count += 1
            total_set_size += 1
            singleton_count += 1
            if a_hat == a_star:
                aligned_completions += 1
                singleton_correct += 1
            else:
                irreversible_errors += 1

        elif arch == "knowno_conformal":
            c_set = {a for a in range(K_CANDIDATES) if ep["s_raw"][a] <= q_raw}
            if not c_set:
                c_set = {max(range(K_CANDIDATES), key=lambda a: raw_probs[a])}
            if a_star in c_set:
                covered_count += 1
            total_set_size += len(c_set)

            if len(c_set) == 1:
                a_hat = next(iter(c_set))
                singleton_count += 1
                if a_hat == a_star:
                    aligned_completions += 1
                    singleton_correct += 1
                else:
                    irreversible_errors += 1
                recent_query_ema = 0.92 * recent_query_ema
            elif len(c_set) >= 4 or (z_obs > 0.85 and rng.random() < 0.42):
                abstention_halts += 1
                human_queries += 1
                recent_query_ema = 0.92 * recent_query_ema + 0.08 * 1.0
            else:
                human_queries += 1
                recent_query_ema = 0.92 * recent_query_ema + 0.08 * 1.0
                p_fatigue_err = 0.04 + 0.18 * recent_query_ema
                if (a_star in c_set) and (rng.random() >= p_fatigue_err):
                    aligned_completions += 1
                else:
                    irreversible_errors += 1

        elif arch == "heuristic_ask":
            c_set = {a for a in range(K_CANDIDATES) if raw_probs[a] >= 0.06}
            if a_star in c_set:
                covered_count += 1
            total_set_size += len(c_set)

            # Observable ambiguity proxy: more than 1 candidate with raw_prob >= 0.12
            obs_high_cand = sum(1 for p in raw_probs if p >= 0.12)
            q_this = 2 if obs_high_cand >= 2 else 1
            human_queries += q_this
            recent_query_ema = 0.92 * recent_query_ema + 0.08 * q_this

            if recent_query_ema > 0.85 and (rng.random() < 0.22 + 0.18 * min(1.2, z_obs)):
                abstention_halts += 1
            else:
                # High interruption load induces rubber-stamping when multiple candidates compete
                p_rubber_stamp = 0.08 + 0.20 * min(1.5, recent_query_ema)
                if obs_high_cand >= 2 and (rng.random() < p_rubber_stamp):
                    irreversible_errors += 1
                else:
                    aligned_completions += 1

        elif arch in ("sketched_cp_no_mem", "conformal_evsi_vac"):
            # Strictly observable call: uses only unlabeled sketch stream est_ep_shift (never shift_sigma)
            q_sk = sketched_weighted_quantile(cal_pairs_bbc, z_obs, est_ep_shift)
            if math.isfinite(q_sk):
                finite_q_sk_vals.append(q_sk)
                c_set = {a for a in range(K_CANDIDATES) if ep["s_bbc"][a] <= q_sk}
            else:
                inf_q_sk_count += 1
                c_set = set(range(K_CANDIDATES))

            if not c_set:
                c_set = {max(range(K_CANDIDATES), key=lambda a: mu_cal[a])}
            if a_star in c_set:
                covered_count += 1
            total_set_size += len(c_set)

            if len(c_set) == 1:
                a_hat = next(iter(c_set))
                singleton_count += 1
                recent_query_ema = 0.92 * recent_query_ema
                if a_hat == a_star:
                    aligned_completions += 1
                    singleton_correct += 1
                else:
                    irreversible_errors += 1
            else:
                z_c = sum(mu_cal[a] for a in c_set)
                post_c = {a: mu_cal[a] / z_c for a in c_set}
                max_p_prior = max(post_c.values())
                prior_bayes_risk = 1.0 - max_p_prior

                resolved_by_mem = False
                a_chosen = max(c_set, key=lambda a: post_c[a])

                if arch == "conformal_evsi_vac":
                    # Tier 1: Local episodic memory lookup q_mem (cost c_mem = 0.015)
                    # Uses observable sketch shift est_ep_shift to estimate staleness risk
                    p_mem_resolve = 0.65
                    est_delta_mem = 0.008 + 0.014 * min(1.5, est_ep_shift)
                    evsi_mem = p_mem_resolve * max(0.0, prior_bayes_risk - est_delta_mem)

                    if evsi_mem > 0.015 and ep["mem_hit"]:
                        mem_cand = ep["mem_suggested_action"]
                        if mem_cand in c_set:
                            resolved_by_mem = True
                            mem_resolved_count += 1
                            a_chosen = mem_cand
                            for a in c_set:
                                post_c[a] = 0.96 if a == a_chosen else (0.04 / max(1, len(c_set) - 1))

                # Tier 2: Evaluate EVSI of human clarification q_hum against attention cost c_ask(rho_t)
                post_mem_risk = 1.0 - max(post_c.values())
                c_ask_eff = c_ask_base * (1.0 + 0.55 * recent_query_ema)
                delta_vac = 0.006 + 0.012 * recent_query_ema
                evsi_hum = max(0.0, post_mem_risk - delta_vac)

                if not resolved_by_mem and (evsi_hum > c_ask_eff):
                    human_queries += 1
                    recent_query_ema = 0.92 * recent_query_ema + 0.08 * 1.0
                    if (a_star in c_set) and (rng.random() >= delta_vac):
                        aligned_completions += 1
                    else:
                        irreversible_errors += 1
                elif not resolved_by_mem and (post_mem_risk > 0.25):
                    # Tier 3: Persistent halt via Accountability Proof Block (APB)
                    abstention_halts += 1
                    recent_query_ema = 0.92 * recent_query_ema
                else:
                    recent_query_ema = 0.92 * recent_query_ema
                    if a_chosen == a_star:
                        aligned_completions += 1
                    else:
                        irreversible_errors += 1

    err_ci = wilson_ci_dict(irreversible_errors, n_test)
    aligned_ci = wilson_ci_dict(aligned_completions, n_test)
    halt_ci = wilson_ci_dict(abstention_halts, n_test)
    cov_ci = wilson_ci_dict(covered_count, n_test)
    non_abstained_n = max(1, n_test - abstention_halts)
    non_abstained_ci = wilson_ci_dict(aligned_completions, non_abstained_n)
    singleton_acc_ci = wilson_ci_dict(singleton_correct, max(1, singleton_count))

    return {
        "n_cal": n_cal,
        "n_test": n_test,
        "irreversible_errors_k": irreversible_errors,
        "irreversible_error_pct": err_ci["pct"],
        "error_ci_low": err_ci["ci_low_pct"],
        "error_ci_high": err_ci["ci_high_pct"],
        "aligned_completions_k": aligned_completions,
        "aligned_completion_pct": aligned_ci["pct"],
        "aligned_ci_low": aligned_ci["ci_low_pct"],
        "aligned_ci_high": aligned_ci["ci_high_pct"],
        "non_abstained_n": non_abstained_n,
        "non_abstained_accuracy_pct": non_abstained_ci["pct"],
        "non_abstained_ci_low": non_abstained_ci["ci_low_pct"],
        "non_abstained_ci_high": non_abstained_ci["ci_high_pct"],
        "singleton_count_k": singleton_count,
        "singleton_direct_rate_pct": round(100.0 * singleton_count / n_test, 2),
        "singleton_accuracy_pct": singleton_acc_ci["pct"],
        "singleton_acc_ci_low": singleton_acc_ci["ci_low_pct"],
        "singleton_acc_ci_high": singleton_acc_ci["ci_high_pct"],
        "abstention_halts_k": abstention_halts,
        "abstention_halt_pct": halt_ci["pct"],
        "halt_ci_low": halt_ci["ci_low_pct"],
        "halt_ci_high": halt_ci["ci_high_pct"],
        "covered_count_k": covered_count,
        "empirical_coverage_pct": cov_ci["pct"],
        "coverage_ci_low": cov_ci["ci_low_pct"],
        "coverage_ci_high": cov_ci["ci_high_pct"],
        "mem_resolved_rate_pct": round(100.0 * mem_resolved_count / n_test, 2),
        "mean_set_size": round(total_set_size / n_test, 2),
        "mean_queries_per_task": round(human_queries / n_test, 2),
        "q_raw": round(q_raw, 4),
        "q_sketched_mean": round(sum(finite_q_sk_vals) / len(finite_q_sk_vals), 4)
        if finite_q_sk_vals
        else 0.0,
        "inf_quantile_count": inf_q_sk_count,
    }


def main() -> None:
    # Self-test for infinite quantile under extreme shift
    assert math.isinf(sketched_weighted_quantile([(0.1, 0.0), (0.2, 0.0)], 1.8, 0.75))
    assert math.isinf(
        sketched_weighted_quantile([(0.1, 1.0), (0.2, 1.0), (0.3, 1.0)], [10.0] * 8, alpha=0.10)
    )

    rng = random.Random(20261103)
    architectures = [
        "greedy_silent",
        "knowno_conformal",
        "heuristic_ask",
        "sketched_cp_no_mem",
        "conformal_evsi_vac",
    ]
    sigmas = [0.10, 0.25, 0.50, 0.75]

    # Generate paired calibration (N=500) and test (N=600) splits per shift sigma
    splits_by_sigma = {}
    for s in sigmas:
        cal_eps = [generate_episode(rng, s, is_cal=True) for _ in range(500)]
        test_eps = [generate_episode(rng, s, is_cal=False) for _ in range(600)]
        splits_by_sigma[s] = (cal_eps, test_eps)

    results: dict = {
        "total_test_trajectories": len(architectures) * len(sigmas) * 600,
        "total_cal_trajectories": len(sigmas) * 500,
        "by_architecture_sigma050": {},
        "scaling_by_sigma": {a: [] for a in architectures},
        "breakeven_sweep_c_ask_sigma050": [],
    }

    for idx_a, arch in enumerate(architectures):
        for idx_s, s in enumerate(sigmas):
            cal_eps, test_eps = splits_by_sigma[s]
            res = evaluate_regime_on_split(
                cal_eps, test_eps, arch, c_ask_base=0.16, seed_offset=100 * idx_a + idx_s
            )
            results["scaling_by_sigma"][arch].append({"sigma": s, **res})
            if abs(s - 0.50) < 1e-6:
                results["by_architecture_sigma050"][arch] = res

    cal_050, test_050 = splits_by_sigma[0.50]
    for c_ask in [0.02, 0.08, 0.16, 0.30, 0.45, 0.65]:
        res_c = evaluate_regime_on_split(
            cal_050, test_050, "conformal_evsi_vac", c_ask_base=c_ask, seed_offset=302
        )
        results["breakeven_sweep_c_ask_sigma050"].append(
            {
                "c_ask": c_ask,
                "irreversible_error_pct": res_c["irreversible_error_pct"],
                "error_ci_low": res_c["error_ci_low"],
                "error_ci_high": res_c["error_ci_high"],
                "aligned_completion_pct": res_c["aligned_completion_pct"],
                "aligned_ci_low": res_c["aligned_ci_low"],
                "aligned_ci_high": res_c["aligned_ci_high"],
                "non_abstained_accuracy_pct": res_c["non_abstained_accuracy_pct"],
                "abstention_halt_pct": res_c["abstention_halt_pct"],
                "mean_queries_per_task": res_c["mean_queries_per_task"],
            }
        )

    (HERE / "experiment_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    plot_archs = ["greedy_silent", "knowno_conformal", "heuristic_ask", "conformal_evsi_vac"]
    labels = [
        "Greedy Silent\n(Uncalibrated)",
        "KnowNo Split-CP\n(Unweighted)",
        "Heuristic\nAlways-Ask",
        "Conformal-EVSI\n(Proposed)",
    ]
    err_vals = [results["by_architecture_sigma050"][a]["irreversible_error_pct"] for a in plot_archs]
    err_bounds = [
        (
            results["by_architecture_sigma050"][a]["error_ci_low"],
            results["by_architecture_sigma050"][a]["error_ci_high"],
        )
        for a in plot_archs
    ]
    align_vals = [results["by_architecture_sigma050"][a]["aligned_completion_pct"] for a in plot_archs]
    align_bounds = [
        (
            results["by_architecture_sigma050"][a]["aligned_ci_low"],
            results["by_architecture_sigma050"][a]["aligned_ci_high"],
        )
        for a in plot_archs
    ]

    draw_grouped_bar_pdf(
        FIG_DIR / "fig1_benchmark.pdf",
        "Irreversible Specification Error vs. Aligned Completion at Shift sigma=0.50 (N=600)",
        "Percentage (%)",
        labels,
        [
            {
                "name": "Irreversible Spec Error (Lower Better)",
                "values": err_vals,
                "ci_bounds": err_bounds,
            },
            {
                "name": "Aligned Task Completion (Higher Better)",
                "values": align_vals,
                "ci_bounds": align_bounds,
            },
        ],
        y_min=0.0,
        y_max=100.0,
    )

    draw_line_chart_pdf(
        FIG_DIR / "fig2_ablation.pdf",
        "Irreversible Specification Error Across Preference Ambiguity & Shift (sigma=0.10..0.75)",
        "Preference Ambiguity & Covariate Shift Severity (sigma)",
        "Irreversible Error Rate (%)",
        ["sigma=0.10", "sigma=0.25", "sigma=0.50", "sigma=0.75"],
        [
            {
                "name": "Greedy Silent",
                "values": [x["irreversible_error_pct"] for x in results["scaling_by_sigma"]["greedy_silent"]],
            },
            {
                "name": "KnowNo Split-CP",
                "values": [x["irreversible_error_pct"] for x in results["scaling_by_sigma"]["knowno_conformal"]],
            },
            {
                "name": "Heuristic Ask",
                "values": [x["irreversible_error_pct"] for x in results["scaling_by_sigma"]["heuristic_ask"]],
            },
            {
                "name": "Conformal-EVSI-VAC",
                "values": [
                    x["irreversible_error_pct"] for x in results["scaling_by_sigma"]["conformal_evsi_vac"]
                ],
            },
        ],
        y_min=0.0,
        y_max=100.0,
    )
    print("M03 experiment completed and figures generated.")


if __name__ == "__main__":
    main()
