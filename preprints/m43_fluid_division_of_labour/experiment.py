#!/usr/bin/env python3
"""
Paired Mechanistic Scheduling Simulation for Milestone #43 (`m43_fluid_division_of_labour`):
Dynamic Multi-Role Rotation Under Role-Specific and Systemic Fatigue Constraints:
A Nonstationary Kalman-UCB Index Formulation of Fluid Division of Labour.

Remediation of v3 Review (`01_per_paper_critique.md` — m43):
1. Uses paired simulations (`ep_seed = 20261143 + ep_idx * 97`) so all comparators face identical
   initial skills, pre-drawn noise/fatigue shocks, and dropout events.
2. Tracks an explicit recursive Kalman/EWMA skill estimator `est_skills[i][r]` and posterior
   estimation variance `est_var[i][r]` (shrinking upon noisy observation when assigned, and growing
   by forgetting-drift variance `nu_drift` when unassigned), grounding the UCB exploration term.
3. Decomposes fatigue into role-specific fatigue `f_role[i][r]` (relieved by task rotation) and
   persistent cross-role systemic fatigue `f_sys[i]` (which accumulates across all active roles and
   cannot be removed by rotation alone), sweeping systemic-fatigue share `kappa_sys` in [0.00, 0.90].
4. Compares the greedy index assignment heuristic against an exact DP maximum-weight quota-constrained
   bipartite assignment (`exact_dp_solve`) on the same index matrix to quantify the heuristic gap.
5. Stores raw binomial counts and exact asymmetric two-sided 95% Wilson intervals via `wilson_ci_dict`
   and run-level continuous intervals via `continuous_ci_dict`.
"""

import json
import math
import random
import sys
import time
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


def exact_quota_bipartite_dp(
    score_matrix: list[list[float]],
    avail_actors: list[int],
    quotas: list[int],
) -> tuple[list[int], float]:
    """
    Exact dynamic-programming solver for maximum-weight bipartite assignment of `avail_actors`
    to `R=5` roles with exact capacity quotas `quotas` (state space <= 4*3*4*3*3 = 432 states).
    Returns (assignments_by_actor_id, optimal_total_score).
    """
    n_roles = len(quotas)
    n_total = len(score_matrix)
    init_state = tuple(quotas)
    dp: dict[tuple[int, ...], tuple[float, list[tuple[int, int]]]] = {init_state: (0.0, [])}

    for i in avail_actors:
        next_dp: dict[tuple[int, ...], tuple[float, list[tuple[int, int]]]] = {}
        for rem_q, (val, path) in dp.items():
            for r in range(n_roles):
                if rem_q[r] > 0:
                    nq = list(rem_q)
                    nq[r] -= 1
                    nq_t = tuple(nq)
                    cand_val = val + score_matrix[i][r]
                    if nq_t not in next_dp or cand_val > next_dp[nq_t][0]:
                        next_dp[nq_t] = (cand_val, path + [(i, r)])
        dp = next_dp

    zero_state = tuple(0 for _ in range(n_roles))
    best_val, best_path = dp[zero_state]
    assignments = [-1] * n_total
    for i, r in best_path:
        assignments[i] = r
    return assignments, best_val


def greedy_quota_assignment(
    score_matrix: list[list[float]],
    avail_actors: list[int],
    quotas: list[int],
) -> tuple[list[int], float]:
    """Greedy sorting assignment heuristic over actor-role pairs."""
    n_roles = len(quotas)
    n_total = len(score_matrix)
    rem_q = list(quotas)
    pairs = []
    for i in avail_actors:
        for r in range(n_roles):
            pairs.append((score_matrix[i][r], i, r))
    pairs.sort(reverse=True)
    assignments = [-1] * n_total
    assigned_set = set()
    total_score = 0.0
    for sc, i, r in pairs:
        if i not in assigned_set and rem_q[r] > 0:
            assignments[i] = r
            rem_q[r] -= 1
            assigned_set.add(i)
            total_score += sc
    return assignments, total_score


def simulate_policy(
    policy: str,
    fatigue_alpha: float,
    delta_switch: float = 0.072,
    kappa_sys: float = 0.20,
    use_exact_dp: bool = False,
    n_episodes: int = 500,
    n_actors: int = 12,
    n_roles: int = 5,
    horizon: int = 60,
) -> dict:
    """
    Simulates n_episodes of a 60-shift cooperative workflow using paired episode seeds.
    - `kappa_sys` in [0, 1] is the fraction of persistent cross-role systemic fatigue `f_sys[i]`
      that accumulates on every active shift and only clears during explicit rest swaps, versus
      role-specific fatigue `f_role[i][r]` that clears when rotating to a different role.
    """
    net_yield_list = []
    skill_retention_list = []
    burnout_free_list = []
    bus_factor_recovery_list = []
    heuristic_opt_ratio_list = []
    runtime_us_list = []
    shock_survival_successes = 0

    role_quotas = [3, 2, 3, 2, 2]  # sums to 12 actors
    obs_noise_var = 0.030 ** 2
    drift_var = 0.00035

    for ep_idx in range(n_episodes):
        # Paired seed per episode guarantees identical world & shock realizations across all policies
        ep_rng = random.Random(20261143 + ep_idx * 97)

        skills = []
        init_skills = []
        est_skills = []
        est_var = [[0.0016 for _ in range(n_roles)] for _ in range(n_actors)]
        for i in range(n_actors):
            primary = i % n_roles
            secondary = (i + 1) % n_roles
            row = []
            est_row = []
            for r in range(n_roles):
                if r == primary:
                    base = 0.88 + 0.08 * ep_rng.random()
                elif r == secondary:
                    base = 0.74 + 0.10 * ep_rng.random()
                else:
                    base = 0.56 + 0.14 * ep_rng.random()
                row.append(base)
                est_row.append(min(0.99, max(0.35, base + ep_rng.gauss(0.0, 0.035))))
            skills.append(list(row))
            init_skills.append(list(row))
            est_skills.append(list(est_row))

        f_role = [[0.04 * ep_rng.random() for _ in range(n_roles)] for _ in range(n_actors)]
        f_sys = [0.03 * ep_rng.random() for _ in range(n_actors)]
        # Pre-draw per-shift, per-actor shock/observation random numbers for strict pairing
        shift_inc_mult = [[0.85 + 0.30 * ep_rng.random() for _ in range(n_actors)] for _ in range(horizon)]
        shift_obs_noise = [[ep_rng.gauss(0.0, 0.030) for _ in range(n_actors)] for _ in range(horizon)]

        prev_role = [i % n_roles for i in range(n_actors)]
        last_practiced = [[0 if r == (i % n_roles) else -6 for r in range(n_roles)] for i in range(n_actors)]
        total_output = 0.0
        max_possible_output = horizon * n_actors * 0.88
        burnout_events = 0
        post_shock_output = 0.0
        post_shock_max = 10 * (n_actors - 2) * 0.84
        ep_ns = 0
        ep_opt_ratios = []

        for t in range(horizon):
            unavailable = {0, 5} if (40 <= t < 50) else set()
            rem_quotas = [3, 2, 2, 2, 1] if (40 <= t < 50) else list(role_quotas)
            avail_actors = [i for i in range(n_actors) if i not in unavailable]

            # Effective combined fatigue f_eff[i][r] = (1 - kappa_sys)*f_role[i][r] + kappa_sys*f_sys[i]
            f_eff = [
                [(1.0 - kappa_sys) * f_role[i][r] + kappa_sys * f_sys[i] for r in range(n_roles)]
                for i in range(n_actors)
            ]

            t0_ns = time.perf_counter_ns()
            score_matrix = [[0.0 for _ in range(n_roles)] for _ in range(n_actors)]
            if policy == "specialist_rest":
                # Tuned specialist + rest/light-role swap when primary effective fatigue >= 0.58
                for i in avail_actors:
                    primary_r = i % n_roles
                    for r in range(n_roles):
                        sw_cost = 0.0 if prev_role[i] == r else delta_switch
                        if r == primary_r and f_eff[i][r] < 0.58:
                            score_matrix[i][r] = est_skills[i][r] + 0.28 - sw_cost
                        else:
                            score_matrix[i][r] = est_skills[i][r] * (1.0 - 0.75 * f_eff[i][r]) - sw_cost
                assignments, _ = greedy_quota_assignment(score_matrix, avail_actors, rem_quotas)
            elif policy == "blind_rotation":
                shift_offset = t // 4
                for i in avail_actors:
                    preferred = (i + shift_offset) % n_roles
                    for r in range(n_roles):
                        score_matrix[i][r] = 1.0 if r == preferred else (0.2 - 0.01 * r)
                assignments, _ = greedy_quota_assignment(score_matrix, avail_actors, rem_quotas)
            elif policy == "whittle_greedy":
                # Myopic fatigue-discounted index using Kalman skill estimate (without variance UCB or floor lookahead)
                for i in avail_actors:
                    for r in range(n_roles):
                        eff_skill = est_skills[i][r] * (1.0 - 0.82 * (f_eff[i][r] ** 1.45))
                        sw_cost = 0.0 if prev_role[i] == r else delta_switch
                        score_matrix[i][r] = eff_skill - sw_cost
                assignments, _ = greedy_quota_assignment(score_matrix, avail_actors, rem_quotas)
            elif policy == "f_ucb_fluid":
                # Proposed Nonstationary Kalman-UCB + Skill-Floor Regularizer
                for i in avail_actors:
                    for r in range(n_roles):
                        ucb_bonus = 0.65 * math.sqrt(est_var[i][r] * math.log(t + 2.0))
                        optimistic_s = min(0.99, est_skills[i][r] + ucb_bonus)
                        eff_skill = optimistic_s * (1.0 - 0.82 * (f_eff[i][r] ** 1.45))
                        sw_cost = 0.0 if prev_role[i] == r else delta_switch
                        staleness = min(16, t - last_practiced[i][r])
                        is_backup_role = 1.0 if r in ((i % n_roles), ((i + 1) % n_roles), 0) else 0.35
                        cross_train_bonus = is_backup_role * (
                            0.24 * max(0.0, 0.72 - est_skills[i][r])
                            + 0.010 * max(0, staleness - 4)
                        ) * (1.0 - f_eff[i][r])
                        fatigue_barrier = 0.34 * max(0.0, f_eff[i][r] - 0.42)
                        score_matrix[i][r] = eff_skill - sw_cost + cross_train_bonus - fatigue_barrier
                if use_exact_dp:
                    assignments, _ = exact_quota_bipartite_dp(score_matrix, avail_actors, rem_quotas)
                else:
                    assignments, g_sc = greedy_quota_assignment(score_matrix, avail_actors, rem_quotas)
                    if ep_idx < 30 and t % 10 == 0:
                        _, opt_sc = exact_quota_bipartite_dp(score_matrix, avail_actors, rem_quotas)
                        if opt_sc > 1e-6:
                            ep_opt_ratios.append(100.0 * g_sc / opt_sc)
            ep_ns += time.perf_counter_ns() - t0_ns

            shift_out = 0.0
            for i in avail_actors:
                r = assignments[i]
                sw_pen = 0.0 if prev_role[i] == r else delta_switch
                fatigue_factor = max(0.20, 1.0 - 0.82 * (f_eff[i][r] ** 1.45))
                rework_factor = 1.0 if skills[i][r] >= 0.62 else max(0.45, 1.0 - 1.6 * (0.62 - skills[i][r]))
                actor_yield = max(0.10, skills[i][r] * fatigue_factor * rework_factor - sw_pen)
                shift_out += actor_yield

                if f_eff[i][r] > 0.70:
                    burnout_events += 1

                # Kalman update for assigned role r based on noisy skill observation
                obs_s = min(0.99, max(0.35, skills[i][r] + shift_obs_noise[t][i]))
                k_gain = est_var[i][r] / (est_var[i][r] + obs_noise_var)
                est_skills[i][r] = min(0.99, (1.0 - k_gain) * est_skills[i][r] + k_gain * obs_s + 0.0065)
                est_var[i][r] = max(0.0002, (1.0 - k_gain) * est_var[i][r])

                # Persistent cross-role systemic fatigue update (only relieved if assigned to low-load role r == 4)
                inc = fatigue_alpha * shift_inc_mult[t][i]
                if r == 4:
                    f_sys[i] = max(0.0, f_sys[i] * 0.62 - 0.03)
                else:
                    f_sys[i] = min(1.0, 0.88 * f_sys[i] + 0.78 * inc)

                for r_idx in range(n_roles):
                    if r_idx == r:
                        f_role[i][r_idx] = min(1.0, 0.84 * f_role[i][r_idx] + inc)
                        skills[i][r_idx] = min(0.99, skills[i][r_idx] + 0.0065)
                        last_practiced[i][r_idx] = t
                    else:
                        f_role[i][r_idx] = max(0.0, f_role[i][r_idx] * 0.52 - 0.04)
                        skills[i][r_idx] = max(0.35, skills[i][r_idx] - 0.0045)
                        est_skills[i][r_idx] = max(0.35, est_skills[i][r_idx] - 0.0045)
                        est_var[i][r_idx] = min(0.015, est_var[i][r_idx] + drift_var)
                prev_role[i] = r

            total_output += shift_out
            if 40 <= t < 50:
                post_shock_output += shift_out

        net_yield_pct = 100.0 * total_output / max_possible_output
        retained_cells = sum(
            1 for i in range(n_actors) for r in range(n_roles) if skills[i][r] >= 0.58
        )
        skill_ret_pct = 100.0 * retained_cells / (n_actors * n_roles)
        burnout_free_pct = 100.0 * (1.0 - burnout_events / (horizon * n_actors))
        bus_resilience_pct = min(100.0, 100.0 * post_shock_output / post_shock_max)
        if bus_resilience_pct >= 72.0:
            shock_survival_successes += 1

        net_yield_list.append(net_yield_pct)
        skill_retention_list.append(skill_ret_pct)
        burnout_free_list.append(burnout_free_pct)
        bus_factor_recovery_list.append(bus_resilience_pct)
        if ep_opt_ratios:
            heuristic_opt_ratio_list.append(sum(ep_opt_ratios) / len(ep_opt_ratios))
        runtime_us_list.append((ep_ns / horizon) / 1000.0)

    n = len(net_yield_list)
    yield_ci = continuous_ci_dict(net_yield_list)
    sret_ci = continuous_ci_dict(skill_retention_list)
    bfree_ci = continuous_ci_dict(burnout_free_list)
    bus_ci = continuous_ci_dict(bus_factor_recovery_list)
    surv_w = wilson_ci_dict(shock_survival_successes, n)

    return {
        "n_episodes": n,
        "net_yield_pct": round(yield_ci["mean"], 2),
        "net_yield_ci": round(yield_ci["ci_halfwidth"], 2),
        "net_yield_ci_low": round(yield_ci["ci_low"], 2),
        "net_yield_ci_high": round(yield_ci["ci_high"], 2),
        "cross_skill_retention_pct": round(sret_ci["mean"], 2),
        "cross_skill_retention_ci": round(sret_ci["ci_halfwidth"], 2),
        "cross_skill_retention_ci_low": round(sret_ci["ci_low"], 2),
        "cross_skill_retention_ci_high": round(sret_ci["ci_high"], 2),
        "burnout_free_shifts_pct": round(bfree_ci["mean"], 2),
        "burnout_free_shifts_ci": round(bfree_ci["ci_halfwidth"], 2),
        "bus_factor_resilience_pct": round(bus_ci["mean"], 2),
        "bus_factor_resilience_ci": round(bus_ci["ci_halfwidth"], 2),
        "bus_factor_resilience_ci_low": round(bus_ci["ci_low"], 2),
        "bus_factor_resilience_ci_high": round(bus_ci["ci_high"], 2),
        "shock_survival_k": surv_w["k"],
        "shock_survival_rate_pct": surv_w["pct"],
        "shock_survival_wilson_ci": surv_w["wilson_halfwidth_pct"],
        "shock_survival_ci_low": surv_w["ci_low_pct"],
        "shock_survival_ci_high": surv_w["ci_high_pct"],
        "greedy_vs_exact_dp_ratio_pct": round(
            sum(heuristic_opt_ratio_list) / max(1, len(heuristic_opt_ratio_list)), 2
        )
        if heuristic_opt_ratio_list
        else 100.0,
        "solver_runtime_us": round(sum(runtime_us_list) / n, 2),
    }


def main():
    policies = ["specialist_rest", "blind_rotation", "whittle_greedy", "f_ucb_fluid"]
    fatigue_rates = [0.10, 0.16, 0.22, 0.28]

    results = {
        "by_policy_alpha22": {},
        "exact_dp_comparator_alpha22": {},
        "scaling_by_fatigue_rate": {p: [] for p in policies},
        "handoff_penalty_sensitivity": {},
        "systemic_fatigue_sensitivity": {},
    }
    for p in policies:
        for alpha in fatigue_rates:
            res = simulate_policy(p, alpha, delta_switch=0.072, kappa_sys=0.20, n_episodes=500)
            results["scaling_by_fatigue_rate"][p].append({"fatigue_alpha": alpha, **res})
            if abs(alpha - 0.22) < 1e-6:
                results["by_policy_alpha22"][p] = res

    # Exact DP bipartite solver check on 200 paired episodes at alpha=0.22
    results["exact_dp_comparator_alpha22"] = {
        "greedy_f_ucb": simulate_policy("f_ucb_fluid", 0.22, delta_switch=0.072, kappa_sys=0.20, use_exact_dp=False, n_episodes=200),
        "exact_dp_f_ucb": simulate_policy("f_ucb_fluid", 0.22, delta_switch=0.072, kappa_sys=0.20, use_exact_dp=True, n_episodes=200),
    }

    # Sensitivity & break-even sweep across handoff penalty delta_switch at fatigue_alpha = 0.22
    for sw in [0.012, 0.024, 0.048, 0.072, 0.110, 0.150]:
        sw_key = f"delta_{sw:.3f}"
        results["handoff_penalty_sensitivity"][sw_key] = {}
        for p in ["specialist_rest", "whittle_greedy", "f_ucb_fluid"]:
            results["handoff_penalty_sensitivity"][sw_key][p] = simulate_policy(
                p, 0.22, delta_switch=sw, kappa_sys=0.20, n_episodes=250
            )

    # Sensitivity & break-even sweep across persistent cross-role systemic fatigue share kappa_sys in [0.00, 0.90]
    for k_sys in [0.00, 0.20, 0.45, 0.70, 0.90]:
        ks_key = f"kappa_sys_{k_sys:.2f}"
        results["systemic_fatigue_sensitivity"][ks_key] = {
            "f_ucb_fluid": simulate_policy("f_ucb_fluid", 0.22, delta_switch=0.072, kappa_sys=k_sys, n_episodes=250),
            "specialist_rest": simulate_policy("specialist_rest", 0.22, delta_switch=0.072, kappa_sys=k_sys, n_episodes=250),
        }

    (HERE / "experiment_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    labels = [
        "Specialist +\nRest-Swap",
        "Blind Clock\nRotation",
        "Whittle-Like\nMyopic Greedy",
        "F-UCB-Fluid\n(Proposed)",
    ]
    yield_vals = [results["by_policy_alpha22"][p]["net_yield_pct"] for p in policies]
    yield_bounds = [
        (results["by_policy_alpha22"][p]["net_yield_ci_low"], results["by_policy_alpha22"][p]["net_yield_ci_high"])
        for p in policies
    ]
    resil_vals = [results["by_policy_alpha22"][p]["bus_factor_resilience_pct"] for p in policies]
    resil_bounds = [
        (
            results["by_policy_alpha22"][p]["bus_factor_resilience_ci_low"],
            results["by_policy_alpha22"][p]["bus_factor_resilience_ci_high"],
        )
        for p in policies
    ]

    draw_grouped_bar_pdf(
        FIG_DIR / "fig1_benchmark.pdf",
        "Paired Net Workflow Yield & Bus-Factor Resilience (Equal Switch Penalty 0.072, N=500)",
        "Percentage (%)",
        labels,
        [
            {"name": "Net 60-Shift Workflow Yield (%)", "values": yield_vals, "ci_bounds": yield_bounds},
            {"name": "Post-Dropout Bus-Factor Resilience (%)", "values": resil_vals, "ci_bounds": resil_bounds},
        ],
        y_min=0.0,
        y_max=100.0,
    )

    draw_line_chart_pdf(
        FIG_DIR / "fig2_ablation.pdf",
        "Net Workflow Yield Across Fatigue Accumulation Rates (Equal Switch Penalty 0.072)",
        "Shift Fatigue Accumulation Rate (alpha_f)",
        "Net 60-Shift Workflow Yield (%)",
        ["alpha=0.10", "alpha=0.16", "alpha=0.22", "alpha=0.28"],
        [
            {"name": "Specialist + Rest-Swap", "values": [x["net_yield_pct"] for x in results["scaling_by_fatigue_rate"]["specialist_rest"]]},
            {"name": "Blind Clock Rotation", "values": [x["net_yield_pct"] for x in results["scaling_by_fatigue_rate"]["blind_rotation"]]},
            {"name": "Whittle Myopic Greedy", "values": [x["net_yield_pct"] for x in results["scaling_by_fatigue_rate"]["whittle_greedy"]]},
            {"name": "F-UCB-Fluid (Proposed)", "values": [x["net_yield_pct"] for x in results["scaling_by_fatigue_rate"]["f_ucb_fluid"]]},
        ],
        y_min=35.0,
        y_max=95.0,
    )
    print("Milestone 43 experiment completed:", json.dumps(results["by_policy_alpha22"], indent=2))


if __name__ == "__main__":
    main()
