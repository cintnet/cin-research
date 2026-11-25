#!/usr/bin/env python3
"""
Discrete-Event Packet-Loss, Head-of-Line (HoL) Blocking, and Dual-Plane QUIC Simulator
for Milestone #10 (`m10_second_internet_quic_fabric`):
Dual-Plane Agent Transport Over IETF QUIC Streams and Unreliable Datagrams:
Eliminating Head-of-Line Blocking in Peer-to-Peer State Sync.

Executes a mechanistic discrete-event packet-transmission, retransmission, and Age-of-Information (AoI)
simulator across N = 600 multi-agent synchronization bursts per cell (2,400 bursts at the primary G=8
benchmark; 9,600 total across G in {2, 4, 8, 16} parallel sub-agent streams), plus:
  - A 2x2 factorial ablation at G=8 separating payload representation (Verbose JSON vs. Compact VQ-Coded)
    from transport multiplexing (Single-Stream TCP vs. Dual-Plane QUIC), ensuring identical packetization
    and per-packet drop probability p_loss = 0.015 across transport comparisons.
  - A break-even packet-loss sensitivity sweep across p_loss in {0.05%, 0.25%, 0.50%, 1.50%, 3.00%, 5.00%}.
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
from vector_pdf_plots import draw_grouped_bar_pdf, draw_line_chart_pdf, wilson_ci_dict, continuous_ci_dict

FIG_DIR = HERE / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)

SLO_THRESHOLD_MS = 65.0
TIMEOUT_CAP_MS = 200.0
INITIAL_CWND_PKTS = 10
BASE_RTT_MS = 24.0
BEACON_INTERVAL_MS = 8.0
LAMBDA_MUTATION_PER_MS = 0.0042  # Context mutation Poisson rate (4.2 mutations/sec)


def draw_packet_retransmissions(t_rng: random.Random, p_loss: float, bursty: bool, ge_state: list[int]) -> int:
    """
    Draws the number of retransmission rounds for a single packet under either:
      - Independent Bernoulli loss (`bursty=False`, drop prob `p_loss`)
      - Gilbert-Elliott 2-state Markov bursty channel (`bursty=True`, Good state 0 vs Bad burst state 1)
    """
    r_cnt = 0
    while True:
        if not bursty:
            dropped = t_rng.random() < p_loss
        else:
            # Transition Markov state: p(G->B)=0.012, p(B->G)=0.35 (stationary P(B) = 0.012/0.362 = 3.31%)
            if ge_state[0] == 0:
                if t_rng.random() < 0.012:
                    ge_state[0] = 1
            else:
                if t_rng.random() < 0.35:
                    ge_state[0] = 0
            p_curr = 0.002 if ge_state[0] == 0 else 0.40
            dropped = t_rng.random() < p_curr
        if not dropped:
            break
        r_cnt += 1
    return r_cnt


def simulate_burst_discrete_event(
    rng: random.Random,
    transport_mode: str,
    payload_mode: str,
    stream_fanout: int,
    p_loss: float = 0.015,
    n_trials: int = 600,
    bursty_ge: bool = False,
) -> dict:
    """
    Discrete-event packet transmission, congestion-window (cwnd=10), and HoL queue simulator
    over `stream_fanout` G parallel sub-agent streams.
    """
    slo_met = 0
    timeout_censored = 0
    drift_events = 0
    latencies: list[float] = []
    aoi_values: list[float] = []

    pkts_per_rpc = 5 if payload_mode == "verbose_json" else 2
    serialization_ms = 2.6 if payload_mode == "verbose_json" else 0.9

    for trial_idx in range(n_trials):
        # Paired trial RNG so transport comparisons see identical RTT, handshake events, and wire loss draws
        t_rng = random.Random(910000 + stream_fanout * 10000 + trial_idx + (500000 if bursty_ge else 0))
        rtt = max(12.0, t_rng.gauss(BASE_RTT_MS, 2.8))
        one_way = 0.5 * rtt

        # 1. Handshake state machine latency
        u_hs = t_rng.random()
        if transport_mode == "tcp_tls_single":
            # 22% of cross-edge bursts require a fresh TCP + TLS 1.3 handshake (2 RTTs); 78% reuse socket
            is_cold = u_hs < 0.22
            hs_ms = 2.0 * rtt if is_cold else 0.0
            crypto_cpu_ms = 0.45
        else:
            # QUIC 0-RTT session resumption succeeds on 82% of bursts; 18% fall back to 1-RTT
            is_1rtt = u_hs < 0.18
            hs_ms = 1.0 * rtt if is_1rtt else 0.0
            # Userspace UDP/AEAD + strike-register Bloom check overhead
            crypto_cpu_ms = 1.15

        # Pre-draw packet loss outcomes across G streams and 6 periodic telemetry beacon ticks
        ge_state = [0]
        stream_losses = []
        for _g in range(stream_fanout):
            pkt_rounds = []
            for _p in range(pkts_per_rpc):
                pkt_rounds.append(draw_packet_retransmissions(t_rng, p_loss, bursty_ge, ge_state))
            stream_losses.append(pkt_rounds)

        beacon_losses = []
        for _b in range(6):
            beacon_losses.append(draw_packet_retransmissions(t_rng, p_loss, bursty_ge, ge_state))

        total_rpc_pkts = stream_fanout * pkts_per_rpc
        # Explicit RFC 6928 / RFC 9002 initial congestion window (cwnd = 10) pacing delay when burst > cwnd
        cwnd_overflow_pkts = max(0, total_rpc_pkts - INITIAL_CWND_PKTS)
        cwnd_pacing_ms = 0.32 * cwnd_overflow_pkts

        # 2. Discrete-event packet transmission across G parallel sub-tasks
        if transport_mode == "tcp_tls_single":
            total_pkts = total_rpc_pkts + 6
            hol_accum_delay = 0.0
            flat_rounds = [r for s in stream_losses for r in s] + beacon_losses
            for pkt_idx, rounds in enumerate(flat_rounds):
                if rounds > 0:
                    hol_accum_delay += rounds * rtt * (0.55 + 0.45 * ((total_pkts - pkt_idx) / total_pkts))
            pacing_ms = 0.28 * total_pkts + cwnd_pacing_ms
            burst_completion_ms = hs_ms + crypto_cpu_ms + serialization_ms + one_way + pacing_ms + hol_accum_delay
            beacon_aoi_ms = one_way + 0.5 * BEACON_INTERVAL_MS + 0.85 * hol_accum_delay + 0.45 * pacing_ms

        elif transport_mode == "quic_streams_only":
            stream_finish_times: list[float] = []
            for g_idx in range(stream_fanout):
                stream_retrans_delay = sum(r * rtt for r in stream_losses[g_idx])
                stream_finish_times.append(one_way + 0.22 * pkts_per_rpc + 0.5 * cwnd_pacing_ms + stream_retrans_delay)

            beacon_hol_delay = sum(b_r * rtt for b_r in beacon_losses)
            burst_completion_ms = (
                hs_ms + crypto_cpu_ms + serialization_ms + max(stream_finish_times) + 0.35 * beacon_hol_delay
            )
            beacon_aoi_ms = one_way + 0.5 * BEACON_INTERVAL_MS + 0.80 * beacon_hol_delay + 0.15 * max(stream_finish_times)

        else:  # transport_mode == "quic_dual_plane"
            stream_finish_times = []
            for g_idx in range(stream_fanout):
                stream_retrans_delay = sum(r * rtt for r in stream_losses[g_idx])
                stream_finish_times.append(one_way + 0.22 * pkts_per_rpc + 0.5 * cwnd_pacing_ms + stream_retrans_delay)

            missed_last = beacon_losses[-1]
            beacon_aoi_ms = one_way + (missed_last + 0.5) * BEACON_INTERVAL_MS
            burst_completion_ms = hs_ms + crypto_cpu_ms + serialization_ms + max(stream_finish_times)

        latencies.append(burst_completion_ms)
        aoi_values.append(beacon_aoi_ms)
        if burst_completion_ms <= SLO_THRESHOLD_MS:
            slo_met += 1
        if burst_completion_ms > TIMEOUT_CAP_MS:
            timeout_censored += 1

        # Context drift occurs if a peer state mutation arrives during the stale AoI window [0, beacon_aoi_ms]
        p_drift_realized = 1.0 - math.exp(-LAMBDA_MUTATION_PER_MS * beacon_aoi_ms)
        if rng.random() < p_drift_realized:
            drift_events += 1

    latencies.sort()
    p50_ms = latencies[n_trials // 2]
    p99_idx = min(n_trials - 1, int(0.99 * n_trials))
    p99_ms = latencies[p99_idx]
    lat_stats = continuous_ci_dict(latencies)
    aoi_stats = continuous_ci_dict(aoi_values)
    slo_stats = wilson_ci_dict(slo_met, n_trials)
    drf_stats = wilson_ci_dict(drift_events, n_trials)
    censor_stats = wilson_ci_dict(timeout_censored, n_trials)

    return {
        "n_trials": n_trials,
        "slo_met_k": slo_met,
        "slo_compliance_pct": slo_stats["pct"],
        "slo_ci": slo_stats["wilson_halfwidth_pct"],
        "slo_ci_low": slo_stats["ci_low_pct"],
        "slo_ci_high": slo_stats["ci_high_pct"],
        "drift_events_k": drift_events,
        "context_drift_pct": drf_stats["pct"],
        "drift_ci": drf_stats["wilson_halfwidth_pct"],
        "drift_ci_low": drf_stats["ci_low_pct"],
        "drift_ci_high": drf_stats["ci_high_pct"],
        "timeout_censored_pct": censor_stats["pct"],
        "mean_latency_ms": round(lat_stats["mean"], 2),
        "p50_latency_ms": round(p50_ms, 2),
        "p99_latency_ms": round(p99_ms, 2),
        "mean_beacon_aoi_ms": round(aoi_stats["mean"], 2),
    }


def main() -> None:
    rng = random.Random(2026110810)
    architectures = [
        ("http11_json_rest", "tcp_tls_single", "verbose_json"),
        ("grpc_http2_tcp", "tcp_tls_single", "compact_vq"),
        ("quic_streams_only", "quic_streams_only", "compact_vq"),
        ("dual_plane_quic_dgram", "quic_dual_plane", "compact_vq"),
    ]
    fanouts = [2, 4, 8, 16]
    n_per_cell = 600

    results: dict = {
        "trial_accounting": {
            "n_bursts_per_cell": n_per_cell,
            "num_architectures": len(architectures),
            "num_fanouts": len(fanouts),
            "g8_benchmark_trials": n_per_cell * len(architectures),
            "total_burst_evaluations": n_per_cell * len(architectures) * len(fanouts),
            "baseline_packet_loss_rate": 0.015,
            "slo_threshold_ms": SLO_THRESHOLD_MS,
            "timeout_cap_ms": TIMEOUT_CAP_MS,
            "initial_cwnd_pkts": INITIAL_CWND_PKTS,
        },
        "by_architecture_g8": {},
        "scaling_by_fanout": {name: [] for name, _, _ in architectures},
        "ablation_2x2_payload_vs_transport_g8": {},
        "gilbert_elliott_bursty_loss_ablation_g8": {},
        "breakeven_packet_loss_sweep_g8": [],
    }

    for name, t_mode, p_mode in architectures:
        for g in fanouts:
            cell_rng = random.Random(20261000 + g * 97 + sum(ord(c) for c in name))
            res = simulate_burst_discrete_event(
                cell_rng, t_mode, p_mode, stream_fanout=g, p_loss=0.015, n_trials=n_per_cell
            )
            results["scaling_by_fanout"][name].append({"stream_fanout": g, **res})
            if g == 8:
                results["by_architecture_g8"][name] = res

    # 2x2 Factorial Ablation at G=8 separating Payload Compression (Verbose JSON vs Compact VQ)
    # from Transport Multiplexing (Single-Stream TCP vs Dual-Plane QUIC) under identical p_loss = 0.015
    for p_mode in ["verbose_json", "compact_vq"]:
        for t_mode in ["tcp_tls_single", "quic_dual_plane"]:
            key = f"{t_mode}__{p_mode}"
            ab_rng = random.Random(20265500 + sum(ord(c) for c in key))
            results["ablation_2x2_payload_vs_transport_g8"][key] = simulate_burst_discrete_event(
                ab_rng, t_mode, p_mode, stream_fanout=8, p_loss=0.015, n_trials=600
            )

    # Gilbert-Elliott Two-State Bursty Packet-Loss Ablation at G=8
    for name, t_mode, p_mode in architectures:
        ge_rng = random.Random(20268800 + sum(ord(c) for c in name))
        results["gilbert_elliott_bursty_loss_ablation_g8"][name] = simulate_burst_discrete_event(
            ge_rng, t_mode, p_mode, stream_fanout=8, p_loss=0.015, n_trials=600, bursty_ge=True
        )

    # Break-even sensitivity sweep across packet loss rate p_loss in {0.05%, 0.25%, 0.50%, 1.50%, 3.00%, 5.00%}
    # comparing Compact-Payload Single-Stream TCP (`grpc_http2_tcp`) vs Dual-Plane QUIC (`dual_plane_quic_dgram`)
    for p_loss in [0.0005, 0.0025, 0.005, 0.015, 0.030, 0.050]:
        tcp_rng = random.Random(int(p_loss * 100000) + 111)
        quic_rng = random.Random(int(p_loss * 100000) + 222)
        tcp_res = simulate_burst_discrete_event(
            tcp_rng, "tcp_tls_single", "compact_vq", stream_fanout=8, p_loss=p_loss, n_trials=600
        )
        quic_res = simulate_burst_discrete_event(
            quic_rng, "quic_dual_plane", "compact_vq", stream_fanout=8, p_loss=p_loss, n_trials=600
        )
        results["breakeven_packet_loss_sweep_g8"].append(
            {
                "p_loss": p_loss,
                "tcp_compact_p50_ms": tcp_res["p50_latency_ms"],
                "tcp_compact_p99_ms": tcp_res["p99_latency_ms"],
                "tcp_compact_slo_pct": tcp_res["slo_compliance_pct"],
                "tcp_compact_drift_pct": tcp_res["context_drift_pct"],
                "quic_dual_p50_ms": quic_res["p50_latency_ms"],
                "quic_dual_p99_ms": quic_res["p99_latency_ms"],
                "quic_dual_slo_pct": quic_res["slo_compliance_pct"],
                "quic_dual_drift_pct": quic_res["context_drift_pct"],
            }
        )

    (HERE / "experiment_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    # Figure 1: Grouped Bar Chart at Fan-Out G=8 Streams
    arch_names = [a[0] for a in architectures]
    labels = [
        "HTTP/1.1+TCP\n(Verbose JSON)",
        "gRPC/HTTP2+TCP\n(Compact VQ)",
        "QUIC Streams\nOnly (RFC 9000)",
        "Dual-Plane QUIC\n+Datagram (Ours)",
    ]
    slo_vals = [results["by_architecture_g8"][a]["slo_compliance_pct"] for a in arch_names]
    slo_bounds = [
        (results["by_architecture_g8"][a]["slo_ci_low"], results["by_architecture_g8"][a]["slo_ci_high"])
        for a in arch_names
    ]
    drf_vals = [results["by_architecture_g8"][a]["context_drift_pct"] for a in arch_names]
    drf_bounds = [
        (results["by_architecture_g8"][a]["drift_ci_low"], results["by_architecture_g8"][a]["drift_ci_high"])
        for a in arch_names
    ]

    draw_grouped_bar_pdf(
        FIG_DIR / "fig1_benchmark.pdf",
        "Sub-65 ms Tail SLO Compliance vs. Stale-Context Drift Rate at Fan-Out G=8 (N=600)",
        "Rate (%)",
        labels,
        [
            {"name": "Sub-65 ms Sync SLO Compliance (Higher Better)", "values": slo_vals, "ci_bounds": slo_bounds},
            {"name": "Stale-Context Drift Rate (Lower Better)", "values": drf_vals, "ci_bounds": drf_bounds},
        ],
        y_min=0.0,
        y_max=100.0,
    )

    # Figure 2: Line Chart of 99th-Percentile Sync Latency across Stream Fan-Out G in {2, 4, 8, 16}
    draw_line_chart_pdf(
        FIG_DIR / "fig2_ablation.pdf",
        "99th-Percentile State Sync Latency Across Parallel Agent Stream Fan-Out (G=2..16)",
        "Concurrent Sub-Agent Stream Fan-Out (G)",
        "p99 Synchronization Latency (ms)",
        ["G=2", "G=4", "G=8", "G=16"],
        [
            {
                "name": "HTTP/1.1+TCP (JSON)",
                "values": [x["p99_latency_ms"] for x in results["scaling_by_fanout"]["http11_json_rest"]],
            },
            {
                "name": "gRPC/HTTP2+TCP (Compact)",
                "values": [x["p99_latency_ms"] for x in results["scaling_by_fanout"]["grpc_http2_tcp"]],
            },
            {
                "name": "QUIC Streams Only",
                "values": [x["p99_latency_ms"] for x in results["scaling_by_fanout"]["quic_streams_only"]],
            },
            {
                "name": "Dual-Plane QUIC+Datagram",
                "values": [x["p99_latency_ms"] for x in results["scaling_by_fanout"]["dual_plane_quic_dgram"]],
            },
        ],
        y_min=0.0,
        y_max=220.0,
    )
    print("Experiment m10 completed and figures generated.")


if __name__ == "__main__":
    main()
