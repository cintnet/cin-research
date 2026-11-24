#!/usr/bin/env python3
"""
Scalable Embedding Clustering (`e-means`) and Deterministic `k-truss` Graph Engine
==================================================================================

Implements and benchmarks two complementary algorithmic primitives for the
Collective Intelligence Network (CIN) research corpus and simulation testbed:

1. `e-means` Exponential Moving Average Clustering (Bessa et al., Meta FAIR &
   Ecole des Ponts, arXiv:2611.09501, Nov 2026; paired with IO-aware exact
   distance reductions motivated by Yang et al., Flash-KMeans, arXiv:2603.09229):
   - Replaces full-batch 25-epoch Lloyd's k-means and stale harmonic (1/t)
     mini-batch accumulation with EMA sufficient statistics:
       S_j <- (1 - alpha_t) * S_j + alpha_t * s_j
       N_j <- (1 - alpha_t) * N_j + alpha_t * n_j
       c_j  = S_j / N_j
   - Uses closed-form empirical scaling laws for batch size B and initial step
     alpha_0 as a function of dataset size n, cluster count k, and epoch budget T,
     decayed on a cosine schedule from alpha_0 to 0.1 * alpha_0 with dead-cluster
     revival. Reaches or beats 25-epoch Lloyd quantization MSE in ~2 epochs
     (~10x-12x fewer distance evaluations).

2. Deterministic Iterative `k-truss` Edge-Triangle Decomposition (Cohen 2008;
   Wang & Cheng, PVLDB 2012; Hossain & Sariyuce, KDD 2026 / arXiv:2603.05207):
   - Computes exact edge trussness tau(u, v) = max { k >= 2 : (u, v) in E(T_k) },
     where every edge in T_k is supported by at least (k - 2) triangles whose
     other two edges ALSO survive inside T_k.
   - Strictly stronger than degree-only `k-core` and single-pass triangle counts:
     peels shallow compromised Sybil bridge triangles while remaining 100%
     deterministic and vertex-permutation invariant.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Sequence, Set, Tuple


@dataclass(frozen=True)
class EMeansScalingParams:
    """Closed-form scaling-law hyperparameters from Bessa et al. (arXiv:2611.09501)."""

    n_samples: int
    n_clusters: int
    epochs: float
    batch_size: int
    alpha_0: float
    alpha_min: float
    total_steps: int


@dataclass(frozen=True)
class ClusteringResult:
    """Standardized evaluation record across Lloyd, harmonic mini-batch, and e-means."""

    method: str
    centroids: Tuple[Tuple[float, ...], ...]
    assignments: Tuple[int, ...]
    mse_loss: float
    epochs_executed: float
    distance_evals: int
    wall_ms: float


@dataclass(frozen=True)
class KTrussResult:
    """Exact edge-trussness decomposition of an undirected graph G = (V, E)."""

    num_nodes: int
    num_edges: int
    max_truss: int
    edge_trussness: Dict[Tuple[int, int], int]
    node_max_truss: Tuple[int, ...]


def _nearest_power_of_two(val: float, low: int, high: int) -> int:
    clipped = max(float(low), min(float(high), val))
    exp = int(round(math.log2(max(1.0, clipped))))
    p2 = 1 << max(0, exp)
    return max(low, min(high, p2))


def compute_emeans_scaling_params(
    n_samples: int,
    n_clusters: int,
    epochs: float = 2.2,
) -> EMeansScalingParams:
    """
    Computes hyperparameter-free batch size B and initial EMA decay rate alpha_0
    following the empirical scaling laws of Bessa et al. (arXiv:2611.09501):
      B_raw   = 0.035 * k^0.13 * n^0.88 * T^0.81
      alpha_0 = min(0.824 * k^-0.46 * B^0.90 * n^-0.45 * T^-0.11, 1.0)
    For compact simulation regimes (small n), enforces a practical mini-batch
    ceiling (n // 4) so multiple EMA steps execute per epoch while preserving
    the exact asymptotic scaling law at large n.
    """
    if n_samples <= 0 or n_clusters <= 0:
        raise ValueError("n_samples and n_clusters must be positive")
    t_eff = max(0.5, float(epochs))
    b_raw = (
        0.035
        * (n_clusters ** 0.13)
        * (n_samples ** 0.88)
        * (t_eff ** 0.81)
    )
    low_b = min(n_samples, max(16, n_clusters))
    high_b = max(low_b, n_samples // 4)
    batch_size = _nearest_power_of_two(b_raw, low_b, high_b)

    alpha_raw = (
        0.824
        * (n_clusters ** -0.46)
        * (batch_size ** 0.90)
        * (n_samples ** -0.45)
        * (t_eff ** -0.11)
    )
    alpha_0 = max(0.05, min(1.0, alpha_raw))
    alpha_min = 0.10 * alpha_0
    total_steps = max(2, int(math.ceil((t_eff * n_samples) / batch_size)))

    return EMeansScalingParams(
        n_samples=n_samples,
        n_clusters=n_clusters,
        epochs=t_eff,
        batch_size=batch_size,
        alpha_0=alpha_0,
        alpha_min=alpha_min,
        total_steps=total_steps,
    )


def _sq_euclid(a: Sequence[float], b: Sequence[float]) -> float:
    # Algebraic identity ||a - b||^2 = sum (a_d - b_d)^2
    return sum((x - y) * (x - y) for x, y in zip(a, b))


def _assign_and_mse(
    points: Sequence[Sequence[float]],
    centroids: Sequence[Sequence[float]],
) -> Tuple[Tuple[int, ...], float, int]:
    """Assigns each point to its nearest centroid and returns (assignments, mse, evals)."""
    n = len(points)
    k = len(centroids)
    if n == 0 or k == 0:
        return (), 0.0, 0
    assigns: List[int] = []
    total_loss = 0.0
    for pt in points:
        best_j = 0
        best_d = _sq_euclid(pt, centroids[0])
        for j in range(1, k):
            d = _sq_euclid(pt, centroids[j])
            if d < best_d:
                best_d = d
                best_j = j
        assigns.append(best_j)
        total_loss += best_d
    return tuple(assigns), total_loss / n, n * k


def _init_centroids_random(
    points: Sequence[Sequence[float]],
    n_clusters: int,
    rng: random.Random,
) -> List[List[float]]:
    indices = rng.sample(range(len(points)), k=min(n_clusters, len(points)))
    return [list(points[idx]) for idx in indices]


def run_lloyd_kmeans(
    points: Sequence[Sequence[float]],
    n_clusters: int,
    epochs: int = 25,
    seed: int = 42,
) -> ClusteringResult:
    """Classical full-batch Lloyd's k-means algorithm over `epochs` full passes."""
    t0 = time.perf_counter()
    rng = random.Random(seed)
    n = len(points)
    dim = len(points[0])
    centroids = _init_centroids_random(points, n_clusters, rng)
    dist_evals = 0

    for _ in range(epochs):
        sums = [[0.0] * dim for _ in range(n_clusters)]
        counts = [0] * n_clusters
        for pt in points:
            best_j = 0
            best_d = _sq_euclid(pt, centroids[0])
            for j in range(1, n_clusters):
                d = _sq_euclid(pt, centroids[j])
                if d < best_d:
                    best_d = d
                    best_j = j
            counts[best_j] += 1
            s_row = sums[best_j]
            for d_idx, val in enumerate(pt):
                s_row[d_idx] += val
        dist_evals += n * n_clusters
        for j in range(n_clusters):
            if counts[j] > 0:
                inv_c = 1.0 / counts[j]
                centroids[j] = [v * inv_c for v in sums[j]]
            else:
                centroids[j] = list(points[rng.randrange(n)])

    assigns, mse, eval_tail = _assign_and_mse(points, centroids)
    wall_ms = (time.perf_counter() - t0) * 1000.0
    return ClusteringResult(
        method="lloyd_kmeans",
        centroids=tuple(tuple(c) for c in centroids),
        assignments=assigns,
        mse_loss=mse,
        epochs_executed=float(epochs),
        distance_evals=dist_evals + eval_tail,
        wall_ms=wall_ms,
    )


def run_harmonic_minibatch_kmeans(
    points: Sequence[Sequence[float]],
    n_clusters: int,
    epochs: float = 2.2,
    batch_size: int | None = None,
    seed: int = 42,
) -> ClusteringResult:
    """
    Classical Sculley (2010) mini-batch k-means with harmonic 1/N_j learning rate
    (accumulating all historical sufficient statistics without exponential forgetting).
    """
    t0 = time.perf_counter()
    rng = random.Random(seed)
    n = len(points)
    params = compute_emeans_scaling_params(n, n_clusters, epochs)
    b_sz = batch_size if batch_size is not None else params.batch_size
    steps = max(2, int(math.ceil((epochs * n) / b_sz)))

    centroids = _init_centroids_random(points, n_clusters, rng)
    total_counts = [1.0] * n_clusters
    dist_evals = 0

    for _ in range(steps):
        batch_indices = [rng.randrange(n) for _ in range(b_sz)]
        batch_assigns: List[int] = []
        for idx in batch_indices:
            pt = points[idx]
            best_j = 0
            best_d = _sq_euclid(pt, centroids[0])
            for j in range(1, n_clusters):
                d = _sq_euclid(pt, centroids[j])
                if d < best_d:
                    best_d = d
                    best_j = j
            batch_assigns.append(best_j)
        dist_evals += b_sz * n_clusters

        for idx, j in zip(batch_indices, batch_assigns):
            total_counts[j] += 1.0
            eta = 1.0 / total_counts[j]
            pt = points[idx]
            c_row = centroids[j]
            for d_idx, val in enumerate(pt):
                c_row[d_idx] = (1.0 - eta) * c_row[d_idx] + eta * val

    assigns, mse, eval_tail = _assign_and_mse(points, centroids)
    wall_ms = (time.perf_counter() - t0) * 1000.0
    return ClusteringResult(
        method="harmonic_minibatch_kmeans",
        centroids=tuple(tuple(c) for c in centroids),
        assignments=assigns,
        mse_loss=mse,
        epochs_executed=round((steps * b_sz) / n, 3),
        distance_evals=dist_evals + eval_tail,
        wall_ms=wall_ms,
    )


def run_emeans_clustering(
    points: Sequence[Sequence[float]],
    n_clusters: int,
    epochs: float = 2.2,
    seed: int = 42,
) -> ClusteringResult:
    """
    `e-means` clustering (Bessa et al., arXiv:2611.09501, Nov 2026):
    - Initializes centroids and sufficient statistics (S_j, N_j) from one mini-batch.
    - Updates running sufficient statistics via EMA with cosine-decayed step alpha_t:
        S_j <- (1 - alpha_t) * S_j + alpha_t * s_j
        N_j <- (1 - alpha_t) * N_j + alpha_t * n_j
        c_j  = S_j / N_j
    - Revives dead/starved clusters by splitting the highest-distortion batch cluster.
    """
    t0 = time.perf_counter()
    rng = random.Random(seed)
    n = len(points)
    dim = len(points[0])
    params = compute_emeans_scaling_params(n, n_clusters, epochs)
    b_sz = params.batch_size
    steps = params.total_steps

    centroids = _init_centroids_random(points, n_clusters, rng)
    init_weight = float(b_sz) / float(n_clusters)
    ema_counts: List[float] = [init_weight for _ in range(n_clusters)]
    ema_sums: List[List[float]] = [
        [c_val * init_weight for c_val in centroids[j]] for j in range(n_clusters)
    ]

    perm = list(range(n))
    rng.shuffle(perm)
    cursor = 0
    dist_evals = 0
    dead_threshold = 0.08 * (float(b_sz) / float(n_clusters))

    for step in range(steps):
        # Cosine schedule from alpha_0 down to alpha_min = 0.1 * alpha_0
        progress = step / float(max(1, steps - 1))
        alpha_t = params.alpha_min + 0.5 * (params.alpha_0 - params.alpha_min) * (
            1.0 + math.cos(math.pi * progress)
        )

        batch_pts: List[Sequence[float]] = []
        for _ in range(b_sz):
            if cursor >= n:
                rng.shuffle(perm)
                cursor = 0
            batch_pts.append(points[perm[cursor]])
            cursor += 1

        batch_sums = [[0.0] * dim for _ in range(n_clusters)]
        batch_counts = [0.0] * n_clusters
        batch_distortion = [0.0] * n_clusters
        furthest_pt_per_cluster: List[Sequence[float] | None] = [None] * n_clusters
        furthest_dist = [-1.0] * n_clusters

        for pt in batch_pts:
            best_j = 0
            best_d = _sq_euclid(pt, centroids[0])
            for j in range(1, n_clusters):
                d = _sq_euclid(pt, centroids[j])
                if d < best_d:
                    best_d = d
                    best_j = j
            batch_counts[best_j] += 1.0
            batch_distortion[best_j] += best_d
            if best_d > furthest_dist[best_j]:
                furthest_dist[best_j] = best_d
                furthest_pt_per_cluster[best_j] = pt
            s_row = batch_sums[best_j]
            for d_idx, val in enumerate(pt):
                s_row[d_idx] += val
        dist_evals += b_sz * n_clusters

        one_minus = 1.0 - alpha_t
        for j in range(n_clusters):
            ema_counts[j] = one_minus * ema_counts[j] + alpha_t * batch_counts[j]
            s_ema = ema_sums[j]
            s_bat = batch_sums[j]
            for d_idx in range(dim):
                s_ema[d_idx] = one_minus * s_ema[d_idx] + alpha_t * s_bat[d_idx]

        # Dead-cluster revival: split highest-distortion cluster if any cluster starves
        for j in range(n_clusters):
            if ema_counts[j] < dead_threshold:
                donor = max(range(n_clusters), key=lambda idx: batch_distortion[idx])
                seed_pt = furthest_pt_per_cluster[donor]
                if seed_pt is not None and donor != j:
                    half_n = max(dead_threshold * 2.0, 0.5 * ema_counts[donor])
                    ema_counts[donor] = half_n
                    ema_counts[j] = half_n
                    ema_sums[j] = [val * half_n for val in seed_pt]
                    ema_sums[donor] = [val * half_n for val in centroids[donor]]
                    batch_distortion[donor] *= 0.25

        for j in range(n_clusters):
            inv_n = 1.0 / max(1e-12, ema_counts[j])
            centroids[j] = [v * inv_n for v in ema_sums[j]]

    assigns, mse, eval_tail = _assign_and_mse(points, centroids)
    wall_ms = (time.perf_counter() - t0) * 1000.0
    return ClusteringResult(
        method="emeans",
        centroids=tuple(tuple(c) for c in centroids),
        assignments=assigns,
        mse_loss=mse,
        epochs_executed=round((steps * b_sz) / n, 3),
        distance_evals=dist_evals + eval_tail,
        wall_ms=wall_ms,
    )


def compute_ktruss_decomposition(adj: Sequence[Sequence[int]]) -> KTrussResult:
    """
    Exact deterministic `k-truss` edge decomposition (Cohen 2008; Wang & Cheng 2012).

    Given an undirected simple graph adjacency list `adj`, iteratively peels the edge
    with minimum triangle support `sup(e)` until all edges are assigned their exact
    truss number `tau(u, v) = k` (meaning `(u, v)` belongs to a maximal subgraph T_k
    where every surviving edge participates in >= k - 2 surviving triangles).
    100% invariant to vertex relabeling.
    """
    n = len(adj)
    nbrs: List[Set[int]] = [set() for _ in range(n)]
    for u in range(n):
        for v in adj[u]:
            if u != v:
                nbrs[u].add(v)
                nbrs[v].add(u)

    edges: List[Tuple[int, int]] = []
    edge_id_of: Dict[Tuple[int, int], int] = {}
    for u in range(n):
        for v in sorted(nbrs[u]):
            if u < v:
                eid = len(edges)
                edges.append((u, v))
                edge_id_of[(u, v)] = eid

    m = len(edges)
    if m == 0:
        return KTrussResult(
            num_nodes=n,
            num_edges=0,
            max_truss=2,
            edge_trussness={},
            node_max_truss=tuple(2 for _ in range(n)),
        )

    support = [0] * m
    for eid, (u, v) in enumerate(edges):
        if len(nbrs[u]) <= len(nbrs[v]):
            support[eid] = sum(1 for w in nbrs[u] if w in nbrs[v])
        else:
            support[eid] = sum(1 for w in nbrs[v] if w in nbrs[u])

    max_sup = max(support)
    bins: List[Set[int]] = [set() for _ in range(max_sup + 1)]
    for eid, sup in enumerate(support):
        bins[sup].append(eid) if hasattr(bins[sup], "append") else bins[sup].add(eid)

    alive = [True] * m
    trussness: Dict[Tuple[int, int], int] = {}
    curr_sup = 0
    peeled = 0

    while peeled < m:
        while curr_sup <= max_sup and not bins[curr_sup]:
            curr_sup += 1
        if curr_sup > max_sup:
            break
        # Deterministic pop (smallest edge id) guarantees strict label invariance on ties
        eid = min(bins[curr_sup])
        bins[curr_sup].remove(eid)
        if not alive[eid]:
            continue

        alive[eid] = False
        peeled += 1
        u, v = edges[eid]
        k_val = curr_sup + 2
        trussness[(u, v)] = k_val

        # Remove edge (u, v) from active adjacency and decrement surviving triangle partners
        nbrs[u].discard(v)
        nbrs[v].discard(u)
        common = nbrs[u] & nbrs[v] if len(nbrs[u]) <= len(nbrs[v]) else nbrs[v] & nbrs[u]
        for w in common:
            e1 = edge_id_of[(u, w) if u < w else (w, u)]
            e2 = edge_id_of[(v, w) if v < w else (w, v)]
            for partner_eid in (e1, e2):
                if alive[partner_eid] and support[partner_eid] > curr_sup:
                    old_s = support[partner_eid]
                    bins[old_s].discard(partner_eid)
                    new_s = old_s - 1
                    support[partner_eid] = new_s
                    bins[new_s].add(partner_eid)

    node_max = [2] * n
    for (u, v), tau in trussness.items():
        if tau > node_max[u]:
            node_max[u] = tau
        if tau > node_max[v]:
            node_max[v] = tau

    max_truss = max(trussness.values()) if trussness else 2
    return KTrussResult(
        num_nodes=n,
        num_edges=m,
        max_truss=max_truss,
        edge_trussness=trussness,
        node_max_truss=tuple(node_max),
    )


def compute_kcore_numbers(adj: Sequence[Sequence[int]]) -> Tuple[int, ...]:
    """Standard linear-time Matula-Beck degree-peeling `k-core` baseline for comparison."""
    n = len(adj)
    nbrs: List[Set[int]] = [set(v for v in adj[u] if v != u) for u in range(n)]
    deg = [len(nbrs[u]) for u in range(n)]
    if n == 0:
        return ()
    max_d = max(deg)
    bins: List[Set[int]] = [set() for _ in range(max_d + 1)]
    for u, d in enumerate(deg):
        bins[d].add(u)

    core = [0] * n
    removed = [False] * n
    curr_d = 0
    for _ in range(n):
        while curr_d <= max_d and not bins[curr_d]:
            curr_d += 1
        u = min(bins[curr_d])
        bins[curr_d].remove(u)
        removed[u] = True
        core[u] = curr_d
        for v in list(nbrs[u]):
            if not removed[v] and deg[v] > curr_d:
                bins[deg[v]].discard(v)
                deg[v] -= 1
                bins[deg[v]].add(v)
    return tuple(core)


def run_hybrid_emeans_ktruss_benchmark(seed: int = 42) -> Dict[str, object]:
    """
    End-to-end benchmark comparing:
      1. Clustering efficiency & MSE: 2.2-epoch `e-means` vs. 25-epoch Lloyd's k-means
         vs. 2.2-epoch harmonic mini-batch k-means on N=2,400 synthetic 16D embeddings
         across K=24 clusters.
      2. Topological Sybil bridge filtering: `k-truss` (tau >= 4) vs. degree `k-core`
         and 1-pass triangle counting against shallow compromised voucher bridges.
    """
    rng = random.Random(seed)
    n_pts = 2400
    k_clusters = 24
    dim = 16

    true_centers = [
        [rng.uniform(-3.0, 3.0) for _ in range(dim)] for _ in range(k_clusters)
    ]
    points: List[List[float]] = []
    for i in range(n_pts):
        c = true_centers[i % k_clusters]
        points.append([c[d] + rng.gauss(0.0, 0.42) for d in range(dim)])
    rng.shuffle(points)

    lloyd_res = run_lloyd_kmeans(points, k_clusters, epochs=25, seed=seed)
    harmonic_res = run_harmonic_minibatch_kmeans(points, k_clusters, epochs=2.2, seed=seed)
    emeans_res = run_emeans_clustering(points, k_clusters, epochs=2.2, seed=seed)

    # Construct an honest 4-truss community (K_5 cliques chained together) attacked by a
    # frontline Sybil node s connected to 4 compromised honest nodes across separate cliques,
    # with a single stray compromised-pair edge forming 1 shallow triangle (tri=1, deg=4).
    n_honest = 20
    sybil = 20
    adj_sets: List[Set[int]] = [set() for _ in range(21)]
    for clique_idx in range(4):
        base = clique_idx * 5
        for a in range(base, base + 5):
            for b in range(a + 1, base + 5):
                adj_sets[a].add(b)
                adj_sets[b].add(a)
    compromised = [0, 5, 10, 15]
    for u in compromised:
        adj_sets[sybil].add(u)
        adj_sets[u].add(sybil)
    # Single coordinated edge between compromised[0] and compromised[1] gives (sybil, 0) tri=1!
    adj_sets[0].add(5)
    adj_sets[5].add(0)

    adj = [sorted(s) for s in adj_sets]
    truss_res = compute_ktruss_decomposition(adj)
    core_nums = compute_kcore_numbers(adj)
    one_pass_sybil_tri = sum(
        1 for u in adj[sybil] if len(adj_sets[sybil] & adj_sets[u]) >= 1
    )

    return {
        "lloyd_25ep_mse": round(lloyd_res.mse_loss, 5),
        "harmonic_2_2ep_mse": round(harmonic_res.mse_loss, 5),
        "emeans_2_2ep_mse": round(emeans_res.mse_loss, 5),
        "eval_speedup_vs_lloyd": round(
            lloyd_res.distance_evals / max(1, emeans_res.distance_evals), 2
        ),
        "honest_min_truss": min(truss_res.node_max_truss[:n_honest]),
        "sybil_max_truss": truss_res.node_max_truss[sybil],
        "sybil_kcore_number": core_nums[sybil],
        "sybil_one_pass_tri_edges": one_pass_sybil_tri,
    }


if __name__ == "__main__":
    report = run_hybrid_emeans_ktruss_benchmark()
    for key, val in report.items():
        print(f"{key}: {val}")
