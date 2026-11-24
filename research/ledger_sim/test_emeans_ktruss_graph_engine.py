#!/usr/bin/env python3
"""Unit and invariant tests for `emeans_ktruss_graph_engine.py`."""

from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from emeans_ktruss_graph_engine import (
    compute_emeans_scaling_params,
    compute_kcore_numbers,
    compute_ktruss_decomposition,
    run_emeans_clustering,
    run_harmonic_minibatch_kmeans,
    run_hybrid_emeans_ktruss_benchmark,
    run_lloyd_kmeans,
)


class TestEMeansAndKTrussEngine(unittest.TestCase):
    def test_scaling_laws_bounded_and_monotonic(self) -> None:
        small = compute_emeans_scaling_params(n_samples=2000, n_clusters=16, epochs=2.0)
        large = compute_emeans_scaling_params(n_samples=200000, n_clusters=64, epochs=2.0)
        self.assertGreaterEqual(small.batch_size, 16)
        self.assertGreater(large.batch_size, small.batch_size)
        self.assertGreater(small.alpha_0, 0.0)
        self.assertLessEqual(small.alpha_0, 1.0)
        self.assertAlmostEqual(small.alpha_min, 0.10 * small.alpha_0, places=9)

    def test_emeans_matches_lloyd_in_one_tenth_epochs_and_beats_harmonic(self) -> None:
        rng = random.Random(20261113)
        k = 20
        dim = 14
        centers = [[rng.uniform(-3.5, 3.5) for _ in range(dim)] for _ in range(k)]
        pts = [
            [centers[i % k][d] + rng.gauss(0.0, 0.40) for d in range(dim)]
            for i in range(2000)
        ]
        rng.shuffle(pts)

        lloyd = run_lloyd_kmeans(pts, k, epochs=25, seed=99)
        harmonic = run_harmonic_minibatch_kmeans(pts, k, epochs=2.2, seed=99)
        emeans = run_emeans_clustering(pts, k, epochs=2.2, seed=99)

        # e-means uses ~8x-10x fewer distance evaluations than 25-epoch Lloyd's k-means
        speedup = lloyd.distance_evals / emeans.distance_evals
        self.assertGreater(speedup, 7.0)
        # e-means beats harmonic 1/t mini-batch MSE and stays within or below 25-epoch Lloyd MSE
        self.assertLess(emeans.mse_loss, harmonic.mse_loss)
        self.assertLessEqual(emeans.mse_loss, lloyd.mse_loss * 1.03)

    def test_ktruss_exact_clique_and_bridge_peeling(self) -> None:
        # Two K_5 cliques (0..4 and 5..9) -> every intra-clique edge has trussness 5.
        # Add a single bridge edge (0, 5) -> trussness 2.
        # Add a shallow triangle node 10 connected to (0, 5) -> edges (10, 0) and (10, 5)
        # participate in 1 triangle, so trussness = 3 (< 5!).
        adj = [set() for _ in range(11)]
        for base in (0, 5):
            for a in range(base, base + 5):
                for b in range(a + 1, base + 5):
                    adj[a].add(b)
                    adj[b].add(a)
        adj[0].add(5)
        adj[5].add(0)
        adj[10].update([0, 5])
        adj[0].add(10)
        adj[5].add(10)

        res = compute_ktruss_decomposition([sorted(s) for s in adj])
        self.assertEqual(res.max_truss, 5)
        self.assertEqual(res.edge_trussness[(1, 2)], 5)
        self.assertEqual(res.edge_trussness[(6, 7)], 5)
        self.assertEqual(res.edge_trussness[(0, 10)], 3)
        self.assertEqual(res.edge_trussness[(5, 10)], 3)
        self.assertEqual(res.edge_trussness[(0, 5)], 3)
        self.assertEqual(res.node_max_truss[10], 3)

    def test_ktruss_vertex_permutation_invariance(self) -> None:
        rng = random.Random(77)
        n = 30
        adj = [set() for _ in range(n)]
        for i in range(n):
            for _ in range(4):
                j = rng.randrange(n)
                if i != j:
                    adj[i].add(j)
                    adj[j].add(i)
        orig = compute_ktruss_decomposition([sorted(s) for s in adj])

        perm = list(range(n))
        rng.shuffle(perm)
        perm_adj = [set() for _ in range(n)]
        for u in range(n):
            for v in adj[u]:
                perm_adj[perm[u]].add(perm[v])
        permuted = compute_ktruss_decomposition([sorted(s) for s in perm_adj])

        self.assertEqual(orig.max_truss, permuted.max_truss)
        for u in range(n):
            self.assertEqual(orig.node_max_truss[u], permuted.node_max_truss[perm[u]])
        for (u, v), tau in orig.edge_trussness.items():
            pu, pv = perm[u], perm[v]
            key = (pu, pv) if pu < pv else (pv, pu)
            self.assertEqual(tau, permuted.edge_trussness[key])

    def test_hybrid_benchmark_peels_sybil_bridge_that_fools_kcore(self) -> None:
        report = run_hybrid_emeans_ktruss_benchmark(seed=42)
        self.assertGreaterEqual(report["eval_speedup_vs_lloyd"], 7.5)
        self.assertLess(report["emeans_2_2ep_mse"], report["harmonic_2_2ep_mse"])
        # Honest K_5 cliques have trussness 5; Sybil node achieves 4-core and 1-pass triangles
        # yet fails 4-truss (max truss = 3)
        self.assertEqual(report["honest_min_truss"], 5)
        self.assertEqual(report["sybil_kcore_number"], 4)
        self.assertGreaterEqual(report["sybil_one_pass_tri_edges"], 2)
        self.assertLess(report["sybil_max_truss"], 4)


if __name__ == "__main__":
    unittest.main()
