# Collective Intelligence Network — Open Research & Reproducible Benchmarks (`cintnet/cin-research`)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24560618.svg)](https://doi.org/10.5281/zenodo.24560618)

Canonical technical monograph, arXiv-ready empirical systems papers, deterministic multi-agent red-team and clearing wind tunnels, 43-lab alignment dossiers, 30-authority sovereign governance papers, and the 348-organisation Institutional Atlas from the [Collective Intelligence Network](https://cintnet.org).

## Start Here

| Artifact | Format | Description |
| :--- | :--- | :--- |
| **Unified Technical Thesis** | [`CIN-TECHNICAL-THESIS.md`](knowledge/CIN-TECHNICAL-THESIS.md) · [`PDF`](knowledge/CIN-TECHNICAL-THESIS.pdf) | Complete 5-layer architecture specification, formal invariants (`C1–C4`), adversary taxonomy (`A1–A6`), post-AGI economic clearing, asymmetric transparency, and unsolved problems. |
| **arXiv Empirical Systems Paper** | [`preprints/cin_sovereign_agent_systems/`](preprints/cin_sovereign_agent_systems/) · [`PDF`](preprints/cin_sovereign_agent_systems/cin_sovereign_agent_systems.pdf) | Focused 13-page `cs.MA` / `cs.CR` empirical paper + arXiv `.tar.gz` bundle + zero-dependency 4-suite benchmark (`experiment.py`). |
| **Curated Preprints (`M03`, `M10`, `M43`)** | [`preprints/`](preprints/README.md) | Standalone reproducible technical preprints covering conformal uncertainty gates, QUIC agent transport, and fluid division of labour. |
| **Multi-Agent Testnet & Simulations** | [`research/ledger_sim/`](research/ledger_sim/) | Deterministic simulation suite (`413` unit tests) verifying silicon/ledger red-teaming, supplier failover, capability leases, collusion detection, and zero-cent conservation. |
| **Lab & Sovereign Technical Dossiers** | [`knowledge/lab_papers/`](knowledge/lab_papers/README.md) · [`knowledge/sovereign_papers/`](knowledge/sovereign_papers/README.md) | Five-section convergence/deviation technical papers across flagship AI labs (`43`-lab overlay dataset) and `30` sovereign/multilateral authorities. |

## Quick Reproduction (Python 3.10+, Zero External Dependencies)

```bash
# Reproduce all 4 empirical benchmark suites & vector PDF figures for the systems paper
python preprints/cin_sovereign_agent_systems/experiment.py

# Run the full multi-agent ledger & red-team verification suite (413 tests)
python -m unittest discover -s research/ledger_sim -p "test_*.py" -v
```

## Repository Map

- `knowledge/CIN-TECHNICAL-THESIS.{md,pdf}` — Unified Technical Thesis (Version 1.0)
- `knowledge/BASE-THESIS.md` & `knowledge/foundations/` — Canonical foundation volumes (cybernetic agency, sensorium attestation & red-teaming)
- `preprints/` — Self-contained arXiv-ready LaTeX, BibTeX, Python experiments, JSON results, vector figures, and compiled PDFs
- `research/ledger_sim/` — Deterministic multi-agent verification harness and conservation tests
- `research/institutions/` — 348-organisation registry, 93-entity lab/safety overlays, and 30-authority sovereign matrix

## Licensing & Citation

- **Code & Benchmarks:** `Apache-2.0` (`LICENSE`)
- **Papers, Specifications & Datasets:** `CC-BY-4.0` (`LICENSE-DOCS`)
- **Citation Metadata:** See [`CITATION.cff`](CITATION.cff) and [`.zenodo.json`](.zenodo.json).
- **Web Edition & Interactive Benches:** [https://cintnet.org/technical-thesis/](https://cintnet.org/technical-thesis/) · [https://cintnet.org/labs/](https://cintnet.org/labs/)
