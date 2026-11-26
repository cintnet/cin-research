# Open Reproducible Preprints (CIN)

Each directory below contains a complete, self-contained technical preprint package (arXiv-ready LaTeX source, pre-compiled `.bbl` + verified bibliography, zero-dependency Python benchmark, reproducible JSON outputs, vector PDF figures, and compiled manuscript PDF).

Every package passes `100/100` static arXiv moderation, statistical-interval (exact two-sided 95% Wilson & continuous CIs), and leak-firewall verification.

## Published Packages

- **`CIN-Thesis-Empirical` (`cin_sovereign_agent_systems`):** LaTeX source (`main.tex`, `main.bbl`, `references.bib`), zero-dependency Python benchmark (`python preprints/cin_sovereign_agent_systems/experiment.py`), JSON outputs, vector PDF figures, and compiled manuscript (`cin_sovereign_agent_systems.pdf`).
- **`M03` (`m03_uncertainty_inversion_gate`):** LaTeX source (`main.tex`, `main.bbl`, `references.bib`), zero-dependency Python benchmark (`python preprints/m03_uncertainty_inversion_gate/experiment.py`), JSON outputs, vector PDF figures, and compiled manuscript (`m03_uncertainty_inversion_gate.pdf`).
- **`M10` (`m10_second_internet_quic_fabric`):** LaTeX source (`main.tex`, `main.bbl`, `references.bib`), zero-dependency Python benchmark (`python preprints/m10_second_internet_quic_fabric/experiment.py`), JSON outputs, vector PDF figures, and compiled manuscript (`m10_second_internet_quic_fabric.pdf`).
- **`M43` (`m43_fluid_division_of_labour`):** LaTeX source (`main.tex`, `main.bbl`, `references.bib`), zero-dependency Python benchmark (`python preprints/m43_fluid_division_of_labour/experiment.py`), JSON outputs, vector PDF figures, and compiled manuscript (`m43_fluid_division_of_labour.pdf`).

## Reproducing Results

From the repository root (Python 3.10+, zero external packages required):

```bash
python preprints/cin_sovereign_agent_systems/experiment.py
python preprints/m03_uncertainty_inversion_gate/experiment.py
python preprints/m10_second_internet_quic_fabric/experiment.py
python preprints/m43_fluid_division_of_labour/experiment.py
```
