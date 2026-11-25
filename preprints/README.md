# Open Reproducible Preprints (CIN)

Each directory below contains a complete, self-contained technical preprint package (LaTeX source, verified bibliography, zero-dependency Python simulation benchmark, reproducible JSON outputs, vector PDF figures, and compiled manuscript PDF).

We publish preprints one cohort at a time after auditing each manuscript against reproducibility, statistical-interval, and bibliographic-verification checks before sequential arXiv submission.

## Published Packages

- **`M03` (`m03_uncertainty_inversion_gate`):** LaTeX source (`main.tex`, `references.bib`), zero-dependency Python benchmark (`python preprints/m03_uncertainty_inversion_gate/experiment.py`), JSON outputs, vector figures, and compiled PDF (`m03_uncertainty_inversion_gate.pdf`).
- **`M10` (`m10_second_internet_quic_fabric`):** LaTeX source (`main.tex`, `references.bib`), zero-dependency Python benchmark (`python preprints/m10_second_internet_quic_fabric/experiment.py`), JSON outputs, vector figures, and compiled PDF (`m10_second_internet_quic_fabric.pdf`).
- **`M43` (`m43_fluid_division_of_labour`):** LaTeX source (`main.tex`, `references.bib`), zero-dependency Python benchmark (`python preprints/m43_fluid_division_of_labour/experiment.py`), JSON outputs, vector figures, and compiled PDF (`m43_fluid_division_of_labour.pdf`).

## Reproducing Results

From the repository root (Python 3.10+, zero external packages required):

```bash
python preprints/m03_uncertainty_inversion_gate/experiment.py
python preprints/m10_second_internet_quic_fabric/experiment.py
python preprints/m43_fluid_division_of_labour/experiment.py
```
