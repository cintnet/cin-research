#!/usr/bin/env python3
"""
research/ledger_sim/test_latent_negotiation_sim.py

Test runner in research/ledger_sim for Bilateral Agent Negotiation over Continuous Latent Vectors.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

LEDGER_SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = LEDGER_SIM_DIR.parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from research.sim.test_latent_negotiation_sim import TestBilateralLatentNegotiationSim

if __name__ == "__main__":
    unittest.main()
