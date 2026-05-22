"""
Drift Monitor -- tracks feature distribution drift using PSI.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

import numpy as np

from ml_engine import FEATURE_COLUMNS


@dataclass
class DriftStatus:
    baseline_ready: bool
    window_size: int
    psi_avg: Optional[float]
    psi_by_feature: Dict[str, float]
    drift_level: str

    def to_dict(self) -> Dict:
        return asdict(self)


class DriftMonitor:
    """Monitor feature drift using Population Stability Index (PSI)."""

    def __init__(self, window_size: int = 500, baseline_size: int = 500, bins: int = 10) -> None:
        self.window_size = window_size
        self.baseline_size = baseline_size
        self.bins = bins

        self._baseline_data: List[List[float]] = []
        self._window_data: List[List[float]] = []
        self._bin_edges: Dict[str, np.ndarray] = {}
        self._baseline_probs: Dict[str, np.ndarray] = {}
        self._last_status = DriftStatus(False, 0, None, {}, "unknown")

    def update(self, features_list: List[Dict]) -> Dict:
        """Update rolling window with new feature vectors and compute PSI."""
        rows = [self._features_to_row(f) for f in features_list]
        if not rows:
            return self._last_status.to_dict()

        # Fill baseline first
        if not self._baseline_ready():
            self._baseline_data.extend(rows)
            if len(self._baseline_data) >= self.baseline_size:
                self._baseline_data = self._baseline_data[: self.baseline_size]
                self._compute_baseline()

        # Update current window
        self._window_data.extend(rows)
        if len(self._window_data) > self.window_size:
            self._window_data = self._window_data[-self.window_size :]

        status = self._compute_status()
        self._last_status = status
        return status.to_dict()

    def get_status(self) -> Dict:
        return self._last_status.to_dict()

    def _baseline_ready(self) -> bool:
        return bool(self._bin_edges) and bool(self._baseline_probs)

    def _features_to_row(self, features: Dict) -> List[float]:
        return [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]

    def _compute_baseline(self) -> None:
        data = np.array(self._baseline_data, dtype=float)
        if data.size == 0:
            return

        for i, col in enumerate(FEATURE_COLUMNS):
            col_values = data[:, i]
            edges = np.quantile(col_values, np.linspace(0, 1, self.bins + 1))
            edges = np.unique(edges)
            if len(edges) < 2:
                edges = np.array([col_values.min(), col_values.max() + 1e-6])

            counts, _ = np.histogram(col_values, bins=edges)
            probs = self._to_probs(counts)

            self._bin_edges[col] = edges
            self._baseline_probs[col] = probs

    def _compute_status(self) -> DriftStatus:
        if not self._baseline_ready() or len(self._window_data) < 50:
            return DriftStatus(False, len(self._window_data), None, {}, "warming")

        window = np.array(self._window_data, dtype=float)
        psi_by_feature: Dict[str, float] = {}
        for i, col in enumerate(FEATURE_COLUMNS):
            edges = self._bin_edges.get(col)
            base_probs = self._baseline_probs.get(col)
            if edges is None or base_probs is None:
                continue

            counts, _ = np.histogram(window[:, i], bins=edges)
            current_probs = self._to_probs(counts)
            psi_by_feature[col] = self._psi(base_probs, current_probs)

        psi_avg = float(np.mean(list(psi_by_feature.values()))) if psi_by_feature else None
        drift_level = self._level_from_score(psi_avg)

        return DriftStatus(True, len(self._window_data), psi_avg, psi_by_feature, drift_level)

    def _level_from_score(self, psi_avg: Optional[float]) -> str:
        if psi_avg is None:
            return "unknown"
        if psi_avg < 0.1:
            return "low"
        if psi_avg < 0.2:
            return "medium"
        return "high"

    def _to_probs(self, counts: np.ndarray) -> np.ndarray:
        counts = counts.astype(float)
        total = counts.sum()
        if total <= 0:
            return np.full_like(counts, 1.0 / len(counts), dtype=float)
        probs = counts / total
        # Avoid zeros to keep PSI stable
        eps = 1e-6
        return np.clip(probs, eps, 1.0)

    def _psi(self, expected: np.ndarray, actual: np.ndarray) -> float:
        expected = np.clip(expected, 1e-6, 1.0)
        actual = np.clip(actual, 1e-6, 1.0)
        return float(np.sum((actual - expected) * np.log(actual / expected)))
