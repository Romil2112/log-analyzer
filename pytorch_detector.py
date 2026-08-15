"""
PyTorch Anomaly Detector
Author: Romil V. Shah

Optional alternative to the default Isolation Forest anomaly detector.
Activate with --detector pytorch (requires: pip install -r requirements-ml.txt).

Architecture: a shallow autoencoder trained unsupervised on the same 8-feature
per-IP behaviour vectors the Isolation Forest uses.  Anomaly score is the
mean squared reconstruction error, normalised to [0, 1] so it is directly
comparable to the Isolation Forest output (0.0 = normal, 1.0 = most anomalous).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import numpy as np
    import torch
    import torch.nn as nn
    from sklearn.preprocessing import StandardScaler
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False

logger = logging.getLogger(__name__)

# Feature names — identical to AnomalyDetector.FEATURES in log_analyzer.py.
FEATURES = [
    "failed_logins", "unique_ports", "unique_usernames",
    "events_per_minute", "active_minutes", "night_ratio",
    "burst_score", "fail_ratio",
]

_MIN_IPS = 3
_EPOCHS = 200
_LR = 1e-3
_BOTTLENECK = 4


# ---------------------------------------------------------------------------
# Feature extraction (mirrors AnomalyDetector in log_analyzer.py)
# ---------------------------------------------------------------------------

def _burst_score(times: list[datetime], total: int) -> float:
    if total <= 1:
        return 1.0
    w = timedelta(seconds=60)
    n = len(times)
    best = j = 0
    for i in range(n):
        if j < i:
            j = i
        while j < n and times[j] - times[i] <= w:
            j += 1
        best = max(best, j - i)
    return best / total


def _ip_feature_row(evts: list[dict]) -> list[float]:
    times = sorted(e["event_time"] for e in evts)
    total = len(evts)
    fails = sum(1 for e in evts if e["event_type"] == "failed_login")
    n_ports = len({e["port"] for e in evts if e.get("port")})
    n_users = len({e.get("username") for e in evts if e.get("username")})
    span_s = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0
    active_min = span_s / 60.0
    rate = total / max(active_min, 1.0)
    night = sum(1 for t in times if t.hour < 6) / total
    burst = _burst_score(times, total)
    return [
        float(fails), float(n_ports), float(n_users),
        float(rate), float(active_min), float(night),
        float(burst), float(fails / total),
    ]


def _build_feature_matrix(events: list[dict]) -> tuple[list[str], list[list[float]]]:
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("source_ip"):
            by_ip[e["source_ip"]].append(e)
    ips, rows = [], []
    for ip, evts in by_ip.items():
        rows.append(_ip_feature_row(evts))
        ips.append(ip)
    return ips, rows


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class PyTorchAnomalyDetector:
    """
    Unsupervised autoencoder anomaly detector.

    Trains on the current run's data (same unsupervised train-and-score pattern
    as the Isolation Forest default) and scores each IP by its mean squared
    reconstruction error.  Scores are normalised to [0, 1].
    """

    def fit_score(self, events: list[dict]) -> dict[str, float]:
        """Return per-IP anomaly scores: 0.0 = normal, 1.0 = most anomalous."""
        if not PYTORCH_AVAILABLE:
            return {}
        ips, rows = _build_feature_matrix(events)
        if len(ips) < _MIN_IPS:
            return {}

        features = np.array(rows, dtype=float)
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)

        features_tensor = torch.tensor(features_scaled, dtype=torch.float32)

        class _LogAutoencoder(nn.Module):
            def __init__(self, input_dim: int, bottleneck: int):
                super().__init__()
                self.encoder = nn.Sequential(nn.Linear(input_dim, bottleneck), nn.ReLU())
                self.decoder = nn.Linear(bottleneck, input_dim)

            def forward(self, x):
                return self.decoder(self.encoder(x))

        model = _LogAutoencoder(input_dim=features_tensor.shape[1], bottleneck=_BOTTLENECK)
        optimiser = torch.optim.Adam(model.parameters(), lr=_LR)
        criterion = nn.MSELoss()

        model.train()
        for _ in range(_EPOCHS):
            optimiser.zero_grad()
            loss = criterion(model(features_tensor), features_tensor)
            loss.backward()
            optimiser.step()

        model.eval()
        with torch.no_grad():
            recon = model(features_tensor)
            per_ip_error = ((recon - features_tensor) ** 2).mean(dim=1).numpy()

        lo, hi = per_ip_error.min(), per_ip_error.max()
        norm = (per_ip_error - lo) / (hi - lo) if hi > lo else np.zeros(len(per_ip_error))
        return {ip: float(round(s, 4)) for ip, s in zip(ips, norm, strict=False)}

    def feature_rows(self, events: list[dict]) -> list[dict]:
        """Return per-IP feature vectors as dicts (same schema as AnomalyDetector)."""
        ips, rows = _build_feature_matrix(events)
        return [
            {"source_ip": ip, **dict(zip(FEATURES, row, strict=False))}
            for ip, row in zip(ips, rows, strict=False)
        ]
