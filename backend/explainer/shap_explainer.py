"""
SHAP Explainability Module — A.I.R.S Backend
Uses TreeExplainer on the trained RandomForest to explain per-prediction
feature contributions. Returns top-8 features sorted by impact.
"""

import logging
import warnings
from typing import List, Dict, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Human-readable labels for our 25 internal feature columns
FEATURE_HUMAN_LABELS: Dict[str, str] = {
    "flow_duration":              "Flow Duration",
    "packet_count":               "Packet Count",
    "byte_count":                 "Byte Volume",
    "packets_per_second":         "Packet Rate",
    "bytes_per_second":           "Byte Rate",
    "avg_packet_size":            "Avg Packet Size",
    "connection_rate":            "Connection Rate",
    "syn_packet_ratio":           "SYN Ratio",
    "unique_ports_contacted":     "Unique Ports",
    "failed_connection_attempts": "Failed Connections",
    "burst_rate":                 "Burst Rate",
    "syn_count":                  "SYN Count",
    "rst_count":                  "RST Count",
    "unique_targets":             "Unique Targets",
    "fwd_packet_count":           "Fwd Packet Count",
    "bwd_packet_count":           "Bwd Packet Count",
    "fwd_byte_count":             "Fwd Byte Count",
    "bwd_byte_count":             "Bwd Byte Count",
    "iat_mean":                   "IAT Mean",
    "iat_std":                    "IAT Std Dev",
    "iat_max":                    "IAT Max",
    "iat_min":                    "IAT Min",
    "is_lateral":                 "Lateral Traffic",
    "is_outbound":                "Outbound Traffic",
    "is_inbound":                 "Inbound Traffic",
}

# Module-level cached explainer — built once, reused
_explainer_cache = None


def _get_explainer(model):
    """Build or return cached SHAP TreeExplainer."""
    global _explainer_cache
    if _explainer_cache is None:
        import shap
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _explainer_cache = shap.TreeExplainer(model)
        logger.info("[SHAP] TreeExplainer built and cached.")
    return _explainer_cache


def get_shap_explanation(
    model,
    features_array: np.ndarray,
    feature_names: List[str],
    predicted_class_idx: int = 0,
    top_n: int = 8,
) -> List[Dict]:
    """
    Compute SHAP feature contributions for a single prediction.

    Args:
        model:              Trained RandomForestClassifier
        features_array:     1D or 2D numpy array of feature values (scaled)
        feature_names:      List of feature name strings (must match model input)
        predicted_class_idx: Class index to explain (default: 0 = predicted class)
        top_n:              Number of top features to return (default: 8)

    Returns:
        List of dicts sorted by abs_contribution descending:
        [{"feature": str, "human_label": str, "contribution": float,
          "abs_contribution": float, "direction": str}]
        Returns empty list on failure (never raises).
    """
    try:
        import shap

        # Ensure 2D array shape
        if features_array.ndim == 1:
            features_array = features_array.reshape(1, -1)

        explainer = _get_explainer(model)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            shap_values = explainer.shap_values(features_array)

        # shap_values shape: (n_classes, n_samples, n_features) for RF classifiers
        # or (n_samples, n_features) for binary
        if isinstance(shap_values, list):
            # Multi-class: pick the predicted class slice
            idx = min(predicted_class_idx, len(shap_values) - 1)
            values = shap_values[idx][0]  # shape: (n_features,)
        else:
            values = shap_values[0]       # binary case

        if len(values) != len(feature_names):
            logger.warning(
                "[SHAP] Feature count mismatch: %d values vs %d names",
                len(values), len(feature_names),
            )
            return []

        results = []
        for fname, val in zip(feature_names, values):
            contribution = float(val)
            results.append({
                "feature":          fname,
                "human_label":      FEATURE_HUMAN_LABELS.get(fname, fname),
                "contribution":     round(contribution, 5),
                "abs_contribution": round(abs(contribution), 5),
                "direction":        "+" if contribution > 0 else "-",
            })

        # Sort by abs contribution descending, return top N
        results.sort(key=lambda x: x["abs_contribution"], reverse=True)
        return results[:top_n]

    except ImportError:
        logger.warning("[SHAP] shap package not installed — skipping explanation.")
        return []
    except Exception as exc:
        logger.warning("[SHAP] Explanation failed: %s", exc)
        return []


def build_shap_summary(shap_features: List[Dict]) -> str:
    """Return a one-line human-readable summary of top SHAP features."""
    if not shap_features:
        return "No explanation available."
    top = shap_features[0]
    pct = round(top["abs_contribution"] * 100, 1)
    return (
        f"Top factor: {top['human_label']} "
        f"({'+' if top['direction'] == '+' else '-'}{pct}% contribution)"
    )


if __name__ == "__main__":
    # Quick smoke test — needs a trained model
    print("SHAP Explainer module loaded. Import and call get_shap_explanation().")
    print("Available feature labels:", list(FEATURE_HUMAN_LABELS.keys()))
