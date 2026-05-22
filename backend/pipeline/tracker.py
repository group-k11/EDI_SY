"""
Pipeline Tracker — A.I.R.S Backend
Records every step of the detection pipeline with timestamps.
Powers the "visual process flow" for the frontend and presentation demo.
"""

import time
from typing import List, Optional, Dict
from dataclasses import dataclass, field


@dataclass
class PipelineStep:
    """A single step in the A.I.R.S detection pipeline."""
    step_name:      str
    status:         str = "pending"        # pending | running | complete | error
    started_at:     Optional[float] = None  # unix timestamp
    completed_at:   Optional[float] = None  # unix timestamp
    duration_ms:    Optional[float] = None  # milliseconds
    output_summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "step_name":      self.step_name,
            "status":         self.status,
            "started_at":     self.started_at,
            "completed_at":   self.completed_at,
            "duration_ms":    round(self.duration_ms, 2) if self.duration_ms else None,
            "output_summary": self.output_summary,
        }


# Canonical 9-step pipeline order
PIPELINE_STEP_NAMES = [
    "Packet Captured",
    "Flow Features Extracted",
    "ML Classification",
    "SHAP Analysis",
    "MITRE Mapping",
    "Severity Scoring",
    "LLM Analysis",
    "Response Action",
    "Alert Logged",
]


class PipelineTracker:
    """
    Tracks the step-by-step journey of a single threat through A.I.R.S.

    Usage:
        tracker = PipelineTracker()
        tracker.start_step("Packet Captured")
        # ... do work ...
        tracker.complete_step("Packet Captured", "47 packets from 10.0.0.5")
        tracker.start_step("ML Classification")
        # ... run model ...
        tracker.complete_step("ML Classification", "DDoS @ 94%")
    """

    def __init__(self):
        self.steps: List[PipelineStep] = [
            PipelineStep(step_name=name) for name in PIPELINE_STEP_NAMES
        ]
        self._index: Dict[str, PipelineStep] = {
            s.step_name: s for s in self.steps
        }

    def _get(self, step_name: str) -> Optional[PipelineStep]:
        return self._index.get(step_name)

    def start_step(self, step_name: str) -> None:
        """Mark a step as running and record start time."""
        step = self._get(step_name)
        if step:
            step.status = "running"
            step.started_at = time.time()

    def complete_step(self, step_name: str, output_summary: str = "") -> None:
        """Mark a step as complete, record end time and compute duration."""
        step = self._get(step_name)
        if step:
            step.status = "complete"
            step.completed_at = time.time()
            step.output_summary = output_summary
            if step.started_at:
                step.duration_ms = (step.completed_at - step.started_at) * 1000

    def fail_step(self, step_name: str, error: str = "") -> None:
        """Mark a step as failed with an error message."""
        step = self._get(step_name)
        if step:
            step.status = "error"
            step.completed_at = time.time()
            step.output_summary = f"ERROR: {error}"
            if step.started_at:
                step.duration_ms = (step.completed_at - step.started_at) * 1000

    def to_dict(self) -> Dict:
        """
        Serialize full pipeline state.
        Returns steps list + total_duration_ms (sum of all completed steps).
        """
        completed = [
            s for s in self.steps
            if s.status in ("complete", "error") and s.duration_ms is not None
        ]
        total_ms = sum(s.duration_ms for s in completed if s.duration_ms)
        return {
            "steps":            [s.to_dict() for s in self.steps],
            "total_duration_ms": round(total_ms, 2),
            "steps_completed":  len(completed),
            "steps_total":      len(self.steps),
            "has_error":        any(s.status == "error" for s in self.steps),
        }

    def get_final_step_label(self) -> str:
        """Return the last completed step's name."""
        completed = [s for s in self.steps if s.status == "complete"]
        return completed[-1].step_name if completed else "Not started"

    def get_last_action(self) -> str:
        """Return the output summary of the last completed step."""
        completed = [s for s in self.steps if s.status == "complete"]
        return completed[-1].output_summary if completed else ""


if __name__ == "__main__":
    import time

    t = PipelineTracker()

    t.start_step("Packet Captured")
    time.sleep(0.01)
    t.complete_step("Packet Captured", "20 features extracted from 47 packets")

    t.start_step("Flow Features Extracted")
    time.sleep(0.005)
    t.complete_step("Flow Features Extracted", "320 pkt/s | 0.87 SYN ratio | 25 features")

    t.start_step("ML Classification")
    time.sleep(0.02)
    t.complete_step("ML Classification", "DDoS detected — confidence 0.94")

    t.start_step("SHAP Analysis")
    time.sleep(0.008)
    t.complete_step("SHAP Analysis", "Top: Packet Rate (+42% contribution)")

    result = t.to_dict()
    print("Steps completed:", result["steps_completed"])
    print("Total time:", result["total_duration_ms"], "ms")
    print("Last step:", t.get_final_step_label())
    for s in result["steps"]:
        status_icon = {"complete": "✅", "pending": "⏳", "running": "🔄", "error": "❌"}.get(s["status"], "?")
        print(f"  {status_icon} {s['step_name']}: {s['output_summary'] or s['status']}")
