"""ml.detector_template — on-device inference template (Phase 0 SAFE stub).

The Pi runs **inference only**: training happens off-device and an exported
model is dropped into `data/models/`. With no model present (Phase 0), this
module reports `is_available -> False` and is skipped cleanly — it never
crashes a run, and a missing or version-incompatible model is treated the same
way (CLAUDE.md: "treat a missing or incompatible model as is_available -> False").

Copy this file to make a real detector: declare the capability you emit, point
`MODEL_NAME` at your exported model, and implement `extract_features`.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from core.module import Module, Manifest
from core.registry import register
from core.schema import Severity

# Name (or glob) of the exported model this detector expects in data/models/.
MODEL_NAME = "detector_template.pkl"


@register
class DetectorTemplate(Module):
    manifest = Manifest(
        name="ml.detector_template",
        category="ml",
        title="ML detector (template)",
        description="On-device inference template; loads an exported model and "
                    "scores extracted features",
        provides=["ml_detections"],
        depends_on=["capture"],   # consumes what blue capture publishes
    )

    # --- availability -----------------------------------------------------
    def is_available(self, ctx) -> Tuple[bool, str]:
        model_path = ctx.config.models_dir / MODEL_NAME
        if not model_path.exists():
            return (False, f"no model at {model_path}")
        try:
            import joblib  # noqa: F401  (ships with scikit-learn)
        except Exception:  # noqa: BLE001
            return (False, "joblib/scikit-learn not importable")
        return (True, "")

    # --- feature-extraction interface (the extension point) ---------------
    def extract_features(self, ctx) -> List[list]:
        """Return a list of feature rows for the model to score.

        Override in a real detector. Typically reads an artifact published by an
        upstream module, e.g. ``pcap = ctx.store.get("capture.pcap")``, and turns
        it into numeric rows. The template has no features to extract.
        """
        return []

    # --- model loading ----------------------------------------------------
    def _load_model(self, ctx) -> Optional[object]:
        import joblib
        model_path = ctx.config.models_dir / MODEL_NAME
        try:
            return joblib.load(model_path)
        except Exception as e:  # noqa: BLE001 — incompatible model != crash
            ctx.log.warning("model load failed (%s); treating as unavailable", e)
            return None

    # --- run --------------------------------------------------------------
    def run(self, ctx) -> None:
        model = self._load_model(ctx)
        if model is None:
            ctx.store.add_finding(
                module=self.manifest.name, type="module_status",
                severity=Severity.INFO, target=ctx.target or "(no target)",
                title="ML detector skipped (model unavailable)",
                detail="Model present but failed to load.", tags=["ml", "stub"],
            )
            return

        rows = self.extract_features(ctx)
        if not rows:
            ctx.store.add_finding(
                module=self.manifest.name, type="module_status",
                severity=Severity.INFO, target=ctx.target or "(no target)",
                title="ML detector: no input features",
                detail="No upstream artifact to score (e.g. no capture).",
                tags=["ml", "stub"],
            )
            return

        try:
            predictions = model.predict(rows)
        except Exception as e:  # noqa: BLE001
            ctx.log.warning("inference failed: %s", e)
            return

        # A real detector maps each positive prediction to a Finding here.
        positives = sum(1 for p in predictions if p)
        ctx.store.add_finding(
            module=self.manifest.name, type="ml_detection_summary",
            severity=Severity.INFO, target=ctx.target or "(no target)",
            title=f"ML detector scored {len(rows)} rows ({positives} positive)",
            detail="Template summary; a real detector emits one finding per "
                   "detection.",
            tags=["ml"],
        )
