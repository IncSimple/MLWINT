from pathlib import Path
from typing import Literal
   
import lightgbm as lgb
import numpy as np
import xgboost as xgb
   
   
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = PROJECT_ROOT / "src" / "models" / "candidates"
EXPECTED_FEATURES = 2381
   
ModelName = Literal["lightgbm", "xgboost", "ensemble"]
   
   
class MalwarePredictor:
       """Inference wrapper for the trained MLWINT EMBER models."""
   
       def __init__(self, model_name: ModelName = "lightgbm") -> None:
           if model_name not in {"lightgbm", "xgboost", "ensemble"}:
               raise ValueError(f"Unsupported model: {model_name}")
   
           self.model_name = model_name
   
           self.lightgbm_model = None
           self.xgboost_model = None
   
           if model_name in {"lightgbm", "ensemble"}:
               path = MODEL_DIR / "lightgbm_baseline.txt"
               if not path.is_file():
                   raise FileNotFoundError(f"LightGBM model not found: {path}")
               self.lightgbm_model = lgb.Booster(model_file=str(path))
   
           if model_name in {"xgboost", "ensemble"}:
               path = MODEL_DIR / "xgboost_ember.json"
               if not path.is_file():
                   raise FileNotFoundError(f"XGBoost model not found: {path}")
               self.xgboost_model = xgb.XGBClassifier()
               self.xgboost_model.load_model(str(path))
   
       @staticmethod
       def _validate_features(features: np.ndarray) -> np.ndarray:
           X = np.asarray(features, dtype=np.float32)
   
           if X.ndim == 1:
               X = X.reshape(1, -1)
   
           if X.ndim != 2:
               raise ValueError("Features must be a 1D or 2D array.")
   
           if X.shape[1] != EXPECTED_FEATURES:
               raise ValueError(
                   f"Expected {EXPECTED_FEATURES} features per sample; "
                   f"received {X.shape[1]}."
               )
   
           if not np.isfinite(X).all():
               raise ValueError("Features contain NaN or infinite values.")
   
           return X
   
       def predict_proba(self, features: np.ndarray) -> np.ndarray:
           """Return the probability of the malicious class for each sample."""
           X = self._validate_features(features)
   
           if self.model_name == "lightgbm":
               probabilities = self.lightgbm_model.predict(X)
   
           elif self.model_name == "xgboost":
               probabilities = self.xgboost_model.predict_proba(X)[:, 1]
   
           else:
               lightgbm_prob = self.lightgbm_model.predict(X)
               xgboost_prob = self.xgboost_model.predict_proba(X)[:, 1]
               probabilities = (lightgbm_prob + xgboost_prob) / 2.0
   
           return np.asarray(probabilities, dtype=np.float64)
   
       def predict(
           self,
           features: np.ndarray,
           threshold: float = 0.5,
       ) -> np.ndarray:
           """Return 0 for benign and 1 for malicious predictions."""
           if not 0.0 <= threshold <= 1.0:
               raise ValueError("Threshold must be between 0 and 1.")
   
           return (self.predict_proba(features) >= threshold).astype(np.int8)