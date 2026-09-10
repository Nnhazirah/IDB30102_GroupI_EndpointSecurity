import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler

class EnsembleRansomwareDetector:
    """
    Multi-Model Ensemble Detector combining Random Forest, XGBoost, and SVM.
    Supports soft voting (probability weighted) and hard voting (majority rule)
    with 3-tier risk classification: Benign, Suspicious, Ransomware.
    """

    def __init__(self, use_soft_voting=True, random_state=42):
        self.use_soft_voting = use_soft_voting
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False

        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=random_state,
                class_weight='balanced'
            ),
            'xgboost': XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=random_state,
                eval_metric='logloss'
            ),
            'svm': SVC(
                kernel='rbf',
                C=1.0,
                probability=True,
                random_state=random_state,
                class_weight='balanced'
            )
        }

    def _format_input(self, features):
        """Converts dict, list, Series, or DataFrame into 2D numpy array."""
        if isinstance(features, dict):
            if self.feature_names:
                vals = [features.get(f, 0.0) for f in self.feature_names]
            else:
                vals = list(features.values())
            return np.array([vals], dtype=float)
        elif isinstance(features, pd.DataFrame):
            return features.values
        elif isinstance(features, (list, tuple)):
            arr = np.array(features, dtype=float)
            return arr.reshape(1, -1) if arr.ndim == 1 else arr
        elif isinstance(features, np.ndarray):
            return features.reshape(1, -1) if features.ndim == 1 else features
        else:
            raise ValueError(f"Unsupported features type: {type(features)}")

    def train(self, X, y, feature_names=None):
        """Trains all base models and evaluates individual and ensemble performance."""
        if isinstance(X, pd.DataFrame):
            self.feature_names = list(X.columns)
            X_arr = X.values
        else:
            self.feature_names = feature_names
            X_arr = np.array(X, dtype=float)

        y_arr = np.array(y, dtype=int)

        X_train, X_test, y_train, y_test = train_test_split(
            X_arr, y_arr, test_size=0.2, random_state=self.random_state, stratify=y_arr
        )

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        results = {}

        for name, model in self.models.items():
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
            results[name] = {
                'accuracy': float(accuracy_score(y_test, y_pred)),
                'precision': float(precision_score(y_test, y_pred, zero_division=0)),
                'recall': float(recall_score(y_test, y_pred, zero_division=0)),
                'f1_score': float(f1_score(y_test, y_pred, zero_division=0))
            }

        self.is_trained = True

        # Evaluate ensemble on test set
        ensemble_preds = []
        for i in range(len(X_test_scaled)):
            pred, _, _, _ = self.predict(X_test_scaled[i], is_pre_scaled=True)
            ensemble_preds.append(pred)

        results['ensemble'] = {
            'accuracy': float(accuracy_score(y_test, ensemble_preds)),
            'precision': float(precision_score(y_test, ensemble_preds, zero_division=0)),
            'recall': float(recall_score(y_test, ensemble_preds, zero_division=0)),
            'f1_score': float(f1_score(y_test, ensemble_preds, zero_division=0))
        }

        return results

    def predict(self, features, is_pre_scaled=False):
        """
        Predicts classification for input features.
        Returns:
            ensemble_pred (int): 0 for benign, 1 for ransomware
            risk_level (str): 'Benign', 'Suspicious', or 'Ransomware'
            confidence (float): Confidence score (0.0 to 1.0)
            breakdown (dict): Individual model predictions and probabilities
        """
        if not self.is_trained:
            raise RuntimeError("Ensemble is not trained. Call train() or load_models() first.")

        if is_pre_scaled:
            X_scaled = features.reshape(1, -1) if features.ndim == 1 else features
        else:
            X = self._format_input(features)
            X_scaled = self.scaler.transform(X)

        individual_preds = {}
        probabilities = []

        for name, model in self.models.items():
            pred = int(model.predict(X_scaled)[0])
            prob = model.predict_proba(X_scaled)[0]
            individual_preds[name] = {
                'prediction': pred,
                'probabilities': [float(p) for p in prob]
            }
            probabilities.append(prob)

        probabilities = np.array(probabilities)

        if self.use_soft_voting:
            avg_probs = np.mean(probabilities, axis=0)
            ransomware_prob = float(avg_probs[1]) if len(avg_probs) > 1 else float(avg_probs[0])
            ensemble_pred = 1 if ransomware_prob >= 0.5 else 0
            confidence = float(np.max(avg_probs))
        else:
            votes = [p['prediction'] for p in individual_preds.values()]
            ensemble_pred = int(np.bincount(votes).argmax())
            confidence = float(votes.count(ensemble_pred) / len(votes))
            ransomware_prob = float(votes.count(1) / len(votes))

        # 3-tier risk assessment aligned with architecture specification
        if ransomware_prob >= 0.8:
            risk_level = 'Ransomware'
        elif ransomware_prob >= 0.4:
            risk_level = 'Suspicious'
        else:
            risk_level = 'Benign'

        breakdown = {
            'individual_models': individual_preds,
            'ransomware_probability': round(ransomware_prob, 4),
            'soft_voting': self.use_soft_voting
        }

        return ensemble_pred, risk_level, round(confidence, 4), breakdown

    def save_models(self, directory):
        """Saves all models, scaler, and metadata into target directory."""
        os.makedirs(directory, exist_ok=True)
        for name, model in self.models.items():
            joblib.dump(model, os.path.join(directory, f"{name}_model.pkl"))
        joblib.dump({
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'use_soft_voting': self.use_soft_voting
        }, os.path.join(directory, "ensemble_metadata.pkl"))

    def load_models(self, directory):
        """Loads all trained models, scaler, and metadata from directory."""
        for name in self.models.keys():
            model_path = os.path.join(directory, f"{name}_model.pkl")
            if os.path.exists(model_path):
                self.models[name] = joblib.load(model_path)
        meta_path = os.path.join(directory, "ensemble_metadata.pkl")
        if os.path.exists(meta_path):
            meta = joblib.load(meta_path)
            self.scaler = meta.get('scaler', self.scaler)
            self.feature_names = meta.get('feature_names')
            self.is_trained = meta.get('is_trained', True)
            self.use_soft_voting = meta.get('use_soft_voting', self.use_soft_voting)
