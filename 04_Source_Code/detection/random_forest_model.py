import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler

class RandomForestDetector:
    """
    Random Forest Classifier for ransomware behavioral detection.
    Features: Write velocity, Shannon entropy, entropy delta, rename rate,
    directory coverage, API frequency, shadow copy attempts, file modification counts.
    """

    def __init__(self, n_estimators=100, max_depth=10, random_state=42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False

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
        """Trains the Random Forest model and evaluates baseline performance."""
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

        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True

        y_pred = self.model.predict(X_test_scaled)

        results = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_test, y_pred, zero_division=0))
        }

        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=min(5, len(y_train)))
        results['cv_mean'] = float(cv_scores.mean())
        results['cv_std'] = float(cv_scores.std())

        return results

    def predict(self, features):
        """Predicts whether an event or feature set is benign (0) or ransomware (1)."""
        if not self.is_trained:
            raise RuntimeError("Model is not trained. Call train() or load_model() first.")

        X = self._format_input(features)
        X_scaled = self.scaler.transform(X)

        pred = int(self.model.predict(X_scaled)[0])
        probabilities = self.model.predict_proba(X_scaled)[0].tolist()
        confidence = float(max(probabilities))

        return pred, probabilities, confidence

    def get_feature_importance(self, feature_names=None):
        """Returns mapping of feature names to their importance scores."""
        if not self.is_trained:
            raise RuntimeError("Model is not trained.")
        names = feature_names or self.feature_names or [f"f_{i}" for i in range(len(self.model.feature_importances_))]
        importance = self.model.feature_importances_
        return {name: float(imp) for name, imp in zip(names, importance)}

    def save_model(self, filepath):
        """Persists trained model, scaler, and feature metadata."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }, filepath)

    def load_model(self, filepath):
        """Loads saved model and metadata."""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data.get('feature_names')
        self.is_trained = data.get('is_trained', True)
