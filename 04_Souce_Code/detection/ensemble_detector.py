import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
import joblib

class EnsembleRansomwareDetector:
    
    def __init__(self, use_soft_voting=True):
        self.use_soft_voting = use_soft_voting
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            ),
            'xgboost': XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            ),
            'svm': SVC(
                kernel='rbf',
                C=1.0,
                probability=True,
                random_state=42
            )
        }
        
    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        results = {}
        
        for name, model in self.models.items():
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            results[name] = {
                'accuracy': accuracy_score(y_test, y_pred),
                'f1_score': f1_score(y_test, y_pred)
            }
        
        return results
    
    def predict(self, features):
        features = np.array([features])
        predictions = []
        probabilities = []
        
        for name, model in self.models.items():
            pred = model.predict(features)[0]
            predictions.append(pred)
            
            if hasattr(model, 'predict_proba'):
                prob = model.predict_proba(features)[0]
                probabilities.append(prob)
        
        if self.use_soft_voting:
            avg_probs = np.mean(probabilities, axis=0)
            ensemble_pred = np.argmax(avg_probs)
            confidence = np.max(avg_probs)
        else:
            ensemble_pred = np.bincount(predictions).argmax()
            confidence = np.sum(np.array(predictions) == ensemble_pred) / len(predictions)
        
        return ensemble_pred, confidence, predictions
    
    def save_models(self, directory):
        for name, model in self.models.items():
            joblib.dump(model, f"{directory}/{name}_model.pkl")
    
    def load_models(self, directory):
        for name in self.models.keys():
            self.models[name] = joblib.load(f"{directory}/{name}_model.pkl")
