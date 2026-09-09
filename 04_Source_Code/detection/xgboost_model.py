import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
import joblib

class XGBoostDetector:
    
    def __init__(self, n_estimators=100, max_depth=6, learning_rate=0.1):
        self.model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=42,
            scale_pos_weight=1
        )
        self.scaler = StandardScaler()
        
    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        self.model.fit(X_train_scaled, y_train)
        
        y_pred = self.model.predict(X_test_scaled)
        
        results = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred)
        }
        
        cv_scores = cross_val_score(
            self.model, X_train_scaled, y_train, cv=5
        )
        results['cv_mean'] = cv_scores.mean()
        results['cv_std'] = cv_scores.std()
        
        return results
    
    def predict(self, features):
        features_scaled = self.scaler.transform([features])
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        confidence = max(probability)
        
        return prediction, probability, confidence
    
    def save_model(self, filepath):
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler
        }, filepath)
    
    def load_model(self, filepath):
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
