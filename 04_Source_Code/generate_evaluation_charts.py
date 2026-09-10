import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from run_pipeline import generate_synthetic_dataset
from detection.random_forest_model import RandomForestDetector
from detection.svm_model import SVMDetector
from detection.xgboost_model import XGBoostDetector
from detection.ensemble_detector import EnsembleRansomwareDetector

# Style configuration for dark modern aesthetic
plt.style.use('dark_background')
DARK_BG = "#0B0F19"
PANEL_BG = "#131C2E"
TEXT_COLOR = "#E2E8F0"
ACCENT_BLUE = "#38BDF8"
ACCENT_GREEN = "#10B981"
ACCENT_RED = "#EF4444"
ACCENT_AMBER = "#F59E0B"

def plot_confusion_matrices(X_test, y_test, models, output_dir):
    """Generates 2x2 grid of confusion matrices for all 4 models."""
    fig, axes = plt.subplots(2, 2, figsize=(12, 10), facecolor=DARK_BG)
    fig.suptitle("Model Evaluation: Confusion Matrices", fontsize=18, fontweight='bold', color=TEXT_COLOR, y=0.98)

    scaler = StandardScaler()
    scaler.fit(X_test)
    X_scaled = scaler.transform(X_test)

    model_items = list(models.items())
    for idx, (name, model) in enumerate(model_items):
        ax = axes[idx // 2, idx % 2]
        ax.set_facecolor(PANEL_BG)

        if hasattr(model, 'predict'):
            if name == "Ensemble Detector":
                preds = [model.predict(x, is_pre_scaled=True)[0] for x in X_scaled]
            else:
                preds = model.model.predict(X_scaled)
        
        cm = confusion_matrix(y_test, preds)
        
        sns.heatmap(
            cm, 
            annot=True, 
            fmt='d', 
            cmap='Blues', 
            cbar=False, 
            ax=ax,
            annot_kws={"size": 14, "weight": "bold"},
            xticklabels=['Benign (0)', 'Ransomware (1)'],
            yticklabels=['Benign (0)', 'Ransomware (1)']
        )
        ax.set_title(name, fontsize=14, fontweight='bold', color=ACCENT_BLUE, pad=12)
        ax.set_xlabel('Predicted Class', fontsize=11, color=TEXT_COLOR, labelpad=8)
        ax.set_ylabel('True Class', fontsize=11, color=TEXT_COLOR, labelpad=8)
        ax.tick_params(colors=TEXT_COLOR)

    plt.tight_layout()
    out_path = os.path.join(output_dir, "confusion_matrices.png")
    plt.savefig(out_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved Confusion Matrices: {out_path}")

def plot_roc_curves(X_test, y_test, models, output_dir):
    """Plots multi-model ROC-AUC curves."""
    fig, ax = plt.subplots(figsize=(10, 7), facecolor=DARK_BG)
    ax.set_facecolor(PANEL_BG)

    scaler = StandardScaler()
    scaler.fit(X_test)
    X_scaled = scaler.transform(X_test)

    colors = [ACCENT_BLUE, ACCENT_GREEN, ACCENT_AMBER, "#C084FC"]

    for (name, model), color in zip(models.items(), colors):
        if name == "Ensemble Detector":
            y_probs = [model.predict(x, is_pre_scaled=True)[2] for x in X_scaled]
        else:
            y_probs = model.model.predict_proba(X_scaled)[:, 1]

        fpr, tpr, _ = roc_curve(y_test, y_probs)
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=color, lw=2.5, label=f"{name} (AUC = {roc_auc:.4f})")

    ax.plot([0, 1], [0, 1], color='#64748B', lw=1.5, linestyle='--', label="Chance Baseline (AUC = 0.50)")
    ax.set_xlim([-0.02, 1.02])
    ax.set_ylim([-0.02, 1.05])
    ax.set_xlabel('False Positive Rate (FPR)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_ylabel('True Positive Rate (TPR / Recall)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_title('Receiver Operating Characteristic (ROC) Comparison', fontsize=16, fontweight='bold', color=TEXT_COLOR, pad=15)
    ax.tick_params(colors=TEXT_COLOR)
    ax.grid(True, linestyle=':', alpha=0.3, color='#94A3B8')

    legend = ax.legend(loc="lower right", facecolor=DARK_BG, edgecolor='#334155', fontsize=11)
    for text in legend.get_texts():
        text.set_color(TEXT_COLOR)

    plt.tight_layout()
    out_path = os.path.join(output_dir, "roc_curves.png")
    plt.savefig(out_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved ROC Curves: {out_path}")

def plot_feature_importance(rf_model, feature_names, output_dir):
    """Generates ranking bar chart for behavioral feature importances."""
    importances = rf_model.model.feature_importances_
    indices = np.argsort(importances)

    sorted_names = [feature_names[i] for i in indices]
    sorted_importances = importances[indices]

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=DARK_BG)
    ax.set_facecolor(PANEL_BG)

    bars = ax.barh(range(len(indices)), sorted_importances, color=ACCENT_BLUE, edgecolor='none', height=0.6)
    
    # Highlight top 2 most influential features
    if len(bars) >= 2:
        bars[-1].set_color(ACCENT_RED)
        bars[-2].set_color(ACCENT_AMBER)

    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels(sorted_names, fontsize=11, color=TEXT_COLOR)
    ax.set_xlabel('Relative Importance Score (Random Forest Gini Impurity)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_title('Behavioural Feature Importance Ranking', fontsize=16, fontweight='bold', color=TEXT_COLOR, pad=15)
    ax.tick_params(colors=TEXT_COLOR)
    ax.grid(True, axis='x', linestyle=':', alpha=0.3, color='#94A3B8')

    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.005, bar.get_y() + bar.get_height()/2, f"{w*100:.1f}%", va='center', ha='left', fontsize=10, color=TEXT_COLOR, fontweight='bold')

    plt.tight_layout()
    out_path = os.path.join(output_dir, "feature_importance.png")
    plt.savefig(out_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved Feature Importance: {out_path}")

def plot_attack_timeline(output_dir):
    """Visualizes live behavioral transition from benign baseline to active ransomware burst."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7), sharex=True, facecolor=DARK_BG)
    ax1.set_facecolor(PANEL_BG)
    ax2.set_facecolor(PANEL_BG)

    time_steps = np.arange(0, 60)
    
    # Benign baseline (0-30s), Attack burst (30-60s)
    write_vel = np.concatenate([
        np.clip(np.random.normal(0.8, 0.3, 30), 0.1, 2.0),
        np.clip(np.random.normal(25.0, 5.0, 30), 12.0, 45.0)
    ])
    entropy = np.concatenate([
        np.clip(np.random.normal(3.8, 0.4, 30), 2.5, 4.8),
        np.clip(np.random.normal(7.7, 0.15, 30), 7.2, 7.95)
    ])

    # Plot 1: Write Velocity
    ax1.plot(time_steps[:31], write_vel[:31], color=ACCENT_GREEN, lw=2.2, label="Normal Operation")
    ax1.plot(time_steps[30:], write_vel[30:], color=ACCENT_RED, lw=2.5, label="Ransomware Encryption Burst")
    ax1.axhline(y=5.0, color=ACCENT_AMBER, linestyle='--', lw=1.5, label="Suspicious Velocity Threshold (5.0 writes/s)")
    ax1.axvline(x=30, color='#64748B', linestyle=':', lw=1.5)
    ax1.set_ylabel("Write Velocity (writes/s)", fontsize=11, color=TEXT_COLOR)
    ax1.set_title("Temporal Behavioural Dynamics: Benign Baseline to Ransomware Outbreak", fontsize=15, fontweight='bold', color=TEXT_COLOR, pad=12)
    ax1.tick_params(colors=TEXT_COLOR)
    ax1.grid(True, linestyle=':', alpha=0.3, color='#94A3B8')
    leg1 = ax1.legend(loc="upper left", facecolor=DARK_BG, edgecolor='#334155', fontsize=10)
    for text in leg1.get_texts():
        text.set_color(TEXT_COLOR)

    # Plot 2: Shannon Entropy
    ax2.plot(time_steps[:31], entropy[:31], color=ACCENT_BLUE, lw=2.2, label="Plaintext Documents (2.5 - 4.5 bits)")
    ax2.plot(time_steps[30:], entropy[30:], color=ACCENT_RED, lw=2.5, label="Ciphertext Overwrite (> 7.2 bits)")
    ax2.axhline(y=7.2, color=ACCENT_RED, linestyle='--', lw=1.5, label="Critical Encryption Threshold (7.2 bits)")
    ax2.axvline(x=30, color='#64748B', linestyle=':', lw=1.5)
    ax2.set_xlabel("Time (seconds)", fontsize=11, color=TEXT_COLOR, labelpad=8)
    ax2.set_ylabel("Shannon Entropy (bits)", fontsize=11, color=TEXT_COLOR)
    ax2.tick_params(colors=TEXT_COLOR)
    ax2.grid(True, linestyle=':', alpha=0.3, color='#94A3B8')
    leg2 = ax2.legend(loc="upper left", facecolor=DARK_BG, edgecolor='#334155', fontsize=10)
    for text in leg2.get_texts():
        text.set_color(TEXT_COLOR)

    plt.tight_layout()
    out_path = os.path.join(output_dir, "attack_timeline.png")
    plt.savefig(out_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Saved Attack Timeline: {out_path}")

def generate_all():
    repo_root = os.path.dirname(BASE_DIR)
    results_dir = os.path.join(repo_root, "06_Result_or_Expected_Outcome")
    os.makedirs(results_dir, exist_ok=True)

    print("\n[*] Synthesizing data & training benchmark models for chart generation...")
    df = generate_synthetic_dataset(1500)
    feature_names = [c for c in df.columns if c != 'label']
    X = df[feature_names].values
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    rf = RandomForestDetector()
    rf.train(X_train, y_train, feature_names=feature_names)

    svm = SVMDetector()
    svm.train(X_train, y_train, feature_names=feature_names)

    xgb = XGBoostDetector()
    xgb.train(X_train, y_train, feature_names=feature_names)

    ensemble = EnsembleRansomwareDetector(use_soft_voting=True)
    ensemble.train(X_train, y_train, feature_names=feature_names)

    models = {
        "Random Forest": rf,
        "SVM (RBF Kernel)": svm,
        "XGBoost": xgb,
        "Ensemble Detector": ensemble
    }

    print("[*] Rendering high-resolution visualization charts...")
    plot_confusion_matrices(X_test, y_test, models, results_dir)
    plot_roc_curves(X_test, y_test, models, results_dir)
    plot_feature_importance(rf, feature_names, results_dir)
    plot_attack_timeline(results_dir)
    print("\n[SUCCESS] All 4 evaluation charts generated successfully!\n")

if __name__ == '__main__':
    generate_all()
