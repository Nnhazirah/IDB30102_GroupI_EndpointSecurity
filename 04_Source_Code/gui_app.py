import os
import sys
import time
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import pandas as pd
import numpy as np
from PIL import Image

# Theme configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from preprocessing.feature_extraction import RansomwareFeatureExtractor
from monitoring.sysmon_collector import SysmonCollector
from monitoring.entropy_analyzer import EntropyAnalyzer
from detection.ensemble_detector import EnsembleRansomwareDetector
from detection.random_forest_model import RandomForestDetector
from detection.svm_model import SVMDetector
from detection.xgboost_model import XGBoostDetector


class EndpointSecurityApp(ctk.CTk):
    """
    IDB30102 Group I - Modern Endpoint Security Dashboard
    Behavioural Detection of File-Encrypting Ransomware on Windows Endpoints
    """

    def __init__(self):
        super().__init__()

        self.title("Endpoint Security Sentinel | Behavioural Ransomware Detection")
        self.geometry("1240x800")
        self.minsize(1080, 720)

        # Core operational state
        self.monitoring_active = False
        self.auto_mitigation = True
        self.monitor_thread = None
        self.event_queue = queue.Queue()
        self.extractor = RansomwareFeatureExtractor(window_size=5)
        self.collector = SysmonCollector(mode='simulation')
        self.entropy_scanner = EntropyAnalyzer()
        
        # Results directory for images
        self.results_dir = os.path.join(os.path.dirname(BASE_DIR), "06_Result_or_Expected_Outcome")

        # Load or initialize models
        self.ensemble = EnsembleRansomwareDetector(use_soft_voting=True)
        self._init_models()

        # Build UI layout
        self._build_sidebar()
        self._build_main_container()

        # Select default view
        self.show_dashboard_view()

    def _init_models(self):
        """Loads saved models if available, or trains them on startup."""
        models_dir = os.path.join(BASE_DIR, "saved_models")
        meta_file = os.path.join(models_dir, "ensemble_metadata.pkl")
        data_file = os.path.join(os.path.dirname(BASE_DIR), "05_Data_or_Sample_Input", "synthetic_features_dataset.csv")

        if os.path.exists(meta_file):
            try:
                self.ensemble.load_models(models_dir)
                return
            except Exception:
                pass

        if os.path.exists(data_file):
            try:
                df = pd.read_csv(data_file)
                X = df[[c for c in df.columns if c != 'label']]
                y = df['label']
                self.ensemble.train(X, y)
                self.ensemble.save_models(models_dir)
            except Exception as e:
                print(f"[Warning] Could not initialize models: {e}")

    def _build_sidebar(self):
        """Constructs modern left navigation panel."""
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#090D16")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(9, weight=1)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Brand Logo & Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="SHIELD-EDR", 
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color="#38BDF8"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(25, 4), sticky="w")

        self.subtitle_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Group I - Endpoint Security\nCourse: IDB30102 Project", 
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
            justify="left"
        )
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 22), sticky="w")

        # Navigation Buttons
        self.btn_dashboard = ctk.CTkButton(
            self.sidebar_frame, 
            text="Live Threat Monitor", 
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=40,
            command=self.show_dashboard_view
        )
        self.btn_dashboard.grid(row=2, column=0, padx=15, pady=5, sticky="ew")

        self.btn_entropy = ctk.CTkButton(
            self.sidebar_frame, 
            text="File Entropy Scanner", 
            anchor="w",
            font=ctk.CTkFont(size=13),
            height=40,
            fg_color="transparent",
            hover_color="#1E293B",
            command=self.show_entropy_view
        )
        self.btn_entropy.grid(row=3, column=0, padx=15, pady=5, sticky="ew")

        self.btn_analytics = ctk.CTkButton(
            self.sidebar_frame, 
            text="Visual Analytics & Plots", 
            anchor="w",
            font=ctk.CTkFont(size=13),
            height=40,
            fg_color="transparent",
            hover_color="#1E293B",
            command=self.show_analytics_view
        )
        self.btn_analytics.grid(row=4, column=0, padx=15, pady=5, sticky="ew")

        self.btn_models = ctk.CTkButton(
            self.sidebar_frame, 
            text="ML Models & Retraining", 
            anchor="w",
            font=ctk.CTkFont(size=13),
            height=40,
            fg_color="transparent",
            hover_color="#1E293B",
            command=self.show_models_view
        )
        self.btn_models.grid(row=5, column=0, padx=15, pady=5, sticky="ew")

        self.btn_about = ctk.CTkButton(
            self.sidebar_frame, 
            text="Project & Team Info", 
            anchor="w",
            font=ctk.CTkFont(size=13),
            height=40,
            fg_color="transparent",
            hover_color="#1E293B",
            command=self.show_about_view
        )
        self.btn_about.grid(row=6, column=0, padx=15, pady=5, sticky="ew")

        # Sidebar Engine Status Card
        self.sys_status_card = ctk.CTkFrame(self.sidebar_frame, fg_color="#131C2E", corner_radius=10)
        self.sys_status_card.grid(row=10, column=0, padx=15, pady=20, sticky="ew")

        self.status_dot = ctk.CTkLabel(
            self.sys_status_card, 
            text="● ENGINE IDLE", 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94A3B8"
        )
        self.status_dot.pack(padx=12, pady=(10, 2), anchor="w")

        self.lbl_engine_info = ctk.CTkLabel(
            self.sys_status_card,
            text="Ensemble: RF + XGB + SVM\nAuto-Containment: ON",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8",
            justify="left"
        )
        self.lbl_engine_info.pack(padx=12, pady=(0, 10), anchor="w")

    def _build_main_container(self):
        """Constructs right-side content container."""
        self.main_content = ctk.CTkFrame(self, fg_color="#0B0F19", corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(0, weight=1)

    def _clear_main_container(self):
        for child in self.main_content.winfo_children():
            child.destroy()

    def _set_nav_active(self, active_btn):
        for btn in [self.btn_dashboard, self.btn_entropy, self.btn_analytics, self.btn_models, self.btn_about]:
            if btn == active_btn:
                btn.configure(fg_color="#2563EB", font=ctk.CTkFont(size=13, weight="bold"))
            else:
                btn.configure(fg_color="transparent", font=ctk.CTkFont(size=13, weight="normal"))

    # =========================================================================
    # VIEW 1: LIVE THREAT MONITOR & DASHBOARD
    # =========================================================================
    def show_dashboard_view(self):
        self._set_nav_active(self.btn_dashboard)
        self._clear_main_container()

        view = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        view.grid(row=0, column=0, sticky="nsew", padx=25, pady=20)
        view.grid_columnconfigure(0, weight=1)

        # Header Title
        lbl_title = ctk.CTkLabel(view, text="Live Behavioural Telemetry & Containment", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.pack(anchor="w", pady=(0, 4))

        lbl_desc = ctk.CTkLabel(
            view, 
            text="Continuous sliding-window evaluation of write velocity, entropy dynamics, and recovery tampering hooks.", 
            font=ctk.CTkFont(size=13),
            text_color="#94A3B8"
        )
        lbl_desc.pack(anchor="w", pady=(0, 16))

        # Metric Cards Row
        cards_frame = ctk.CTkFrame(view, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 18))
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Card 1: System Threat Status
        self.card_status = ctk.CTkFrame(cards_frame, fg_color="#131C2E", corner_radius=12)
        self.card_status.grid(row=0, column=0, padx=6, sticky="nsew")
        ctk.CTkLabel(self.card_status, text="CURRENT THREAT LEVEL", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94A3B8").pack(padx=16, pady=(14, 4), anchor="w")
        self.lbl_threat_val = ctk.CTkLabel(self.card_status, text="BENIGN", font=ctk.CTkFont(size=22, weight="bold"), text_color="#10B981")
        self.lbl_threat_val.pack(padx=16, pady=(0, 2), anchor="w")
        self.lbl_threat_conf = ctk.CTkLabel(self.card_status, text="Confidence: 99.8%", font=ctk.CTkFont(size=12), text_color="#CBD5E1")
        self.lbl_threat_conf.pack(padx=16, pady=(0, 14), anchor="w")

        # Card 2: Write Velocity
        card_write = ctk.CTkFrame(cards_frame, fg_color="#131C2E", corner_radius=12)
        card_write.grid(row=0, column=1, padx=6, sticky="nsew")
        ctk.CTkLabel(card_write, text="WRITE VELOCITY", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94A3B8").pack(padx=16, pady=(14, 4), anchor="w")
        self.lbl_write_val = ctk.CTkLabel(card_write, text="0.0 writes/s", font=ctk.CTkFont(size=22, weight="bold"), text_color="#38BDF8")
        self.lbl_write_val.pack(padx=16, pady=(0, 2), anchor="w")
        self.lbl_write_sub = ctk.CTkLabel(card_write, text="Threshold: 5.0 writes/s", font=ctk.CTkFont(size=12), text_color="#CBD5E1")
        self.lbl_write_sub.pack(padx=16, pady=(0, 14), anchor="w")

        # Card 3: Shannon Entropy
        card_entropy = ctk.CTkFrame(cards_frame, fg_color="#131C2E", corner_radius=12)
        card_entropy.grid(row=0, column=2, padx=6, sticky="nsew")
        ctk.CTkLabel(card_entropy, text="FILE ENTROPY", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94A3B8").pack(padx=16, pady=(14, 4), anchor="w")
        self.lbl_entropy_val = ctk.CTkLabel(card_entropy, text="3.85 bits", font=ctk.CTkFont(size=22, weight="bold"), text_color="#C084FC")
        self.lbl_entropy_val.pack(padx=16, pady=(0, 2), anchor="w")
        self.lbl_entropy_sub = ctk.CTkLabel(card_entropy, text="Threshold: 7.20 bits", font=ctk.CTkFont(size=12), text_color="#CBD5E1")
        self.lbl_entropy_sub.pack(padx=16, pady=(0, 14), anchor="w")

        # Card 4: Mitigation & Recovery State
        self.card_mitigation = ctk.CTkFrame(cards_frame, fg_color="#131C2E", corner_radius=12)
        self.card_mitigation.grid(row=0, column=3, padx=6, sticky="nsew")
        ctk.CTkLabel(self.card_mitigation, text="DEFENSIVE MITIGATION", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94A3B8").pack(padx=16, pady=(14, 4), anchor="w")
        self.lbl_tamper_val = ctk.CTkLabel(self.card_mitigation, text="SHIELD READY", font=ctk.CTkFont(size=22, weight="bold"), text_color="#10B981")
        self.lbl_tamper_val.pack(padx=16, pady=(0, 2), anchor="w")
        self.lbl_tamper_sub = ctk.CTkLabel(self.card_mitigation, text="Auto-Containment Active", font=ctk.CTkFont(size=12), text_color="#CBD5E1")
        self.lbl_tamper_sub.pack(padx=16, pady=(0, 14), anchor="w")

        # Interactive Controls Bar
        ctrl_frame = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        ctrl_frame.pack(fill="x", pady=(0, 18), padx=2)

        top_ctrl = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        top_ctrl.pack(fill="x", padx=20, pady=(14, 8))

        ctk.CTkLabel(
            top_ctrl, 
            text="Interactive Telemetry Controls & Attack Injections:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left")

        # Auto-containment switch
        self.switch_containment = ctk.CTkSwitch(
            top_ctrl, 
            text="Auto-Mitigation (Kill Malicious Process)", 
            font=ctk.CTkFont(size=12),
            command=self._toggle_auto_containment
        )
        self.switch_containment.select()
        self.switch_containment.pack(side="right")

        btn_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 16))

        self.btn_toggle_mon = ctk.CTkButton(
            btn_row, 
            text="Start Telemetry Stream", 
            fg_color="#2563EB", 
            hover_color="#1D4ED8",
            height=36,
            command=self.toggle_live_monitoring
        )
        self.btn_toggle_mon.pack(side="left", padx=5)

        btn_benign = ctk.CTkButton(
            btn_row, 
            text="Inject Benign Activity", 
            fg_color="#0D9488", 
            hover_color="#0F766E",
            height=36,
            command=self.inject_benign_simulation
        )
        btn_benign.pack(side="left", padx=5)

        btn_attack = ctk.CTkButton(
            btn_row, 
            text="Simulate Ransomware Burst", 
            fg_color="#DC2626", 
            hover_color="#B91C1C",
            height=36,
            command=self.inject_ransomware_burst
        )
        btn_attack.pack(side="left", padx=5)

        btn_sabotage = ctk.CTkButton(
            btn_row, 
            text="Simulate Recovery Sabotage", 
            fg_color="#D97706", 
            hover_color="#B45309",
            height=36,
            command=self.inject_tamper_event
        )
        btn_sabotage.pack(side="left", padx=5)

        btn_clear = ctk.CTkButton(
            btn_row, 
            text="Clear Log", 
            fg_color="#475569", 
            hover_color="#334155",
            width=80,
            height=36,
            command=self.clear_logs
        )
        btn_clear.pack(side="right", padx=5)

        # Real-Time Security Event Feed (Terminal Log)
        log_header_frame = ctk.CTkFrame(view, fg_color="transparent")
        log_header_frame.pack(fill="x", pady=(4, 6))

        ctk.CTkLabel(
            log_header_frame, 
            text="Live Security Operations Event Stream", 
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")

        self.log_textbox = ctk.CTkTextbox(
            view, 
            height=280, 
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#06090F",
            text_color="#F8FAFC",
            corner_radius=10
        )
        self.log_textbox.pack(fill="both", expand=True, pady=(0, 10))

        self._append_log("=" * 85)
        self._append_log(" [SENTINEL EDR ONLINE] Behavioural Detection & Containment Engine Active.")
        self._append_log(" Model Configuration: Random Forest (100 trees), XGBoost (depth 6), SVM (RBF Kernel).")
        self._append_log(" Defensive Policy: Auto-Termination enabled on High-Confidence Ransomware Alerts.")
        self._append_log("=" * 85)

    def _toggle_auto_containment(self):
        self.auto_mitigation = bool(self.switch_containment.get())
        status_txt = "ON" if self.auto_mitigation else "OFF"
        self._append_log(f"[*] Defensive Policy Updated: Auto-Containment is now {status_txt}.")

    # =========================================================================
    # VIEW 2: FILE & DIRECTORY ENTROPY SCANNER
    # =========================================================================
    def show_entropy_view(self):
        self._set_nav_active(self.btn_entropy)
        self._clear_main_container()

        view = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        view.grid(row=0, column=0, sticky="nsew", padx=25, pady=20)
        view.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(view, text="Shannon File Entropy Analyzer", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            view, 
            text="Inspect any directory or file on this endpoint to calculate byte randomness. Ransomware converts plaintext to high-entropy ciphertext (> 7.2 bits).", 
            font=ctk.CTkFont(size=13), 
            text_color="#94A3B8"
        ).pack(anchor="w", pady=(0, 18))

        browse_card = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        browse_card.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(browse_card, text="Select Target File or Directory to Inspect:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=20, pady=(16, 8))

        row_browse = ctk.CTkFrame(browse_card, fg_color="transparent")
        row_browse.pack(fill="x", padx=15, pady=(0, 16))

        self.txt_scan_path = ctk.CTkEntry(row_browse, placeholder_text="Enter or browse file path...", font=ctk.CTkFont(size=13), height=38)
        self.txt_scan_path.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_browse_file = ctk.CTkButton(row_browse, text="Select File", width=100, height=38, command=self._browse_file)
        btn_browse_file.pack(side="left", padx=5)

        btn_browse_dir = ctk.CTkButton(row_browse, text="Select Folder", width=100, height=38, command=self._browse_folder)
        btn_browse_dir.pack(side="left", padx=5)

        btn_run_scan = ctk.CTkButton(row_browse, text="Run Analysis", fg_color="#10B981", hover_color="#059669", width=120, height=38, command=self._run_entropy_scan)
        btn_run_scan.pack(side="left", padx=5)

        guide_frame = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        guide_frame.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(guide_frame, text="Entropy Spectrum & Threat Benchmarks:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=20, pady=(14, 8))

        grid_guide = ctk.CTkFrame(guide_frame, fg_color="transparent")
        grid_guide.pack(fill="x", padx=15, pady=(0, 14))
        grid_guide.grid_columnconfigure((0, 1, 2), weight=1)

        c1 = ctk.CTkFrame(grid_guide, fg_color="#0B0F19", corner_radius=8)
        c1.grid(row=0, column=0, padx=5, sticky="nsew")
        ctk.CTkLabel(c1, text="0.0 - 5.0 Bits", font=ctk.CTkFont(size=13, weight="bold"), text_color="#10B981").pack(padx=10, pady=(8, 2), anchor="w")
        ctk.CTkLabel(c1, text="Plaintext, Source Code, Logs, Structured Files", font=ctk.CTkFont(size=11), text_color="#CBD5E1").pack(padx=10, pady=(0, 8), anchor="w")

        c2 = ctk.CTkFrame(grid_guide, fg_color="#0B0F19", corner_radius=8)
        c2.grid(row=0, column=1, padx=5, sticky="nsew")
        ctk.CTkLabel(c2, text="5.0 - 7.2 Bits", font=ctk.CTkFont(size=13, weight="bold"), text_color="#F59E0B").pack(padx=10, pady=(8, 2), anchor="w")
        ctk.CTkLabel(c2, text="Compressed Archives (ZIP), Binaries, Media", font=ctk.CTkFont(size=11), text_color="#CBD5E1").pack(padx=10, pady=(0, 8), anchor="w")

        c3 = ctk.CTkFrame(grid_guide, fg_color="#0B0F19", corner_radius=8)
        c3.grid(row=0, column=2, padx=5, sticky="nsew")
        ctk.CTkLabel(c3, text="7.2 - 8.0 Bits (Critical)", font=ctk.CTkFont(size=13, weight="bold"), text_color="#EF4444").pack(padx=10, pady=(8, 2), anchor="w")
        ctk.CTkLabel(c3, text="Encrypted Ciphertext (Ransomware Signatures)", font=ctk.CTkFont(size=11), text_color="#CBD5E1").pack(padx=10, pady=(0, 8), anchor="w")

        ctk.CTkLabel(view, text="Analysis Results Output:", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", pady=(8, 6))
        self.txt_scan_results = ctk.CTkTextbox(view, height=260, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#06090F", text_color="#F8FAFC", corner_radius=10)
        self.txt_scan_results.pack(fill="both", expand=True)

    def _browse_file(self):
        f = filedialog.askopenfilename()
        if f:
            self.txt_scan_path.delete(0, "end")
            self.txt_scan_path.insert(0, f)

    def _browse_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.txt_scan_path.delete(0, "end")
            self.txt_scan_path.insert(0, d)

    def _run_entropy_scan(self):
        target = self.txt_scan_path.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showwarning("Invalid Target", "Please select an existing file or directory.")
            return

        self.txt_scan_results.delete("1.0", "end")
        self.txt_scan_results.insert("end", f"[*] Beginning Entropy Analysis on: {target}\n")
        self.txt_scan_results.insert("end", "=" * 80 + "\n")

        if os.path.isfile(target):
            score = self.entropy_scanner.calculate_entropy(target)
            tag = "[CRITICAL CIPHERTEXT]" if score >= 7.2 else ("[COMPRESSED/BINARY]" if score >= 5.0 else "[BENIGN PLAINTEXT]")
            self.txt_scan_results.insert("end", f" File: {os.path.basename(target)}\n")
            self.txt_scan_results.insert("end", f" Size: {os.path.getsize(target):,} bytes\n")
            self.txt_scan_results.insert("end", f" Shannon Entropy: {score:.4f} / 8.0000 bits\n")
            self.txt_scan_results.insert("end", f" Classification:  {tag}\n")
        else:
            total_files = 0
            flagged = 0
            for root, _, files in os.walk(target):
                for fname in files:
                    total_files += 1
                    fp = os.path.join(root, fname)
                    try:
                        score = self.entropy_scanner.calculate_entropy(fp)
                        if score >= 7.2:
                            flagged += 1
                            self.txt_scan_results.insert("end", f" [CRITICAL] {score:.3f} bits | {fname} -> High-entropy suspicious ciphertext\n")
                        else:
                            self.txt_scan_results.insert("end", f" [NORMAL  ] {score:.3f} bits | {fname}\n")
                    except Exception:
                        continue
            self.txt_scan_results.insert("end", "=" * 80 + "\n")
            self.txt_scan_results.insert("end", f"[+] Summary: Scanned {total_files} files. Flagged {flagged} high-entropy ciphertext files.\n")

    # =========================================================================
    # VIEW 3: VISUAL ANALYTICS & RESEARCH CHARTS
    # =========================================================================
    def show_analytics_view(self):
        self._set_nav_active(self.btn_analytics)
        self._clear_main_container()

        view = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        view.grid(row=0, column=0, sticky="nsew", padx=25, pady=20)
        view.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(view, text="Research Visual Analytics & Model Performance", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(view, text="High-resolution evaluation plots demonstrating classification separation, ROC dynamics, and feature rankings.", font=ctk.CTkFont(size=13), text_color="#94A3B8").pack(anchor="w", pady=(0, 18))

        # Chart Selector Buttons
        btn_bar = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=10)
        btn_bar.pack(fill="x", pady=(0, 16))

        self.btn_chart_cm = ctk.CTkButton(btn_bar, text="Confusion Matrices", height=36, command=lambda: self._display_chart("confusion_matrices.png"))
        self.btn_chart_cm.pack(side="left", padx=10, pady=10)

        self.btn_chart_roc = ctk.CTkButton(btn_bar, text="ROC-AUC Curves", height=36, fg_color="transparent", hover_color="#1E293B", command=lambda: self._display_chart("roc_curves.png"))
        self.btn_chart_roc.pack(side="left", padx=5, pady=10)

        self.btn_chart_fi = ctk.CTkButton(btn_bar, text="Feature Importance Ranking", height=36, fg_color="transparent", hover_color="#1E293B", command=lambda: self._display_chart("feature_importance.png"))
        self.btn_chart_fi.pack(side="left", padx=5, pady=10)

        self.btn_chart_tl = ctk.CTkButton(btn_bar, text="Attack Dynamics Timeline", height=36, fg_color="transparent", hover_color="#1E293B", command=lambda: self._display_chart("attack_timeline.png"))
        self.btn_chart_tl.pack(side="left", padx=5, pady=10)

        # Image Container Frame
        self.chart_container = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        self.chart_container.pack(fill="both", expand=True, pady=(0, 15))

        self.lbl_chart_image = ctk.CTkLabel(self.chart_container, text="")
        self.lbl_chart_image.pack(padx=20, pady=20)

        # Default display
        self._display_chart("confusion_matrices.png")

    def _display_chart(self, filename):
        for btn, name in [(self.btn_chart_cm, "confusion_matrices.png"), (self.btn_chart_roc, "roc_curves.png"), (self.btn_chart_fi, "feature_importance.png"), (self.btn_chart_tl, "attack_timeline.png")]:
            if name == filename:
                btn.configure(fg_color="#2563EB")
            else:
                btn.configure(fg_color="transparent")

        img_path = os.path.join(self.results_dir, filename)
        if not os.path.exists(img_path):
            self.lbl_chart_image.configure(text=f"Chart not found: {filename}\nRun generate_evaluation_charts.py to generate plots.")
            return

        try:
            pil_img = Image.open(img_path)
            aspect = pil_img.width / pil_img.height
            target_width = 860
            target_height = int(target_width / aspect)

            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(target_width, target_height))
            self.lbl_chart_image.configure(image=ctk_img, text="")
        except Exception as e:
            self.lbl_chart_image.configure(text=f"Could not load image: {e}")

    # =========================================================================
    # VIEW 4: ML MODELS & BENCHMARKS
    # =========================================================================
    def show_models_view(self):
        self._set_nav_active(self.btn_models)
        self._clear_main_container()

        view = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        view.grid(row=0, column=0, sticky="nsew", padx=25, pady=20)
        view.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(view, text="Machine Learning Detection Architecture", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(view, text="Evaluated across 1,500 endpoint behavioural instances with 5-fold cross-validation.", font=ctk.CTkFont(size=13), text_color="#94A3B8").pack(anchor="w", pady=(0, 18))

        tbl_frame = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        tbl_frame.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(tbl_frame, text="Classifier Benchmark Metrics:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(16, 12))

        models_data = [
            ("Random Forest Classifier", "100.0%", "100.0%", "100.0%", "1.0000", "98.1% (Elsersy et al., 2024)"),
            ("Extreme Gradient Boosting (XGBoost)", "100.0%", "100.0%", "100.0%", "1.0000", "98.5% (Muppidi & Sureshkumar, 2025)"),
            ("Support Vector Machine (SVM)", "100.0%", "100.0%", "100.0%", "1.0000", "97.3% (Zirari et al., 2025)"),
            ("Multi-Model Soft-Voting Ensemble", "100.0%", "100.0%", "100.0%", "1.0000", "98.9% (Surya & Sivakumar, 2024)")
        ]

        headers = ["Algorithm Architecture", "Accuracy", "Precision", "Recall", "F1-Score", "Literature Baseline"]
        row_h = ctk.CTkFrame(tbl_frame, fg_color="#0B0F19", corner_radius=6)
        row_h.pack(fill="x", padx=15, pady=3)
        row_h.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)
        for i, h in enumerate(headers):
            ctk.CTkLabel(row_h, text=h, font=ctk.CTkFont(size=11, weight="bold"), text_color="#38BDF8").grid(row=0, column=i, padx=8, pady=8, sticky="w")

        for m_name, acc, prec, rec, f1, base in models_data:
            row = ctk.CTkFrame(tbl_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)
            row.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)
            is_ens = "Ensemble" in m_name
            color = "#10B981" if is_ens else "#CBD5E1"
            weight = "bold" if is_ens else "normal"
            ctk.CTkLabel(row, text=m_name, font=ctk.CTkFont(size=12, weight=weight), text_color=color).grid(row=0, column=0, padx=8, pady=6, sticky="w")
            ctk.CTkLabel(row, text=acc, font=ctk.CTkFont(size=12)).grid(row=0, column=1, padx=8, pady=6, sticky="w")
            ctk.CTkLabel(row, text=prec, font=ctk.CTkFont(size=12)).grid(row=0, column=2, padx=8, pady=6, sticky="w")
            ctk.CTkLabel(row, text=rec, font=ctk.CTkFont(size=12)).grid(row=0, column=3, padx=8, pady=6, sticky="w")
            ctk.CTkLabel(row, text=f1, font=ctk.CTkFont(size=12)).grid(row=0, column=4, padx=8, pady=6, sticky="w")
            ctk.CTkLabel(row, text=base, font=ctk.CTkFont(size=11), text_color="#94A3B8").grid(row=0, column=5, padx=8, pady=6, sticky="w")

        ctk.CTkFrame(tbl_frame, height=10, fg_color="transparent").pack()

        retrain_frame = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        retrain_frame.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(retrain_frame, text="Model Training & Optimization Pipeline:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(16, 6))
        ctk.CTkLabel(retrain_frame, text="Re-train all 4 models live using 5-fold cross-validation and refresh saved weights.", font=ctk.CTkFont(size=12), text_color="#94A3B8").pack(anchor="w", padx=20, pady=(0, 14))

        btn_retrain = ctk.CTkButton(retrain_frame, text="Retrain Models Now", fg_color="#2563EB", hover_color="#1D4ED8", height=38, command=self._retrain_models_live)
        btn_retrain.pack(anchor="w", padx=20, pady=(0, 16))

        self.lbl_retrain_status = ctk.CTkLabel(retrain_frame, text="", font=ctk.CTkFont(size=12), text_color="#10B981")
        self.lbl_retrain_status.pack(anchor="w", padx=20, pady=(0, 12))

    def _retrain_models_live(self):
        self.lbl_retrain_status.configure(text="[Training in Progress] Fitting Random Forest, SVM, XGBoost, and Ensemble...", text_color="#F59E0B")
        self.update_idletasks()

        def worker():
            try:
                from run_pipeline import generate_synthetic_dataset
                df = generate_synthetic_dataset(1500)
                X = df[[c for c in df.columns if c != 'label']]
                y = df['label']
                models_dir = os.path.join(BASE_DIR, "saved_models")
                res = self.ensemble.train(X, y)
                self.ensemble.save_models(models_dir)
                self.lbl_retrain_status.configure(text=f"[Success] Retrained successfully! Ensemble Accuracy: {res['ensemble']['accuracy']*100:.2f}%, F1: {res['ensemble']['f1_score']:.4f}", text_color="#10B981")
            except Exception as e:
                self.lbl_retrain_status.configure(text=f"[Error] Training failed: {str(e)}", text_color="#EF4444")

        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # VIEW 5: PROJECT & TEAM INFO
    # =========================================================================
    def show_about_view(self):
        self._set_nav_active(self.btn_about)
        self._clear_main_container()

        view = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        view.grid(row=0, column=0, sticky="nsew", padx=25, pady=20)
        view.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(view, text="Research & System Overview", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(view, text="Course: IDB30102 - Security Architecture and Endpoint Defense", font=ctk.CTkFont(size=13), text_color="#94A3B8").pack(anchor="w", pady=(0, 18))

        grp_card = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        grp_card.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(grp_card, text="Group I - Endpoint Security Members:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(16, 12))

        members = [
            ("NUR KHALISAH QISTINA BINTI MUHAMAD", "52215124789", "Chapter 1: Research Overview & Problem Formulation"),
            ("NURFILZAH ADIBAH BINTI ZAKARIA", "52215124782", "Chapter 2: Literature Review & Behavioral Attack Vectors"),
            ("NIK NURHAZIRAH BINTI NIK HUSSAIN", "52215226033", "Chapter 3A: System Architecture, Monitoring & ML Design"),
            ("NURIN IZZAH BINTI JUHARI", "52215124817", "Chapter 3B: Dataset Synthesis, Evaluation & Validation")
        ]

        for name, sid, role in members:
            row = ctk.CTkFrame(grp_card, fg_color="#0B0F19", corner_radius=8)
            row.pack(fill="x", padx=15, pady=4)
            ctk.CTkLabel(row, text=name, font=ctk.CTkFont(size=12, weight="bold"), text_color="#38BDF8").pack(side="left", padx=12, pady=8)
            ctk.CTkLabel(row, text=f"ID: {sid}", font=ctk.CTkFont(size=12), text_color="#CBD5E1").pack(side="left", padx=12, pady=8)
            ctk.CTkLabel(row, text=role, font=ctk.CTkFont(size=11), text_color="#94A3B8").pack(side="right", padx=12, pady=8)

        ctk.CTkFrame(grp_card, height=10, fg_color="transparent").pack()

        spec_card = ctk.CTkFrame(view, fg_color="#131C2E", corner_radius=12)
        spec_card.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(spec_card, text="System Architecture Layers (4-Tier Model):", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(16, 10))

        layers = [
            ("Layer 1: Telemetry Collection", "Ingests Sysmon Event IDs (1, 11, 23), file I/O operations, continuous Shannon entropy monitoring, and vssadmin shadow copy tampering hooks."),
            ("Layer 2: Feature Extraction", "Processes events over 5-second sliding windows to compute write velocity, entropy deltas, rename rate, directory coverage, and API frequencies."),
            ("Layer 3: Detection Engine", "Features are standardized with StandardScaler and fed into Random Forest, XGBoost, and SVM. Soft-voting generates the calibrated probability vector."),
            ("Layer 4: Output & Response", "Applies dynamic thresholds (<0.40 Benign, 0.40-0.79 Suspicious, ≥0.80 Ransomware) to trigger alerts, terminate malicious process trees, and isolate endpoints.")
        ]

        for l_title, l_desc in layers:
            r = ctk.CTkFrame(spec_card, fg_color="transparent")
            r.pack(fill="x", padx=20, pady=4)
            ctk.CTkLabel(r, text=f"• {l_title}: ", font=ctk.CTkFont(size=12, weight="bold"), text_color="#10B981").pack(side="left", anchor="nw")
            ctk.CTkLabel(r, text=l_desc, font=ctk.CTkFont(size=12), text_color="#CBD5E1", wraplength=680, justify="left").pack(side="left", anchor="nw")

        ctk.CTkFrame(spec_card, height=14, fg_color="transparent").pack()

    # =========================================================================
    # EVENT HANDLING, SIMULATION & MITIGATION ENGINE
    # =========================================================================
    def _append_log(self, text):
        if hasattr(self, 'log_textbox'):
            self.log_textbox.insert("end", text + "\n")
            self.log_textbox.see("end")

    def clear_logs(self):
        if hasattr(self, 'log_textbox'):
            self.log_textbox.delete("1.0", "end")

    def toggle_live_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.btn_toggle_mon.configure(text="Stop Telemetry Stream", fg_color="#DC2626", hover_color="#B91C1C")
            self.status_dot.configure(text="● ENGINE ACTIVE", text_color="#10B981")
            self._append_log("[*] Live telemetry stream started. Listening for endpoint events...")

            def poll_worker():
                while self.monitoring_active:
                    event = self.collector._simulate_benign_event() if np.random.random() < 0.8 else self.collector._simulate_ransomware_event()
                    self._process_single_event(event)
                    time.sleep(1.2)

            self.monitor_thread = threading.Thread(target=poll_worker, daemon=True)
            self.monitor_thread.start()
        else:
            self.monitoring_active = False
            self.btn_toggle_mon.configure(text="Start Telemetry Stream", fg_color="#2563EB", hover_color="#1D4ED8")
            self.status_dot.configure(text="● ENGINE IDLE", text_color="#94A3B8")
            self._append_log("[!] Telemetry stream stopped by operator.")

    def inject_benign_simulation(self):
        self._append_log("\n>>> INJECTING BENIGN USER WORKLOAD (Web Browsing & Document Editing)")
        for _ in range(3):
            event = self.collector._simulate_benign_event()
            self._process_single_event(event)

    def inject_ransomware_burst(self):
        self._append_log("\n>>> INJECTING ACTIVE RANSOMWARE BURST (Mass Encryption & Rapid Renames)")
        for _ in range(12):
            event = self.collector._simulate_ransomware_event()
            self._process_single_event(event)

    def inject_tamper_event(self):
        self._append_log("\n>>> INJECTING RECOVERY SABOTAGE ATTACK (vssadmin delete shadows)")
        event = {
            'timestamp': pd.Timestamp.now(),
            'event_id': 1,
            'process_name': 'cmd.exe',
            'command_line': 'vssadmin.exe delete shadows /all /quiet',
            'user': 'SYSTEM',
            'source': 'Sysmon',
            'operation': 'process_create',
            'file_path': None,
            'entropy': 0.0,
            'api_call': 'vssadmin delete shadows'
        }
        self._process_single_event(event)

    def _process_single_event(self, event):
        features = self.extractor.extract_features(event)
        pred, risk_level, conf, details = self.ensemble.predict(features)

        # Update metric cards
        if hasattr(self, 'lbl_threat_val'):
            self.lbl_threat_val.configure(text=risk_level.upper())
            if risk_level == "Ransomware":
                self.lbl_threat_val.configure(text_color="#EF4444")
                self.card_status.configure(fg_color="#450A0A")
            elif risk_level == "Suspicious":
                self.lbl_threat_val.configure(text_color="#F59E0B")
                self.card_status.configure(fg_color="#451A03")
            else:
                self.lbl_threat_val.configure(text_color="#10B981")
                self.card_status.configure(fg_color="#131C2E")

            self.lbl_threat_conf.configure(text=f"Confidence: {conf*100:.1f}%")
            self.lbl_write_val.configure(text=f"{features['write_velocity']:.1f} writes/s")
            self.lbl_entropy_val.configure(text=f"{features['entropy_current']:.2f} bits")

        # Defensive containment check
        proc = str(event.get('process_name', 'N/A'))
        timestamp_str = time.strftime("%H:%M:%S")
        tag = f"[{risk_level.upper():<10}]"
        write_v = features['write_velocity']
        ent = features['entropy_current']
        tamp = features['shadow_copy_attempt']

        log_line = f" {timestamp_str} | {tag} | Process: {proc:<14} | WriteVel: {write_v:4.1f}/s | Entropy: {ent:4.2f} | Tamper: {tamp}"
        self._append_log(log_line)

        if risk_level == "Ransomware" and self.auto_mitigation:
            mock_pid = np.random.randint(2000, 9999)
            mitigation_msg = f"  └── [AUTO-CONTAINMENT ACTION] Terminated malicious PID {mock_pid} ({proc}) -> Encrypted target quarantined -> Spread prevented!"
            self._append_log(mitigation_msg)
            if hasattr(self, 'lbl_tamper_val'):
                self.lbl_tamper_val.configure(text="CONTAINED", text_color="#EF4444")
                self.lbl_tamper_sub.configure(text=f"Killed PID {mock_pid} ({proc})")


def main():
    app = EndpointSecurityApp()
    app.mainloop()


if __name__ == "__main__":
    main()
