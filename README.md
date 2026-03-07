# IDS (Intrusion Detection System)

A simple Python-based Intrusion Detection System (IDS) prototype that captures live TCP/IP traffic, extracts basic flow features, and detects suspicious activity using:

- Signature-based rules (e.g., SYN flood, port scan heuristics)
- Anomaly detection using Isolation Forest (scikit-learn)

Alerts are written to a local log file (ids_alerts.log).

## Repository layout

- main.py — entry point; wires together capture → analysis → detection → alerts
- packet_capture.py — packet capture using Scapy (sniff) in a background thread
- traffic_analysis.py — feature extraction / flow statistics
- detection_engine.py — signature rules + IsolationForest anomaly detector
- alert_system.py — alert generation + logging to ids_alerts.log
- ids_alerts.log — alert output file (generated/updated at runtime)

## Requirements

- Python 3.9+ recommended
- scapy
- scikit-learn
- numpy

Example install:

pip install scapy scikit-learn numpy

Note: Packet sniffing often requires elevated privileges (e.g., running with sudo) depending on your OS.

## Usage

Run the IDS (default interface is eth0):

python main.py

To use a different interface, update the IntrusionDetectionSystem(interface="...") value in main.py (or extend the script to accept CLI args).

## How it works (high level)

1) Capture: PacketCapture collects TCP/IP packets and pushes them into a queue.
2) Analyze: TrafficAnalyzer maintains per-flow stats and produces a feature dictionary (packet size, rates, TCP flags, etc.).
3) Detect: DetectionEngine:
   - checks signature rules (e.g., SYN-only packets with high packet rate),
   - optionally applies anomaly detection if the IsolationForest model has been trained.
4) Alert: AlertSystem writes JSON alerts to ids_alerts.log and logs higher-severity events as CRITICAL when confidence is high.

## Training the anomaly detector (optional)

The anomaly detector only runs once trained (DetectionEngine.is_trained == True). You can train it with “normal traffic” features (list of feature dicts or an n x 3 numpy array with [packet_size, packet_rate, byte_rate]).

Pseudo-example:

from detection_engine import DetectionEngine

engine = DetectionEngine()
engine.train_anomaly_detector(normal_traffic_feature_dicts)  # list of dicts

## Output / Alerts

Alerts are logged to:

- ids_alerts.log

Each alert is JSON containing timestamp, threat type, source/destination IP, confidence, and details.

## Disclaimer

This project is an educational prototype and not a production-ready IDS. Use responsibly and only on networks you own or have explicit permission to monitor.
