from sklearn.ensemble import IsolationForest
import numpy as np


class DetectionEngine:
    def __init__(self):
        # IsolationForest used for unsupervised anomaly detection.  We
        # keep a simple flag so that callers can know whether the model
        # has been trained/fitted yet and avoid raising a
        # NotFittedError.
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
        )
        self.is_trained = False

        self.signature_rules = self.load_signature_rules()
        self.training_data = []

    def load_signature_rules(self):
        return {
            "syn_flood": {
                "condition": lambda features: (
                    features["tcp_flags"] == 2  # SYN flag
                    and features["packet_rate"] > 100
                )
            },
            "port_scan": {
                "condition": lambda features: (
                    features["packet_size"] < 100 and features["packet_rate"] > 50
                ),
            },
        }

    def train_anomaly_detector(self, normal_traffic_data):
        """Fit the anomaly detector.

        ``normal_traffic_data`` may be either a numpy array shaped
        (n_samples, 3) or a list of feature dictionaries produced by
        :meth:`TrafficAnalyzer.extract_features`.
        """
        # convert list-of-dicts into the expected numpy array
        if isinstance(normal_traffic_data, list):
            normal_traffic_data = np.array(
                [
                    [f["packet_size"], f["packet_rate"], f["byte_rate"]]
                    for f in normal_traffic_data
                ]
            )

        self.anomaly_detector.fit(normal_traffic_data)
        self.is_trained = True

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule["condition"](features):
                threats.append(
                    {
                        "type": "signature",
                        "rule": rule_name,
                        "confidence": 1.0,
                    }
                )

        # Anomaly-based detection
        feature_vector = np.array(
            [
                [
                    features["packet_size"],
                    features["packet_rate"],
                    features["byte_rate"],
                ]
            ]
        )

        # only attempt scoring if the detector has been trained; otherwise
        # ``score_samples`` will raise a NotFittedError.  We catch that as
        # a safety net in case the caller forgets to train.
        if self.is_trained:
            try:
                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            except Exception:  # sklearn throws NotFittedError here
                # skip anomaly detection if model isn't ready
                return threats

            if anomaly_score < -0.5:  # Threshold for anomaly detection
                threats.append(
                    {
                        "type": "anomaly",
                        "score": anomaly_score,
                        "confidence": min(1.0, abs(anomaly_score)),
                    }
                )
        else:
            # detector not yet trained; callers may wish to log or provide
            # training data before relying on anomalies
            pass

        return threats