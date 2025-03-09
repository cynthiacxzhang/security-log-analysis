### **Security Log Analysis & Intrusion Detection**

##### *Description*

This project ingests security logs (e.g., login attempts, port scans) and detects suspicious activity based on simple rules:

- Threshold-Based Anomaly Detection (too many login failures within a time window).
- Event Correlation (e.g., PORT_SCAN followed quickly by LOGIN_FAILED from the same IP).
- The system outputs any detected suspicious events to a dedicated file for review.

##### *Features*

- Log Parsing: Converts each raw log line into a structured Python dictionary using regex.
- Threshold Anomalies: Flags IP addresses that exceed a defined threshold of failures within a specific time window.
- Correlation Rules: Identifies multi-step suspicious sequences, such as a PORT_SCAN quickly followed by a LOGIN_FAILED.
- Isolation Forest: Simple ML-based anomaly detection that isolates anomalies by randomly partitioning features

##### *Project Structure*

security-log-analysis/
  ├── logs/
  │   └── sample.log                # Example input file with raw logs
  ├── output/
  │   └── suspicious_events.txt     # Generated output listing alerts
  ├── src/
  │   ├── parse.py                  # Contains parse_log_line (log parser)
  │   ├── anomaly.py                # Contains detect_threshold_anomalies (threshold-based detection)
  │   ├── correlation.py            # Contains correlate_events (event correlation rules)
  │   ├── ml_anomaly.py             # Contains MLAnomalyDetector class + feature extraction
  │   └── main.py                   # Orchestrator that ties everything together
  ├── requirements.txt
  └── README.md

- logs/ – Holds raw log files.
- output/ – Stores generated alerts.
- src/ – Contains all source code, divided into multiple files based on functionality.
