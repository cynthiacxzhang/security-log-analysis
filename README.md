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
