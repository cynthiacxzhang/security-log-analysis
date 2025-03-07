"""
main.py

The main entry point of the Security Log Analysis & Intrusion Detection system. 
It reads raw log lines from a file, uses 'parse.py' to convert them into structured 
data, and periodically runs both threshold-based anomaly detection (from 'anomaly.py') 
and event correlation checks (from 'correlation.py'). Any suspicious findings get 
written to an output file for later review.

"""

import os
from parse import parse_log_line        # <-- Updated import from 'parse.py'
from anomaly import detect_threshold_anomalies
from correlation import correlate_events

def main():
    """
    The primary execution function:
      1. Define where to read logs and where to write alerts.
      2. Parse each log line into a structured dictionary.
      3. Periodically run detection (both anomaly & correlation).
      4. Write suspicious events to an output file.
    """

    # Paths to the input log file and the output file
    LOG_FILE = os.path.join("logs", "sample.log")
    OUTPUT_FILE = os.path.join("output", "suspicious_events.txt")

    # If an output file already exists, remove it to start fresh
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    # We'll store all parsed events here
    parsed_events = []

    # Read the log file line by line
    with open(LOG_FILE, "r") as log_f:
        for line in log_f:
            # Parse each line using our custom parser (now in parse.py)
            event_data = parse_log_line(line)
            if event_data:
                parsed_events.append(event_data)

            # Every 10 events, we run our detection logic
            if len(parsed_events) % 10 == 0:
                # 1. Run threshold anomaly detection
                anomaly_alerts = detect_threshold_anomalies(parsed_events)

                # 2. Run event correlation checks
                correlation_alerts = correlate_events(parsed_events)

                # Combine all alerts into a single list
                all_alerts = anomaly_alerts + correlation_alerts

                # If we found any suspicious events, append them to the output file
                if all_alerts:
                    with open(OUTPUT_FILE, "a") as out_f:
                        for alert in all_alerts:
                            out_f.write(alert + "\n")

    # Print a quick message to let us know processing is complete
    print(f"Done processing logs. Check '{OUTPUT_FILE}' for alerts.")

# Standard Python entry point
if __name__ == "__main__":
    main()
