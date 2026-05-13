import json
import os
from datetime import datetime, timezone

# Paths
EVE_LOG = "/var/log/suricata/eve.json"
OUTPUT_LOG = "ids_logs.json"

# ANSI Colors
RESET = "\033[0m"
GREEN = "\033[92m"   # low
YELLOW = "\033[93m"  # medium
RED = "\033[91m"     # high/critical
CYAN = "\033[96m"    # info

def load_existing_logs(output_file):
    """Load existing alerts from JSON file, if present."""
    if os.path.exists(output_file):
        with open(output_file, "r") as out:
            try:
                return json.load(out)
            except json.JSONDecodeError:
                return []
    return []

def save_logs(alerts, output_file):
    """Save alerts back to file."""
    with open(output_file, "w") as out:
        json.dump(alerts, out, indent=2)

def follow(file):
    """Generator that yields all lines (existing + new) as they are written to a file."""
    # Start from beginning instead of end
    file.seek(0)
    while True:
        line = file.readline()
        if not line:
            continue
        yield line

def severity_color(severity):
    """Return color code based on severity level."""
    try:
        sev = int(severity)
    except:
        return CYAN  # fallback

    if sev == 1:
        return GREEN
    elif sev == 2:
        return YELLOW
    elif sev >= 3:
        return RED
    return CYAN

def monitor_suricata(log_file=EVE_LOG, output_file=OUTPUT_LOG):
    alerts = load_existing_logs(output_file)
    event_counter = len(alerts)

    if not os.path.exists(log_file):
        print(f"[!] Log file not found: {log_file}")
        return

    print(f"{CYAN}[+] Monitoring Suricata log: {log_file}{RESET}")
    print(f"{CYAN}[+] Starting with {event_counter} existing alerts in {output_file}{RESET}")

    with open(log_file, "r") as f:
        for line in follow(f):
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    event_counter += 1
                    severity = str(event["alert"].get("severity", "N/A"))
                    color = severity_color(severity)

                    log_entry = {
                        "sme_id": "SME001",
                        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "event_id": f"evt-{event_counter:04d}",
                        "event_type": "intrusion_detected",
                        "details": {
                            "attack_type": event["alert"].get("signature", "N/A"),
                            "source_ip": event.get("src_ip", "N/A"),
                            "destination_ip": event.get("dest_ip", "N/A"),
                            "severity": severity,
                            "autofix": False,
                            "fix_action": None
                        },
                        "status": "unresolved"
                    }

                    alerts.append(log_entry)
                    save_logs(alerts, output_file)

                    print(
                        f"{color}[NEW ALERT]{RESET} "
                        f"{log_entry['details']['attack_type']} | "
                        f"{log_entry['details']['source_ip']} -> {log_entry['details']['destination_ip']} | "
                        f"Severity: {severity}"
                    )
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    monitor_suricata()
