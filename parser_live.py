import json
import os
from datetime import datetime, timezone

EVE_LOG = "/var/log/suricata/eve.json"
OUTPUT_LOG = "ids_logs_live.json"

# Colors
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"

def severity_color(sev):
    try:
        s = int(sev)
    except:
        return CYAN
    if s == 1:
        return GREEN
    elif s == 2:
        return YELLOW
    else:
        return RED

def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            continue
        yield line

def load_logs():
    if os.path.exists(OUTPUT_LOG):
        try:
            with open(OUTPUT_LOG, "r") as f:
                return json.load(f)
        except:
            return []
    return []

def save_logs(data):
    with open(OUTPUT_LOG, "w") as f:
        json.dump(data, f, indent=2)

def monitor():
    if not os.path.exists(EVE_LOG):
        print("[!] eve.json not found. Is Suricata running?")
        return

    logs = load_logs()
    counter = len(logs)

    print(f"{CYAN}[+] Monitoring started...{RESET}")

    with open(EVE_LOG, "r") as f:
        for line in follow(f):
            try:
                event = json.loads(line)

                if event.get("event_type") != "alert":
                    continue
                if "SURICATA STREAM" in event["alert"].get("signature", ""):
                    continue

                counter += 1

                severity = str(event["alert"].get("severity", "N/A"))
                color = severity_color(severity)

                entry = {
                    "event_id": f"evt-{counter:04d}",
                    "timestamp": event.get(
                        "timestamp",
                        datetime.now(timezone.utc).isoformat()
                    ),
                    "source_ip": event.get("src_ip", "N/A"),
                    "destination_ip": event.get("dest_ip", "N/A"),
                    "attack_type": event["alert"].get("signature", "N/A"),
                    "severity": severity
                }

                logs.append(entry)
                save_logs(logs)

                print(
                    f"{color}[ALERT]{RESET} "
                    f"{entry['attack_type']} | "
                    f"{entry['source_ip']} -> {entry['destination_ip']} | "
                    f"Severity: {severity}"
                )

            except:
                continue

if __name__ == "__main__":
    monitor()