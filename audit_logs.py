import json
from datetime import datetime
import os

AUDIT_LOG_FILE = 'audit_logs.json'

def log_audit(action, username, details=None):
    log_entry = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "action": action,
        "username": username,
        "details": details
    }
    if not os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, 'w') as f:
            json.dump([], f)
    with open(AUDIT_LOG_FILE, 'r') as f:
        logs = json.load(f)
    logs.append(log_entry)
    with open(AUDIT_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

