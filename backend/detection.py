import uuid
from collections import defaultdict, deque
from datetime import timedelta
from .models import SecurityAlert

class DetectionEngine:
    def __init__(self):
        self.failed = defaultdict(deque)
        self.seen = set()

    def evaluate(self, event):
        out = []
        if event.event_type == "authentication_failure":
            key = (event.hostname, event.username, event.source_ip)
            bucket = self.failed[key]
            bucket.append(event.timestamp)
            cutoff = event.timestamp - timedelta(minutes=2)
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= 5:
                marker = (key, event.timestamp.replace(second=0, microsecond=0))
                if marker not in self.seen:
                    self.seen.add(marker)
                    out.append(self.make(event, "Repeated failed logins",
                        f"{len(bucket)} failed sign-ins for {event.username} from {event.source_ip} within two minutes.",
                        "high", "SIM-001", "T1110"))
        rules = {
            "powershell_suspicious": ("Suspicious PowerShell activity", "A synthetic PowerShell event matched a suspicious command-line rule.", "high", "SIM-002", "T1059.001"),
            "outbound_connection_suspicious": ("Unusual outbound connection", "A host connected to a documentation-only test IP address.", "medium", "SIM-003", "T1071"),
            "malware_indicator": ("Malware indicator observed", "A synthetic file/hash indicator matched the demo rule.", "critical", "SIM-004", "T1204"),
            "port_scan": ("Network scanning detected", "Many sequential port connection attempts from one source matched the scanning demo rule.", "medium", "SIM-005", "T1046"),
            "unusual_login_location": ("Unusual login location", "A successful sign-in came from a location not previously seen for this account.", "high", "SIM-006", "T1078"),
        }
        if event.event_type in rules:
            out.append(self.make(event, *rules[event.event_type]))
        return out

    @staticmethod
    def make(e, title, description, severity, rule_id, technique):
        return SecurityAlert(id=uuid.uuid4().hex, event_id=e.id, event_type=e.event_type,
            timestamp=e.timestamp, title=title, description=description,
            severity=severity, hostname=e.hostname, username=e.username,
            source_ip=e.source_ip, rule_id=rule_id, mitre_technique=technique, geo=e.geo)