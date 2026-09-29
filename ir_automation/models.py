"""Shared data structures."""
import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc)


@dataclass
class Incident:
    incident_type: str            # e.g. BRUTE_FORCE_LOGIN
    severity: str                 # CRITICAL | HIGH | MEDIUM | LOW
    resource_type: str            # IAMUser | S3Bucket | SecurityGroup
    resource_id: str
    summary: str
    principal: str = ""
    source_ip: str = ""
    evidence_events: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    incident_id: str = field(default_factory=lambda: "IR-" + uuid.uuid4().hex[:10].upper())
    detected_at: str = field(default_factory=lambda: utcnow().isoformat())
    investigation: dict = field(default_factory=dict)
    containment: list = field(default_factory=list)   # audit trail of actions
    status: str = "DETECTED"

    def to_dict(self):
        return asdict(self)

    def fingerprint(self):
        """SHA-256 over the incident record, stored with the evidence so any
        later tampering is detectable (chain of custody)."""
        body = json.dumps(self.to_dict(), sort_keys=True, default=str).encode()
        return hashlib.sha256(body).hexdigest()
