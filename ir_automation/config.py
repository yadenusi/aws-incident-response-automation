"""Central configuration. Every threshold can be overridden by an environment
variable so the Lambda can be tuned without a code change."""
import os


def _int(name, default):
    return int(os.environ.get(name, default))


# Detection thresholds
FAILED_LOGIN_THRESHOLD = _int("FAILED_LOGIN_THRESHOLD", 5)        # failures
FAILED_LOGIN_WINDOW_MIN = _int("FAILED_LOGIN_WINDOW_MIN", 10)     # minutes
MASS_DELETE_THRESHOLD = _int("MASS_DELETE_THRESHOLD", 20)         # delete calls
MASS_DELETE_WINDOW_MIN = _int("MASS_DELETE_WINDOW_MIN", 5)        # minutes
LOOKBACK_MIN = _int("LOOKBACK_MIN", 15)                           # CloudTrail scan window

# IPs / CIDR prefixes considered normal for this company (corporate VPN egress)
KNOWN_IP_PREFIXES = [p.strip() for p in os.environ.get(
    "KNOWN_IP_PREFIXES", "10.,172.16.,192.168.,203.0.113.").split(",") if p.strip()]

# Ports that must never be open to the internet
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}

# IAM calls that can grant or widen privilege
PRIV_ESC_CALLS = {
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AddUserToGroup", "UpdateAssumeRolePolicy", "CreateAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "PassRole",
}
ADMIN_POLICY_MARKERS = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")
# Principals allowed to change IAM (break glass role and the IaC pipeline)
IAM_ADMIN_ALLOWLIST = set(os.environ.get(
    "IAM_ADMIN_ALLOWLIST", "iac-pipeline,breakglass-admin").split(","))

# Response configuration
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "ir-evidence-store")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
QUARANTINE_POLICY_NAME = "IR-Quarantine-DenyAll"
QUARANTINE_SG_NAME = "ir-quarantine-sg"

# Severity based SNS routing
SNS_TOPICS = {
    "CRITICAL": os.environ.get("SNS_CRITICAL", ""),   # on call pager + SOC + CISO
    "HIGH": os.environ.get("SNS_HIGH", ""),           # SOC analysts
    "MEDIUM": os.environ.get("SNS_MEDIUM", ""),       # SOC ticket queue
    "LOW": os.environ.get("SNS_LOW", ""),             # daily digest
}
# Minutes an alert may go unacknowledged before it escalates one tier
ACK_SLA_MIN = {"CRITICAL": 10, "HIGH": 20, "MEDIUM": 120, "LOW": 1440}
