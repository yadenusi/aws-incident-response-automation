"""Detection layer. Two families of detectors:
  * event detectors analyse CloudTrail records (API behaviour)
  * posture detectors query live resource configuration (misconfigurations)
Every detector returns a list of Incident objects and has no side effects."""
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from . import config
from .models import Incident


# ---------------------------------------------------------------- helpers
def normalize_event(raw):
    """Accept a CloudTrail LookupEvents record, an EventBridge envelope, or a
    plain CloudTrail record and return the plain record."""
    if "CloudTrailEvent" in raw:
        return json.loads(raw["CloudTrailEvent"])
    if "detail" in raw and isinstance(raw["detail"], dict):
        return raw["detail"]
    return raw


def principal_of(ev):
    ui = ev.get("userIdentity", {})
    return ui.get("userName") or ui.get("arn", "").split("/")[-1] or ui.get("principalId", "unknown")


def ts(ev):
    return datetime.fromisoformat(ev["eventTime"].replace("Z", "+00:00"))


def is_known_ip(ip):
    return any(ip.startswith(p) for p in config.KNOWN_IP_PREFIXES)


def fetch_cloudtrail_events(cloudtrail, minutes=None):
    """Pull management events for the scan window (scheduled mode)."""
    minutes = minutes or config.LOOKBACK_MIN
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    events, token = [], None
    while True:
        kw = {"StartTime": start, "EndTime": end, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        page = cloudtrail.lookup_events(**kw)
        events += [normalize_event(e) for e in page.get("Events", [])]
        token = page.get("NextToken")
        if not token:
            return events


def _sliding_window_hits(events, window_min, threshold):
    """Return the first window of >= threshold events inside window_min."""
    events = sorted(events, key=ts)
    lo = 0
    for hi in range(len(events)):
        while ts(events[hi]) - ts(events[lo]) > timedelta(minutes=window_min):
            lo += 1
        if hi - lo + 1 >= threshold:
            return events[lo:hi + 1]
    return None


# ------------------------------------------------------- 1. brute force / odd location
def detect_unauthorized_access(events):
    incidents = []
    failures = defaultdict(list)
    for ev in map(normalize_event, events):
        if ev.get("eventName") != "ConsoleLogin":
            continue
        result = (ev.get("responseElements") or {}).get("ConsoleLogin")
        key = (principal_of(ev), ev.get("sourceIPAddress", ""))
        if result == "Failure":
            failures[key].append(ev)
        elif result == "Success" and not is_known_ip(key[1]):
            incidents.append(Incident(
                incident_type="UNUSUAL_LOCATION_LOGIN", severity="HIGH",
                resource_type="IAMUser", resource_id=key[0], principal=key[0],
                source_ip=key[1], evidence_events=[ev],
                summary=f"Successful console login for {key[0]} from unrecognised IP {key[1]}",
                details={"mfa_used": (ev.get("additionalEventData") or {}).get("MFAUsed")}))

    for (user, ip), evs in failures.items():
        hit = _sliding_window_hits(evs, config.FAILED_LOGIN_WINDOW_MIN, config.FAILED_LOGIN_THRESHOLD)
        if hit:
            incidents.append(Incident(
                incident_type="BRUTE_FORCE_LOGIN", severity="HIGH", resource_type="IAMUser",
                resource_id=user, principal=user, source_ip=ip, evidence_events=hit,
                summary=f"{len(hit)} failed console logins for {user} from {ip} "
                        f"within {config.FAILED_LOGIN_WINDOW_MIN} min",
                details={"failed_attempts": len(hit)}))
    # escalate brute force to CRITICAL if the same user/IP later succeeded
    successes = {(i.principal, i.source_ip) for i in incidents if i.incident_type == "UNUSUAL_LOCATION_LOGIN"}
    for inc in incidents:
        if inc.incident_type == "BRUTE_FORCE_LOGIN" and (inc.principal, inc.source_ip) in successes:
            inc.severity = "CRITICAL"
            inc.summary += " followed by a SUCCESSFUL login"
    return incidents


# ------------------------------------------------------- 2. unusual API: mass deletion
def detect_mass_deletion(events):
    incidents = []
    by_principal = defaultdict(list)
    for ev in map(normalize_event, events):
        name = ev.get("eventName", "")
        if (name.startswith("Delete") or name in ("TerminateInstances", "PutBucketLifecycle")) \
                and not ev.get("errorCode"):
            by_principal[principal_of(ev)].append(ev)
    for user, evs in by_principal.items():
        hit = _sliding_window_hits(evs, config.MASS_DELETE_WINDOW_MIN, config.MASS_DELETE_THRESHOLD)
        if hit:
            ips = sorted({e.get("sourceIPAddress", "") for e in hit})
            incidents.append(Incident(
                incident_type="MASS_DELETION", severity="CRITICAL", resource_type="IAMUser",
                resource_id=user, principal=user, source_ip=ips[0], evidence_events=hit,
                summary=f"{len(hit)} destructive API calls by {user} in "
                        f"{config.MASS_DELETE_WINDOW_MIN} min",
                details={"calls": sorted({e['eventName'] for e in hit}), "source_ips": ips}))
    return incidents


# ------------------------------------------------------- 3. privilege escalation
def detect_privilege_escalation(events):
    incidents = []
    for ev in map(normalize_event, events):
        name = ev.get("eventName")
        if name not in config.PRIV_ESC_CALLS or ev.get("errorCode"):
            continue
        actor = principal_of(ev)
        if actor in config.IAM_ADMIN_ALLOWLIST:
            continue
        params = ev.get("requestParameters") or {}
        target = params.get("userName") or params.get("roleName") or params.get("groupName") or actor
        blob = json.dumps(params)
        admin_grant = any(m in blob for m in config.ADMIN_POLICY_MARKERS) or '"Action": "*"' in blob \
            or '\\"Action\\":\\"*\\"' in blob
        self_grant = target == actor
        if admin_grant or (self_grant and name != "CreateAccessKey"):
            sev = "CRITICAL" if admin_grant else "HIGH"
            incidents.append(Incident(
                incident_type="PRIVILEGE_ESCALATION", severity=sev, resource_type="IAMUser",
                resource_id=actor, principal=actor, source_ip=ev.get("sourceIPAddress", ""),
                evidence_events=[ev],
                summary=f"{actor} called {name} on {target}"
                        + (" granting administrative rights" if admin_grant else " (self modification)"),
                details={"api": name, "target": target, "admin_grant": admin_grant}))
    return incidents


# ------------------------------------------------------- 4a. public S3 buckets
PUBLIC_GRANTEES = ("http://acs.amazonaws.com/groups/global/AllUsers",
                   "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


def detect_public_buckets(s3):
    incidents = []
    for b in s3.list_buckets().get("Buckets", []):
        name, reasons = b["Name"], []
        if name == config.EVIDENCE_BUCKET:
            continue
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(pab.values())
        except s3.exceptions.ClientError:
            fully_blocked = False
        if fully_blocked:
            continue
        for g in s3.get_bucket_acl(Bucket=name).get("Grants", []):
            if g["Grantee"].get("URI") in PUBLIC_GRANTEES:
                reasons.append(f"ACL grants {g['Permission']} to {g['Grantee']['URI'].split('/')[-1]}")
        try:
            pol = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            for st in pol.get("Statement", []):
                if st.get("Effect") == "Allow" and st.get("Principal") in ("*", {"AWS": "*"}) \
                        and "Condition" not in st:
                    reasons.append(f"Bucket policy allows {st.get('Action')} to Principal *")
        except s3.exceptions.ClientError:
            pass
        if reasons:
            incidents.append(Incident(
                incident_type="PUBLIC_S3_BUCKET", severity="HIGH", resource_type="S3Bucket",
                resource_id=name, summary=f"Bucket {name} is publicly accessible",
                details={"reasons": reasons}))
    return incidents


# ------------------------------------------------------- 4b. open security groups
def detect_open_security_groups(ec2):
    incidents = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        bad = []
        for perm in sg.get("IpPermissions", []):
            world = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            world += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
            if not world:
                continue
            proto = perm.get("IpProtocol")
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            if proto == "-1" or any(lo <= p <= hi for p in config.SENSITIVE_PORTS):
                bad.append({"protocol": proto, "from": lo, "to": hi, "cidrs": world})
        if bad:
            sev = "CRITICAL" if any(b["protocol"] == "-1" for b in bad) else "HIGH"
            incidents.append(Incident(
                incident_type="OPEN_SECURITY_GROUP", severity=sev, resource_type="SecurityGroup",
                resource_id=sg["GroupId"],
                summary=f"Security group {sg['GroupId']} ({sg.get('GroupName')}) exposes "
                        f"sensitive ports to the internet",
                details={"offending_rules": bad, "vpc_id": sg.get("VpcId")}))
    return incidents


def run_event_detectors(events):
    incidents = (detect_unauthorized_access(events) + detect_mass_deletion(events)
                 + detect_privilege_escalation(events))
    for inc in incidents:   # record whether the actor is an IAM user or a federated/SSO role
        first = inc.evidence_events[0] if inc.evidence_events else {}
        inc.details["identity_type"] = (first.get("userIdentity") or {}).get("type", "unknown")
    return incidents


def run_posture_detectors(s3, ec2):
    return detect_public_buckets(s3) + detect_open_security_groups(ec2)
