"""Lambda entry point. Two triggers:
  * EventBridge rule on CloudTrail management events (near real time)
  * EventBridge schedule every 5 minutes (posture scan + CloudTrail sweep)
Both run the same pipeline: detect -> investigate -> contain -> notify."""
import json
import os
import time

import boto3

from . import detectors, investigator
from .containment import Containment
from .notifier import notify


def make_clients(session=None):
    s = session or boto3.session.Session()
    return {n: s.client(svc) for n, svc in [
        ("iam", "iam"), ("s3", "s3"), ("ec2", "ec2"), ("sns", "sns"), ("logs", "logs"),
        ("cloudtrail", "cloudtrail"), ("config", "config")]}


def run_pipeline(clients, events=None, posture=True, dry_run=None, flow_log_group=None):
    t0 = time.perf_counter()
    incidents = detectors.run_event_detectors(events or [])
    if posture:
        incidents += detectors.run_posture_detectors(clients["s3"], clients["ec2"])
    t_detect = time.perf_counter()
    responder = Containment(clients, dry_run=dry_run)
    results = []
    for inc in incidents:
        s = time.perf_counter()
        investigator.investigate(inc, clients, flow_log_group)
        responder.contain(inc)
        subject, _ = notify(clients["sns"], inc)
        results.append({"incident_id": inc.incident_id, "type": inc.incident_type,
                        "severity": inc.severity, "resource": inc.resource_id,
                        "status": inc.status, "actions": len(inc.containment),
                        "seconds": round(time.perf_counter() - s, 3), "subject": subject,
                        "fingerprint": inc.fingerprint()})
    return {"incidents": results, "detect_seconds": round(t_detect - t0, 3),
            "total_seconds": round(time.perf_counter() - t0, 3)}, incidents


def lambda_handler(event, context):
    clients = make_clients()
    flow = os.environ.get("FLOW_LOG_GROUP")
    dry = os.environ.get("DRY_RUN", "true") == "true"
    if "dry_run" in event:                              # per invocation override for testing
        dry = str(event["dry_run"]).lower() == "true"
    if event.get("source") == "aws.events":            # scheduled sweep or manual invoke
        events = detectors.fetch_cloudtrail_events(clients["cloudtrail"], event.get("lookback_min"))
        summary, _ = run_pipeline(clients, events, posture=True, flow_log_group=flow,
                                  dry_run=dry)
    else:                                               # single CloudTrail event
        summary, _ = run_pipeline(clients, [event], posture=False, flow_log_group=flow,
                                  dry_run=dry)
    print(json.dumps(summary))
    return summary
