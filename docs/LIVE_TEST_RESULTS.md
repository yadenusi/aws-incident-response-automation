# Live test results (AWS lab account, 2026-09-29)

Deployed with CloudFormation to a UMGC lab account in us-east-1 and run against real test incidents.
Account number and access key IDs are partly masked.

| Run | Mode | Incidents | Outcome | Time |
|---|---|---|---|---|
| 1 | Dry run | 6 | All 5 test incidents plus the author's own SSO sign in; SSO containment failed; dry run alerts mislabeled | 2.23 s |
| 2 | Dry run | 6 | After fixes: SSO login monitor only; every status DRY_RUN; nothing changed | 2.33 s |
| 3 | Live | 6 | 4 contained; both buckets CONTAINMENT_FAILED (PutBucketAcl rejected on ACL-disabled buckets) | 3.31 s |
| 4 | Live | 3 | Buckets and security group no longer detected: fixes persisted | 1.83 s |
| 5 | Live | 4 | New public bucket contained; ACL step skipped; 3 existing tags kept | 3.13 s |

## Defects found only in the live test
1. Reserved concurrency of 5 broke the lab account's 10 execution limit (deploy failed). Removed.
2. IAM Identity Center (SSO) sign ins are roles, not IAM users, so user quarantine failed. Now monitor only with evidence preserved.
3. Dry run alerts said CONTAINED. Now report DRY_RUN (no changes made).
4. PutBucketAcl is rejected on BucketOwnerEnforced buckets (the S3 default). ACL step now skipped when ACLs are disabled.
5. PutBucketTagging replaced existing tags. Quarantine tag is now merged.

## E1. Deployment and identity
```
$ aws sts get-caller-identity
  "Account": "3473XXXX2472",
  "Arn": "arn:aws:sts::3473XXXX2472:assumed-role/AWSReservedSSO_StudentAdminAccess_.../yadenusi@student.umgc.edu"

$ aws cloudformation deploy ... (first attempt)
  ResponderFunction: Specified ReservedConcurrentExecutions for function decreases account's
  UnreservedConcurrentExecution below its minimum value of [10].
$ aws cloudformation deploy ... (after removing the reservation)
  Successfully created/updated stack - ir-automation
```

## E2. Test incidents created (simulate.py and CLI)
```
Region: us-east-1   Account: 3473XXXX2472
[1] Privilege escalation test user
    done: ir-test-user called PutUserPolicy on itself        (run twice)
[2] Security group with SSH open to the internet
    skipped: no default VPC in this region
    -> created by CLI instead: VPC=vpc-006be0f75071709cb  SG=sg-08e497a022fc7a5fe (tcp/22 from 0.0.0.0/0)
[3] Public S3 bucket
    done: ir-test-public-d8e0d58d, ir-test-public-4b55df25, later ir-test-public-d7e44fcd
```

## E3. Run 3, first live run (excerpt)
```
UNUSUAL_LOCATION_LOGIN  yadenusi@student.umgc.edu  CONTAINED+NOTIFIED           3 actions  0.362 s
PRIVILEGE_ESCALATION    ir-test-user               CONTAINED+NOTIFIED           7 actions  0.613 s
PRIVILEGE_ESCALATION    ir-test-user               CONTAINED+NOTIFIED           5 actions  0.481 s
PUBLIC_S3_BUCKET        ir-test-public-4b55df25    CONTAINMENT_FAILED+NOTIFIED  4 actions  0.398 s
PUBLIC_S3_BUCKET        ir-test-public-d8e0d58d    CONTAINMENT_FAILED+NOTIFIED  4 actions  0.405 s
OPEN_SECURITY_GROUP     sg-08e497a022fc7a5fe       CONTAINED+NOTIFIED           4 actions  0.574 s
detect_seconds: 0.477   total_seconds: 3.314
```

## E4. Run 5, final live run
```
IR-8CD289FC00  UNUSUAL_LOCATION_LOGIN  yadenusi@student.umgc.edu  CONTAINED+NOTIFIED  3 actions  0.273 s
IR-7908C73BD7  PRIVILEGE_ESCALATION    ir-test-user               CONTAINED+NOTIFIED  5 actions  1.137 s
IR-E859CE8C4C  PRIVILEGE_ESCALATION    ir-test-user               CONTAINED+NOTIFIED  5 actions  0.602 s
IR-B82781E878  PUBLIC_S3_BUCKET        ir-test-public-d7e44fcd    CONTAINED+NOTIFIED  5 actions  0.595 s
detect_seconds: 0.519   total_seconds: 3.127
```

## E5. Verification of AWS state after containment
```
$ aws iam list-user-policies --user-name ir-test-user
  "PolicyNames": ["escalated", "IR-Quarantine-DenyAll", "self-manage"]
$ aws iam list-access-keys --user-name ir-test-user
  AKIAVBXGKQDU....MVHW  Inactive
  AKIAVBXGKQDU....M2Q4  Inactive
$ aws ec2 describe-security-groups --group-ids sg-08e497a022fc7a5fe --query "SecurityGroups[0].IpPermissions"
  []
$ aws s3api get-public-access-block --bucket ir-test-public-d7e44fcd
  BlockPublicAcls: true  IgnorePublicAcls: true  BlockPublicPolicy: true  RestrictPublicBuckets: true
$ aws s3api get-bucket-tagging --bucket ir-test-public-d7e44fcd
  ir:quarantined=IR-B82781E878  DataClassification=Confidential  Owner=lab  ir:test=true
```

## E6. Evidence bucket listing (excerpt)
```
$ aws s3 ls s3://ir-automation-evidencebucket-v7mavcitga67 --recursive
23:28:51   1567 IR-798A037D8D/audit_trail.json
23:28:51   1441 IR-798A037D8D/cloudtrail_events.json
23:28:51    730 IR-798A037D8D/identity_snapshot.json
23:28:53    893 IR-EBCE4275EB/audit_trail.json
23:28:53    551 IR-EBCE4275EB/security_group_before.json
23:34:20   1118 IR-B82781E878/audit_trail.json
23:34:20   1291 IR-B82781E878/bucket_config_before.json
... 25 objects across 10 incident folders
```

## E7. Audit trail for incident IR-B82781E878 (bucket containment after the fix)
```
23:34:19.430  PRESERVE_EVIDENCE           s3://.../IR-B82781E878/bucket_config_before.json  SUCCESS
              sha256 63ea224c121024b522f0874c6b5d57074c72e132dfbaa72465f2790e671c0dce  (1291 bytes)
23:34:19.584  ENABLE_PUBLIC_ACCESS_BLOCK  ir-test-public-d7e44fcd  SUCCESS
23:34:19.623  RESET_ACL_PRIVATE           ir-test-public-d7e44fcd  SKIPPED
              reason: ACLs disabled (BucketOwnerEnforced); nothing to reset
23:34:19.740  TAG_RESOURCE                ir-test-public-d7e44fcd  SUCCESS  tags_preserved: 3
```
