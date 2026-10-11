# Free workspace access

The free tier is a registered workspace for submitting a bounded project and run request. It is not a purchase, a paid subscription, or a promise of unattended software publication.

## Access and limits

Visitors can view the product page and choose the free signup action. Cloudflare Access authenticates the user before registration. Public signup requires an Access application policy permitting the intended authenticated audience; opening that policy does not grant operator privileges.

Free accounts can create one project and submit one run request per rolling 24 hours. The run limit counts stored requests, including requests awaiting authorization or review. Retrying the same idempotency key returns the original request rather than spending another allowance. Quotas must be checked in the same database write that inserts the project or request so simultaneous requests cannot bypass them. The server derives the plan; request bodies cannot select an operator or paid plan.

Operator access is granted only through the deployment's independently managed `OWNER_EMAILS` allowlist matched against a verified Access identity. Browser fields, project ownership and a submitted email string cannot grant that role. Access policy and operator membership are separate controls. Authenticated requests synchronize the stored plan with the current allowlist. Both background queue selection and claiming also require the current trusted owner-email allowlist as an independent argument, in addition to the stored operator plan. A stale database role alone therefore cannot authorize execution. Supply this list from trusted deployment configuration, never from a submitted job.

## Execution gates

A free account's own-software request enters `awaiting_authorization`. It cannot be selected or claimed by the operator queue until a separately implemented and authorized approval path exists. Clean-room requests continue to enter `awaiting_review`; free signup does not satisfy either reviewer signature, the independent root of trust or Room B isolation requirements.

The queue must independently exclude non-operator projects even if a row is mistakenly marked `queued`. A stored request or quota acceptance is not execution evidence. Implementation, tests, benchmarks and release receipts remain distinct gates. Product Hunt launches remain unscheduled drafts.

The upgrade action records interest only. A unique pending request per account deduplicates retries; it does not change entitlements. There is no billing integration or paid-plan checkout in this scope. Do not display an invented subscription price, successful payment or upgrade entitlement. A future paid tier needs a real billing provider, verified server-side entitlement changes and separate release authorization.

## Existing database migration

Existing deployments need an explicit migration before the freemium Worker serves writes:

1. Add the users plan column with a constrained, safe free default. Classify existing operator accounts from independently verified deployment configuration; do not infer operator status merely because an account predates this migration.
2. SQLite cannot expand an existing table's status CHECK constraint with a column alteration. Rebuild the runs table to include `awaiting_authorization`, preserving every row's ID, owner, project, status, idempotency key, timestamps, evidence, error and lease fields.
3. Preserve the composite project/owner foreign key, the per-owner idempotency uniqueness constraint and indexes. Use the transactional migration mechanism supported by the deployed D1 environment and check foreign-key integrity before declaring success.
4. Verify existing rows and leases are unchanged, the new default is free, and old queued rows belonging to free users cannot be claimed. Do not reset, delete or requeue historical runs as part of a schema upgrade.

Test simultaneous free requests, idempotent retries, isolation between users, forged plan fields, allowlisted operator access and both queue selection and claim exclusion. Test the migration against the old schema with representative existing rows, not only an empty database. Record the actual migration result before reporting freemium access as deployed.
