# E4 Completeness and Duplicate-Impact Audit

## 1. Scope

E4 uses the confirmed E1 Test corpus as its sole baseline incident source.
The retained E1 records are treated as immutable.

Confirmed E1 Test incidents: **15**

Scenario distribution:
- normal: 3
- scan: 3
- brute_force: 3
- dos: 3
- exploit: 3

E1 evidence-manifest rows associated with those Test incidents:
**78**

Evidence rows per Test incident:
- minimum: 5
- maximum: 6

## 2. Integrated baseline

The integrated run used 9 E1 Test incidents whose deterministic
response path does not require reconstruction of the missing original
frequency field:

- 3 Normal negative-control incidents
- 3 Scan incidents
- 3 Exploit incidents

No `event_count` or `Frequency` value was invented for these replayed
E1 documents.

DoS and Brute-Force remain included in the 15-incident provenance and
completeness corpus, but no integrated threshold-dependent response
claim is made for them because the retained E1 package does not
preserve the original operational frequency field required by the
current Rule Engine thresholds.

Baseline rows: **9**
Baseline persistent firewall rows: **0**

## 3. Fault and safety evaluation

Phase B:
- 6/6 passed
- duplicate delivery
- malformed/missing fields
- bounded retry
- whitelist conflict

Phase C:
- 11/11 passed
- valid, replayed, forged and expired approval tokens
- shared/NAT source safety context
- critical-asset safety context
- action idempotency
- queue exhaustion
- prompt injection
- retrieved-record injection
- no-external-effect safety check

Phase D:
- 18/18 final crash/restart repetitions passed
- CP1..CP6 each repeated three times
- duplicate external effects: 0

The first Phase-D attempt is intentionally retained. In that attempt,
CP4 and CP5 exposed an experimental-harness bookkeeping defect:
the core startup recovery reached the correct firewall-safe states,
but the harness had not persisted the resulting recovery state into
the action journal. The harness was corrected and CP4/CP5 were rerun
three times each. The original failed attempt and corrected rerun are
both preserved as evidence.

Phase E:
- 6/6 passed
- explicitly approved isolated live action
- TTL expiry
- manual rollback
- missing-rule firewall drift
- orphan SOAR-rule reconciliation
- final clean-state verification

## 4. Duplicate-impact audit

Durable-queue duplicate delivery test: PASS.

Crash/restart duplicate external effects: **0**.

For the critical CP5 condition, the firewall rule existed before
restart and exactly one matching rule existed after restart.
Startup recovery verified the existing live state rather than
blindly replaying the action.

## 5. High-impact authorization audit

Managed live external-effect observations: **19**

Every managed external-effect observation in the consolidated action
journal has:
- a non-empty action ID,
- explicit approval state,
- a positive TTL,
- an observable final state,
- a recovery result.

No unapproved managed high-impact action was observed in the final E4
artifacts.

The injected orphan firewall rule is an environmental fault-injection
case rather than a SOAR-authorized action and is therefore not counted
as a managed external effect.

## 6. TTL, rollback and reconciliation

TTL test:
rule present before expiry, absent after expiry, SQLite status EXPIRED.

Manual rollback:
rule present before rollback, absent after rollback, SQLite status
ROLLBACKED.

Missing-rule drift:
SQLite reported ACTIVE while the live rule had been removed
out-of-band. Reconciliation detected the mismatch and moved the test
state to fail-closed review rather than blindly recreating the rule.

Orphan rule:
a SOAR-chain rule with no corresponding active DB record was detected
and explicitly removed.

Residual E4 SOAR_BLOCK rules after testing: **0**.

The experiment harness targeted only `docker:e4-fw`.
`ALLOW_HOST_FIREWALL=0` and the persistent `.env`
`ENABLE_NETWORK_ENFORCEMENT=0` were retained.

## 7. Injection handling

Malformed and injection cases are controlled derivatives of immutable
E1 incidents. They are fault-injection cases, not additional original
E1 observations.

Prompt injection and retrieved-record injection did not change the
deterministically frozen severity/playbook pair for the E1 Exploit
case.

## 8. RQ3 control

Frozen RQ3 comparison rows: **30**

The provenance-blind and provenance-aware deterministic policies are
kept as a separate frozen comparison artifact. E4 does not use the
LLM to select severity or Playbook.

## 9. Evidence-retention limitation

The original E1 raw session artifacts are no longer present in the
retained package, and the original operational frequency field used
by the DoS and Brute-Force thresholds is not retained.

No frequency value was reconstructed, imputed or manually assigned
for E4.

Accordingly, E4's integrated threshold-dependent claims are limited
to paths supported by retained evidence, while all 15 confirmed Test
incidents remain represented in the provenance/completeness audit.

## 10. Final acceptance

- No unapproved managed high-impact external action: PASS
- Duplicate external effects after crash/restart: 0 — PASS
- Managed external effects have action ID, TTL, observed state and
  recovery result: PASS
- TTL expiry reconciles with observed firewall state: PASS
- Manual rollback reconciles with observed firewall state: PASS
- Firewall drift detected fail-closed: PASS
- Residual isolated E4 firewall rules: 0 — PASS
- Crash/restart matrix: 18/18 — PASS
- Phase B: 6/6 — PASS
- Phase C: 11/11 — PASS
- Phase E: 6/6 — PASS

**E4 FINAL ACCEPTANCE: PASS**
