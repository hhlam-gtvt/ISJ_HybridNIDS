# Specification versus runtime: differential test

Produced by `spec_runtime_differential.py` (spec-runtime-differential-1.0, Python 3.13.18). Every number in this report is read from `spec_runtime_differential.json`, which the same run writes. The runtime functions are the archived ones: they are imported or executed from the archive and are not re-implemented.

## 1. Files

| file | SHA-256 | role |
| --- | --- | --- |
| `E4_SOAR_NO_ACTION.py` | `4188c22e9df786d81994f199331e0f6045eea565f63443f2fa521fa814c67f71` | T3 (executed from a byte-identical copy, external modules stubbed) |
| `e1_ground_truth.csv` | `d51afc2f91064e8bfa472aff87030fc1855c0b8cdad750fa4c9904fccde7ed8e` | T1 (corroboration values), T1r, T1x |
| `e1_session_manifest.csv` | `ebc588f993f6e3324195872c9002d692fa430bdc4e752bb0bcd498c7cc221277` | hashed, not read by any target |
| `e3_elk_routing_adapter.py` | `1287cef5eb54c7aca808ee6dc9afd1ad99bf895f0a96b4c25309fb021ace25fe` | T2bc (executed as a script, Elasticsearch reply stubbed) |
| `e3_response_routing.py` | `fc620ad537aaf6957dd1223bc73710a0653c886e92ed835032acf1e8a527a491` | T2a (executed as a script) |
| `e3_response_safety_boundary.py` | `e3df5fd0284f6310fb79d126e2c98e78b68c2962e088e3f2862594f0a18c3dca` | T2bc (executed as a script) |
| `e4_control_plane.py` | `b2315f04ac7772f5e838092e535ac2f21732b4c1d8a28f542bd3e479d0720ca8` | T1x (imported) |
| `e4_experiment_runner.py` | `110133dac685ebd5320d3bc8fcf9954365ea424ee860f0b88b00180c421afadc` | T1a, T1b, T1c, T1r (imported) |
| `policy_property_check.py` | `d611aff1de33fce2c88feb304816947461f31a1b68a92371af38bb6208ba4e70` | specification (`repaired`), imported |
| `E3_RQ3_LAM_SELF_REFERENCE_COMPARISON.csv` | `3488a47304a791b877634212fdb7d410546e36e6aa735dad81e895a44e232457` | T2bc (archived tier-to-route pairs) |
| `e3_event_matches.csv` | `297862ac5770a68608bf891b0ad878b9d7e5103dbcc47b2a04d54e788c81eb4f` | T2bc (archived tier-to-route pairs) |
| `e4_rq3_comparison.csv` | `5782195493e38bcbcaf1ca8cefee733ebfd35951ba7c0dbcc870fae0ca4b68ad` | T1r (archived decisions) |

Reference check: the repaired specification is total on 3840 inputs, with 0 monotonicity violations and 0 containment-precondition violations (recomputed in this run with the specification's own `check`).

## 2. Runtime input domains

`<MISSING>` denotes a key that is absent from the input. Each domain is the full product of the listed values and is enumerated completely.

| target | runtime function(s) | inputs |
| --- | --- | --- |
| T1a | `evidence_quality` -> `aware_policy` -> `apply_safety_gates` | 233280 |
| T1b | `aware_policy` -> `apply_safety_gates`, quality field set directly | 25920 |
| T1c | `outcome_row` (final action, execution mode, approval token) | 17280 |
| T1r | `aware_policy` -> `apply_safety_gates` on the archived RQ3 rows | 30 |
| T1x | `E4ControlPlane.safety_context` | 12 |
| T2a | `e3_response_routing.py`, one input row | 13122 |
| T2bc | `e3_elk_routing_adapter.py` -> `e3_response_safety_boundary.py` | 150 documents; 5 tiers x 9 policy variants |
| T3a | `normalize_event` | 2304 |
| T3b | `decide_rule` | 6006 |
| T3c | `insert_queue` -> `worker_loop` -> `process_event` | 118272 |
| T3d | `manual_decision` | 2016 calls on 84 pending signatures |
| T3e | `ingest_es_once` / `is_context_only_document` | 15 |

**T1a fields.** `confidence_status` in {`high`, `not_applicable`, `<MISSING>`}; `corroboration_type` in {`controller_plus_pcap_traffic_volume`, `none_insufficient`, ``, `<MISSING>`}; `critical_asset` in {`False`, `True`, `<MISSING>`}; `evidence_count` in {`5`, `4`, `3`, `0`, `<MISSING>`, `abc`}; `ground_truth_status` in {`confirmed`, `excluded`, `<MISSING>`}; `scenario` in {`normal`, `scan`, `brute_force`, `dos`, `exploit`, ``, `<MISSING>`, `unlisted_scenario`}; `shared_address` in {`False`, `True`, `<MISSING>`}; `source_ip` in {`192.168.10.101`, `<MISSING>`, ``, `not-an-ip`, `999.999.1.1`}; `whitelist_match` in {`False`, `True`, `<MISSING>`}.

**T1b fields.** `corroboration_type` in {`controller_plus_pcap_traffic_volume`, `none_insufficient`, ``, `<MISSING>`}; `critical_asset` in {`False`, `True`, `<MISSING>`}; `evidence_quality` in {`HIGH`, `LOW`, `<MISSING>`, ``, `MEDIUM`, `high`}; `scenario` in {`normal`, `scan`, `brute_force`, `dos`, `exploit`, ``, `<MISSING>`, `unlisted_scenario`}; `shared_address` in {`False`, `True`, `<MISSING>`}; `source_ip` in {`192.168.10.101`, `<MISSING>`, ``, `not-an-ip`, `999.999.1.1`}; `whitelist_match` in {`False`, `True`, `<MISSING>`}.

**T1c fields.** `approval_token` in {`valid`, `none`, `expired`, `forged`, `malformed`}; `corroboration_type` in {`controller_plus_pcap_traffic_volume`, `none_insufficient`, `<MISSING>`}; `critical_asset` in {`False`, `True`}; `evidence_quality` in {`HIGH`, `LOW`, `<MISSING>`}; `execution_mode` in {`DRY_RUN`, `ISOLATED_REVERSIBLE_SIM`}; `scenario` in {`normal`, `scan`, `brute_force`, `dos`, `exploit`, ``, `<MISSING>`, `unlisted_scenario`}; `shared_address` in {`False`, `True`}; `source_ip` in {`192.168.10.101`, `<MISSING>`, `999.999.1.1`}; `whitelist_match` in {`False`, `True`}.

**T2a fields.** `each_of_S1..S6` in {`0`, `1`, ``}; `routing_tier_W60` in {`HYBRID_CORRELATED`, `BOTH_UNCORRELATED`, `SURICATA_ONLY`, `RF_ONLY_REVIEW`, `BENIGN`, `UNLISTED_TIER`}; `source` in {`primary`, `supplementary`, ``}.

**T3c fields.** `allow_private_block` in {`0`, `1`}; `auto_block_high` in {`1`, `0`}; `category` in {`NORMAL`, `DOS`, `BRUTE FORCE`, `EXPLOIT`, `SCAN`, `UNLISTED_CATEGORY`, `<MISSING>`}; `emergency_stop` in {`0`, `1`}; `frequency` in {`<MISSING>`, `0`, `1`, `9`, `10`, `49`, `50`, `149`, `150`, `-1`, `x`}; `ip_class` in {`lab_testnet`, `public`, `private`, `loopback`, `multicast`, `reserved`, `malformed`, `absent`}; `prior_watch_strikes` in {`0`, `2`}; `strict_category` in {`1`, `0`}; `whitelist_state` in {`NOT_MATCHED`, `MATCHED_IP`, `MATCHED_CIDR`, `LOOKUP_ERROR`, `NOT_MATCHED_THEN_MATCHED`, `NOT_MATCHED_THEN_ERROR`}.

T3c address classes: absent = `<MISSING>`; lab_testnet = `203.0.113.10`; loopback = `127.0.0.1`; malformed = `999.1.1.1`; multicast = `224.0.0.1`; private = `192.168.10.101`; public = `8.8.8.8`; reserved = `240.0.0.1`.
The frequency values of T3c are the two sides of each rule-engine threshold; T3b confirms on every integer from 0 to 1000 that `decide_rule` changes only at those thresholds (DOS at 50, 150, BRUTE_FORCE at 10, 50, no change for the other categories).

## 3. Abstraction maps

Authority scale of the specification: containment proposal 3, analyst triage 2, watchlist 1, monitor 0, safety hold 0. A runtime field the specification does not model is reported as a grouping variable, never folded into a specification field. A specification field the runtime does not read is handled in two ways that are reported side by side: the *favourable completion* sets it to its best value (correlated, high, clear), so the specification is at its most permissive; the *sweep* enumerates every value of it.

### T1 (E4 policy path)

| runtime field | specification field | map (primary choice) | alternative reported |
| --- | --- | --- | --- |
| `corroboration_type` | P | non-empty value other than `none_insufficient` -> correlated; `none_insufficient` -> none; empty or absent -> none | `none_insufficient` -> rf_only, sur_only or both_uncorrelated |
| `evidence_quality` (T1a: output of `evidence_quality()`) | Q | HIGH -> high; LOW -> low; absent or empty -> missing; any other string -> missing | other string -> low; T1a: LOW caused by an absent input -> missing |
| `whitelist_match` | whitelist | True -> raised; False -> clear; absent -> clear (the runtime treats an absent flag as false) | absent -> missing |
| `shared_address` | shared_address | as for `whitelist_match` | absent -> missing |
| not read | drift, schema | favourable completion: clear | sweep: all 16 combinations |
| `scenario` | none | grouping variable (ground-truth label that selects the action matrix row); results are reported per scenario and impact class |  |
| `source_ip` validity | none | invalid or absent -> `REJECT_INPUT`, not comparable |  |
| `critical_asset` | none | runtime-only safety condition, not mapped |  |
| execution mode, approval token (T1c) | none | runtime-only |  |

Outcome map: `BLOCK`, `RATE_LIMIT` -> 3; `PENDING_EXPLICIT_APPROVAL` -> 3 (a high-impact proposal awaiting approval; alternative reading 2); `WATCHLIST` -> 1; `NO_ACTION`, `SAFETY_HOLD`, `SKIPPED_WHITELIST`, `REJECTED_APPROVAL` -> 0; `REJECT_INPUT` -> 0 for the monotonicity check and not comparable in the differential. The provenance values rf_only, sur_only and both_uncorrelated, the quality value missing (in T1a), and the safety value conflicting have no runtime counterpart in T1. The runtime field `corroboration_type` records how the ground truth was corroborated (controller log with host log or packet capture), not which detector fired, so the map to P is an analogy between two notions of corroboration. All 4 corroboration values in `e1_ground_truth.csv` other than `none_insufficient` were checked to give identical outcomes.

### T2 (E3 routing tier logic)

Tier -> P: HYBRID_CORRELATED -> correlated, BOTH_UNCORRELATED -> both_uncorrelated, SURICATA_ONLY -> sur_only, RF_ONLY_REVIEW -> rf_only, BENIGN -> none. Q and the four safety fields are not read by any of the three scripts. The outcome of the chain is a review queue. Three authority readings are reported: A (literal) PRIORITY_ANALYST_REVIEW 2, EVIDENCE_REVIEW 2, NO_DETECTOR_TRIGGER 0; B PRIORITY_ANALYST_REVIEW 3, EVIDENCE_REVIEW 2; C PRIORITY_ANALYST_REVIEW 3, EVIDENCE_REVIEW 1. Reading A follows the code, which records playbook `NOT_EVALUATED`, external action `NOT_EXECUTED` and states that a priority review is not a pending high-severity action. Strategies S1 to S5 produce `NOT_EVALUATED` and are not mapped.

### T3 (SOAR responder)

The responder reads the alert category, the event count, the source address, the whitelist table, the emergency-stop flag and four configuration flags. It reads no provenance field, no evidence-quality field, no drift or schema field and no shared-address field. Whitelist map, from the gate readings the runtime actually performed in the run: all readings clear -> clear; all matched -> raised; lookup error -> missing; successive readings disagree -> conflicting; no reading (NORMAL category) -> not read. Category, event count, address class, emergency stop, `AUTO_BLOCK_HIGH`, `STRICT_CATEGORY`, `ALLOW_PRIVATE_BLOCK` and the watchlist strike history are runtime-only. Outcome map: `NO_ACTION` -> 0; `WATCHLIST` -> 1; `AUTO_BLOCK_DRY_RUN` (block playbook executed in dry-run without human approval) -> 3; `PENDING_APPROVAL_BLOCK`, `PENDING_APPROVAL_RATE_LIMIT` -> 3 (alternative 2); `SKIPPED_WHITELIST`, `SAFETY_HOLD`, `RESPONSE_REFUSED_FAILED` -> 0; queue item `DEAD` -> not comparable.

## 4. Properties checked on the runtime itself

| target | inputs | no defined outcome (exception) | degradation edges checked | monotonicity violations | containment-class outcomes | precondition violations |
| --- | --- | --- | --- | --- | --- | --- |
| T1a | 233280 | 4320 | 1262088 | 0 | 48 strict, 108 extended | 0 strict, 36 extended |
| T1b | 25920 | 0 | 113616 | 0 | 48 strict, 108 extended | 24 strict, 72 extended |
| T1c | 17280 | 0 | 80064 | 0 | 54 strict, 114 extended | 33 strict, 81 extended |
| T2a | 13122 | 0 (plus 4 absent-column probes) | not applicable (label pass-through) | not applicable | 0 | 0 |
| T2bc (reading A) | 5 tiers | 0 | 5 | 0 | 0 | 0 |
| T3c | 118272 | 0 | 335104 (98560 on the whitelist field) | 0 on the whitelist field; 3224 on runtime-only control flags | 16244 | 0 on the field the runtime reads; provenance and quality are not read |
| T3d | 2016 calls | 336 | not applicable | not applicable | not applicable | 0 executions after a reject or with the whitelist not clear |

Notes on the table.

- Totality, T1a: 4320 inputs raise `ValueError` inside `evidence_quality` (non-numeric `evidence_count` when the two preceding checks pass). Example: `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": "abc", "ground_truth_status": "confirmed", "scenario": "normal", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`. The archived runner sets this field from `len()`, so the exception is not reachable through its own normalisation.
- Strict containment outcomes are final `BLOCK` or `RATE_LIMIT`; extended adds `PENDING_EXPLICIT_APPROVAL`. The precondition is: mapped P correlated, mapped Q high, mapped whitelist and shared_address clear. Drift and schema cannot be part of it because the runtime does not read them.
- T1b strict violations (24): `aware_policy` tests only that `corroboration_type` is non-empty, so the value `none_insufficient` with a directly supplied quality HIGH yields a high-impact action. Example: `{"corroboration_type": "none_insufficient", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "brute_force", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `RATE_LIMIT`. In T1a the same value forces quality LOW inside `evidence_quality`, and the strict count is 0.
- T1a extended violations (36): a pending high-impact proposal is issued while a mapped safety field is raised. Example: `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "brute_force", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `PENDING_EXPLICIT_APPROVAL`.
- T1c: 24 rows have a simulated external effect, 0 of them without a valid approval; 0 rows fail the runner's own acceptance flag. A final `BLOCK` or `RATE_LIMIT` is reached with a raised shared-address or critical-asset flag in 18 rows, 18 of them with a valid approval token in the simulated execution mode (the approval overrides the gate, by design of the runner).
- T1a monotonicity: 32616 further edges have an endpoint without a defined outcome (the exception above) and are not counted as checked.
- T1x: `safety_context` raises `ValueError` for 8 of 12 address pairs (any malformed or empty address). With the control plane's default networks, 32 of the 32 rows of `e1_ground_truth.csv` have a shared source and 32 a critical destination, so explicit approval would be required for 32; the archived runner does not call this function and its RQ3 rows carry neither flag.
- T2a: the script copies the pre-computed tier to the route for strategy S6 (320 of 320 triggered rows identical) and assigns no severity, playbook or action. It accepts 64 rows that carry an S6 trigger together with the tier BENIGN, a combination the adapter rejects. An absent column ends the script with an uncaught `KeyError` (`S1`, `S6`, `routing_tier_W60`, `source`).
- T3c monotonicity: the 3224 violations all lie on the two runtime-only control edges (emergency stop switched on, `AUTO_BLOCK_HIGH` switched off). Transitions: auto_block_high: RESPONSE_REFUSED_FAILED -> PENDING_APPROVAL_BLOCK (364); auto_block_high: SAFETY_HOLD -> PENDING_APPROVAL_BLOCK (624); auto_block_high: SKIPPED_WHITELIST -> PENDING_APPROVAL_BLOCK (624); emergency_stop: RESPONSE_REFUSED_FAILED -> PENDING_APPROVAL_BLOCK (364); emergency_stop: SAFETY_HOLD -> PENDING_APPROVAL_BLOCK (624); emergency_stop: SKIPPED_WHITELIST -> PENDING_APPROVAL_BLOCK (624). In each of them the high-severity path stops at a pending approval before the second whitelist reading and before target validation, which the automatic path performs immediately. In T3d the whitelist is read again and the target validated when the approval arrives.
  Example: `{"allow_private_block": 0, "auto_block_high": 1, "category": "DOS", "emergency_stop": 0, "frequency": 150, "ip_class": "lab_testnet", "prior_watch_strikes": 0, "strict_category": 0, "whitelist_state": "NOT_MATCHED_THEN_MATCHED"}` gives `SKIPPED_WHITELIST`; with `emergency_stop` degraded the outcome is `PENDING_APPROVAL_BLOCK`.
- T3c containment: 16244 containment-class outcomes, of which 260 are block playbooks executed (dry-run) without human approval. None occurs with a whitelist reading other than clear. All 16244 are issued without any provenance or quality input, because the responder has none.
- T3d: `manual_decision` raises `OperationalError` in 336 of 2016 calls, always for an approval while the whitelist table cannot be read; the incident stays `PENDING`. No call executes a playbook after a reject or with the whitelist matched (0).
- T3a: of 2304 inputs, 588 are accepted and 1716 rejected (ValidationError 84, ValueError 1632). Event counts are parsed as: '150' -> 150, '<MISSING>' -> 1, 0 -> 1, 1 -> 1, 1.9 -> 1, 150 -> 150, None -> 1. The category string `Normal traffic` is canonicalised to `UNKNOWN`.
- T3c dead-letter reasons: ValidationError after 1 deliveries (10368); ValueError after 3 deliveries (45696).
- Advisory text: 29568 T3c inputs were replayed with adversarial text returned by the stubbed explanation functions; 0 decisions changed.

## 5. Runtime authority versus the repaired specification

Favourable completion (unread specification fields at their best value). One comparison per runtime input.

| target | inputs | comparable | agree | runtime more permissive | runtime more restrictive | not comparable | distinct specification inputs reached |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1a | 233280 | 34344 | 30468 | 3828 | 48 | 198936 | 12 |
| T1b | 25920 | 3888 | 3372 | 492 | 24 | 22032 | 24 |
| T1c | 17280 | 8040 | 7552 | 421 | 67 | 9240 | 24 |
| T1r (archived rows) | 30 | 30 | 21 | 3 | 6 | 0 | 2 |
| T2bc, reading A | 5 | 5 | 3 | 1 | 1 | 0 | 5 |
| T2bc, reading B | 5 | 5 | 4 | 1 | 0 | 0 | 5 |
| T2bc, reading C | 5 | 5 | 3 | 0 | 2 | 0 | 5 |
| T3c | 118272 | 62208 | 43412 | 0 | 18796 | 56064 | 4 |

The T2bc rows use the policy variant in which both unarchived tier routes carry a label other than PRIORITY_REVIEW and NO_DETECTOR_TRIGGER (section 8).

Sweep over the specification fields the runtime does not read. One comparison per pair (runtime input, completion).

| target | swept fields | pairs | agree | runtime more permissive | runtime more restrictive | not comparable | inputs permissive for at least one completion | inputs agreeing for every completion |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T1a | drift, schema | 3732480 | 486768 | 62688 | 48 | 3182976 | 3924 | 30396 |
| T1b | drift, schema | 414720 | 53592 | 8592 | 24 | 352512 | 540 | 3336 |
| T1c | drift, schema | 276480 | 121042 | 7531 | 67 | 147840 | 474 | 7519 |
| T2bc, reading A | Q and four safety fields | 3840 | 770 | 3069 | 1 | 0 | 4 | 1 |
| T3c | P, Q | 1774080 | 549880 | 316120 | 67120 | 840960 | 24308 | 27168 |
| T3c | P, Q, drift, schema, shared_address | 113541120 | 36365380 | 23287180 | 67120 | 53821440 | 24308 | 27168 |

Reading of the T3c rows: against the most permissive specification input the responder is never more permissive (0 of 62208 comparable inputs). Because it reads neither provenance nor quality, each of the 24308 inputs with a non-zero authority exceeds the specification for at least one of the 15 (P, Q) combinations, and 27168 of the 62208 comparable inputs agree for all of them.

T1a by scenario and impact class (favourable completion, primary map):

| scenario / impact | agree | runtime more permissive | runtime more restrictive | not comparable |
| --- | --- | --- | --- | --- |
| `scenario=<MISSING>, impact=UNLISTED` | 1908 | 0 | 0 | 27252 |
| `scenario=brute_force, impact=HIGH` | 5712 | 12 | 0 | 23436 |
| `scenario=dos, impact=HIGH` | 5712 | 12 | 0 | 23436 |
| `scenario=exploit, impact=HIGH` | 5712 | 12 | 0 | 23436 |
| `scenario=normal, impact=NONE` | 5700 | 0 | 24 | 23436 |
| `scenario=scan, impact=INTERNAL` | 1908 | 3792 | 24 | 23436 |
| `scenario=unlisted_scenario, impact=UNLISTED` | 1908 | 0 | 0 | 27252 |
| `scenario=, impact=UNLISTED` | 1908 | 0 | 0 | 27252 |

T3c by category (favourable completion, primary map), summed over severities:

| category | agree | runtime more permissive | runtime more restrictive | not comparable |
| --- | --- | --- | --- | --- |
| `category=<MISSING>` | 3888 | 0 | 1296 | 11712 |
| `category=BRUTE FORCE` | 9132 | 0 | 1236 | 6528 |
| `category=DOS` | 8612 | 0 | 1756 | 6528 |
| `category=EXPLOIT` | 10116 | 0 | 252 | 6528 |
| `category=NORMAL` | 0 | 0 | 10368 | 6528 |
| `category=SCAN` | 7776 | 0 | 2592 | 6528 |
| `category=UNLISTED_CATEGORY` | 3888 | 0 | 1296 | 11712 |

## 6. Divergence classes with minimal examples

A minimal example is the input with the fewest fields away from the target's baseline input, ties broken by enumeration order. Sub-classes are named by the runtime outcome and the specification route.

**T1a, favourable completion**

- `runtime_more_permissive`: 3828. Example: runtime input `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "scan", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `WATCHLIST` (authority 1); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "raised", "whitelist": "clear"}` gives `safety_hold` (authority 0).
  - PENDING_EXPLICIT_APPROVAL where the specification gives safety_hold: 36. Example input: `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "brute_force", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - WATCHLIST where the specification gives monitor: 2520. Example input: `{"confidence_status": "high", "corroboration_type": "none_insufficient", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "scan", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - WATCHLIST where the specification gives safety_hold: 1272. Example input: `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "scan", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}`.
- `runtime_more_restrictive`: 48. Example: runtime input `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "normal", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `NO_ACTION` (authority 0); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - NO_ACTION where the specification gives containment_proposal: 24. Example input: `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "normal", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - WATCHLIST where the specification gives containment_proposal: 24. Example input: `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "scan", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
- `not_comparable`: 198936. Example: runtime input `{"confidence_status": "high", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_count": 5, "ground_truth_status": "confirmed", "scenario": "normal", "shared_address": false, "source_ip": "<MISSING>", "whitelist_match": false}` gives `REJECT_INPUT` (authority 0); REJECT_INPUT: invalid scenario or source address has no specification counterpart.
  - REJECT_INPUT: invalid scenario or source address has no specification counterpart: 194616 runtime inputs.
  - runtime raised ValueError: 4320 runtime inputs.

**T1b, favourable completion**

- `runtime_more_permissive`: 492. Example: runtime input `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "scan", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `WATCHLIST` (authority 1); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "raised", "whitelist": "clear"}` gives `safety_hold` (authority 0).
  - BLOCK where the specification gives monitor: 8. Example input: `{"corroboration_type": "none_insufficient", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "exploit", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - PENDING_EXPLICIT_APPROVAL where the specification gives monitor: 12. Example input: `{"corroboration_type": "none_insufficient", "critical_asset": true, "evidence_quality": "HIGH", "scenario": "brute_force", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - PENDING_EXPLICIT_APPROVAL where the specification gives safety_hold: 36. Example input: `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "brute_force", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - RATE_LIMIT where the specification gives monitor: 16. Example input: `{"corroboration_type": "none_insufficient", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "brute_force", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - WATCHLIST where the specification gives monitor: 276. Example input: `{"corroboration_type": "none_insufficient", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "scan", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - WATCHLIST where the specification gives safety_hold: 144. Example input: `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "scan", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}`.
- `runtime_more_restrictive`: 24. Example: runtime input `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "normal", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `NO_ACTION` (authority 0); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - NO_ACTION where the specification gives containment_proposal: 12. Example input: `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "normal", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
  - WATCHLIST where the specification gives containment_proposal: 12. Example input: `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "scan", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}`.
- `not_comparable`: 22032. Example: runtime input `{"corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "scenario": "normal", "shared_address": false, "source_ip": "<MISSING>", "whitelist_match": false}` gives `REJECT_INPUT` (authority 0); REJECT_INPUT: invalid scenario or source address has no specification counterpart.
  - REJECT_INPUT: invalid scenario or source address has no specification counterpart: 22032 runtime inputs.

**T1c, favourable completion**

- `runtime_more_permissive`: 421. Example: runtime input `{"approval_token": "valid", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "execution_mode": "DRY_RUN", "scenario": "scan", "shared_address": true, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `WATCHLIST` (authority 1); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "raised", "whitelist": "clear"}` gives `safety_hold` (authority 0).
  - BLOCK where the specification gives monitor: 7.
  - BLOCK where the specification gives safety_hold: 4.
  - PENDING_EXPLICIT_APPROVAL where the specification gives monitor: 12.
  - PENDING_EXPLICIT_APPROVAL where the specification gives safety_hold: 36.
  - RATE_LIMIT where the specification gives monitor: 14.
  - RATE_LIMIT where the specification gives safety_hold: 8.
  - WATCHLIST where the specification gives monitor: 160.
  - WATCHLIST where the specification gives safety_hold: 180.
- `runtime_more_restrictive`: 67. Example: runtime input `{"approval_token": "valid", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "execution_mode": "DRY_RUN", "scenario": "normal", "shared_address": false, "source_ip": "192.168.10.101", "whitelist_match": false}` gives `NO_ACTION` (authority 0); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - NO_ACTION where the specification gives containment_proposal: 20.
  - REJECTED_APPROVAL where the specification gives containment_proposal: 27.
  - WATCHLIST where the specification gives containment_proposal: 20.
- `not_comparable`: 9240. Example: runtime input `{"approval_token": "valid", "corroboration_type": "controller_plus_pcap_traffic_volume", "critical_asset": false, "evidence_quality": "HIGH", "execution_mode": "DRY_RUN", "scenario": "normal", "shared_address": false, "source_ip": "<MISSING>", "whitelist_match": false}` gives `REJECT_INPUT` (authority 0); REJECT_INPUT: invalid scenario or source address has no specification counterpart.
  - REJECT_INPUT: invalid scenario or source address has no specification counterpart: 9240 runtime inputs.

**T1r, the 30 archived RQ3 rows (replayed decisions identical to the archive: 30 of 30)**

- `runtime_more_permissive`: 3. Example: runtime input `{"evidence_quality": "LOW", "pair_id": "RQ3-EVT_TEST_SCAN_01_001-DEGRADED_PROVENANCE_SAME_INCIDENT", "provenance_fields_available": "no", "scenario": "scan"}` gives `WATCHLIST` (authority 1); specification input `{"drift": "clear", "prov": "none", "qual": "low", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `monitor` (authority 0).
  - WATCHLIST where the specification gives monitor: 3. Example input: `{"evidence_quality": "LOW", "pair_id": "RQ3-EVT_TEST_SCAN_01_001-DEGRADED_PROVENANCE_SAME_INCIDENT", "provenance_fields_available": "no", "scenario": "scan"}`.
- `runtime_more_restrictive`: 6. Example: runtime input `{"evidence_quality": "HIGH", "pair_id": "RQ3-EVT_TEST_NORMAL_01_001-REAL_E1_TEST", "provenance_fields_available": "yes", "scenario": "normal"}` gives `NO_ACTION` (authority 0); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - NO_ACTION where the specification gives containment_proposal: 3. Example input: `{"evidence_quality": "HIGH", "pair_id": "RQ3-EVT_TEST_NORMAL_01_001-REAL_E1_TEST", "provenance_fields_available": "yes", "scenario": "normal"}`.
  - WATCHLIST where the specification gives containment_proposal: 3. Example input: `{"evidence_quality": "HIGH", "pair_id": "RQ3-EVT_TEST_SCAN_01_001-REAL_E1_TEST", "provenance_fields_available": "yes", "scenario": "scan"}`.
- `not_comparable`: 0. Example: none.

**T2bc, reading A, favourable completion**

- `runtime_more_permissive`: 1. Example: runtime input `{"e3_routing_tier": "RF_ONLY_REVIEW", "route": "RF_EVIDENCE_REVIEW"}` gives `EVIDENCE_REVIEW` (authority 2); specification input `{"drift": "clear", "prov": "rf_only", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `watchlist` (authority 1).
  - EVIDENCE_REVIEW where the specification gives watchlist: 1.
- `runtime_more_restrictive`: 1. Example: runtime input `{"e3_routing_tier": "HYBRID_CORRELATED", "route": "PRIORITY_REVIEW"}` gives `PRIORITY_ANALYST_REVIEW` (authority 2); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - PRIORITY_ANALYST_REVIEW where the specification gives containment_proposal: 1.
- `not_comparable`: 0. Example: none.

**T3c, favourable completion**

- `runtime_more_permissive`: 0. Example: none.
- `runtime_more_restrictive`: 18796. Example: runtime input `{"allow_private_block": 0, "auto_block_high": 1, "category": "NORMAL", "emergency_stop": 0, "frequency": 150, "ip_class": "lab_testnet", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}` gives `NO_ACTION` (authority 0); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - NO_ACTION where the specification gives containment_proposal: 10368. Example input: `{"allow_private_block": 0, "auto_block_high": 1, "category": "NORMAL", "emergency_stop": 0, "frequency": 150, "ip_class": "lab_testnet", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}`.
  - RESPONSE_REFUSED_FAILED where the specification gives containment_proposal: 364. Example input: `{"allow_private_block": 0, "auto_block_high": 1, "category": "EXPLOIT", "emergency_stop": 0, "frequency": 150, "ip_class": "private", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}`.
  - WATCHLIST where the specification gives containment_proposal: 8064. Example input: `{"allow_private_block": 0, "auto_block_high": 1, "category": "SCAN", "emergency_stop": 0, "frequency": 150, "ip_class": "lab_testnet", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}`.
- `not_comparable`: 56064. Example: runtime input `{"allow_private_block": 0, "auto_block_high": 1, "category": "EXPLOIT", "emergency_stop": 0, "frequency": 150, "ip_class": "malformed", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}` gives `INPUT_REJECTED_DEAD` (authority 0); queue item DEAD: malformed alert has no specification counterpart.
  - queue item DEAD: malformed alert has no specification counterpart: 56064 runtime inputs.

**T3c, sweep over P and Q**

- `runtime_more_permissive`: 316120. Example: runtime input `{"allow_private_block": 0, "auto_block_high": 1, "category": "EXPLOIT", "emergency_stop": 0, "frequency": 150, "ip_class": "lab_testnet", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}` gives `AUTO_BLOCK_DRY_RUN` (authority 3); specification input `{"drift": "clear", "prov": "none", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `monitor` (authority 0).
  - AUTO_BLOCK_DRY_RUN where the specification gives analyst_triage: 520.
  - AUTO_BLOCK_DRY_RUN where the specification gives monitor: 2860.
  - AUTO_BLOCK_DRY_RUN where the specification gives watchlist: 260.
  - PENDING_APPROVAL_BLOCK where the specification gives analyst_triage: 11232.
  - PENDING_APPROVAL_BLOCK where the specification gives monitor: 61776.
  - PENDING_APPROVAL_BLOCK where the specification gives watchlist: 5616.
  - PENDING_APPROVAL_RATE_LIMIT where the specification gives analyst_triage: 20736.
  - PENDING_APPROVAL_RATE_LIMIT where the specification gives monitor: 114048.
  - PENDING_APPROVAL_RATE_LIMIT where the specification gives watchlist: 10368.
  - WATCHLIST where the specification gives monitor: 88704.
- `runtime_more_restrictive`: 67120. Example: runtime input `{"allow_private_block": 0, "auto_block_high": 1, "category": "NORMAL", "emergency_stop": 0, "frequency": 150, "ip_class": "lab_testnet", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}` gives `NO_ACTION` (authority 0); specification input `{"drift": "clear", "prov": "correlated", "qual": "high", "schema": "clear", "shared_address": "clear", "whitelist": "clear"}` gives `containment_proposal` (authority 3).
  - NO_ACTION where the specification gives analyst_triage: 20736.
  - NO_ACTION where the specification gives containment_proposal: 10368.
  - NO_ACTION where the specification gives watchlist: 10368.
  - RESPONSE_REFUSED_FAILED where the specification gives analyst_triage: 728.
  - RESPONSE_REFUSED_FAILED where the specification gives containment_proposal: 364.
  - RESPONSE_REFUSED_FAILED where the specification gives watchlist: 364.
  - WATCHLIST where the specification gives analyst_triage: 16128.
  - WATCHLIST where the specification gives containment_proposal: 8064.
- `not_comparable`: 840960. Example: runtime input `{"allow_private_block": 0, "auto_block_high": 1, "category": "EXPLOIT", "emergency_stop": 0, "frequency": 150, "ip_class": "malformed", "prior_watch_strikes": 0, "strict_category": 1, "whitelist_state": "NOT_MATCHED"}` gives `INPUT_REJECTED_DEAD` (authority 0); queue item DEAD: malformed alert has no specification counterpart.
  - queue item DEAD: malformed alert has no specification counterpart: 56064 runtime inputs.

**Outside the authority scale (T3c).** 260 inputs end in a block playbook executed in dry-run mode with no human approval (`AUTO_BLOCK_DRY_RUN`, default `AUTO_BLOCK_HIGH=1`, emergency stop off). The specification's highest route is a containment *proposal*; these inputs are counted at authority 3 above, which understates the difference in kind.

## 7. Sensitivity to the mapping choices

| target | variant | agree | runtime more permissive | runtime more restrictive | strict precondition violations | extended precondition violations |
| --- | --- | --- | --- | --- | --- | --- |
| T1a | `primary` | 30468 | 3828 | 48 | 0 | 36 |
| T1a | `none_insufficient_as_rf_only` | 30468 | 3828 | 48 | 0 | 36 |
| T1a | `none_insufficient_as_sur_only` | 30468 | 3828 | 48 | 0 | 36 |
| T1a | `none_insufficient_as_both_uncorrelated` | 30468 | 3828 | 48 | 0 | 36 |
| T1a | `absent_flag_as_missing` | 30432 | 3900 | 12 | 36 | 90 |
| T1a | `pending_approval_as_analyst_triage` | 30444 | 3828 | 72 | 0 | 36 |
| T1a | `quality_alternative` | 30468 | 3828 | 48 | 0 | 36 |
| T1b | `primary` | 3372 | 492 | 24 | 24 | 72 |
| T1b | `none_insufficient_as_rf_only` | 3372 | 480 | 36 | 24 | 72 |
| T1b | `none_insufficient_as_sur_only` | 3360 | 480 | 48 | 24 | 72 |
| T1b | `none_insufficient_as_both_uncorrelated` | 3360 | 480 | 48 | 24 | 72 |
| T1b | `absent_flag_as_missing` | 3354 | 528 | 6 | 42 | 99 |
| T1b | `pending_approval_as_analyst_triage` | 3360 | 492 | 36 | 24 | 72 |
| T1b | `quality_alternative` | 3372 | 492 | 24 | 24 | 72 |
| T3c | `pending_approval_as_analyst_triage` | 27428 | 0 | 34780 | not applicable | not applicable |
| T3c | `primary` | 43412 | 0 | 18796 | not applicable | not applicable |

The variant `absent_flag_as_missing` reads an absent whitelist or shared-address flag as the specification value missing, for which the specification holds. The runtime treats an absent flag as false. The 30 archived RQ3 rows carry neither flag.

## 8. E3 tier table

The file `E3_LAM_EXPLORATORY_ROUTING_POLICY.json`, from which the adapter reads the tier-to-route table, is not in the archive. Two pairs are recovered from archived outputs (30 joined rows): HYBRID_CORRELATED -> PRIORITY_REVIEW, RF_ONLY_REVIEW -> RF_EVIDENCE_REVIEW. BENIGN -> NO_DETECTOR_TRIGGER is inferred from the code. The routes of BOTH_UNCORRELATED and SURICATA_ONLY are unknown; each was set in turn to the three classes the downstream script distinguishes (PRIORITY_REVIEW, NO_DETECTOR_TRIGGER, OTHER_ROUTE_LABEL), giving 9 policy variants. The table shows the variant in which both take a label other than the two special ones.

| tier | route | basis | queue | specification (favourable) | reading A | reading B | reading C |
| --- | --- | --- | --- | --- | --- | --- | --- |
| HYBRID_CORRELATED | PRIORITY_REVIEW | archived output | PRIORITY_ANALYST_REVIEW | containment_proposal (3) | 2, more_restrictive | 3, agree | 3, agree |
| BOTH_UNCORRELATED | UNARCHIVED_ROUTE_LABEL | not archived (hypothetical) | EVIDENCE_REVIEW | analyst_triage (2) | 2, agree | 2, agree | 1, more_restrictive |
| SURICATA_ONLY | UNARCHIVED_ROUTE_LABEL | not archived (hypothetical) | EVIDENCE_REVIEW | analyst_triage (2) | 2, agree | 2, agree | 1, more_restrictive |
| RF_ONLY_REVIEW | RF_EVIDENCE_REVIEW | archived output | EVIDENCE_REVIEW | watchlist (1) | 2, more_permissive | 2, more_permissive | 1, agree |
| BENIGN | NO_DETECTOR_TRIGGER | inferred from code | NO_DETECTOR_TRIGGER | monitor (0) | 0, agree | 0, agree | 0, agree |

The rows for HYBRID_CORRELATED, RF_ONLY_REVIEW and BENIGN are the same in all 9 policy variants. Policy variants with at least one monotonicity violation along the tier degradation chain: reading A 3 of 9, reading B 4 of 9, reading C 4 of 9. Policy variants in which a queue read as a containment proposal is reached from a tier other than HYBRID_CORRELATED: reading A 0, reading B 5, reading C 5.

Adapter document domain: 150 trigger and tier encodings, 5 accepted (0/0/BENIGN; 1/1/HYBRID_CORRELATED; 1/1/BOTH_UNCORRELATED; 1/1/SURICATA_ONLY; 1/1/RF_ONLY_REVIEW), 145 rejected with an explicit message, 0 uncaught exceptions. Safety-boundary probes: invalid_source -> SYSTEM_EXIT UNEXPECTED SOURCE; non_numeric_s6 -> EXCEPTION ValueError; policy_id_mismatch -> SYSTEM_EXIT POLICY ID MISMATCH; route_not_matching_tier -> SYSTEM_EXIT ROUTE/TIER MISMATCH; s6_tier_inconsistent -> SYSTEM_EXIT INCONSISTENT S6/TIER; unlisted_tier -> SYSTEM_EXIT UNKNOWN E3 TIER; unverified_reference -> SYSTEM_EXIT UNVERIFIED OFFLINE REFERENCE.

## 9. T3 coverage

Exercised offline, on a byte-identical copy of `E4_SOAR_NO_ACTION.py`: alert normalisation (`normalize_event`, `normalize_category`), the rule engine (`decide_rule`), the durable queue and worker (`insert_queue`, `worker_loop`), the response decision (`process_event`) with both whitelist gates, target validation and the dry-run branches of the block and rate-limit playbooks, the watchlist escalation, the human approval step (`manual_decision`) and the ingestion filter (`ingest_es_once` with a stand-in search client). SQLite is real (a scratch database created by the file's own `init_db`).

Stubbed modules (not installed or not reachable offline): `dotenv`, `ollama`, `requests`, `elasticsearch`, `fpdf`, `pdf_report_pro`, `static_rag`. Functions replaced on the loaded copy: `static_analysis`, `call_llm`, `export_pdf`, `run_cmd`, `traceback.print_exc` (the two explanation functions return fixed text, `export_pdf` returns a file name, `run_cmd` raises if a firewall command is attempted, which never happened). Functions wrapped without changing their result: `get_policy`, `get_whitelist_entry` (to record whitelist readings and to change the whitelist between the two gates).

Executed lines per decision function (line numbers of the archived file):

| function | lines | executed | not executed |
| --- | --- | --- | --- |
| `normalize_category` | 9 | 9 | none |
| `normalize_event` | 24 | 24 | none |
| `decide_rule` | 13 | 13 | none |
| `is_context_only_document` | 5 | 5 | none |
| `ingest_es_once` | 37 | 35 | 4316-4317 |
| `insert_queue` | 6 | 6 | none |
| `worker_loop` | 34 | 33 | 4365 |
| `process_event` | 265 | 262 | 2897, 2949, 2990 |
| `get_whitelist_entry` | 16 | 16 | none |
| `find_whitelist_match_in_rows` | 13 | 10 | 591-597 |
| `whitelist_target_matches` | 3 | 3 | none |
| `get_policy` | 5 | 3 | 538-539 |
| `execute_playbook` | 36 | 33 | 2396-2398 |
| `execute_block` | 15 | 6 | 2324-2332 |
| `execute_rate_limit` | 16 | 6 | 2342-2351 |
| `validate_target` | 21 | 14 | 2239-2246 |
| `update_watchlist` | 16 | 16 | none |
| `insert_alert` | 48 | 48 | none |
| `manual_decision` | 306 | 265 | 3469, 3474, 3601-3603, 3615, 3620-3621, 3627, 3632-3633, 3663-3665, 3672, 3680-3687, 3712-3714, 3756-3767, 3789-3800 |
| `row_to_event` | 12 | 11 | 2667 |

37 of the 82 module-level functions were entered. Never entered: `_event_destination`, `_event_evidence`, `_event_message`, `_event_time`, `_extract_json_object`, `_llm_acquire_slot`, `_llm_release_slot`, `_llm_trace_record`, `_record_recovered_rule_metadata`, `_recovery_rule_definition`, `_regenerate_incident_pdf`, `_sanitize_llm_key`, `_sanitize_llm_text`, `_sanitizer_record`, `_select_prompt`, `add_rule`, `api_loop`, `call_llm`, `cleanup_expired_firewall_rules`, `collect_post_response_context`, `compact_post_context_for_llm`, `dispatcher_loop`, `ensure_chain`, `ensure_es_index`, `export_pdf`, `firewall_targets`, `high_report_worker`, `is_whitelisted`, `main`, `normalize_whitelist_target`, `parse_llm`, `post_block_admin_decision`, `prefix`, `recover_stale_executing_incidents`, `remove_accents`, `retrieve_knowledge`, `rollback_firewall_rule`, `run_cmd`, `safe_text`, `sanitize_llm_output`, `save_rule`, `send_post_block_review_request`, `static_analysis`, `telegram_loop`, `verify_firewall_rule_for_recovery`.

Not exercised, with the reason and what would be needed:

- Live enforcement branches of `execute_block`, `execute_rate_limit`, `add_rule`, `ensure_chain`, `save_rule`, `cleanup_expired_firewall_rules`, `rollback_firewall_rule`, and the startup recovery functions: they run `docker exec ... iptables` or `sudo iptables`. Needed: the isolated firewall container of the archived run, with `ENABLE_NETWORK_ENFORCEMENT=1`.
- `static_analysis`, `call_llm`, `collect_post_response_context`, `high_report_worker`, `parse_llm`, `sanitize_llm_output`: they need the local language-model service, `static_rag.py` and `knowledge_base.json`, none of which is in the archive. Their return values are stored in the incident record; the adversarial-text replay above is the only evidence here that the decision does not read them.
- `export_pdf`, `PDFReport`: need `fpdf` and `pdf_report_pro.py`.
- `APIHandler` (HTTP endpoints, including whitelist administration and the `/decision` endpoint that calls `manual_decision`), `telegram_loop`, `post_block_admin_decision`: network-facing wrappers. `manual_decision` itself was called directly.
- `dispatcher_loop`, `api_loop`, `main`: infinite loops. The re-delivery of `RETRY` items that `dispatcher_loop` performs was reproduced by the test driver; concurrency of several workers was not.

## 10. Limitations and items not verified

1. The comparison depends on the abstraction maps of section 3, which are choices. Where a choice changes a count, both counts are in section 7. The favourable completion compares against the specification at its most permissive, so a 'more restrictive' count in that view is an upper bound on restriction and a 'more permissive' count is a lower bound on permission.
2. No runtime target reads a drift or schema field. The specification rows that depend on them cannot be tested against any archived code; in the sweep they appear as pairs in which the runtime is more permissive.
3. T1 keys its action on the ground-truth scenario and its provenance input is ground-truth corroboration. It is a policy experiment on labelled incidents, not a router of detector alerts. The SOAR responder (T3) is the code that handles alerts, and it implements a category and frequency rule engine with a whitelist gate, not the provenance and quality routing table of the specification.
4. The function that derives the E3 tier from detector outputs is not in the archive; T2 starts from a tier that is already computed. The routing policy file is not in the archive; three of the five tier routes are inferred or hypothetical (section 8).
5. Domains are exhaustive over the listed values. Other values are covered only by the observation that the functions compare by equality, truthiness or numeric threshold. Flag values other than the booleans and an absent key were not enumerated (a non-empty string such as `"False"` is truthy in the runtime).
6. T3c uses one address per class, an unexpired watchlist entry with 0 or 2 prior strikes, and whitelist entries in status ACTIVE. Watchlist expiry, disabled whitelist entries, IPv6 sources (T3a only) and the 24-hour window were not enumerated.
7. T3d replays one representative per distinct (playbook, category, address class, `ALLOW_PRIVATE_BLOCK`) signature of the 15984 pending T3c cases, not every pending case.
8. The adversarial advisory replay covers the quarter of T3c with `STRICT_CATEGORY=1` and `ALLOW_PRIVATE_BLOCK=0`. It shows independence from the text returned by the stubs, not from the behaviour of the real language-model pipeline.
9. All T3 runs are dry-run (`ENABLE_NETWORK_ENFORCEMENT=0`). No statement is made about the live firewall path.
10. The whitelist lookup failure was induced by renaming the table; other failure modes of SQLite were not induced.

