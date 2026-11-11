#!/usr/bin/env python3
"""Read-only direct function tests of frozen E4 experiment runner; NOT an E8a specification checker.
Executes only E4 pure policy functions and its simulated adapter. Never starts SOAR/firewall.
"""
import argparse, csv, hashlib, importlib.util, itertools, json
from pathlib import Path

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runner', type=Path, required=True)
    p.add_argument('--freeze', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    freeze = json.loads(args.freeze.read_text(encoding='utf8'))
    spec = importlib.util.spec_from_file_location('frozen_e4_policy_for_isolated_readonly_audit', args.runner)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    assert m.ACTION_MATRIX == freeze['action_matrix'], 'E4 matrix differs from freeze'
    assert m.RUN_VERSION == freeze['runner_version'], 'E4 runner version differs from freeze'
    rows = []; fails = []
    sentinel_accepted = 0
    for scenario, qual, prov, wl, shared, critical in itertools.product(
      freeze['action_matrix'], ('HIGH','LOW'), ('','none_insufficient','corroborated','UNVALIDATED'), (False,True), (False,True), (False,True)):
        inc = {'scenario':scenario,'evidence_quality':qual,'corroboration_type':prov,
               'whitelist_match':wl,'shared_address':shared,'critical_asset':critical,
               'source_ip':'192.0.2.8', 'source_event_id':'UNITTEST-READONLY'}
        blind,_ = m.blind_policy(inc); aware,_ = m.aware_policy(inc)
        gate,_ = m.apply_safety_gates(inc,aware)
        impact = freeze['action_matrix'][scenario]['impact']
        expected = freeze['action_matrix'][scenario]['action']
        checks = {
          'blind_matrix': blind == expected,
          'low_quality_withheld': not (impact=='HIGH' and qual!='HIGH') or aware=='SAFETY_HOLD',
          'missing_provenance_withheld': not (impact=='HIGH' and not prov) or aware=='SAFETY_HOLD',
          'whitelist_gate': not wl or gate=='SKIPPED_WHITELIST',
          'shared_address_gate': not (impact=='HIGH' and aware in ('BLOCK','RATE_LIMIT') and shared and not wl) or gate=='PENDING_EXPLICIT_APPROVAL',
          'critical_asset_gate': not (impact=='HIGH' and aware in ('BLOCK','RATE_LIMIT') and critical and not wl) or gate=='PENDING_EXPLICIT_APPROVAL',
        }
        failures=[k for k,v in checks.items() if not v]
        if failures: fails.append({'scenario':scenario,'quality':qual,'provenance':prov,'failures':failures})
        note = int(impact=='HIGH' and qual=='HIGH' and prov=='none_insufficient' and aware in ('BLOCK','RATE_LIMIT'))
        sentinel_accepted += note
        rows.append({'scenario':scenario,'quality':qual,'corroboration_type':prov or '(empty)',
                     'whitelist':wl,'shared_address':shared,'critical_asset':critical,
                     'blind_candidate':blind,'aware_candidate':aware,'safety_gate':gate,
                     'insufficient_sentinel_high_candidate':note,'checks_passed':len(checks)-len(failures),
                     'failed_checks':';'.join(failures)})
    with (args.out/'e4_runtime_matrix.csv').open('w',newline='',encoding='utf8') as f:
      w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

    # Adapter-only approval tests. All external effects are simulated, not live.
    inc = {'scenario':'exploit','evidence_quality':'HIGH','corroboration_type':'corroborated',
           'source_ip':'192.0.2.8','source_event_id':'UNITTEST-READONLY','whitelist_match':False,
           'shared_address':False,'critical_asset':False}
    cid='E4-UNIT-AUTH'; aid=m.stable_action_id(cid,inc['source_event_id'],'BLOCK'); now=2000000000
    valid=m.issue_approval(cid,aid,now+300)
    no_token,_=m.outcome_row(cid,inc,'PROVENANCE_AWARE','VALIDATE_APPROVAL',force_execution_mode='ISOLATED_REVERSIBLE_SIM',now_epoch=now)
    expired=m.issue_approval(cid,aid,now-1)
    expired_row,_=m.outcome_row(cid,inc,'PROVENANCE_AWARE','VALIDATE_APPROVAL',force_execution_mode='ISOLATED_REVERSIBLE_SIM',explicit_approval_token=expired,now_epoch=now)
    approved,_=m.outcome_row(cid,inc,'PROVENANCE_AWARE','VALIDATE_APPROVAL',force_execution_mode='ISOLATED_REVERSIBLE_SIM',explicit_approval_token=valid,now_epoch=now)
    approval_checks={
      'missing_token_no_effect':no_token['external_effect']=='NONE',
      'expired_token_no_effect':expired_row['external_effect']=='NONE',
      'approved_effect_adapter_only':approved['external_effect']=='SIMULATED_ADAPTER_ONLY',
    }
    summary={
      'scope':'Frozen E4 policy function tests on E4 runner, NOT E8a 3840-input specification, NOT production SOAR',
      'source_runner_sha256':digest(args.runner), 'freeze_sha256':digest(args.freeze),
      'matrix_matches_freeze':True, 'combinations':len(rows), 'individual_property_assertions':len(rows)*6,
      'assertion_failures':len(fails), 'approval_checks':approval_checks,
      'diagnostic_insufficient_provenance_sentinel_accepted_as_high_candidate':sentinel_accepted,
      'diagnostic_explanation':'aware_policy trusts precomputed HIGH quality and any nonempty corroboration_type; none_insufficient is nonempty. Upstream evidence_quality() would call this LOW, but direct function does not revalidate it.',
      'external_firewall_effects':'NONE. Isolated adapter test only.',
    }
    (args.out/'e4_runtime_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    if fails or not all(approval_checks.values()):
      raise SystemExit('FAIL: one or more E4 checks did not satisfy asserted properties')
    print('PASS: E4 implementation-level checks complete; NOT an E8a runtime verification')

if __name__=='__main__': main()
