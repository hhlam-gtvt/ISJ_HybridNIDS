#!/usr/bin/env python3
"""Negative-control tests on the archived E4 OFFLINE adapter, not deployed SOAR.
This is not producer authentication or live pre-execution firewall verification.
"""
import csv, hashlib, importlib.util, itertools, json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE=HERE/'e4_experiment_runner.py'
spec=importlib.util.spec_from_file_location('e4_real_runner_negative_control',SOURCE)
e4=importlib.util.module_from_spec(spec);spec.loader.exec_module(e4)
now=2_000_000_000
cases=[]
for scenario, (wl, shared, critical), token_kind in itertools.product(
  ('exploit','dos','brute_force'),itertools.product((False,True),repeat=3),
  ('valid','absent','expired','wrong_case','wrong_event','wrong_action','tampered','malformed')):
    case_id=f'ISO-{scenario}'
    inc={'scenario':scenario, 'source_ip':'192.0.2.8','source_event_id':f'EVENT-{scenario}',
         'evidence_quality':'HIGH','corroboration_type':'corroborated',
         'whitelist_match':wl, 'shared_address':shared, 'critical_asset':critical}
    candidate=e4.ACTION_MATRIX[scenario]['action']
    action_id=e4.stable_action_id(case_id,inc['source_event_id'],candidate)
    token=e4.issue_approval(case_id, action_id,now+300)
    if token_kind=='absent': token=None
    elif token_kind=='expired': token=e4.issue_approval(case_id,action_id,now-1)
    elif token_kind=='wrong_case': token=e4.issue_approval('OTHER-CASE',action_id,now+300)
    elif token_kind=='wrong_event': token=e4.issue_approval(case_id,e4.stable_action_id(case_id,'OTHER-EVENT',candidate),now+300)
    elif token_kind=='wrong_action': token=e4.issue_approval(case_id,e4.stable_action_id(case_id,inc['source_event_id'],'OTHER_ACTION'),now+300)
    elif token_kind=='tampered':
        a,b=token.split('.');token=a+'.'+('0' if b[0]!='0' else '1')+b[1:]
    elif token_kind=='malformed':token='not-a-token'
    row,_=e4.outcome_row(case_id,inc,'PROVENANCE_AWARE','NEGATIVE_CONTROL',
         force_execution_mode='ISOLATED_REVERSIBLE_SIM',explicit_approval_token=token,now_epoch=now)
    effect=row['external_effect']=='SIMULATED_ADAPTER_ONLY'
    expected=(token_kind=='valid' and not wl)
    passed=(effect==expected and row['acceptance_pass'] and not (wl and effect))
    cases.append({'scenario':scenario,'token':token_kind,'whitelist':int(wl),
        'shared_address':int(shared),'critical_asset':int(critical),
        'approval_state':row['approval_state'],'final_action':row['final_action'],
        'external_effect':row['external_effect'],'simulated_effect_expected':int(expected),
        'pass':int(passed)})

# Extended negative cases for malformed source IP and low evidence must remain no effect.
for scenario, source_ip, quality, provenance in itertools.product(
    ('exploit','dos','brute_force'),('','not-an-ip','999.1.2.3'),('HIGH','LOW'),('corroborated','')):
    inc={'scenario':scenario,'source_ip':source_ip,'source_event_id':'CASE-IP',
       'evidence_quality':quality,'corroboration_type':provenance,
       'whitelist_match':False,'shared_address':False,'critical_asset':False}
    cid='ISO-INVALID-SOURCE'
    candidate=e4.ACTION_MATRIX[scenario]['action']
    token=e4.issue_approval(cid,e4.stable_action_id(cid,inc['source_event_id'],candidate),now+300)
    row,_=e4.outcome_row(cid,inc,'PROVENANCE_AWARE','INVALID_IP_OR_WEAK_PROVENANCE',
         force_execution_mode='ISOLATED_REVERSIBLE_SIM',explicit_approval_token=token,now_epoch=now)
    # Even valid approval is not supposed to bypass source IP safety guard.
    effect=row['external_effect']=='SIMULATED_ADAPTER_ONLY'
    cases.append({'scenario':scenario,'token':'valid_with_bad_source','whitelist':0,
        'shared_address':0,'critical_asset':0,'approval_state':row['approval_state'],
        'final_action':row['final_action'],'external_effect':row['external_effect'],
        'simulated_effect_expected':0,'pass':int(not effect)})

with (HERE/'e4_approval_binding_matrix.csv').open('w',newline='',encoding='utf8') as f:
    w=csv.DictWriter(f,fieldnames=list(cases[0]));w.writeheader();w.writerows(cases)
count=sum(int(r['pass']) for r in cases)
report={'scope':'ARCHIVED E4 PURE POLICY + SIMULATED ADAPTER, NOT DEPLOYED PRODUCTION SOAR',
    'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    'tested_combinations':len(cases),'pass':count,'failed':len(cases)-count,
    'negative_result_count':sum(x['simulated_effect_expected']==0 for x in cases),
    'simulated_allowed_effect_count':sum(x['simulated_effect_expected']==1 for x in cases),
    'firewall_effects':'NONE','producer_authentication':'NOT_TESTED',
    'approval_binding_scope':'HMAC token bound to case_id and action_id in E4 function',
    'replay_revocation_and_persistence':'NOT_TESTED',
    'runtime_parity':'NOT_TESTED',
    'test_semantics':'valid token permits simulated effect when whitelist false; invalid token, whitelist or invalid source IP must not',
    'limitations':['Uses hard-coded laboratory-only HMAC secret from E4 archived runner',
    'No live firewall / packet propagation / production approval service',
    'No actual producer authentication, credential storage or key rotation']}
(HERE/'e4_approval_binding_summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
print(json.dumps(report,indent=2,ensure_ascii=False))
if count!=len(cases):
    raise SystemExit('FAIL: Some negative-control expectations violated (retain failures in report)')
print('PASS: isolated E4 simulated approval binding and safety-gate negative controls')
