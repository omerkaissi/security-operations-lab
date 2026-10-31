"""Write separately authored, deterministic development and holdout fixtures."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 1, 15, tzinfo=timezone.utc)
SEEDS = {'development': 20261101, 'holdout': 20261102}


def stamp(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def signin(name, actor, start, failures, success, truth, base_expected, revised_expected):
    events=[]
    for i, offset in enumerate(failures, 1):
        events.append({'schema_version':'1.0', 'event_id':f'{name}_F{i}', 'timestamp':stamp(start+offset), 'actor_id':actor,
                       'event_type':'sign_in', 'outcome':'failure', 'source':'identity_audit', 'source_ip':'192.0.2.80'})
    events.append({'schema_version':'1.0', 'event_id':f'{name}_S', 'timestamp':stamp(start+success), 'actor_id':actor,
                   'event_type':'sign_in', 'outcome':'success', 'source':'identity_audit', 'source_ip':'192.0.2.80'})
    return name, truth, events, {'baseline':base_expected, 'revised':revised_expected}, 'signin_failure_then_success'


def role(name, actor, seconds, truth, change, expected):
    e={'schema_version':'1.0', 'event_id':name+'_R', 'timestamp':stamp(seconds), 'actor_id':actor, 'event_type':'role_change', 'outcome':'success',
       'source':'identity_audit', 'target_user_id':'actor_analyst_01', 'previous_role':'member', 'new_role':'data_export_admin'}
    if change is not None: e['change_id']=change
    return name, truth, [e], {'baseline':expected,'revised':expected}, 'unexpected_protected_role'


def export(name, actor, seconds, count, truth, expected):
    e={'schema_version':'1.0','event_id':name+'_E','timestamp':stamp(seconds),'actor_id':actor,'event_type':'data_export','outcome':'success',
       'source':'application_audit','resource':'fitness_session_metadata','record_count':count}
    return name, truth, [e], {'baseline':expected,'revised':expected}, 'large_export'


def definitions(split):
    if split=='development':
        specs=[('D01','malicious',[0,60,120,180],240,False,True),('D02','benign',[0,40,80,120],150,False,True),
               ('D03','malicious',[0,30,60,90,120],180,True,True),('D04','benign',[0,40,80,120,160],180,True,True),
               ('D05','malicious',[0,60,120],180,False,False),('D06','malicious',[0,200,400,601],650,False,False),
               ('D07','benign',[0,30,60,90],391,False,False),('D08','malicious',[0,120,240,360,480,600],900,True,True)]
        tail=[role('D09','actor_admin_01',13*3600,'benign','CHG-LAB-001',False), role('D10','dev_admin_10',13*3600+60,'malicious',None,True),
              export('D11','dev_export_11',4*3600,999,'benign',False),export('D12','dev_export_12',5*3600,1000,'malicious',True)]
    else:
        specs=[('H01','malicious',[0,45,90,135],160,False,True),('H02','benign',[0,15,45,75],80,False,True),
               ('H03','malicious',[0,10,20,30,40],90,True,True),('H04','benign',[0,120,240],300,False,False),
               ('H05','malicious',[0,20,40,60],361,False,False),('H06','benign',[0,200,400,601],602,False,False),
               ('H07','benign',[0,10,50,100,140],150,True,True),('H08','malicious',[0,200,400,600],900,False,True)]
        tail=[role('H09','actor_admin_01',13*3600+1800,'benign','CHG-LAB-001',False),role('H10','hold_admin_10',13*3600+100,'benign','CHG-UNKNOWN',True),
              export('H11','hold_export_11',6*3600,1001,'malicious',True),export('H12','actor_job_01',2*3600+900,1500,'benign',False)]
    return [signin(name, f'{split}_actor_{i:02}', 8*3600+i*1800, failures, success, truth, b, r)
            for i,(name,truth,failures,success,b,r) in enumerate(specs,1)]+tail


def write_immutable(path, content):
    if path.exists() and path.read_bytes()!=content:
        raise ValueError(f'refusing to replace different existing fixture: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def main():
    manifest={}
    for split in ('development','holdout'):
        events=[]; labels={'baseline':[], 'revised':[]}
        for name, truth, records, flags, rule in definitions(split):
            events.extend(records)
            for profile in labels:
                expected=[]
                if flags[profile]:
                    anchor=records[-1]['event_id']
                    item={'rule_id':rule,'rule_version':('1.1' if profile=='revised' and rule=='signin_failure_then_success' else '1.0'),
                          'evidence_event_ids':[e['event_id'] for e in records]}
                    item['success_event_id' if rule=='signin_failure_then_success' else 'anchor_event_id']=anchor
                    expected.append(item)
                labels[profile].append({'scenario_id':name,'security_truth':truth,'event_ids':[e['event_id'] for e in records], 'expected_candidates':expected})
        random.Random(SEEDS[split]).shuffle(events)
        objects={f'data/events/strengthening_{split}_v1.jsonl':''.join(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n' for e in events).encode()}
        for profile, scenarios in labels.items():
            objects[f'data/labels/strengthening_{split}_{profile}_v1.json']= (json.dumps({'label_version':'1.0','dataset_version':f'{split}-1.0','synthetic':True,'seed':SEEDS[split],'scenarios':scenarios},sort_keys=True,indent=2)+'\n').encode()
        for path,content in objects.items():
            write_immutable(ROOT / path,content)
            manifest[path]={'sha256':hashlib.sha256(content).hexdigest(),'bytes':len(content),'seed':SEEDS[split]}
    path=ROOT/'data/strengthening_fixture_manifest.json'
    write_immutable(path,(json.dumps({'description':'Self-authored fictional development and held-out sets; seed shuffles order only.','files':manifest},sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps(manifest,indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
