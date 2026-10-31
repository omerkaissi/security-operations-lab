import copy
import json
from pathlib import Path
import unittest

from secops_lab.core import detect, load_events, load_policy
from secops_lab.evaluate import evaluate
from secops_lab.rules import export_alerts, role_alerts
from scripts.verify_checkpoint04 import verify_followup
from test_checkpoint02 import event, ingest

ROOT=Path(__file__).resolve().parents[1]


class ProfileTests(unittest.TestCase):
    def test_four_failures_change_only_versioned_signin_profile(self):
        events, counts=ingest([event(f'f{i}', i) for i in range(4)]+[event('s', 5, 'success')])
        self.assertEqual(counts['rejected_lines'], 0)
        base=load_policy(ROOT/'config/policy.json')
        revised=load_policy(ROOT/'config/policy_signin_v11.json')
        self.assertEqual(detect(events,base['sign_in']), [])
        alert=detect(events,revised['sign_in'])[0]
        self.assertEqual(alert['rule_version'],'1.1')
        self.assertEqual(alert['evidence_event_ids'],['f0','f1','f2','f3','s'])
        self.assertEqual(revised['role_change'],base['role_change'])
        self.assertEqual(revised['export'],base['export'])
        self.assertEqual(revised['sign_in']['failure_window_seconds'],base['sign_in']['failure_window_seconds'])
        self.assertEqual(revised['sign_in']['success_delay_seconds'],base['sign_in']['success_delay_seconds'])

    def test_development_authored_conformance(self):
        events, counts=load_events(ROOT/'data/events/strengthening_development_v1.jsonl')
        self.assertFalse(counts['errors'])
        for profile, policy_path in (('baseline','config/policy.json'),('revised','config/policy_signin_v11.json')):
            with self.subTest(profile=profile):
                policy=load_policy(ROOT/policy_path)
                alerts=detect(events,policy['sign_in'])+role_alerts(events,policy['role_change'])+export_alerts(events,policy['export'])
                result={'status':'complete','input_event_ids':[e['event_id'] for e in events],'alerts':alerts}
                labels=json.loads((ROOT/f'data/labels/strengthening_development_{profile}_v1.json').read_text())
                report=evaluate(result,labels)['candidate_conformance']
                self.assertEqual(report['missing'],[])
                self.assertEqual(report['extra'],[])


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.followup=json.loads((ROOT/'data/investigations/followup_evidence_v1.json').read_text())
        events,_=load_events(ROOT/'data/events/checkpoint03.jsonl')
        self.events={e['event_id']:e for e in events}

    def test_valid_fictional_followup(self):
        self.assertEqual(len(verify_followup(self.followup,self.events)),4)

    def test_invalid_references_and_assertions_are_rejected(self):
        for evidence_id, field, value in [('FU029_MFA','session_id','wrong'),('FU017_CHANGE','authorization_result','approved'),
                                          ('FU029_USER','event_ids',['missing_event']),('FU017_USER','confirmation','owner_recognizes'),
                                          ('FU017_CHANGE','recorded_at','2026-01-01T00:00:00Z')]:
            with self.subTest(id=evidence_id,field=field):
                changed=copy.deepcopy(self.followup)
                next(x for x in changed['records'] if x['evidence_id']==evidence_id)[field]=value
                with self.assertRaises(ValueError): verify_followup(changed,self.events)


if __name__=='__main__': unittest.main()
