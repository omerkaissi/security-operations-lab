"""Summarize stored, frozen experiment runs without running either detector."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports/runs/strengthening_summary.json")
    args=parser.parse_args()
    freeze=json.loads((ROOT/'reports/strengthening/freeze.json').read_text())
    for path,digest in freeze['files'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:
            raise ValueError(f'frozen artifact changed: {path}')
    summary={'status':'complete','dataset':'self-authored synthetic scenarios; not independently collected or representative',
             'holdout_runs':'one detector/evaluator run per profile after freeze', 'splits':{}}
    for split in ('development','holdout'):
        summary['splits'][split]={}
        predicted={}
        for profile in ('baseline','revised'):
            prefix=ROOT/f'reports/strengthening/{split}_{profile}'
            result=json.loads(Path(str(prefix)+'_alerts.json').read_text())
            evaluation=json.loads(Path(str(prefix)+'_evaluation.json').read_text())
            labels=json.loads((ROOT/f'data/labels/strengthening_{split}_{profile}_v1.json').read_text())
            owners={event:scenario['scenario_id'] for scenario in labels['scenarios'] for event in scenario['event_ids']}
            predicted[profile]={owners.get(alert.get('success_event_id',alert.get('anchor_event_id'))) for alert in result['alerts']}
            summary['splits'][split][profile]={'events':result['input']['valid_unique_events_accepted'], 'alerts':len(result['alerts']),
                                             'priority_counts':dict(Counter(alert['severity'] for alert in result['alerts'])),
                                             'candidate_conformance':evaluation['candidate_conformance'], 'scenario_security':evaluation['scenario_security']}
            if result['status']!='complete' or evaluation['candidate_conformance']['missing'] or evaluation['candidate_conformance']['extra']:
                raise ValueError('run incomplete or candidate conformance failed')
        truth={s['scenario_id']:s['security_truth'] for s in labels['scenarios']}
        added=predicted['revised']-predicted['baseline']
        lost=predicted['baseline']-predicted['revised']
        summary['splits'][split]['changed_scenarios']={'new_malicious_candidates':sorted(x for x in added if truth[x]=='malicious'),
            'new_benign_candidates':sorted(x for x in added if truth[x]=='benign'),
            'lost_malicious_candidates':sorted(x for x in lost if truth[x]=='malicious'),
            'lost_benign_candidates':sorted(x for x in lost if truth[x]=='benign')}
    text=json.dumps(summary,indent=2,sort_keys=True)+'\n'
    destination=Path(args.output)
    if not destination.is_absolute(): destination=ROOT/destination
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(text)
    print(text)


if __name__=='__main__': main()
