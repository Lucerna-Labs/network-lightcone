#!/usr/bin/env python3
"""Render one recorded frame for inspection; all steps remain in events.jsonl."""
import argparse
from collections import Counter
import json
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--logs',type=Path,required=True);p.add_argument('--sequence',type=int,required=True);p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
with (a.logs/'events.jsonl').open() as f:
    event=next((row for line in f if (row:=json.loads(line))['sequence']==a.sequence),None)
if event is None:raise SystemExit('Sequence not present in log')
world=json.loads((a.logs/'world.json').read_text());admission=event['admission'];observer=event['observer']
ids={n['index']:n['record']['id'] for n in world['nodes']}
actions=Counter(t['detail']['action'] for t in event['trace'])
lines=[f"# Frame {a.sequence}","",f"Event: `{event['event_id']}`", "",f"Input: {event['frame_len']} bytes, SHA-256 `{event['frame_sha256']}`.","",
       f"Capture location: `{json.dumps(event['capture'],sort_keys=True)}`.","",f"Parser: **{observer['kind']}**, `{observer['reason']}`.","",
       "Direct seeds: "+(', '.join('`'+ids[n['index']]+'`' for n in observer['seeds']) or 'none')+".","",
       f"Admission: **{admission['status']}**. Raw frame bytes included: {event['frame_hex'] is not None}.",""]
lines+=['## Parser stages and fields','','| Stage or field | Value |','|---|---|']
for t in event['trace']:
    d=t['detail']
    if t['actor']!='observer':continue
    if d['action']=='enter':lines.append(f"| Enter {d['stage']} | offset {d['offset']}, length {d['length']} |")
    elif d['action']=='field':lines.append(f"| {d['name']} | {d['value']} |")
    elif d['action']=='check':lines.append(f"| Check against `{d['rejection_reason']}` | {'passed' if d['passed'] else '**failed**'} |")
    elif d['action']=='seeds_discarded':lines.append(f"| Discard tentative seeds | {d['reason']} |")
lines+=['','## Exact admission decisions','','| Recorded action | Count |','|---|---|']
for action,count in sorted(actions.items()):lines.append(f'| `{action}` | {count} |')
for key,label in [('nodes','Admitted nodes'),('excluded','Excluded by node cap'),('hop_frontier','Hop frontier')]:
    lines+=['',f'## {label}','',(', '.join('`'+ids[n['index']]+'`' for n in admission.get(key,[])) or 'none')]
lines+=['','## Interpretation','',world['admission_driver']+'.',
        '', 'The 4D view is observer-only. Edge conditions are recorded as evidence, not evaluated against connection state. A neighborhood is not permission or an attack verdict.',
        '', 'This is a readable summary. The complete ordered per-edge trace, source evidence and hashes are retained in `events.jsonl` and `world.json`.']
with a.out.open('x') as f:f.write('\n'.join(lines)+'\n')
print(a.out)
