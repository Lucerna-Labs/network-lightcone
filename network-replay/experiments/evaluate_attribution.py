#!/usr/bin/env python3
"""Verify C02 counterfactual identity and quantify actual mechanism dependence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('trace_verify',ROOT/'network-replay/tools/verify_trace.py')
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)
CONTROLS=['original','erased_coordinates','shuffled_coordinates','relations_disabled','past_only','future_only']


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def content(row):return tuple(tuple(row[k]) for k in ['nodes','edges','excluded','frontier'])


def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();root=a.directory
    inputs=json.loads((root/'input.json').read_text());raw=(ROOT/'kernel-lightcone/src/world.bin').read_bytes()
    assert sha(ROOT/'kernel-lightcone/src/world.bin')==inputs['pack_sha256']
    for name,h in inputs['source_log_hashes'].items():assert sha(ROOT/name)==h
    world=json.loads((ROOT/'artifacts/experiments/covered-scope-results-20261001/variant-0/world.json').read_text())
    n=len(world['nodes']);erased=bytearray(raw);erased[84:1044]=bytes(960)
    for axis in range(4):struct.pack_into('<i',erased,84+48*4+(axis*4+axis)*4,1000000)
    shuffled=bytearray(raw);changed_rows=0
    for i in range(n):
        at=1044+i*216+8;other=1044+(n-1-i)*216+8
        erased[at:at+208]=bytes(208);shuffled[at:at+208]=raw[other:other+208]
        changed_rows+=raw[at:at+208]!=raw[other:other+208]
    hashes={'original':hashlib.sha256(raw).hexdigest(),'erased_coordinates':hashlib.sha256(erased).hexdigest(),
            'shuffled_coordinates':hashlib.sha256(shuffled).hexdigest()}
    expected={q['id']:q for q in inputs['queries']};by_query={};verified=0;steps=0
    with (root/'results.jsonl').open() as f:
        header=json.loads(next(f));assert header['kind']=='controls' and header['input_sha256']==sha(root/'input.json')
        for line in f:
            row=json.loads(line);q=expected[row['id']];control=row['control'];assert control in CONTROLS
            assert row['seeds']==q['seeds'] and row['query_sha256']==hashlib.sha256(q['id'].encode()).hexdigest()
            assert row['pack_sha256']==hashes.get(control,hashes['original'])
            policy={'direction':inputs['policy']['direction'],'max_hops':inputs['policy']['max_hops'],
                    'max_nodes':inputs['policy']['max_nodes'],'relation_mask':inputs['policy']['relation_mask'],'polarity':0}
            if control=='relations_disabled':policy['relation_mask']=0
            elif control=='past_only':policy['direction']='past'
            elif control=='future_only':policy['direction']='future'
            assert row['policy']==policy
            nodes,edges,excluded,frontier,trace=verify.graph_replay(world,set(q['seeds']),policy)
            assert [row[k] for k in ['nodes','edges','excluded','frontier']]==[sorted(x) for x in [nodes,edges,excluded,frontier]]
            assert row['trace']==trace
            material=b'ATOM-NETWORK-ADMISSION-2'+bytes.fromhex(row['pack_sha256'])+bytes.fromhex(row['query_sha256'])
            material+=bytes([{'past':0,'future':1,'both':2}[policy['direction']],policy['max_hops'],policy['relation_mask'],policy['polarity']&255])+struct.pack('<H',policy['max_nodes'])
            for values,count in [(set(q['seeds']),4),(nodes,4),(edges,8),(excluded,4),(frontier,4)]:material+=b''.join(struct.pack('<Q',v) for v in verify.words(values,count))
            assert row['receipt_sha256']==hashlib.sha256(material).hexdigest()
            # Retain compact content and a trace digest after full verification.
            row['trace_sha256']=hashlib.sha256(verify.canonical(row.pop('trace'))).hexdigest()
            assert control not in by_query.setdefault(row['id'],{})
            by_query[row['id']][control]=row;verified+=1;steps+=len(trace)
    assert set(by_query)==set(expected) and all(set(v)==set(CONTROLS) for v in by_query.values())
    changes={c:sum(content(v[c])!=content(v['original']) for v in by_query.values()) for c in CONTROLS[1:]}
    same_seed_groups=[]
    for q in inputs['queries']:
        if 'frames' not in q:continue
        outputs={(tuple(r['nodes']),tuple(r['edges'])) for r in q['frames']}
        same_seed_groups.append({'id':q['id'],'frames':len(q['frames']),'distinct_frame_hashes':len({r['frame_sha256'] for r in q['frames']}),
                                'admitted_content_identical':len(outputs)==1})
    empty=[v for key,v in by_query.items() if not expected[key]['seeds']]
    zero_empty=all(not r['nodes'] and not r['edges'] for v in empty for r in v.values())
    result={'queries':len(expected),'verified_runs':verified,'verified_steps':steps,'controls':header,'pack_hashes':hashes,
            'shuffled_coordinate_rows_changed':changed_rows,'coordinate_erasure_changed_bytes':sum(x!=y for x,y in zip(raw,erased)),
            'content_changes_vs_original':changes,
            'coordinate_trace_changes':{c:sum(v[c]['trace_sha256']!=v['original']['trace_sha256'] for v in by_query.values()) for c in ['erased_coordinates','shuffled_coordinates']},
            'coordinate_receipt_hash_changes':{c:sum(v[c]['receipt_sha256']!=v['original']['receipt_sha256'] for v in by_query.values()) for c in ['erased_coordinates','shuffled_coordinates']},
            'past_vs_future_content_changes':sum(content(v['past_only'])!=content(v['future_only']) for v in by_query.values()),
            'all_empty_inputs_stay_empty':zero_empty,'same_seed_groups':same_seed_groups,
            'geometry_contribution_status':'NOT_EXERCISED_BY_PACKET_ADMISSION' if changes['erased_coordinates']==changes['shuffled_coordinates']==0 else 'MEASURED_DEPENDENCE',
            'source_world_unchanged':sha(ROOT/'kernel-lightcone/src/world.bin')==inputs['pack_sha256'],
            'input_sha256':sha(root/'input.json'),'results_sha256':sha(root/'results.jsonl'),
            'scope':'mechanism attribution with fixed graph/content; no architecture-wide or defensive-effectiveness verdict'}
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    (root/'verified-content.json').write_text(json.dumps(by_query,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='same_seed_groups'},indent=2))


if __name__=='__main__':main()
