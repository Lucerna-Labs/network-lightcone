#!/usr/bin/env python3
"""End-to-end trace acceptance against a pre-change executable and real PCAP."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import traceback

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('verify_trace',ROOT/'network-replay/tools/verify_trace.py')
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)


def events(path): return [json.loads(x) for x in (path/'events.jsonl').read_text().splitlines()]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--corpus',type=Path,required=True);p.add_argument('--live',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);checks=[];measurements={}
    def check(name,value,detail=None):
        checks.append({'name':name,'passed':bool(value),'detail':detail})
    def run(name,input_path,flags=(),baseline=False,expected_success=True):
        log=out/name
        command=[str((a.baseline if baseline else a.binary).resolve()),'--input',str(input_path.resolve()),'--out',str(log),*flags]
        result=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,timeout=60)
        (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
        check(name+'_exit', (result.returncode==0)==expected_success, result.returncode)
        return log
    def verify_run(name,logs,input_path,incomplete=False):
        result=verify.verify(logs,input_path,incomplete)
        check(name+'_verified',result['verified'],result)
        measurements[name]=result
    def equivalent(first,second):
        x,y=events(first),events(second)
        return len(x)==len(y) and all(a['observer']==b['observer'] and a['admission']==b['admission'] and a['frame_sha256']==b['frame_sha256'] for a,b in zip(x,y))
    def rewrite_chain(directory,rows):
        previous=None;lines=[]
        for row in rows:
            row.pop('event_sha256',None);row['previous_event_sha256']=previous
            row['event_sha256']=hashlib.sha256(verify.canonical(row)).hexdigest();previous=row['event_sha256']
            lines.append(verify.canonical(row)+b'\n')
        (directory/'events.jsonl').write_bytes(b''.join(lines))
        summary=json.loads((directory/'summary.json').read_text())
        summary['events_sha256']=sha(directory/'events.jsonl');summary['last_event_sha256']=previous
        (directory/'summary.json').write_text(json.dumps(summary))
    def rejected(name,logs,input_path):
        try: verify.verify(logs,input_path)
        except (ValueError,KeyError,AssertionError) as error: check(name,True,str(error))
        else: check(name,False,'tampered log was accepted')
    try:
        input_hashes={str(x):sha(x) for x in [a.corpus,a.live]}
        pack_hash=sha(ROOT/'kernel-lightcone/src/world.bin')
        for name,input_path in [('corpus',a.corpus),('live',a.live)]:
            old=run(name+'-baseline',input_path,baseline=True)
            traced=run(name+'-traced',input_path,['--include-frame-bytes'] if name=='live' else [])
            plain=run(name+'-no-trace',input_path,['--no-trace'])
            verify_run(name,traced,input_path);verify_run(name+'-no-trace',plain,input_path)
            check(name+'_baseline_equivalence',equivalent(old,traced))
            check(name+'_trace_equivalence',equivalent(traced,plain))
            summary=json.loads((traced/'summary.json').read_text())
            check(name+'_source_matches_build',summary['source_tree_matches_build'])
            check(name+'_unsealed',summary['sealed'] is False)
            measurements[name]['p95_traced_us']=summary['p95_total_us']
            measurements[name]['p95_untraced_us']=json.loads((plain/'summary.json').read_text())['p95_total_us']
            measurements[name]['event_log_bytes']=(traced/'events.jsonl').stat().st_size
        check('default_payload_omitted',all(e['frame_hex'] is None and 'source_address' not in e['wire_hint'] for e in events(out/'corpus-traced')))
        check('live_exact_bytes_present',all(e['frame_hex'] for e in events(out/'live-traced')))
        short=out/'short.hex';short.write_text('001122\n00000000000000000000000088b5\n')
        logs=run('short-unknown',short);verify_run('short-unknown',logs,short)
        check('short_unknown_no_context',all(not e['admission']['nodes'] for e in events(logs)))
        demo=ROOT/'network-replay/fixtures/demo.hex'
        frame=next(verify.input_frames(demo))[0]
        truncated=out/'truncated.pcap'
        truncated.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',1,0,len(frame),len(frame)+12)+frame)
        logs=run('capture-truncated',truncated);verify_run('capture-truncated',logs,truncated)
        check('truncated_admission_skipped',events(logs)[0]['admission']['attempted'] is False)
        partial=out/'partial.pcap';partial.write_bytes(a.corpus.read_bytes()+b'\x01\x02')
        logs=run('partial',partial,expected_success=False);verify_run('partial',logs,partial,True)
        broken=out/'invalid.hex';broken.write_text(frame.hex()+'\nnot-hex\n')
        logs=run('invalid-hex',broken,expected_success=False);verify_run('invalid-hex',logs,broken,True)
        logs=run('frame-limit',a.corpus,['--max-frames','1'],expected_success=False);verify_run('frame-limit',logs,a.corpus,True)
        unsupported=out/'unsupported.txt';unsupported.write_bytes(b'placeholder input')
        logs=run('unsupported-format',unsupported,expected_success=False)
        check('startup_failure_logged',json.loads((logs/'summary.json').read_text())['status']=='failed' and json.loads((logs/'lifecycle.jsonl').read_text().splitlines()[-1])['stage']=='run_failed')
        raw=run('raw-demo',demo,['--include-frame-bytes']);verify_run('raw-demo',raw,demo)
        altered=out/'tampered-hash';shutil.copytree(raw,altered)
        with (altered/'events.jsonl').open('ab') as f:f.write(b' ')
        rejected('tampered_file_hash_rejected',altered,demo)
        altered=out/'missing-step';shutil.copytree(raw,altered);rows=events(altered)
        timeline=rows[0]['trace'];index=next(i for i,t in enumerate(timeline) if t['actor']=='admission' and t['detail']['action']=='walk_not_incident')
        timeline.pop(index)
        for i,t in enumerate(timeline):t['ordinal']=i
        rewrite_chain(altered,rows);rejected('missing_step_with_rehashed_log_rejected',altered,demo)
        altered=out/'tampered-bytes';shutil.copytree(raw,altered);rows=events(altered)
        rows[0]['frame_hex']='ff'+rows[0]['frame_hex'][2:];rewrite_chain(altered,rows)
        rejected('tampered_bytes_with_rehashed_log_rejected',altered,demo)
        again=subprocess.run([str(a.binary.resolve()),'--input',str(demo),'--out',str(raw)],capture_output=True,text=True)
        check('existing_output_not_overwritten',again.returncode!=0)
        check('source_inputs_unchanged',all(sha(Path(p))==h for p,h in input_hashes.items()))
        check('trained_pack_unchanged',sha(ROOT/'kernel-lightcone/src/world.bin')==pack_hash)
        result={'passed':all(c['passed'] for c in checks),'checks':checks,'measurements':measurements,
                'binary_sha256':sha(a.binary),'baseline_binary_sha256':sha(a.baseline),
                'test_sha256':sha(Path(__file__)),'verifier_sha256':sha(ROOT/'network-replay/tools/verify_trace.py'),
                'pack_sha256':pack_hash,'input_hashes':input_hashes,'scope':'logging and behavior preservation, not defensive effectiveness'}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'passed':result['passed'],'checks':len(checks),'failures':[c for c in checks if not c['passed']],'measurements':measurements},indent=2))
        return 0 if result['passed'] else 1
    except Exception:
        (out/'failure.txt').write_text(traceback.format_exc());raise


if __name__=='__main__':raise SystemExit(main())
