#!/usr/bin/env python3
"""C01 covered-wire, evidence, native catalog and capture-boundary evaluation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import struct
import subprocess
import traceback
from covered_scope import V4,V6,UDP,TCP,ICMP6,AUTH,checksum

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('trace_verify',ROOT/'network-replay/tools/verify_trace.py')
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def records(path):
    with path.open() as f:
        for line in f:yield json.loads(line)


def live_expectation(frame):
    """Independent expected seeds for ordinary, unfragmented covered lab traffic."""
    if len(frame)<14:raise ValueError('short live Ethernet')
    ether=int.from_bytes(frame[12:14],'big');ip=frame[14:]
    if ether==0x806:
        if len(ip)<28 or ip[:6]!=bytes.fromhex('000108000604'):raise ValueError('invalid live ARP')
        op=int.from_bytes(ip[6:8],'big')
        if op not in (1,2):raise ValueError('unexpected live ARP opcode')
        return {'arp_request' if op==1 else 'arp_reply'},'arp',True
    if ether==0x800:
        if len(ip)<20 or ip[0]>>4!=4:raise ValueError('invalid IPv4 header')
        header=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
        if not 20<=header<=total<=len(ip) or checksum(ip[:header])!=0:raise ValueError('IPv4 length/checksum failed independently')
        if int.from_bytes(ip[6:8],'big') & 0x3fff:raise ValueError('unexpected live fragment')
        seeds=set(V4);proto=ip[9];data=ip[header:total]
        if ip[8]==0:seeds.remove('ip_ttl')
        pseudo=ip[12:20]+bytes([0,proto])+len(data).to_bytes(2,'big');version=4
    elif ether==0x86dd:
        if len(ip)<40 or ip[0]>>4!=6:raise ValueError('invalid IPv6 header')
        end=40+int.from_bytes(ip[4:6],'big')
        if end>len(ip):raise ValueError('IPv6 length exceeds captured bytes')
        seeds=set(V6);proto=ip[6];offset=40
        while proto in (0,43,60):
            length=(ip[offset+1]+1)*8
            if offset+length>end:raise ValueError('IPv6 extension length')
            seeds.add('ipv6_extension');proto,offset=ip[offset],offset+length
        data=ip[offset:end];pseudo=ip[8:40]+len(data).to_bytes(4,'big')+bytes([0,0,0,proto]);version=6
    else:raise ValueError(f'unexpected live ethertype {ether}')
    if proto==6:
        if len(data)<20 or not 20<=(data[12]>>4)*4<=len(data) or checksum(pseudo+data)!=0:raise ValueError('TCP checksum/length failed independently')
        seeds|=TCP
        for flag,name in [(2,'tcp_syn'),(16,'tcp_ack'),(1,'tcp_fin'),(4,'tcp_rst')]:
            if data[13]&flag:seeds.add(name)
        if len(data)>(data[12]>>4)*4:seeds.add('tcp_payload')
        return seeds,f'ipv{version}_tcp',True
    if proto==17:
        if len(data)<8 or int.from_bytes(data[4:6],'big')!=len(data):raise ValueError('UDP length failed independently')
        check=int.from_bytes(data[6:8],'big')
        if (version==6 or check!=0) and (check==0 or checksum(pseudo+data)!=0):raise ValueError('UDP checksum failed independently')
        seeds|=UDP
        if data[:2]==bytes(2):seeds.add('udp_source_zero')
        seeds|={'udp_checksum','udp_integrity'} if check else {'udp_no_checksum'}
        return seeds,f'ipv{version}_udp',True
    if proto==1 and version==4:
        if len(data)<8 or checksum(data)!=0:raise ValueError('ICMPv4 checksum failed independently')
        seeds.add('icmp_checksum')
        mapping={8:'icmp_request',0:'icmp_reply',3:'icmp_unreachable',11:'icmp_expired',5:'icmp_redirect',12:'icmp_parameter_problem'}
        if data[0] in mapping:seeds.add(mapping[data[0]])
        return seeds,'icmpv4',True
    if proto==58 and version==6:
        if len(data)<8 or checksum(pseudo+data)!=0:raise ValueError('ICMPv6 checksum failed independently')
        seeds|=ICMP6
        if data[0] in (1,2,3,4):seeds.add('icmpv6_error')
        mapping={133:'router_solicitation',134:'router_advertisement',135:'neighbor_solicitation',136:'neighbor_advertisement'}
        if data[0] in mapping:
            if ip[7]!=255 or data[1]!=0:raise ValueError('NDP hop/code validation failed independently')
            seeds|={'ndp',mapping[data[0]]}
            return seeds,'ndp',True
        return seeds,'icmpv6',True
    return seeds,f'ipv{version}_header_only',True


def native_receipt_digest(row,world,sets):
    nodes,edges,excluded,frontier=sets;p=world['policy'];seeds=[] if row['symbol'] is None or row['kind']=='out_of_capacity' else [row['symbol']]
    data=b'ATOM-NETWORK-ADMISSION-2'+bytes.fromhex(row['pack'])+bytes.fromhex(row['query'])
    data+=bytes([2,p['max_hops'],p['relation_mask'],p['polarity']&255])+struct.pack('<H',p['max_nodes'])
    for indices,count in [(seeds,4),(nodes,4),(edges,8),(excluded,4),(frontier,4)]:data+=b''.join(struct.pack('<Q',v) for v in verify.words(indices,count))
    return hashlib.sha256(data).hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--live',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,default=ROOT/'target/trace-dev/debug/network-lightcone-replay')
    p.add_argument('--catalog-binary',type=Path,default=ROOT/'target/trace-dev/debug/examples/covered_catalog');a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve();manifest=json.loads((a.inputs/'manifest.json').read_text())
    source=ROOT/'network-lightcone/sources/world.json';pack=ROOT/'kernel-lightcone/src/world.bin';before={str(p):sha(p) for p in [source,pack,ROOT/'network-lightcone/coverage.json',a.binary]}
    rows=[];trace_checks=[]
    def replay(name,path):
        log=out/name
        result=subprocess.run([str(a.binary.resolve()),'--input',str(path.resolve()),'--out',str(log),'--max-frames','1000'],cwd=ROOT,capture_output=True,text=True,timeout=120)
        (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
        if result.returncode:raise RuntimeError(name+' replay failed')
        trace_checks.append({'name':name,**verify.verify(log,path)})
        return log
    try:
        for variant in range(3):
            path=a.inputs/f'variant-{variant}.pcap'
            if sha(path)!=manifest['inputs'][path.name]:raise ValueError('fixture hash changed')
            log=replay(f'variant-{variant}',path)
            expected=[r for r in manifest['cases'] if r['variant']==variant]
            actual=list(records(log/'events.jsonl'))
            if len(expected)!=len(actual):raise ValueError('case/event count differs')
            for case,event in zip(expected,actual):
                direct={n['record']['id'] for n in event['observer']['seeds']}
                edges={e['record']['id']:e['record'] for e in event['admission'].get('edges',[])}
                known={r['id']:r for r in json.loads(source.read_text())['edges']}
                correctness={'frame_hash':case['frame_sha256']==event['frame_sha256'],
                    'exact_direct_seeds':direct==set(case['expected_seeds']),
                    'kind':event['observer']['kind']==case['expected_kind'],'reason':event['observer']['reason']==case['expected_reason'],
                    'no_authority_seeds':not direct & set(case['forbidden_direct_seeds']),
                    'empty_if_unrepresented':bool(direct) or not event['admission'].get('nodes',[])}
                missing=sorted(set(case['required_relations'])-set(edges))
                wrong_scope=sorted(set(case['forbidden_unqualified_edges']) & set(edges))
                provenance=all(edges[k]==known[k] for k in edges)
                rows.append({'id':case['id'],'family':case['family'],'variant':variant,'kind':case['expected_kind'],
                    'checks':correctness,'wire_pass':all(correctness.values()),'required_relations':case['required_relations'],
                    'missing_relations':missing,'evidence_pass':not missing and provenance,'unqualified_ipv4_prerequisites':wrong_scope,
                    'semantic_scope_pass':not wrong_scope,'nodes':len(event['admission'].get('nodes',[])),
                    'edges':len(edges),'direct_seeds':len(direct),'receipt_sha256':event['admission'].get('receipt_sha256')})
            del actual
        world=json.loads((out/'variant-0/world.json').read_text())
        native=out/'catalog.jsonl'
        result=subprocess.run([str(a.catalog_binary.resolve()),str(native)],cwd=ROOT,capture_output=True,text=True,timeout=120)
        if result.returncode:raise RuntimeError(result.stderr)
        catalog_rows=[]
        for row in records(native):
            if row['kind']=='invalid_policy':passed=row['error']=='Policy' and row['trace']==['policy_rejected']
            elif row['kind']=='out_of_world':passed=row['receipt'].get('error')=='Index' and row['trace'][-1]['action']=='seed_out_of_range'
            else:
                seeds={row['symbol']} if row['kind']=='represented' else set()
                n,e,x,h,t=verify.graph_replay(world,seeds,world['policy'])
                passed=(set(row['receipt']['nodes'])==n and set(row['receipt']['edges'])==e and set(row['receipt']['excluded'])==x
                    and set(row['receipt']['frontier'])==h and row['trace']==t and row['receipt']['digest']==native_receipt_digest(row,world,(n,e,x,h)))
                if row['kind']=='represented':passed=passed and row['host_accepted'] is True and row['symbol'] in n
                if row['kind']=='out_of_capacity':passed=passed and row['host_accepted'] is False
            catalog_rows.append({'kind':row['kind'],'index':row.get('index'),'passed':bool(passed)})
        live_capture=json.loads((a.live/'capture.json').read_text());live_path=a.live/'capture.pcap';live_log=replay('live',live_path)
        live_rows=[]
        for (frame,truncated,_),event in zip(verify.input_frames(live_path),records(live_log/'events.jsonl')):
            try:
                expected,family,_=live_expectation(frame)
                got={n['record']['id'] for n in event['observer']['seeds']}
                passed=not truncated and got==expected and event['observer']['kind']=='decoded'
                live_rows.append({'sequence':event['sequence'],'family':family,'passed':passed,'reason':event['observer']['reason'],'missing':sorted(expected-got),'extra':sorted(got-expected)})
            except ValueError as error:live_rows.append({'sequence':event['sequence'],'passed':False,'error':str(error)})
        required_live={'arp','ndp','ipv4_tcp','ipv6_tcp','ipv4_udp','ipv6_udp','icmpv4','icmpv6'}
        live_families={r.get('family') for r in live_rows}
        live_pass=all(r['passed'] for r in live_rows) and required_live<=live_families and all(r['passed'] for r in live_capture['application_exchanges']) and all(r['passed'] for r in live_capture['server']) and live_capture['ping4_pass'] and live_capture['ping6_pass'] and '0 packets dropped by kernel' in live_capture['capture_stderr']
        positive=[r for r in rows if r['direct_seeds']]
        required_total=sum(len(r['required_relations']) for r in rows);missing_total=sum(len(r['missing_relations']) for r in rows)
        report={'status':'EVALUATED','wire_pass':all(r['wire_pass'] for r in rows),'evidence_pass':all(r['evidence_pass'] for r in rows),
            'semantic_scope_pass':all(r['semantic_scope_pass'] for r in rows),'catalog_pass':all(r['passed'] for r in catalog_rows) and len(catalog_rows)==212,
            'live_pass':live_pass,'source_unchanged':all(sha(Path(p))==h for p,h in before.items()),
            'case_count':len(rows),'wire_pass_count':sum(r['wire_pass'] for r in rows),'required_relation_occurrences':required_total,
            'required_relation_hits':required_total-missing_total,'semantic_scope_failures':sum(not r['semantic_scope_pass'] for r in rows),
            'catalog_queries':len(catalog_rows),'live_frames':len(live_rows),'live_families':sorted(x for x in live_families if x),
            'median_admitted_nodes':statistics.median(r['nodes'] for r in positive),'full_catalog_nodes':len(world['nodes']),
            'median_admitted_edges':statistics.median(r['edges'] for r in positive),'full_catalog_edges':len(world['edges']),
            'seeds_only_relation_hits':0,'full_catalog_relation_hits':required_total,
            'scope':'covered structural observation, exact bounded context, source/polarity retention; no attack prevention/LLM improvement claim',
            'cases':rows,'catalog_results':catalog_rows,'live_results':live_rows,'trace_checks':trace_checks,
            'pinned_hashes':before,'input_manifest_sha256':sha(a.inputs/'manifest.json'),'live_pcap_sha256':sha(live_path),
            'evaluator_sha256':sha(Path(__file__)),'verifier_sha256':sha(ROOT/'network-replay/tools/verify_trace.py')}
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k not in ['cases','catalog_results','live_results','pinned_hashes','trace_checks']},indent=2))
        return 0
    except Exception:
        (out/'failure.txt').write_text(traceback.format_exc());raise


if __name__=='__main__':raise SystemExit(main())
