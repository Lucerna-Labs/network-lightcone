#!/usr/bin/env python3
"""Mechanically replay frozen C03 items with constrained JSON output."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.error
from concept_downstream import http,ARMS,MODEL


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);frozen=json.loads((a.source/'frozen.json').read_text())
    items=[]
    schema={'type':'json_schema','json_schema':{'name':'protocol_choice','strict':True,'schema':{'type':'object','properties':{'choice':{'type':'string','enum':['A','B','C']}},'required':['choice'],'additionalProperties':False}}}
    for item in frozen['items']:
        old=item['request']
        request={'model':old['model'],'messages':[{'role':'system','content':old['system_prompt']},{'role':'user','content':old['input']}],
                 'temperature':old['temperature'],'max_tokens':old['max_output_tokens'],'stream':False,
                 'reasoning_effort':'none','chat_template_kwargs':{'enable_thinking':False},'response_format':schema}
        items.append({**{k:v for k,v in item.items() if k!='request'},'request':request})
    prepared={'status':'frozen_before_format_control_calls','source_frozen_sha256':sha(a.source/'frozen.json'),
              'source_summary_sha256':sha(a.source/'summary.json'),'protocol_sha256':sha(Path(__file__).parents[1]/'CONCEPT-DOWNSTREAM-FORMAT-CONTROL.md'),
              'script_sha256':sha(Path(__file__)),'items':items,'arm_order':frozen['arm_order']}
    (a.out/'frozen.json').write_text(json.dumps(prepared,indent=2)+'\n')
    rows=[]
    with (a.out/'responses.jsonl').open('x') as f:
        for repetition in range(2):
            for arm in prepared['arm_order'][str(repetition)]:
                for item in [x for x in items if x['repetition']==repetition and x['arm']==arm]:
                    started=time.perf_counter();response=None;errors=[]
                    for attempt in range(2):
                        try:response=http('/v1/chat/completions',item['request']);break
                        except (urllib.error.URLError,TimeoutError) as e:
                            errors.append(str(e))
                            if isinstance(e,urllib.error.HTTPError) and e.code<500:break
                    text='';choice=None
                    try:
                        text=response['choices'][0]['message']['content'];value=json.loads(text)
                        if set(value)=={'choice'} and value['choice'] in ['A','B','C']:choice=value['choice']
                    except (KeyError,TypeError,ValueError):pass
                    row={k:item[k] for k in ['id','arm','repetition','gold','context_characters']}
                    row.update(choice=choice,correct=choice==item['gold'],text=text,response=response,errors=errors,
                               elapsed_seconds=time.perf_counter()-started,request_sha256=hashlib.sha256(json.dumps(item['request'],sort_keys=True).encode()).hexdigest())
                    f.write(json.dumps(row)+'\n');f.flush();rows.append(row)
                    print(f"{len(rows)}/128 rep={repetition} arm={arm} case={item['id']} correct={row['correct']}",flush=True)
    summary={'arms':{},'paired':{},'unique_questions':16,'trials_per_arm':32,'source_questions_are_regression':True,
             'same_model':all(r['response'] and r['response'].get('model')==MODEL for r in rows),
             'reasoning_tokens':sum((r['response'] or {}).get('usage',{}).get('completion_tokens_details',{}).get('reasoning_tokens',0) for r in rows),
             'frozen_sha256':sha(a.out/'frozen.json'),'responses_sha256':sha(a.out/'responses.jsonl')}
    for arm in ARMS:
        selected=[r for r in rows if r['arm']==arm]
        summary['arms'][arm]={'correct':sum(r['correct'] for r in selected),'total':len(selected),'malformed':sum(r['choice'] is None for r in selected),
                             'input_tokens':sum((r['response'] or {}).get('usage',{}).get('prompt_tokens',0) for r in selected)}
    for arm in ['none','seeds','full']:
        wins=losses=ties=0
        for r in [r for r in rows if r['arm']=='admitted']:
            other=next(x for x in rows if x['arm']==arm and x['id']==r['id'] and x['repetition']==r['repetition'])
            wins+=r['correct'] and not other['correct'];losses+=other['correct'] and not r['correct'];ties+=r['correct']==other['correct']
        summary['paired'][arm]={'wins':wins,'losses':losses,'ties':ties}
    (a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
