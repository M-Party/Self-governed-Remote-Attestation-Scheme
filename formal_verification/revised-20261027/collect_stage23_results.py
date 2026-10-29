#!/usr/bin/env python3
"""Collect new Stage 2-3 runs from immutable snapshots; leave old reports intact."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parent
PROPERTIES=('Agreement','Authenticity','Completeness','Issuance')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def extract_queries(source):
    return [(source[:m.start()].count('\n')+1,m.group())
            for m in re.finditer(r'^query\b.*?\.',source,re.M|re.S)]

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('runs',nargs='+',help='Existing directory names under results/')
    cli.add_argument('--report-prefix',default='stage23',help='Output prefix, preserving earlier reports')
    cli.add_argument('--select-json',type=Path,help='Optional run-name to selected-job-name mapping')
    cli.add_argument('--evidence-json',type=Path,help='Optional per-job control scope and input classification')
    args=cli.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]+',args.report_prefix):cli.error('Invalid report prefix')
    selection=json.loads(args.select_json.read_text()) if args.select_json else None
    evidence=json.loads(args.evidence_json.read_text()) if args.evidence_json else {}
    rows=[]
    runs=[]
    issues=[]
    details=[]
    for name in args.runs:
        if not re.fullmatch(r'[A-Za-z0-9_-]+',name):
            cli.error('Invalid run name')
        directory=ROOT/'results'/name
        for line in (directory/'jobs.txt').read_text().splitlines():
            job,source,recorded_category,n=line.split('|')
            if selection is not None and job not in selection.get(name,[]):continue
            meta=evidence.get(job,{})
            extent=meta.get('process_extent','')
            category=recorded_category
            if recorded_category.startswith('controlled-') and extent:
                category='controlled-Stage123-quote-prefix' if 'prefix' in extent else 'controlled-full-Stage123'
            d=directory/job
            frozen=d/'model.pv'
            if not frozen.exists():
                issues.append(f'{name}/{job}: not run')
                continue
            sha=digest(frozen)
            assert sha==(d/'model.sha256').read_text().split()[0],f'Frozen source mismatch: {d}'
            queries=extract_queries(frozen.read_text())
            log=(d/'output.log').read_text() if (d/'output.log').exists() else ''
            raw=list(re.finditer(r'^RESULT (.+?) (?:is (true|false)|cannot be proved)\.$',log,re.M))
            parse=int((d/'parse-exit.txt').read_text()) if (d/'parse-exit.txt').exists() else None
            exit_code=int((d/'exit.txt').read_text()) if (d/'exit.txt').exists() else None
            timing=(d/'time.txt').read_text() if (d/'time.txt').exists() else ''
            tm=dict(re.findall(r'(\w+)=([\d.]+)',timing))
            elapsed=float(tm['elapsed_seconds']) if 'elapsed_seconds' in tm else None
            record=dict(run=name,job=job,source=source,sha256=sha,category=category,
                        recorded_category=recorded_category,process_extent=extent,input_nature=meta.get('nature',''),
                        parse_exit=parse,exit=exit_code,elapsed_seconds=elapsed,
                        query_count=len(queries),result_count=len(raw),
                        source_still_matches=digest(ROOT/source)==sha,
                        log_sha256=digest(d/'output.log') if (d/'output.log').exists() else None)
            runs.append(record)
            if exit_code!=0 or len(raw)!=len(queries):
                issues.append(f'{name}/{job}: exit={exit_code}, {len(raw)}/{len(queries)} results')
            last=0
            for i,(lineno,query) in enumerate(queries):
                trace=False
                if i<len(raw):
                    result=raw[i][2] or 'cannot be proved'
                    trace='A trace has been found.' in log[last:raw[i].end()]
                    last=raw[i].end()
                    if '==>' in query:
                        meaning={'true':'proved','false':'confirmed_counterexample' if trace else 'unconfirmed_false',
                                 'cannot be proved':'inconclusive'}[result]
                    else:
                        meaning={'true':'unreachable','false':'reachable' if trace else 'unconfirmed_false',
                                 'cannot be proved':'inconclusive'}[result]
                    raw_line=raw[i].group()
                else:
                    result='no result'
                    meaning='timed_out' if exit_code==124 else 'parse_failed' if parse not in (0,None) else 'unfinished'
                    raw_line=''
                if category=='primary-single':
                    qid=job.rsplit('-',1)[1]
                    prop=PROPERTIES[int(qid[1:])-1]
                elif category=='primary':
                    qid='Q'+str(i+1)
                    props=('Authorization',)+PROPERTIES if 'stage123' in job else PROPERTIES
                    prop=props[i]
                else:
                    qid=str(i+1)
                    prop=category
                row=dict(run=name,model=job,participants=n,category=category,query_id=qid,property=prop,
                         recorded_category=recorded_category,process_extent=extent,input_nature=meta.get('nature',''),
                         raw_result=result,result=meaning,model_sha256=sha,elapsed_seconds=elapsed,
                         timing_scope='single query, whole verifier command' if len(queries)==1 else 'whole model, all queries combined',
                         query_line=lineno,query=query,source=source,frozen_source=str(frozen.relative_to(ROOT)),
                         log=str((d/'output.log').relative_to(ROOT)),trace_reconstructed=trace,
                         graph_directory=str((d/'graphs').relative_to(ROOT)))
                rows.append(row)
                details.append(f'{name}/{job}/{qid}\n{query}\n{raw_line}\nResult: {meaning}; wall={elapsed}s ({row["timing_scope"]})\nSHA256: {sha}\nLog: {row["log"]}\n')
    reports=ROOT/'reports'
    with (reports/(args.report_prefix+'-results-table.csv')).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    latest={r['job']:r['run'] for r in runs}
    current=[r for r in rows if latest[r['model']]==r['run']]
    result={'baseline':'3766338d5301d543434a57fdcb3aea037aea512a','runs':runs,'results':rows,'current_results':current,'issues':issues,
            'source_and_log_integrity':all(r['source_still_matches'] for r in runs),
            'all_runs_complete':not issues,
            'latest_run_per_model':latest,
            'current_unresolved_queries':sum(r['result'] in ('inconclusive','timed_out','parse_failed','unfinished','unconfirmed_false') for r in current),
            'clock_scope':'GNU time includes ProVerif parsing/translation/solving and requested graph generation; preliminary parse-only and Docker startup are separate.'}
    (reports/(args.report_prefix+'-results.json')).write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    (reports/(args.report_prefix+'-queries-and-results.txt')).write_text('\n'.join(details))
    print(json.dumps({'runs':len(runs),'query_results':len(rows),'issues':issues,'integrity':result['source_and_log_integrity']},indent=2))

if __name__=='__main__':
    main()
