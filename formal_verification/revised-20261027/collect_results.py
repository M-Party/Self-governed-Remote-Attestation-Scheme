#!/usr/bin/env python3
"""Collect real ProVerif outputs and check source/log identity, without rerunning."""
from pathlib import Path
import csv
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
REPORTS=ROOT/'reports'

def extract_queries(text):
    return [(text[:m.start()].count('\n')+1,m.group())
            for m in re.finditer(r'^query\b.*?\.',text,re.M|re.S)]

def expected(name,count):
    if name=='join-regression': return ['true']*8+['false']*4+['true']*8
    if name=='join-specialization-regression': return ['true']*2
    if 'no-confirm-coordination' in name: return ['false']
    if 'reachability' in name: return ['false']*count
    if name.startswith('sras-') or re.match(r'n[23]-Q[1-4]$',name): return ['true']*count
    if name.startswith('n2-'):
        return ['false','true','false']+(['true'] if count==4 else [])
    return ['false','true']+(['false'] if count==3 else [])

def main():
    rows=[]
    run_checks=[]
    details=[]
    specs=[('jobs.txt','final-v2'),('jobs-primary-single.txt','primary-single')]
    for jobfile,run in specs:
        for line in (ROOT/jobfile).read_text().splitlines():
            name,source,category,n=line.split('|')
            model=ROOT/source
            dest=ROOT/'results'/run/name
            digest=hashlib.sha256(model.read_bytes()).hexdigest()
            saved=(dest/'model.sha256').read_text().split()[0]
            assert digest==saved, f'Source/log mismatch: {name}'
            assert (dest/'parse-exit.txt').read_text().strip()=='0', f'Parse failed: {name}'
            assert (dest/'exit.txt').read_text().strip()=='0', f'Run failed: {name}'
            log=(dest/'output.log').read_text()
            matches=list(re.finditer(r'^RESULT (.+?) (?:is (true|false)|cannot be proved)\.$',log,re.M))
            queries=extract_queries(model.read_text())
            assert len(matches)==len(queries)>0, (name,len(matches),len(queries))
            times=dict(re.findall(r'(\w+)=([\d.]+)',(dest/'time.txt').read_text()))
            seconds=float(times['elapsed_seconds'])
            actual=[m[2] or 'cannot be proved' for m in matches]
            targets=expected(name,len(actual))
            assert actual==targets, f'Unexpected result: {name}: {actual}, expected {targets}'
            run_checks.append({'model':name,'source':source,'sha256':digest,'run':run,
                               'query_count':len(queries),'raw_results':actual,'elapsed_seconds':seconds,
                               'parse_exit':0,'exit':0,'expected_behavior_observed':True})
            details.append(f'===== {name} (N={n}, {category}) =====\nSource: {source}\nSHA256: {digest}\n')
            last=0
            for i,((lineno,code),m) in enumerate(zip(queries,matches),1):
                raw=m[2] or 'cannot be proved'
                trace='A trace has been found.' in log[last:m.end()]
                last=m.end()
                if '==>' in code:
                    interpretation={'true':'证明成立','false':'可确认反例','cannot be proved':'无法证明'}[raw]
                else:
                    interpretation={'true':'目标事件/组合不可达','false':'目标事件/组合可达','cannot be proved':'无法判定可达性'}[raw]
                if raw=='false': assert trace, f'Unreconstructed false result: {name}/{i}'
                qid=('Q'+str(i)) if name.endswith('primary') else (name.rsplit('-',1)[1] if category=='primary-single' else f'{i:02d}')
                prop=['Agreement','Authenticity','Completeness','Issuance'][i-1] if name.endswith('primary') else category
                if category=='primary-single': prop=['Agreement','Authenticity','Completeness','Issuance'][int(qid[1:])-1]
                row={'模型':name,'参与方数量':n,'类别':category,'查询编号':qid,'性质':prop,'工具原始结果':raw,
                     '解释':interpretation,'耗时秒':seconds,'计时范围':'单查询整次运行' if category=='primary-single' else '该模型全部查询合计',
                     '源文件':source,'查询起始行':lineno,'准确查询代码':code,
                     '原始日志':str((dest/'output.log').relative_to(ROOT)),
                     '重建轨迹':'是' if trace else '否','图目录':str((dest/'graphs').relative_to(ROOT))}
                rows.append(row)
                details.append(f'{qid} @ line {lineno}\n{code}\n{m.group()}\n解释：{interpretation}；整模型耗时 {seconds:.2f}s；trace={trace}\n日志：{row["原始日志"]}\n')
    REPORTS.mkdir(exist_ok=True)
    with (REPORTS/'results-table.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    (REPORTS/'queries-and-results.txt').write_text('\n'.join(details))
    status={'authoritative_run':'final-v2','isolated_primary_timings_run':'primary-single',
            'model_runs':len(run_checks),'query_results':len(rows),
            'primary_protocol_queries':7,'all_sources_match_logs':True,
            'all_parsers_exit_zero':True,'all_runs_exit_zero':True,
            'confirmed_correspondence_counterexamples':sum(r['解释']=='可确认反例' for r in rows),
            'inconclusive_final_queries':sum(r['工具原始结果']=='cannot be proved' for r in rows),
            'total_model_wall_seconds':round(sum(x['elapsed_seconds'] for x in run_checks),2),
            'runs':run_checks}
    (REPORTS/'verification-checks.json').write_text(json.dumps(status,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in status.items() if k!='runs'},ensure_ascii=False,indent=2))

if __name__=='__main__': main()
