#!/usr/bin/env python3
"""Complete the agreed twelve-profile model with an explicit serialized Self TEE.

All protocol bodies are inherited from generate_models.py. This revision adds
one policy metadata field and its real Stage 1 check. The aggregate still has
the original 21 constraint fields, with no input history in the result.
"""
import argparse
import json
from pathlib import Path
import re
import generate_models as g

ROOT=Path(__file__).resolve().parent

def self_tee(text):
    text=text.replace('free E1, E2, E3: entity.','const E1, E2, E3: entity [data].')
    text=text.replace('fun pol(party, roster,','fun pol(party, entity, roster,')
    text=text.replace('forall a: party, members: roster,','forall a: party, selfTEE: entity, members: roster,')
    text=text.replace('pol(a, members,','pol(a, selfTEE, members,')
    text=re.sub(r'\bpol\((P[123]),\s*',lambda m:'pol('+m[1]+', E'+m[1][1]+', ',text)
    fields=['t1: tcbreq','t2: tcbreq','t3: tcbreq','e1: entry','e2: entry','e3: entry']
    getter='reduc forall a: party, selfTEE: entity, members: roster, '+', '.join(fields)+';\n  policySelfTEE(pol(a, selfTEE, members, t1, t2, t3, e1, e2, e3)) = selfTEE.\n'
    declaration=re.search(r'^fun pol\([^\n]+\): policy \[private\]\.\n',text,re.M)
    if declaration:
        text=text[:declaration.end()]+getter+text[declaration.end():]
    for i in (1,2,3):
        text=text.replace(f'if policySelf(rho{i})=P{i} then',
                          f'if policySelf(rho{i})=P{i} && policySelfTEE(rho{i})=E{i} then')
    return text

def normalized(text):return self_tee(g.common_hash_encoding(text))

def policy(i,profile='Compatible'):return normalized(g.policy(3,i,profile))

def model(kind='primary'):
    basekind='reachability' if kind=='reachability-weak' else kind
    text=self_tee(g.stage123_model(basekind))
    if kind=='reachability-weak':
        needle='event(AuthorizationAccepted(P3,kr3,r3,o3,s3a))'
        assert text.count(needle)==1
        text=text.replace(needle,f'event(AuthorizationAccepted(P3,kr3,{policy(3,"Weak")},o3,s3a))')
        text=text.replace(',r3:policy','')
    return '(* Revision r2: explicit serialized Self-TEE and actual check; twelve profiles. *)\n'+text

def declarations():
    text=model().split('(* Stage 3: shared verifier,')[0]
    return re.sub(r'^query\b.*?\.', '',text,flags=re.M|re.S)

def role(i):return normalized(g.stage123_role(i))

def owner(i):return normalized(g.stage1_owner(i))

def strip_queries(source,keep):
    blocks=list(re.finditer(r'^query\b.*?\.',source,re.M|re.S))
    for j,block in reversed(list(enumerate(blocks))):
        if j!=keep:source=source[:block.start()]+f'(* Query {j+1} checked separately. *)'+source[block.end():]
    return source

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--install',action='store_true',help='Update the original N3 entry after verification')
    args=cli.parse_args()
    for kind in ('primary','auxiliary','reachability','reachability-profile12','reachability-weak'):
        (ROOT/'models'/f'sras-n3-stage123r2-{kind}.pv').write_text(model(kind))
    names=['Authorization','Agreement','Authenticity','Completeness','Issuance']
    jobs=[]
    for i,name in enumerate(names):
        path=ROOT/'queries'/f'n3-stage123r2-{name}.pv'
        path.write_text(strip_queries(model(),i))
        jobs.append(f'{path.stem}|{path.relative_to(ROOT)}|{name}|3')
    (ROOT/'jobs-stage123r2-main.txt').write_text('\n'.join(jobs)+'\n')
    (ROOT/'jobs-stage123r2-pilot.txt').write_text(jobs[0]+'\n')
    aux=model('auxiliary')
    groups=[[],[],[]]
    for i,_ in enumerate(re.finditer(r'^query\b.*?\.',aux,re.M|re.S)):
        path=ROOT/'queries'/f'n3-stage123r2-A{i+1:02d}.pv'
        path.write_text(strip_queries(aux,i))
        groups[min(i//5,2)].append(f'{path.stem}|{path.relative_to(ROOT)}|auxiliary|3')
    for i,jobs in enumerate(groups,1):
        (ROOT/f'jobs-stage123r2-aux{i}.txt').write_text('\n'.join(jobs)+'\n')
    witnesses=[]
    for kind in ('reachability','reachability-profile12','reachability-weak'):
        name=f'sras-n3-stage123r2-{kind}'
        witnesses.append(f'{name}|models/{name}.pv|reachability|3')
    (ROOT/'jobs-stage123r2-witness.txt').write_text('\n'.join(witnesses)+'\n')
    (ROOT/'models/policy-catalog-stage123r2-p12.json').write_text(json.dumps({p:policy(3,p) for p in g.EXTENDED_PROFILES},indent=2)+'\n')
    if args.install:(ROOT.parent/'sras-n3.pv').write_text(model())
    print('Generated r2: explicit Self TEE, five main queries, fourteen auxiliary queries and three joint witnesses.')

if __name__=='__main__':main()
