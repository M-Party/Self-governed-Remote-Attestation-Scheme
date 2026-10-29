#!/usr/bin/env python3
"""Local control fixtures for the actual Stage 1 checks, plus all 12 join cases.

Fixtures use a private channel to deliver an exact faulty message. They are
guard checks with reachable predecessors, not additional public-network proofs.
The main five queries remain over the full public-network Stage 1-3 process.
"""
import json
from pathlib import Path
import re
import generate_models as g

ROOT=Path(__file__).resolve().parent

def declarations():
    text=g.stage123_model().split('(* Stage 3: shared verifier,')[0]
    return re.sub(r'^query\b.*?\.', '',text,flags=re.M|re.S)

def norm(source):
    return g.common_hash_encoding(source)

def auth_fixture(scenario):
    prefix=g.stage123_role(3).split('    event AuthorizedPolicyDeclared')[0]+'    0\n  ).\n'
    prefix=norm(prefix)
    prefix=prefix.replace('    if signedKey=pk3',
                          '    event FixtureAuthorizationCryptoChecked;\n    if signedKey=pk3')
    rho=norm(g.policy(3,3))
    owner='skO3'
    signed_key='k'
    signed_hash=f'H(policyBytes({rho}))'
    signing='skO3'
    if scenario=='wrong-signature':signing='wrong'
    elif scenario=='fingerprint-mismatch':owner=signing='skO1'
    elif scenario=='key-rebinding':signed_key='pk(wrong)'
    elif scenario=='policy-rebinding':signed_hash=f'H(policyBytes({norm(g.policy(3,3,"Weak"))}))'
    elif scenario=='wrong-self':
        rho=norm(g.policy(3,1));owner=signing='skO1';signed_hash=f'H(policyBytes({rho}))'
    elif scenario=='wrong-attester':
        rho=rho.replace('Assign(P3)','Assign(P1)');signed_hash=f'H(policyBytes({rho}))'
    elif scenario=='nonconcrete-signer':
        rho=rho.replace('exact(H(pk(skO3)))','Any');signed_hash=f'H(policyBytes({rho}))'
    body='0' if scenario=='no-authorization' else f'out(net,(P3,k,{rho},sign(({signed_key},{signed_hash}),{signing}),pk({owner})))'
    fixture=f'''
let fixture(akR:skey)=
  new wrong:skey;
  new n:bitstring;
  in(net,(=P3,k:bitstring));
  out(net,(P3,n));
  in(net,(=P3,=k,q:bitstring));
  let rpeQuote(=mRPE,=Good,=H((k,n)))=checksign(q,pk(akR)) in
  event FixtureQuoteReady;
  {body}.
process
  new akR:skey;
  new akE:skey;
  (rpe3(akR,pk(akR),pk(akE)) | fixture(akR))
'''
    queries='''query event(FixtureQuoteReady).
query k:bitstring,r:policy,o:bitstring; event(AuthorizationReceived(P3,k,r,o)).
query event(FixtureAuthorizationCryptoChecked).
query k:bitstring,r:policy,o:bitstring; event(AuthorizationSignatureChecked(P3,k,r,o)).
query k:bitstring,r:policy,o:bitstring; event(AuthorizationSelfChecked(P3,k,r,o)).
query k:bitstring,r:policy,o:bitstring,s:bitstring; event(AuthorizationAccepted(P3,k,r,o,s)).
'''
    text=declarations().replace('free net: channel.','free net: channel [private].')
    return text+'event FixtureQuoteReady.\nevent FixtureAuthorizationCryptoChecked.\n'+queries+prefix+fixture

def owner_fixture(scenario):
    owner=norm(g.stage1_owner(1))
    original='  let rpeQuote(=mRPE,status:tcbstatus,binding:bitstring)=checksign(q,pkAKR) in'
    owner=owner.replace(original,'''  let signedQuote=checksign(q,pkAKR) in
  event FixtureOwnerCryptoChecked;
  let rpeQuote(=mRPE,status:tcbstatus,binding:bitstring)=signedQuote in''')
    assert 'event FixtureOwnerCryptoChecked' in owner
    code='mBad' if scenario=='wrong-code' else 'mRPE'
    status='Outdated' if scenario=='wrong-tcb' else 'Good'
    key='pk(wrong)' if scenario=='key-rebinding' else 'pk(target)'
    nonce='stale' if scenario=='nonce-rebinding' else 'n'
    signing='wrong' if scenario=='wrong-signature' else 'akR'
    fixture=f'''
let fixture(akR:skey)=
  new target:skey;
  new wrong:skey;
  new stale:bitstring;
  in(net,(=P1,n:bitstring));
  event FixtureOwnerResponseSent;
  out(net,(P1,pk(target),sign(rpeQuote({code},{status},H(({key},{nonce}))),{signing}))).
process
  new akR:skey;
  (owner1(pk(akR)) | fixture(akR))
'''
    queries='''query event(FixtureOwnerResponseSent).
query event(FixtureOwnerCryptoChecked).
query o:bitstring,k:bitstring,r:policy,n:bitstring; event(OwnerAttested(o,k,r,n)).
query o:bitstring,k:bitstring,h:bitstring; event(OwnerSigned(o,k,h)).
'''
    text=declarations().replace('free net: channel.','free net: channel [private].')
    return text+'event FixtureOwnerResponseSent.\nevent FixtureOwnerCryptoChecked.\n'+queries+owner+fixture

def join_fixture():
    types=['tcbreq']*3+['entry']*3
    left=[f'l{i}' for i in range(6)];right=[f'r{i}' for i in range(6)]
    lp='mkstar('+','.join(f'{x}:{t}' for x,t in zip(left,types))+')'
    rp='mkstar('+','.join(f'{x}:{t}' for x,t in zip(right,types))+')'
    lines=[f'letfun genericJoin(x:polstar,y:polstar)=\n  let {lp}=x in\n  let {rp}=y in']
    for i in range(6):
        function='jointcb' if i<3 else 'joinentry'
        lines.append(f'  let j{i}={function}({left[i]},{right[i]}) in')
    lines.append('  mkstar('+','.join(f'j{i}' for i in range(6))+').\n')
    body=f'''
let checkProfile(pr:profile)=
  let a=constraints({norm(g.policy(3,1))}) in
  let b=constraints({norm(g.policy(3,2))}) in
  let c=constraints(choosePolicy(pr)) in
  let first=joinstar(a,b) in
  let generalFirst=genericJoin(a,b) in
  let actual=joinstar(first,c) in
    (let expected=genericJoin(generalFirst,c) in
      if actual=expected then event FixtureJoinPassed(pr) else event FixtureJoinWrong(pr)
     else event FixtureJoinWrong(pr))
  else
    (let expected=genericJoin(generalFirst,c) in event FixtureJoinWrong(pr)
     else event FixtureJoinPassed(pr)).
process
  ('''+ ' |\n   '.join(f'checkProfile({p})' for p in g.EXTENDED_PROFILES)+')\n'
    queries='query pr:profile; event(FixtureJoinWrong(pr)).\nquery '+ ' && '.join(f'event(FixtureJoinPassed({p}))' for p in g.EXTENDED_PROFILES)+'.\n'
    return declarations()+'event FixtureJoinWrong(profile).\nevent FixtureJoinPassed(profile).\n'+queries+'\n'.join(lines)+body

def main():
    jobs=[];expected={}
    receiver=['normal','wrong-signature','fingerprint-mismatch','key-rebinding',
              'policy-rebinding','wrong-self','wrong-attester','nonconcrete-signer','no-authorization']
    for case in receiver:
        name='n3-stage123-auth-'+case
        path=ROOT/'scenarios'/(name+'.pv');path.write_text(auth_fixture(case))
        # true means the query target is reachable; collector interprets raw false.
        behavior=[True,True,True,True,True,case=='normal']
        if case=='wrong-signature':behavior[2:]=[False]*4
        elif case in ('key-rebinding','policy-rebinding'):behavior[3:]=[False]*3
        elif case=='wrong-self':behavior[4:]=[False]*2
        elif case=='no-authorization':behavior=[True]+[False]*5
        expected[name]=behavior
        jobs.append(f'{name}|{path.relative_to(ROOT)}|local-Stage1-receiver|3')
    for case in ('normal','wrong-code','wrong-tcb','key-rebinding','nonce-rebinding','wrong-signature'):
        name='n3-stage123-owner-'+case
        path=ROOT/'scenarios'/(name+'.pv');path.write_text(owner_fixture(case))
        expected[name]=[True,case!='wrong-signature',case=='normal',case=='normal']
        jobs.append(f'{name}|{path.relative_to(ROOT)}|local-Stage1-owner|3')
    path=ROOT/'models/join-stage123-p12-regression.pv';path.write_text(join_fixture())
    expected[path.stem]=[False,True]
    jobs.append(f'{path.stem}|{path.relative_to(ROOT)}|algebra|3')
    (ROOT/'jobs-stage123-regression.txt').write_text('\n'.join(jobs)+'\n')
    (ROOT/'reports/stage123-regression-expectations.json').write_text(json.dumps({
        'scope':'Local private-channel control fixtures; not substitutes for the full public-network proofs',
        'values_mean':'True = reachable; False = unreachable, not raw ProVerif true/false',
        'expected_reachability':expected},indent=2)+'\n')
    print(f'Generated {len(jobs)} local Stage 1/join checks.')

if __name__=='__main__':main()
