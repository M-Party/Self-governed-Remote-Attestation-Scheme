#!/usr/bin/env python3
"""Current Stage 1-3 controlled regressions, preserving actual authorization.

The public-network r2 model proves the five properties separately. These
fixtures route the same three owner/RPE bodies over private buffered test
channels to fix a fault and observe its real predecessor. Sender/hardware
fault injection is labelled separately from loss/replay by a network attacker.
"""
import json
from pathlib import Path
import re
import generate_models as g
import stage123_complete as v
import stage123_regression as old

ROOT=Path(__file__).resolve().parent
META={}

EVENTS='''
event ControlQuoteReceived(party,party).
event ControlPolicyReceived(party,party).
event ControlConfirmationReceived(party,party).
event ControlInitialHashRequested.
'''

def constraints(policy):
    args=g.parse_term(policy)[1]
    assert len(args)==9
    return ('mkstar',args[3:])

def case_policies(case):
    profile={'conflict-measurement':'ConflictMeasurement','conflict-signer':'ConflictSigner',
             'conflict-product':'ConflictProduct','conflict-tcb':'ConflictTCB',
             'conflict-attester':'ConflictAttester','reject-peer-tcb':'RejectPeerTCB'}.get(case,'Compatible')
    policies=[v.policy(1),v.policy(2),v.policy(3,profile)]
    if case=='authorized-signer-peer-conflict':
        for i in (0,1):
            # Change only honest peers' expectation for E3, never their own
            # signer or the actual P3 authorization signer H(pk(skO3)).
            policies[i]=policies[i].replace('exact(H(pk(skO3)))','exact(sBad)')
    return policies

def table_for_case(policies):
    a,b,c=map(constraints,policies)
    middle=g.merge_star(3,a,b)
    rules={(a,b):middle}
    try:rules[(middle,c)]=g.merge_star(3,middle,c)
    except ValueError:pass
    return 'fun joinstar(polstar,polstar):polstar\nreduc '+'\notherwise '.join(
        f'joinstar({g.render(x)},{g.render(y)})={g.render(z)}' for (x,y),z in rules.items())+'.\n'

def header(policies):
    text=v.declarations().replace('free net: channel.','free net: channel [private].')
    text=re.sub(r'fun joinstar\(polstar, polstar\): polstar\nreduc .*?\.\n',
                table_for_case(policies),text,count=1,flags=re.S)
    assert 'fun joinstar(polstar,polstar):polstar' in text
    channels=['collabOut','collabIn']
    for i in (1,2,3):channels += [f'initTo{i}',f'initFrom{i}',f'ceIn{i}',f'ceOut{i}']
    return '(* CONTROL FIXTURE: real three-party authorization, private buffered delivery. *)\n'+text+'\nfree '+','.join(channels)+':channel [private].\n'+EVENTS

def owner(i,policy):
    text=v.owner(i).replace(v.policy(i),policy)
    return text.replace('out(net,',f'out(initTo{i},').replace('in(net,',f'in(initFrom{i},')

def attest():
    text=v.normalized(g.ATTEST)
    text=text.replace('pkAK: bitstring) =','pkAK: bitstring, incoming:channel, outgoing:channel) =')
    assert 'incoming:channel' in text
    return text.replace('in(net,','in(incoming,').replace('out(net,','out(outgoing,')

def role(i,case):
    text=v.role(i)
    marker=f'  let q{i} = sign('
    start=text.index(marker)
    init=text[:start].replace('out(net,',f'out(initFrom{i},').replace('in(net,',f'in(initTo{i},')
    body=text[start:]
    if i==3 and case in ('missing-quote','duplicate-quote','policy-hash-mismatch'):
        needle='  out(net,(P3,q3,pk3,H(policyBytes(rho3))));\n'
        assert needle in body
        body=body.replace(needle,'')
    if i==2 and case=='duplicate-quote':
        needle='  out(net,(P2,q2,pk2,H(policyBytes(rho2))));\n'
        body=body.replace(needle,needle+'  out(net,(P3,q2,pk2,H(policyBytes(rho2))));\n')
    if i==3 and case in ('bad-rpe-code','bad-rpe-tcb'):
        body=body.replace('rpeQuote(mRPE,Good,',
                          'rpeQuote(mBad,Good,' if case=='bad-rpe-code' else 'rpeQuote(mRPE,Revoked,',1)
    if i==3 and case in ('missing-policy','duplicate-policy'):
        needle='  out(net,(P3,P1,sign(policyMsg(pk1,rho3),sk3)));\n'
        assert needle in body
        body=body.replace(needle,'')
    if i==2 and case=='duplicate-policy':
        needle='  out(net,(P2,P1,sign(policyMsg(pk1,rho2),sk2)));\n'
        body=body.replace(needle,needle+'  out(net,(P3,P1,sign(policyMsg(pk1,rho2),sk2)));\n')
    if i==3 and case in ('missing-confirmation','duplicate-confirmation'):
        needle='  out(net,(P3,P1,sign(confirmMsg(pk1,H(starBytes(pistar))),sk3)));\n'
        assert needle in body
        body=body.replace(needle,'')
    if i==2 and case=='duplicate-confirmation':
        needle='  out(net,(P2,P1,sign(confirmMsg(pk1,H(starBytes(pistar))),sk2)));\n'
        body=body.replace(needle,needle+'  out(net,(P3,P1,sign(confirmMsg(pk1,H(starBytes(pistar))),sk2)));\n')
    if i==3 and case=='confirmation-mismatch':
        body=body.replace('sign(confirmMsg(pk1,H(starBytes(pistar))),sk3)','sign(confirmMsg(pk1,badHash),sk3)')
    # Observation events do not alter guards or message payloads.
    if i==1:
        for kind,needle,event in [
            ('quote','  in(net,(=P3,q3: bitstring,pk3: bitstring,hb3: bitstring));','ControlQuoteReceived'),
            ('policy','  in(net,(=P3,=P1,msg3: bitstring));','ControlPolicyReceived'),
            ('confirmation','  in(net,(=P3,=P1,confirmation3: bitstring));','ControlConfirmationReceived')]:
            assert needle in body,(kind,case)
            body=body.replace(needle,needle+f'\n  event {event}(P1,P3);')
    target=2 if case=='wrong-attester' and i==1 else i
    original=f'attest(P{i},E{i},sk{i},pistar,starEntry{i}(pistar),pkAKE)'
    replacement=f'attest(P{i},E{target},sk{i},pistar,starEntry{target}(pistar),pkAKE,ceIn{i},ceOut{i})'
    assert original in body
    body=body.replace(original,replacement)
    return init+body.replace('out(net,','out(collabOut,').replace('in(net,','in(collabIn,')

def instance(i,case):
    target=2 if case=='wrong-attester' and i==1 else i
    actual=f'Identity(mE{target},H(pk(skO{target})),prodA,V2)'
    status='Good';signing='akTEE';key='pk(skE)';nonce='challenge'
    if i==1:
        actual={
          'bad-measurement':'Identity(mBad,H(pk(skO1)),prodA,V2)',
          'bad-signer':'Identity(mE1,sBad,prodA,V2)',
          'bad-product':'Identity(mE1,H(pk(skO1)),prodB,V2)',
          'bad-svn':'Identity(mE1,H(pk(skO1)),prodA,V0)',
        }.get(case,actual)
        status={'bad-tcb':'Outdated','revoked-tcb':'Revoked','invalid-tcb':'Invalid'}.get(case,status)
        if case=='invalid-signature':signing='akADV'
        if case=='wrong-challenge':nonce='stale'
        if case=='wrong-instance-key':key='pk(other)'
    return f'''
let inst{i}(akTEE:skey,akADV:skey)=
  new skE:skey;
  new other:skey;
  new stale:bitstring;
  out(ceIn{i},pk(skE));
  in(ceOut{i},challenge:bitstring);
  event QuoteProduced({key},{nonce},{actual},{status});
  out(ceIn{i},sign(teeQuote({actual},{status},H(({key},{nonce}))),{signing})).
'''

def query_all_auth(extra):
    variables=[];facts=[]
    for i in (1,2,3):
        variables += [f'k{i}:bitstring',f'r{i}:policy',f'o{i}:bitstring',f's{i}:bitstring']
        facts += [f'event(AuthorizationAccepted(P{i},k{i},r{i},o{i},s{i}))']
    variables += ['h:bitstring','r:policy','x:polstar','ke:bitstring','n:bitstring','id:identity','t:tcbstatus']
    return 'query '+','.join(variables)+';\n  '+' && '.join(facts+[extra])+'.\n'

def queries(case):
    if case=='normal':
        return v.model('reachability')[v.model('reachability').index('query '):].split('(* Stage 3: shared verifier,')[0],[True]
    if case in ('missing-quote','duplicate-quote','bad-rpe-code','bad-rpe-tcb'):
        before='event(EvidenceChecked(P1,P2,k2,h))'
        text=query_all_auth(before)+'query event(QuotesComplete(P1)).\n'
        expected=[True,False]
        if case!='missing-quote':text+='query event(ControlQuoteReceived(P1,P3)).\n';expected.append(True)
        return text,expected
    if case in ('missing-policy','duplicate-policy','policy-hash-mismatch'):
        before='event(QuotesComplete(P1)) && event(PolicyAccepted(P1,P2,r))'
        text=query_all_auth(before)+'query event(PoliciesComplete(P1)).\n';expected=[True,False]
        if case=='duplicate-policy':text+='query event(ControlPolicyReceived(P1,P3)).\n';expected.append(True)
        if case=='policy-hash-mismatch':
            text+='query r:policy; event(PolicyAuthenticated(P1,P3,r)).\nquery event(ControlInitialHashRequested).\n'
            expected += [True,True]
        return text,expected
    if case in ('missing-confirmation','duplicate-confirmation','confirmation-mismatch'):
        text=query_all_auth('event(FullJoin(P1,x)) && event(ConfirmationAccepted(P1,P2,H(starBytes(x))))')
        text+='query x:polstar; event(Confirm(P1,x)).\n';expected=[True,False]
        if case=='duplicate-confirmation':text+='query event(ControlConfirmationReceived(P1,P3)).\n';expected.append(True)
        if case=='confirmation-mismatch':text+='query event(ConfirmationAuthenticated(P1,P3,badHash)).\n';expected.append(True)
        return text,expected
    if case.startswith('conflict-') or case=='authorized-signer-peer-conflict':
        text=query_all_auth('event(PoliciesComplete(P1))')+'query x:polstar; event(FullJoin(P1,x)).\n'
        return text,[True,False]
    if case=='reject-peer-tcb':
        return query_all_auth('event(PolicyDeclared(P3,r))')+'query event(QuotesComplete(P3)).\n',[True,False]
    entity='E2' if case=='wrong-attester' else 'E1'
    text=query_all_auth('event(Confirm(P1,x))')
    text+=f'query kr:bitstring,ke:bitstring,n:bitstring,id:identity,t:tcbstatus,x:polstar,b:bitstring; event(CertIssued(P1,{entity},kr,ke,n,id,t,x,b)).\n'
    expected=[True,False]
    if case=='invalid-signature':
        text+=f'query ke:bitstring,n:bitstring; event(QuoteReceived(P1,{entity},ke,n)).\n'
        text+=f'query ke:bitstring,n:bitstring,id:identity,t:tcbstatus; event(QuoteSignatureChecked(P1,{entity},ke,n,id,t)).\n'
        expected += [True,False]
    elif case in ('wrong-challenge','wrong-instance-key'):
        text+=f'query ke:bitstring,n:bitstring,id:identity,t:tcbstatus; event(QuoteSignatureChecked(P1,{entity},ke,n,id,t)).\n'
        text+=f'query ke:bitstring,n:bitstring,id:identity,t:tcbstatus; event(QuoteVerified(P1,{entity},ke,n,id,t)).\n'
        expected += [True,False]
    else:
        text+=f'query ke:bitstring,n:bitstring,id:identity,t:tcbstatus; event(QuoteVerified(P1,{entity},ke,n,id,t)).\n'
        expected.append(True)
    return text,expected

def control_model(case):
    policies=case_policies(case)
    text=header(policies)
    query,expected=queries(case)
    text+=query+attest()+''.join(owner(i,policies[i-1]) for i in (1,2,3))
    text+=''.join(role(i,case) for i in (1,2,3))+''.join(instance(i,case) for i in (1,2,3))
    # Buffered private transport reproduces asynchronous public delivery. Only
    # Evidence is broadcast; policy/confirmation already include recipient tags.
    text+='''
let transport()=
  !in(collabOut,m:bitstring);
    let (a:party,q:bitstring,k:bitstring,h:bitstring)=m in
      (out(collabIn,m) | out(collabIn,m))
    else out(collabIn,m).
'''
    if case=='policy-hash-mismatch':
        weak=v.policy(3,'Weak')
        text+=f'''
(* Normal protected initial Quote service creates the alternate commitment;
   no hardware signature or protected RPE policy signature is forged. *)
let alternateQuote()=
  in(initFrom3,(=P3,k:bitstring));
  event ControlInitialHashRequested;
  out(initTo3,(P3,H(policyBytes({weak}))));
  in(initFrom3,(=P3,=k,q:bitstring));
  out(collabOut,(P3,q,k,H(policyBytes({weak})))).
'''
    text+='process\n  new akRPE:skey;\n  new akTEE:skey;\n  new akADV:skey;\n'
    text+='  event HonestOwner(pk(skO1));\n  event HonestOwner(pk(skO2));\n  (transport() |\n'
    actors=[]
    for i in (1,2,3):
        actors += [f'owner{i}(pk(akRPE))',f'rpe{i}(akRPE,pk(akRPE),pk(akTEE))',f'inst{i}(akTEE,akADV)']
        if i==3 and case=='policy-hash-mismatch':actors.append('alternateQuote()')
        else:actors.append(f'(in(initFrom{i},(=P{i},k:bitstring));0)')
        actors.append(f'(in(ceOut{i},(a:bitstring,b:bitstring,c:bitstring,d:bitstring));0)')
    text+='   '+' |\n   '.join(actors)+')\n'
    return text,expected,policies

def main():
    cases=['normal','authorized-signer-peer-conflict','missing-quote','duplicate-quote',
           'bad-rpe-code','bad-rpe-tcb','missing-policy','duplicate-policy','policy-hash-mismatch',
           'missing-confirmation','duplicate-confirmation','confirmation-mismatch',
           'conflict-measurement','conflict-signer','conflict-product','conflict-tcb','conflict-attester','reject-peer-tcb',
           'bad-measurement','bad-signer','bad-product','bad-svn','bad-tcb','revoked-tcb','invalid-tcb',
           'wrong-attester','wrong-challenge','wrong-instance-key','invalid-signature']
    jobs=[];metadata={}
    for case in cases:
        name='n3-stage123r2-control-'+case
        source,expected,policies=control_model(case)
        path=ROOT/'scenarios'/(name+'.pv');path.write_text(source)
        nature='controlled-network-delivery'
        if case in ('confirmation-mismatch','bad-rpe-code','bad-rpe-tcb'):
            nature='protected-sender-or-hardware-fault-injection'
        elif case.startswith('bad-') or case in ('revoked-tcb','invalid-tcb','wrong-challenge','wrong-instance-key','invalid-signature'):
            nature='controlled-instance-quote-input'
        elif case=='wrong-attester':nature='receiver-asked-to-attest-other-designated-instance'
        elif case=='authorized-signer-peer-conflict':nature='explicit-control-configuration-different-peer-signer-expectation'
        metadata[name]={'case':case,'expected_reachability':expected,'nature':nature,
                        'actual_stage1_all_three':True,'private_buffered_fixture':True,'policies':policies,
                        'source':str(path.relative_to(ROOT))}
        jobs.append(f'{name}|{path.relative_to(ROOT)}|controlled-full-Stage123|3')
    # Refresh the original single-party guard fixtures against the r2 code.
    old_expected=json.loads((ROOT/'reports/stage123-regression-expectations.json').read_text())['expected_reachability']
    locals=[]
    for name,expected in old_expected.items():
        if name.startswith('n3-stage123-auth-'):
            case=name.removeprefix('n3-stage123-auth-');source=v.self_tee(old.auth_fixture(case))
        elif name.startswith('n3-stage123-owner-'):
            case=name.removeprefix('n3-stage123-owner-');source=v.self_tee(old.owner_fixture(case))
        else:case='join';source=v.self_tee(old.join_fixture())
        newname=name.replace('stage123-','stage123r2-')
        path=ROOT/('models' if case=='join' else 'scenarios')/(newname+'.pv');path.write_text(source)
        locals.append(f'{newname}|{path.relative_to(ROOT)}|local-r2-Stage1-or-algebra|3')
        metadata[newname]={'case':case,'expected_reachability':expected,'nature':'local-guard-or-algebra',
                           'actual_stage1_all_three':False,'private_buffered_fixture':True,'source':str(path.relative_to(ROOT))}
    source=v.self_tee(old.auth_fixture('normal'))
    start=source.index('let fixture(')
    source=source[:start]+source[start:].replace('pol(P3, E3,','pol(P3, E2,')
    name='n3-stage123r2-auth-wrong-self-tee'
    path=ROOT/'scenarios'/(name+'.pv');path.write_text(source)
    metadata[name]={'case':'wrong-self-tee','expected_reachability':[True,True,True,True,False,False],
                    'nature':'local-extra-SelfTEE-control','actual_stage1_all_three':False,
                    'private_buffered_fixture':True,'source':str(path.relative_to(ROOT))}
    locals.append(f'{name}|{path.relative_to(ROOT)}|local-r2-Stage1-or-algebra|3')
    (ROOT/'jobs-stage123r2-controls.txt').write_text('\n'.join(jobs)+'\n')
    (ROOT/'jobs-stage123r2-local.txt').write_text('\n'.join(locals)+'\n')
    pilot=[jobs[cases.index(c)] for c in ('normal','duplicate-quote','policy-hash-mismatch','authorized-signer-peer-conflict')]
    (ROOT/'jobs-stage123r2-control-pilot.txt').write_text('\n'.join(pilot)+'\n')
    (ROOT/'reports/stage123r2-control-expectations.json').write_text(json.dumps(metadata,indent=2,ensure_ascii=False)+'\n')
    print(f'Generated {len(jobs)} three-party authorized control scenarios and {len(locals)} local/alias checks.')

if __name__=='__main__':main()
