#!/usr/bin/env python3
"""Generate auditable standalone PV models; no external Python dependencies.

The RPE roles, four primary event names/queries, and N=2/N=3 split are
retained from the original models. Generated files are checked in as artifacts.
"""
from pathlib import Path
import json
import re
import argparse

ROOT = Path(__file__).resolve().parent
MODELS = ROOT / 'models'
SCENARIOS = ROOT / 'scenarios'
MODELS.mkdir(exist_ok=True)
SCENARIOS.mkdir(exist_ok=True)
ALGEBRA = (MODELS / 'algebra.pvl').read_text()
PROFILES = ['Compatible', 'Weak', 'StrongerSVN', 'ConflictMeasurement',
            'ConflictSigner', 'ConflictProduct', 'ConflictTCB', 'ConflictAttester',
            'RejectPeerTCB', 'NoAssignments', 'PermissiveRpeTCB']
EXTENDED_PROFILES = PROFILES + ['StrongerSVNE2']

def req(j, weak=False, **kw):
    fields = [f'exact(mE{j})', f'exact(s{j})', 'exact(prodA)', 'V1', 'OnlyGood', f'Assign(P{j})']
    if weak:
        fields = ['Any', 'Any', 'Any', 'V0', 'Both', 'NoAtt']
    for key, val in kw.items():
        fields[{'m':0, 's':1, 'p':2, 'v':3, 't':4, 'a':5}[key]] = val
    return 'Req(' + ', '.join(fields) + ')'

def policy(n, owner, profile='Compatible', scenario=''):
    rt = ['OnlyGood'] * n
    entries = [req(j) for j in range(1, n+1)]
    if profile == 'Weak':
        rt = ['Both'] * n
        entries = [req(j, weak=True, **({'s':f'exact(s{owner})', 'a':f'Assign(P{owner})'} if j == owner else {})) for j in range(1,n+1)]
    elif profile == 'StrongerSVN':
        entries[0] = req(1, v='V2')
    elif profile == 'StrongerSVNE2':
        entries[1] = req(2, v='V2')
    elif profile == 'ConflictMeasurement': entries[0] = req(1, m='exact(mBad)')
    elif profile == 'ConflictSigner': entries[0] = req(1, s='exact(sBad)')
    elif profile == 'ConflictProduct': entries[0] = req(1, p='exact(prodB)')
    elif profile == 'ConflictTCB': entries[0] = req(1, t='OnlyOutdated')
    elif profile == 'ConflictAttester': entries[0] = req(1, a=f'Assign(P{n})')
    elif profile == 'RejectPeerTCB': rt[0] = 'OnlyOutdated'
    elif profile == 'NoAssignments': entries = [req(j, a=f'Assign(P{owner})' if j==owner else 'NoAtt') for j in range(1,n+1)]
    elif profile == 'PermissiveRpeTCB': rt = ['Both'] * n
    return 'pol(' + ', '.join([f'P{owner}', f'Members{n}'] + rt + entries) + ')'

def parse_term(source):
    tokens = iter(re.findall(r'\w+|[(),]', source))
    tok = next(tokens, None)
    def consume():
        nonlocal tok
        name = tok
        tok = next(tokens, None)
        if tok != '(':
            return name
        tok = next(tokens, None)
        args = [consume()]
        while tok == ',':
            tok = next(tokens, None)
            args.append(consume())
        assert tok == ')'
        tok = next(tokens, None)
        return (name, tuple(args))
    result = consume()
    assert tok is None
    return result

def render(t):
    return t if isinstance(t,str) else t[0]+'('+','.join(map(render,t[1]))+')'

def constraints_term(n, source):
    parsed = parse_term(source)
    assert parsed[0]=='pol' and len(parsed[1])==2+2*n
    return ('mkstar', parsed[1][2:])

def intersect_tcb(a,b):
    sets = {'Both':frozenset(['Good','Outdated']), 'OnlyGood':frozenset(['Good']), 'OnlyOutdated':frozenset(['Outdated'])}
    intersection = sets[a] & sets[b]
    if not intersection: raise ValueError('incompatible TCB requirements')
    return next(k for k,v in sets.items() if v==intersection)

def merge_entry(a,b):
    assert a[0]==b[0]=='Req'
    out=[]
    for k,(x,y) in enumerate(zip(a[1],b[1])):
        if k in (0,1,2,5):
            bottom = 'NoAtt' if k==5 else 'Any'
            if x==bottom: out.append(y)
            elif y==bottom or x==y: out.append(x)
            else: raise ValueError('conflicting exact requirement')
        elif k==3: out.append(max((x,y),key=['V0','V1','V2'].index))
        else: out.append(intersect_tcb(x,y))
    return ('Req',tuple(out))

def merge_star(n,a,b):
    return ('mkstar',tuple(intersect_tcb(x,y) if k<n else merge_entry(x,y)
                          for k,(x,y) in enumerate(zip(a[1],b[1]))))

def specialized_join(n,scenario,profiles=None):
    # The canonical fold always starts with honest P1; in N3 the next input
    # is honest P2 with the same constraints. The final input is one catalog
    # policy. This table is EXACT on every authenticated input tuple in this
    # finite model. Unreachable tuples are not used to enlarge its conclusions.
    base=constraints_term(n,policy(n,1,scenario=scenario))
    inputs={constraints_term(n,policy(n,n,p,scenario)) for p in (PROFILES if profiles is None else profiles)}
    inputs.add(base)
    rules=[]
    for right in sorted(inputs,key=render):
        try: joined=merge_star(n,base,right)
        except ValueError: continue
        rules.append(f'joinstar({render(base)}, {render(right)}) = {render(joined)}')
    return ('\n(* Exact finite-domain specialization of the componentwise join.\n'
            ' * Conflicting tuples have no rule. No input history enters mkstar.\n'
            ' * Generic scalar/entry semantics are checked in join-regression.pv. *)\n'
            'fun joinstar(polstar, polstar): polstar\nreduc '+
            '\notherwise '.join(rules)+'.\n')

def schema(n, scenario, profiles=None):
    profiles=PROFILES if profiles is None else profiles
    pvars = [f't{i}: tcbreq' for i in range(1,n+1)] + [f'e{i}: entry' for i in range(1,n+1)]
    names = [x.split(':')[0] for x in pvars]
    args = ', '.join(names)
    result = f'''
type policy.
type polstar.
type roster.
type profile.
type entity.
type nonce.
type pkey.
type skey.
free net: channel.
free E1, E2, E3: entity.
const Members{n}: roster [data].
free badHash: bitstring.
fun pol(party, roster, {', '.join(['tcbreq']*n+['entry']*n)}): policy [data].
(* mkstar now stores only normalized joined constraints, NOT source policies. *)
fun mkstar({', '.join(['tcbreq']*n+['entry']*n)}): polstar [data].
reduc forall a: party, members: roster, {', '.join(pvars)};
  policySelf(pol(a, members, {args})) = a.
reduc forall a: party, members: roster, {', '.join(pvars)};
  constraints(pol(a, members, {args})) = mkstar({args}).
'''
    for j in range(1,n+1):
        result += f'''reduc forall a: party, members: roster, {', '.join(pvars)};
  rpeTcb{j}(pol(a, members, {args})) = t{j}.
reduc forall {', '.join(pvars)};
  starEntry{j}(mkstar({args})) = e{j}.
'''
    result += specialized_join(n,scenario,profiles)
    for pr in profiles: result += f'const {pr}: profile [data].\n'
    result += '\n(* Explicit finite policy domain for the adversarial owner; see policy-catalog.json. *)\n'
    result += 'fun choosePolicy(profile): policy\n'
    result += '\notherwise '.join(('reduc ' if k==0 else '')+f'choosePolicy({pr}) = {policy(n,n,pr,scenario)}' for k,pr in enumerate(profiles)) + '.\n'
    return result

CRYPTO = '''
(* Perfect signatures/hashes. All communication remains on public net.
 * Receiver-key arguments encode authentication-channel endpoint association,
 * not new SRAS fields, a new round, or a session identifier.
 * Confidentiality/TLS internals are deliberately not proved by this model.
 *)
fun pk(skey): pkey.
fun sign(bitstring, skey): bitstring.
reduc forall m: bitstring, k: skey; getmess(sign(m,k)) = m.
reduc forall m: bitstring, k: skey; checksign(sign(m,k), pk(k)) = m.
fun hpol(policy): bitstring.
fun hbind(pkey, bitstring): bitstring.
fun hstar(polstar): bitstring.
fun hchal(nonce, pkey): bitstring.
fun hcert(pkey, pkey, bitstring): bitstring.
fun rpeQuote(attr, tcbstatus, bitstring): bitstring [data].
fun teeQuote(identity, tcbstatus, bitstring): bitstring [data].
fun policyMsg(pkey, policy): bitstring [data].
fun confirmMsg(pkey, bitstring): bitstring [data].

event PolicyDeclared(party, policy).
(* EvidenceChecked labels a collection slot, not authenticated policy Self. *)
event EvidenceChecked(party, party, pkey, bitstring).
event QuotesComplete(party).
event PolicySent(party, pkey, policy).
event PolicyAuthenticated(party, party, policy).
event PolicyAccepted(party, party, policy).
event PolicyAcceptedKeys(party, party, pkey, pkey, policy).
event PoliciesComplete(party).
event FullJoin(party, polstar).
event ConfirmationSent(party, party, bitstring).
event ConfirmationAuthenticated(party, party, bitstring).
event ConfirmationAccepted(party, party, bitstring).
event Confirm(party, polstar).
event QuoteProduced(pkey, nonce, identity, tcbstatus).
event ChallengeSent(party, pkey, nonce).
event QuoteReceived(party, entity, pkey, nonce).
event QuoteSignatureChecked(party, entity, pkey, nonce, identity, tcbstatus).
event QuoteVerified(party, entity, pkey, nonce, identity, tcbstatus).
event QuoteSatisfied(party, entity, pkey, pkey, nonce, identity, tcbstatus, polstar).
event CertIssued(party, entity, pkey, pkey, nonce, identity, tcbstatus, polstar, bitstring).
'''

PRIMARY = '''
(* Q1 Agreement: same collaboration, distinct completed RPEs. *)
query a: party, b: party, x: polstar, y: polstar;
  event(Confirm(a,x)) && event(Confirm(b,y)) && a <> b ==> x = y.
(* Q2 Authenticity: original correspondence, now after endpoint authentication. *)
query a: party, b: party, r: policy;
  event(PolicyAccepted(a,b,r)) ==> event(PolicyDeclared(b,r)).
(* Q3 Completeness: original query and names retained. *)
query a: party, x: polstar;
  event(Confirm(a,x)) ==> event(FullJoin(a,x)).
'''
ISSUANCE = '''
(* Q4 Issuance: same correspondence with explicit subject/key/challenge/attributes. *)
query a: party, e: entity, kr: pkey, ke: pkey, n: nonce, id: identity, t: tcbstatus, x: polstar, body: bitstring;
  event(CertIssued(a,e,kr,ke,n,id,t,x,body)) ==> event(QuoteSatisfied(a,e,kr,ke,n,id,t,x)).
'''

def auxiliary(n, no_confirm=False, with_stage3=False):
    s = '''
(* A1: actual recipient key, not an untrusted pre-policy slot label. *)
query a: party, b: party, ka: pkey, kb: pkey, r: policy;
  event(PolicyAcceptedKeys(a,b,ka,kb,r)) ==> event(PolicySent(b,ka,r)).
(* A2: the all-Quote gate precedes policy dissemination. *)
query a: party, kb: pkey, r: policy;
  event(PolicySent(a,kb,r)) ==> event(QuotesComplete(a)).
(* A3: local aggregation is after the all-policy collection gate. *)
query a: party, x: polstar;
  event(FullJoin(a,x)) ==> event(PoliciesComplete(a)).
'''
    for i in range(1,n+1):
        peers = [j for j in range(1,n+1) if j != i]
        variables = ', '.join(f'r{j}: policy' for j in peers)
        # RHS-only variables are existential in ProVerif correspondence queries.
        s += f'query x: polstar, {variables};\n  event(FullJoin(P{i},x)) ==> ' + ' && '.join(f'event(PolicyAccepted(P{i},P{j},r{j}))' for j in peers) + '.\n'
    if not no_confirm:
        s += '''
query a: party, b: party, h: bitstring;
  event(ConfirmationAccepted(a,b,h)) ==> event(ConfirmationSent(b,a,h)).
'''
        for i in range(1,n+1):
            s += f'query x: polstar;\n  event(Confirm(P{i},x)) ==> ' + ' && '.join(f'event(ConfirmationAccepted(P{i},P{j},hstar(x)))' for j in range(1,n+1) if j!=i) + '.\n'
    if n == 2 or with_stage3:
        s += '''
(* A4: evidence, request, Stage 2 completion, and certificate payload binding. *)
query a: party, e: entity, kr: pkey, ke: pkey, n: nonce, id: identity, t: tcbstatus, x: polstar, body: bitstring;
  event(CertIssued(a,e,kr,ke,n,id,t,x,body)) ==>
    event(Confirm(a,x)) && event(ChallengeSent(a,ke,n)) && event(QuoteProduced(ke,n,id,t)) && body = hcert(ke,kr,hstar(x)).
'''
    return s

def reachability(n, with_stage3=False):
    # One conjunction demands a common trace, not N separate reachable runs.
    s = '\n(* R1: joint completion; `not ... is false` plus a reconstructed trace means reachable. *)\n'
    s += 'query ' + ', '.join(f'x{i}: polstar' for i in range(1,n+1)) + ';\n  ' + ' && '.join(f'event(Confirm(P{i},x{i}))' for i in range(1,n+1)) + '.\n'
    if n == 2:
        s += '''
(* R2: both completed and both legitimately issued, in a single trace. *)
query x1: polstar, x2: polstar, kr1: pkey, kr2: pkey, ke1: pkey, ke2: pkey,
      n1: nonce, n2: nonce, id1: identity, id2: identity, t1: tcbstatus, t2: tcbstatus, b1: bitstring, b2: bitstring;
  event(Confirm(P1,x1)) && event(Confirm(P2,x2)) &&
  event(CertIssued(P1,E1,kr1,ke1,n1,id1,t1,x1,b1)) &&
  event(CertIssued(P2,E2,kr2,ke2,n2,id2,t2,x2,b2)).
'''
    if n == 3 and with_stage3:
        variables = []
        facts = []
        for i in range(1, n+1):
            variables.extend([f'x{i}: polstar', f'kr{i}: pkey', f'ke{i}: pkey',
                              f'n{i}: nonce', f'id{i}: identity',
                              f't{i}: tcbstatus', f'b{i}: bitstring'])
            facts.extend([f'event(Confirm(P{i},x{i}))',
                          f'event(CertIssued(P{i},E{i},kr{i},ke{i},n{i},id{i},t{i},x{i},b{i}))'])
        s += '\n(* R2: all three complete and issue in ONE execution. *)\n'
        s += 'query ' + ', '.join(variables) + ';\n  ' + ' &&\n  '.join(facts) + '.\n'
    return s

def coordination(n):
    # Optional confirmation diagnostic, not a replacement for Q1--Q4.
    if n==2:
        return '''
(* D1: issuance implies the peer has already completed the same local join.
 * This does NOT assert that the peer has itself received every confirmation. *)
query kr: pkey, ke: pkey, n: nonce, id: identity, t: tcbstatus, x: polstar, body: bitstring;
  event(CertIssued(P1,E1,kr,ke,n,id,t,x,body)) ==> event(FullJoin(P2,x)).
'''
    return '''
(* D1: completion implies both peers have already computed the same result. *)
query x: polstar;
  event(Confirm(P1,x)) ==> event(FullJoin(P2,x)) && event(FullJoin(P3,x)).
'''

ATTEST = '''
(* Stage 3: shared verifier, invoked only after this RPE's Confirm event. *)
let attest(a: party, e: entity, skR: skey, pistar: polstar, c: entry, pkAK: pkey) =
  in(net, pkE: pkey);
  new challenge: nonce;
  event ChallengeSent(a,pkE,challenge);
  out(net, challenge);
  in(net, qe: bitstring);
  event QuoteReceived(a,e,pkE,challenge);
  let teeQuote(actual: identity, status: tcbstatus, binding: bitstring) = checksign(qe,pkAK) in
  event QuoteSignatureChecked(a,e,pkE,challenge,actual,status);
  if binding = hchal(challenge,pkE) then
  event QuoteVerified(a,e,pkE,challenge,actual,status);
  let allowed = checkentry(c,a,actual,status) in
  if allowed = true then
  event QuoteSatisfied(a,e,pk(skR),pkE,challenge,actual,status,pistar);
  let body = hcert(pkE,pk(skR),hstar(pistar)) in
  let certificate = sign(body,skR) in
  event CertIssued(a,e,pk(skR),pkE,challenge,actual,status,pistar,body);
  out(net,(pkE,pk(skR),hstar(pistar),certificate)).
'''

def instance(scenario):
    s = '\n(* Genuine hardware may attest conforming or nonconforming TEE attributes.\n * Every instance generates its own protected key; the attacker never gets it. *)\nlet instance(ak: skey) =\n'
    faults = {
        'bad-measurement': ('Identity(mBad,s1,prodA,V2)','Good'),
        'bad-signer': ('Identity(mE1,sBad,prodA,V2)','Good'),
        'bad-product': ('Identity(mE1,s1,prodB,V2)','Good'),
        'bad-svn': ('Identity(mE1,s1,prodA,V0)','Good'),
        'bad-tcb': ('Identity(mE1,s1,prodA,V2)','Outdated'),
        'revoked-tcb': ('Identity(mE1,s1,prodA,V2)','Revoked'),
        'invalid-tcb': ('Identity(mE1,s1,prodA,V2)','Invalid'),
    }
    if scenario in faults:
        actual, ts = faults[scenario]
        s += f'  let actual = {actual} in\n  let status = {ts} in\n'
    else:
        s += '  in(net,(actual: identity,status: tcbstatus));\n'
    s += '  new skE: skey;\n  out(net,pk(skE));\n  in(net,challenge: nonce);\n'
    if scenario == 'wrong-challenge':
        s += '  new stale: nonce;\n  event QuoteProduced(pk(skE),stale,actual,status);\n  out(net,sign(teeQuote(actual,status,hchal(stale,pk(skE))),ak)).\n'
    else:
        s += '  event QuoteProduced(pk(skE),challenge,actual,status);\n  out(net,sign(teeQuote(actual,status,hchal(challenge,pk(skE))),ak)).\n'
    return s

def role(n, i, scenario='', no_confirm=False, with_stage3=False):
    peers = [j for j in range(1,n+1) if j != i]
    s = f'\n(* RPE_{i}: required peers are the fixed Members{n} configuration minus self. *)\n'
    s += f'let rpe{i}(akR: skey, pkAKR: pkey, pkAKE: pkey) =\n'
    if i==n:
        fixed = {'policy-hash-mismatch':'Compatible', 'conflict-measurement':'ConflictMeasurement','conflict-signer':'ConflictSigner',
                 'conflict-product':'ConflictProduct','conflict-tcb':'ConflictTCB',
                 'conflict-attester':'ConflictAttester','reject-peer-tcb':'RejectPeerTCB'}.get(scenario)
        if fixed: s += f'  let selectedProfile = {fixed} in\n'
        else: s += '  in(net,selectedProfile: profile) [precise];\n'
        s += f'  let rho{i} = choosePolicy(selectedProfile) in\n'
    else: s += f'  let rho{i} = {policy(n,i,scenario=scenario)} in\n'
    s += f'''  (* Stage 1 is an initialization premise: Self=P{i}, authorized policy/key,
   * concrete own signer s{i}; owner signature verification is not proved here. *)
  new sk{i}: skey;
  let pk{i} = pk(sk{i}) in
  event PolicyDeclared(P{i},rho{i});
'''
    rpetcb = 'Revoked' if scenario=='bad-rpe-tcb' and i==n else 'Good'
    rpem = 'mBad' if scenario=='bad-rpe-code' and i==n else 'mRPE'
    s += f'  let q{i} = sign(rpeQuote({rpem},{rpetcb},hbind(pk{i},hpol(rho{i}))),akR) in\n'
    if not (scenario=='missing-quote' and i==n):
        s += f'  out(net,(P{i},q{i},pk{i},hpol(rho{i})));\n'
    seen = [i]
    for j in peers:
        s += f'''  in(net,(=P{j},q{j}: bitstring,pk{j}: pkey,hb{j}: bitstring));
  let rpeQuote(=mRPE,ts{j}: tcbstatus,d{j}: bitstring) = checksign(q{j},pkAKR) in
  if d{j} = hbind(pk{j},hb{j}) then
  let tcbok{j} = matchtcb(rpeTcb{j}(rho{i}),ts{j}) in
  if tcbok{j} = true then
'''
        s += '  if ' + ' && '.join(f'pk{j} <> pk{k}' for k in seen) + ' then\n'
        s += f'  event EvidenceChecked(P{i},P{j},pk{j},hb{j});\n'
        seen.append(j)
    s += f'  event QuotesComplete(P{i});\n'
    for j in peers:
        if i==n and scenario in ('missing-policy','duplicate-policy'): continue
        payload = policy(n,n,'Weak') if i==n and scenario=='policy-hash-mismatch' else f'rho{i}'
        s += f'  event PolicySent(P{i},pk{j},{payload});\n'
        s += f'  out(net,(P{i},P{j},sign(policyMsg(pk{j},{payload}),sk{i})));\n'
        if scenario=='duplicate-policy' and i==2 and j==1:
            s += f'  out(net,(P{n},P1,sign(policyMsg(pk1,rho2),sk2))); (* attacker-relabelled duplicate *)\n'
    for j in peers:
        s += f'''  in(net,(=P{j},=P{i},msg{j}: bitstring));
  let policyMsg(=pk{i},rho{j}: policy) = checksign(msg{j},pk{j}) in
  event PolicyAuthenticated(P{i},P{j},rho{j});
  if hpol(rho{j}) = hb{j} then
  if policySelf(rho{j}) = P{j} then
  event PolicyAccepted(P{i},P{j},rho{j});
  event PolicyAcceptedKeys(P{i},P{j},pk{i},pk{j},rho{j});
'''
    s += f'  event PoliciesComplete(P{i});\n'
    s += '  let joined12 = joinstar(constraints(rho1),constraints(rho2)) in\n'
    s += '  let pistar = ' + ('joined12' if n==2 else 'joinstar(joined12,constraints(rho3))') + ' in\n'
    s += f'  event FullJoin(P{i},pistar);\n'
    if not no_confirm:
        for j in peers:
            if scenario=='missing-confirmation' and i==n and j==1: continue
            h = 'badHash' if scenario=='confirmation-mismatch' and i==n and j==1 else 'hstar(pistar)'
            s += f'  event ConfirmationSent(P{i},P{j},{h});\n'
            s += f'  out(net,(P{i},P{j},sign(confirmMsg(pk{j},{h}),sk{i})));\n'
        for j in peers:
            s += f'''  in(net,(=P{j},=P{i},confirmation{j}: bitstring));
  let confirmMsg(=pk{i},hs{j}: bitstring) = checksign(confirmation{j},pk{j}) in
  event ConfirmationAuthenticated(P{i},P{j},hs{j});
  if hs{j} = hstar(pistar) then
  event ConfirmationAccepted(P{i},P{j},hs{j});
'''
    s += f'  event Confirm(P{i},pistar)'
    target = 2 if scenario=='wrong-attester' and i==1 else i
    s += f';\n  attest(P{i},E{target},sk{i},pistar,starEntry{target}(pistar),pkAKE).\n' if n==2 or with_stage3 else '.\n'
    return s

def scenario_queries(n, scenario):
    # A reachable preceding gate guards against a trivial dead model.
    if scenario in ('missing-quote','bad-rpe-tcb','bad-rpe-code'):
        return 'query k: pkey, h: bitstring; event(EvidenceChecked(P1,P2,k,h)).\nquery event(QuotesComplete(P1)).\n'
    if scenario in ('missing-policy','duplicate-policy','policy-hash-mismatch'):
        s = 'query event(QuotesComplete(P1)).\nquery event(PoliciesComplete(P1)).\n'
        if scenario=='policy-hash-mismatch': s += f'query r: policy; event(PolicyAuthenticated(P1,P{n},r)).\n'
        return s
    if scenario in ('missing-confirmation','confirmation-mismatch'):
        s = 'query x: polstar; event(FullJoin(P1,x)).\nquery x: polstar; event(Confirm(P1,x)).\n'
        if scenario=='confirmation-mismatch': s += f'query event(ConfirmationAuthenticated(P1,P{n},badHash)).\n'
        return s
    if scenario.startswith('conflict-'):
        return 'query event(PoliciesComplete(P1)).\nquery x: polstar; event(FullJoin(P1,x)).\n'
    if scenario=='reject-peer-tcb':
        return f'query r: policy; event(PolicyDeclared(P{n},r)).\nquery event(QuotesComplete(P{n})).\n'
    e = 'E2' if scenario=='wrong-attester' else 'E1'
    s = f'''query x: polstar; event(Confirm(P1,x)).
query kr: pkey, ke: pkey, n: nonce, id: identity, t: tcbstatus, x: polstar, body: bitstring;
  event(CertIssued(P1,{e},kr,ke,n,id,t,x,body)).
'''
    if scenario=='invalid-signature':
        s += f'query ke: pkey, n: nonce; event(QuoteReceived(P1,{e},ke,n)).\n'
        s += f'query ke: pkey, n: nonce, id: identity, t: tcbstatus; event(QuoteSignatureChecked(P1,{e},ke,n,id,t)).\n'
    elif scenario=='wrong-challenge':
        s += f'query ke: pkey, n: nonce, id: identity, t: tcbstatus; event(QuoteSignatureChecked(P1,{e},ke,n,id,t)).\n'
        s += f'query ke: pkey, n: nonce, id: identity, t: tcbstatus; event(QuoteVerified(P1,{e},ke,n,id,t)).\n'
    elif scenario=='wrong-attester':
        s += 'query ke: pkey, n: nonce; event(QuoteVerified(P1,E2,ke,n,Identity(mE2,s2,prodA,V2),Good)).\n'
    else:
        s += f'query ke: pkey, n: nonce, id: identity, t: tcbstatus; event(QuoteVerified(P1,{e},ke,n,id,t)).\n'
    return s

def model(n, kind='primary', scenario='', no_confirm=False, with_stage3=False, profiles=None):
    head = f'''(* SRAS revision 20261027; N={n}; kind={kind}; scenario={scenario or 'none'}.
 * SINGLE static initialization with exactly N protected RPE roles.
 * The adversary chooses the last owner's policy from {len(PROFILES if profiles is None else profiles)} documented profiles.
 * All network sends/receives are public and adversary-controlled.
 * This file is generated by generate_models.py; original models remain intact.
 *)\n'''
    text = head + ALGEBRA + schema(n,scenario,profiles) + CRYPTO
    if with_stage3:
        text += '\n(* 20261028 extension of commit 3766338: Stage 3 runs after Confirm at every RPE. *)\n'
    if kind=='primary': text += PRIMARY + (ISSUANCE if n==2 or with_stage3 else '')
    elif kind=='auxiliary': text += auxiliary(n,no_confirm,with_stage3)
    elif kind=='reachability': text += reachability(n,with_stage3)
    elif kind=='coordination': text += coordination(n)
    else: text += scenario_queries(n,scenario)
    if n==2 or with_stage3: text += ATTEST + instance(scenario)
    text += ''.join(role(n,i,scenario,no_confirm,with_stage3) for i in range(1,n+1))
    text += '''
process
  new akRPE: skey;
  new akTEE: skey;
  new akADV: skey;
  out(net,(pk(akRPE),pk(akTEE),pk(akADV),akADV));
  ('''
    text += ' |\n   '.join(f'rpe{i}(akRPE,pk(akRPE),pk(akTEE))' for i in range(1,n+1))
    if n==2 or with_stage3: text += ' |\n   !instance(' + ('akADV' if scenario=='invalid-signature' else 'akTEE') + ')'
    text += ')\n'
    return text

def main():
    catalog = {}
    for n in [2,3]:
        catalog[f'N{n}'] = {pr:policy(n,n,pr) for pr in PROFILES}
        for kind in ['primary','auxiliary','reachability','coordination']:
            (MODELS/f'sras-n{n}-{kind}.pv').write_text(model(n,kind))
        for kind in ['primary','reachability','coordination']:
            (MODELS/f'sras-n{n}-no-confirm-{kind}.pv').write_text(model(n,kind,no_confirm=True))
    (MODELS/'policy-catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')
    stage2 = ['missing-quote','bad-rpe-code','bad-rpe-tcb','missing-policy','duplicate-policy',
              'policy-hash-mismatch','missing-confirmation','confirmation-mismatch',
              'conflict-measurement','conflict-signer','conflict-product','conflict-tcb','conflict-attester','reject-peer-tcb']
    stage3 = ['bad-measurement','bad-signer','bad-product','bad-svn','bad-tcb','revoked-tcb','invalid-tcb','wrong-attester','wrong-challenge','invalid-signature']
    for scenario in stage2:
        (SCENARIOS/f'n3-{scenario}.pv').write_text(model(3,'regression',scenario))
    for scenario in stage3:
        (SCENARIOS/f'n2-{scenario}.pv').write_text(model(2,'regression',scenario))
    jobs=[]
    for f in sorted(MODELS.glob('*.pv')):
        cat='algebra' if f.name.startswith('join-') else ('no-confirm' if 'no-confirm' in f.name else f.stem.rsplit('-',1)[1])
        n='2' if 'n2-' in f.name else '3' if 'n3-' in f.name else '0'
        jobs.append('|'.join((f.stem,str(f.relative_to(ROOT)),cat,n)))
    for f in sorted(SCENARIOS.glob('*.pv')):
        jobs.append('|'.join((f.stem,str(f.relative_to(ROOT)),'regression',f.name[1])))
    (ROOT/'jobs.txt').write_text('\n'.join(jobs)+'\n')
    query_dir=ROOT/'queries'
    query_dir.mkdir(exist_ok=True)
    timed_jobs=[]
    for n in (2,3):
        src=(MODELS/f'sras-n{n}-primary.pv').read_text()
        blocks=list(re.finditer(r'^query\b.*?\.',src,re.M|re.S))
        for i,_ in enumerate(blocks,1):
            timed=src
            for j,m in reversed(list(enumerate(blocks,1))):
                if j!=i:
                    timed=timed[:m.start()]+f'(* Q{j} omitted only for isolated timing. *)'+timed[m.end():]
            (query_dir/f'n{n}-Q{i}.pv').write_text(timed)
            timed_jobs.append(f'n{n}-Q{i}|queries/n{n}-Q{i}.pv|primary-single|{n}')
    (ROOT/'jobs-primary-single.txt').write_text('\n'.join(timed_jobs)+'\n')
    print('Generated primary, auxiliary, reachability, single-change no-confirm, and regression models.')

def stage23_main(profiles=None):
    """Extend the requested baseline in place; preserve every historical model/log.

    No change to the policy catalog, specialized join, Stage 2, or ATTEST body.
    New evidence uses distinct filenames in the existing artifact directories.
    """
    tag='stage23' if profiles is None else 'stage23p12'
    jobs=[]
    for kind in ('primary','auxiliary','reachability'):
        path=MODELS/f'sras-n3-{tag}-{kind}.pv'
        path.write_text(model(3,kind,with_stage3=True,profiles=profiles))
        jobs.append(f'{path.stem}|{path.relative_to(ROOT)}|{kind}|3')
    src=(MODELS/f'sras-n3-{tag}-primary.pv').read_text()
    blocks=list(re.finditer(r'^query\b.*?\.',src,re.M|re.S))
    timed_jobs=[]
    for i in range(1,len(blocks)+1):
        timed=src
        for j,m in reversed(list(enumerate(blocks,1))):
            if j!=i:
                timed=timed[:m.start()]+f'(* Q{j} omitted only for isolated timing. *)'+timed[m.end():]
        path=ROOT/'queries'/f'n3-{tag}-Q{i}.pv'
        path.write_text(timed)
        timed_jobs.append(f'{path.stem}|{path.relative_to(ROOT)}|primary-single|3')
    stage3=['bad-measurement','bad-signer','bad-product','bad-svn','bad-tcb',
            'revoked-tcb','invalid-tcb','wrong-attester','wrong-challenge','invalid-signature']
    regressions=[]
    for scenario in stage3:
        path=SCENARIOS/f'n3-{tag}-{scenario}.pv'
        path.write_text(model(3,'regression',scenario,with_stage3=True,profiles=profiles))
        regressions.append(f'{path.stem}|{path.relative_to(ROOT)}|regression-stage3|3')
    for name,lines in [(f'jobs-{tag}.txt',jobs),(f'jobs-{tag}-single.txt',timed_jobs),
                       (f'jobs-{tag}-regression.txt',regressions)]:
        (ROOT/name).write_text('\n'.join(lines)+'\n')
    # The user's original N3 entry point now runs all four requested properties.
    (ROOT.parent/'sras-n3.pv').write_text(src)
    if profiles is not None:
        (MODELS/'policy-catalog-p12.json').write_text(json.dumps({pr:policy(3,3,pr) for pr in profiles},indent=2)+'\n')
    print(f'Generated N3 {tag}; baseline models and logs preserved.')


STAGE1_EVENTS = '''
(* HonestOwner specifies the uncompromised keys covered by Authorization. *)
event HonestOwner(pkey).
event OwnerChallenge(pkey,nonce).
event OwnerAttested(pkey,pkey,policy,nonce).
event OwnerSigned(pkey,pkey,bitstring).
event AuthorizationReceived(party,pkey,policy,pkey).
event AuthorizationSignatureChecked(party,pkey,policy,pkey).
event AuthorizationSelfChecked(party,pkey,policy,pkey).
event AuthorizationAccepted(party,pkey,policy,pkey,attr).
event AuthorizedPolicyDeclared(party,pkey,policy).
'''

AUTHORIZATION = '''
(* The policy's claimed self signer, not an assumed owner identity, selects
   the honest authority. A malicious owner signing with its own key is allowed. *)
query a:party,k:pkey,r:policy,supplied:pkey,honest:pkey;
  event(AuthorizationAccepted(a,k,r,supplied,H(honest))) && event(HonestOwner(honest))
  ==> event(OwnerSigned(honest,k,hpol(r))).
'''

def stage1_owner(i):
    return f'''
(* Owner {i} learns the RPE key only through the public Quote exchange. *)
let owner{i}(pkAKR:pkey) =
  let rho={policy(3,i)} in
  new n:nonce;
  event OwnerChallenge(pk(skO{i}),n);
  out(net,(P{i},n));
  in(net,(=P{i},candidate:pkey,q:bitstring));
  let rpeQuote(=mRPE,status:tcbstatus,binding:bitstring)=checksign(q,pkAKR) in
  if binding=hbind(candidate,n) then
  let platformOK=matchtcb(rpeTcb{i}(rho),status) in
  if platformOK=true then
  event OwnerAttested(pk(skO{i}),candidate,rho,n);
  let authorization=sign((candidate,hpol(rho)),skO{i}) in
  event OwnerSigned(pk(skO{i}),candidate,hpol(rho));
  out(net,(P{i},candidate,rho,authorization,pk(skO{i}))).
'''

def stage123_role(i):
    """Reuse the baseline Stage 2-3 suffix with the ACTUAL authorized state."""
    old=role(3,i,with_stage3=True)
    marker=f'  let q{i} = sign('
    suffix=old[old.index(marker):]
    # Put the quote service beside, not before, the actual authorization receiver.
    # Same RPE key in both branches; no secret provisioning channel.
    assert suffix.endswith('.\n')
    suffix=suffix[:-2]+'\n  ).\n'
    return f'''
let rpe{i}(akR:skey,pkAKR:pkey,pkAKE:pkey) =
  new sk{i}:skey;
  let pk{i}=pk(sk{i}) in
  out(net,(P{i},pk{i}));
  (
    (* An initial Quote is obtainable for any requested nonce, even after
       authorization. Its payload is NOT separated from Stage 2 by a tag. *)
    (!in(net,(=P{i},requested:nonce));
      out(net,(P{i},pk{i},sign(rpeQuote(mRPE,Good,hbind(pk{i},requested)),akR))))
  |
    in(net,(=P{i},=pk{i},rho{i}:policy,authorization:bitstring,ownerKey:pkey)) [precise];
    event AuthorizationReceived(P{i},pk{i},rho{i},ownerKey);
    let (signedKey:pkey,signedHash:bitstring)=checksign(authorization,ownerKey) in
    if signedKey=pk{i} && signedHash=hpol(rho{i}) then
    event AuthorizationSignatureChecked(P{i},pk{i},rho{i},ownerKey);
    if policySelf(rho{i})=P{i} then
    event AuthorizationSelfChecked(P{i},pk{i},rho{i},ownerKey);
    let Req(cm:ident,exact(selfSigner:attr),cp:ident,cv:svn,ct:tcbreq,ca:attreq)=starEntry{i}(constraints(rho{i})) in
    if selfSigner=H(ownerKey) && ca=Assign(P{i}) then
    event AuthorizationAccepted(P{i},pk{i},rho{i},ownerKey,selfSigner);
    event AuthorizedPolicyDeclared(P{i},pk{i},rho{i});
    event PolicyDeclared(P{i},rho{i});
'''+suffix

def common_hash_encoding(text):
    """Inline legacy hash names as one H over canonically serialized inputs.

    In particular Stage 1 H(key,nonce) and Stage 2 H(key,H(policy)) have the
    SAME shape. Nonces and keys use bytes, so no type barrier prevents mixing.
    """
    for name in ('hpol','hbind','hstar','hchal','hcert'):
        text=re.sub(r'^fun '+name+r'\([^\n]*\n','',text,flags=re.M)
    def rewrite(src):
        pattern=re.compile(r'\b(hpol|hbind|hstar|hchal|hcert)\(')
        match=pattern.search(src)
        if match is None:return src
        pos=match.end();depth=1;start=pos;args=[]
        while depth:
            ch=src[pos]
            if ch=='(':depth+=1
            elif ch==')':depth-=1
            if ch==',' and depth==1:
                args.append(src[start:pos].strip());start=pos+1
            if depth==0:args.append(src[start:pos].strip())
            pos+=1
        args=[rewrite(a) for a in args]
        name=match[1]
        if name=='hpol':value=f'H(policyBytes({args[0]}))'
        elif name=='hstar':value=f'H(starBytes({args[0]}))'
        elif name=='hchal':value=f'H(({args[1]},{args[0]}))'
        else:value='H(('+','.join(args)+'))'
        return src[:match.start()]+value+rewrite(src[pos:])
    text=rewrite(text)
    for oldtype in ('attr','nonce','pkey'):
        text=text.replace(f'type {oldtype}.\n','')
        text=re.sub(r'\b'+oldtype+r'\b','bitstring',text)
    for i in (1,2,3):
        text=text.replace(f'const s{i}: bitstring [data].\n','')
        text=re.sub(r'\bs'+str(i)+r'\b',f'H(pk(skO{i}))',text)
    return text

def stage123_model(kind='primary'):
    declarations='''type skey.
fun pk(skey):bitstring.
const skO1,skO2,skO3:skey [private].
fun H(bitstring):bitstring.
'''+ALGEBRA+schema(3,'',EXTENDED_PROFILES).replace('type skey.\n','')
    # Bound the adversary's POLICY domain without inserting an extra protocol
    # allow-list check after authorization. Public factories expose every P3
    # profile; both honest policies are also published. Public projections keep
    # fields readable. All RPEs still accept arbitrary messages/owner keys and
    # actually check signatures, Self, self signer, and own attester.
    declarations=re.sub(r'(fun pol\([^\n]*: policy) \[data\]\.',r'\1 [private].',declarations)
    crypto=CRYPTO.replace('fun pk(skey): pkey.', '''fun policyBytes(policy):bitstring [data].
fun starBytes(polstar):bitstring [data].''')
    queries=AUTHORIZATION+PRIMARY+ISSUANCE
    if kind=='auxiliary':
        queries=auxiliary(3,with_stage3=True)+'''
query a:party,k:pkey,r:policy,o:pkey,s:attr;
  event(AuthorizedPolicyDeclared(a,k,r)) ==> event(AuthorizationAccepted(a,k,r,o,s)).
query a:party,b:party,ka:pkey,kb:pkey,r:policy,o:pkey,s:attr;
  event(PolicyAcceptedKeys(a,b,ka,kb,r)) ==> event(AuthorizationAccepted(b,kb,r,o,s)).
query o:pkey,k:pkey,r:policy,n:nonce;
  event(OwnerSigned(o,k,hpol(r))) ==> event(OwnerAttested(o,k,r,n)).
'''
    elif kind in ('reachability','reachability-profile12'):
        witness=None
        if kind=='reachability-profile12':
            witness=render(merge_star(3,constraints_term(3,policy(3,1)),
                                         constraints_term(3,policy(3,3,'StrongerSVNE2'))))
        variables=[];facts=[]
        for i in (1,2,3):
            if witness is None:variables.append(f'x{i}:polstar')
            variables += [f'kr{i}:pkey',f'ke{i}:pkey',f'n{i}:nonce',f'id{i}:identity',f't{i}:tcbstatus',f'b{i}:bitstring',f'r{i}:policy',f'o{i}:pkey',f's{i}a:attr']
            x=witness or f'x{i}'
            facts += [f'event(AuthorizationAccepted(P{i},kr{i},r{i},o{i},s{i}a))',f'event(Confirm(P{i},{x}))',f'event(CertIssued(P{i},E{i},kr{i},ke{i},n{i},id{i},t{i},{x},b{i}))']
        queries='query '+','.join(variables)+';\n  '+' &&\n  '.join(facts)+'.\n'
    text='''(* N3 Stage 1-3; extension of 3766338 with twelve explicit P3 profiles.
   Two honest owner keys; O3's signing key is public, RPE keys protected.
   One initialization; three fixed role/instance pairs P1/E1, P2/E2, P3/E3.
   Stage 1 and Stage 2 use the SAME rpeQuote/hardware key/report-data format.
   The finite policy domain is a scope restriction, not a new wire check.
   Stage 3 retains the baseline distinct TEE hardware-key abstraction.
*)\n'''+declarations+crypto+STAGE1_EVENTS+queries
    text+=ATTEST+instance('')+stage1_owner(1)+stage1_owner(2)
    text+=''.join(stage123_role(i) for i in (1,2,3))
    text+='''
process
  new akRPE:skey;
  new akTEE:skey;
  new akADV:skey;
  event HonestOwner(pk(skO1));
  event HonestOwner(pk(skO2));
  out(net,(pk(akRPE),pk(akTEE),pk(akADV),akADV,pk(skO1),pk(skO2),pk(skO3),skO3));
'''
    text+=f'  out(net,({policy(3,1)},{policy(3,2)}));\n'
    text+='  (owner1(pk(akRPE)) | owner2(pk(akRPE)) |\n'
    text+=' |\n'.join(f'   rpe{i}(akRPE,pk(akRPE),pk(akTEE))' for i in (1,2,3))
    text+=' | !instance(akTEE))\n'
    return common_hash_encoding(text)

def stage123_main():
    for kind in ('primary','auxiliary','reachability','reachability-profile12'):
        (MODELS/f'sras-n3-stage123-{kind}.pv').write_text(stage123_model(kind))
    source=stage123_model()
    blocks=list(re.finditer(r'^query\b.*?\.',source,re.M|re.S))
    names=['Authorization','Agreement','Authenticity','Completeness','Issuance']
    assert len(blocks)==len(names)
    jobs=[]
    for i,name in enumerate(names):
        single=source
        for j,m in reversed(list(enumerate(blocks))):
            if i!=j:single=single[:m.start()]+f'(* {names[j]} queried separately. *)'+single[m.end():]
        path=ROOT/'queries'/f'n3-stage123-{name}.pv'
        path.write_text(single)
        jobs.append(f'{path.stem}|{path.relative_to(ROOT)}|{name}|3')
    (ROOT/'jobs-stage123-single.txt').write_text('\n'.join(jobs)+'\n')
    (ROOT/'jobs-stage123-pilot.txt').write_text('\n'.join([jobs[0],jobs[1]])+'\n')
    (ROOT/'jobs-stage123-remaining.txt').write_text('\n'.join(jobs[2:])+'\n')
    (ROOT/'jobs-stage123-normal.txt').write_text('sras-n3-stage123-reachability|models/sras-n3-stage123-reachability.pv|reachability|3\n')
    (ROOT/'jobs-stage123-checks.txt').write_text('\n'.join(f'sras-n3-stage123-{k}|models/sras-n3-stage123-{k}.pv|{k}|3' for k in ('auxiliary','reachability'))+'\n')
    aux=stage123_model('auxiliary')
    blocks=list(re.finditer(r'^query\b.*?\.',aux,re.M|re.S))
    grouped=[[],[],[]]
    for i in range(len(blocks)):
        single=aux
        for j,m in reversed(list(enumerate(blocks))):
            if i!=j:single=single[:m.start()]+f'(* Auxiliary {j+1} queried separately. *)'+single[m.end():]
        path=ROOT/'queries'/f'n3-stage123-A{i+1:02d}.pv'
        path.write_text(single)
        grouped[min(i//5,2)].append(f'{path.stem}|{path.relative_to(ROOT)}|auxiliary|3')
    for i,jobs in enumerate(grouped,1):
        (ROOT/f'jobs-stage123-auxiliary{i}.txt').write_text('\n'.join(jobs)+'\n')
    (ROOT/'jobs-stage123-profile12.txt').write_text('sras-n3-stage123-reachability-profile12|models/sras-n3-stage123-reachability-profile12.pv|reachability|3\n')
    (MODELS/'policy-catalog-p12.json').write_text(json.dumps({pr:policy(3,3,pr) for pr in EXTENDED_PROFILES},indent=2)+'\n')
    (MODELS/'policy-catalog-stage123-p12.json').write_text(json.dumps({pr:common_hash_encoding(policy(3,3,pr)) for pr in EXTENDED_PROFILES},indent=2)+'\n')
    (ROOT.parent/'sras-n3.pv').write_text(source)
    print('Generated Stage 1-3 owner authorization, same-key continuation, and five property queries.')

if __name__ == '__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--stage23',action='store_true',help='Extend commit 3766338 N3 with its existing N2 Stage 3')
    cli.add_argument('--profiles12',action='store_true',help='Add the E2-only minimum-SVN strengthening profile')
    cli.add_argument('--stage123',action='store_true',help='Add real owner authorization before the three-party Stage 2-3 process')
    args=cli.parse_args()
    if args.stage123:stage123_main()
    elif args.stage23:stage23_main(EXTENDED_PROFILES if args.profiles12 else None)
    else:main()
