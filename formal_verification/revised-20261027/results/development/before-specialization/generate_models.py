#!/usr/bin/env python3
"""Generate auditable standalone PV models; no external Python dependencies.

The RPE roles, four primary event names/queries, and N=2/N=3 split are
retained from the original models. Generated files are checked in as artifacts.
"""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent
MODELS = ROOT / 'models'
SCENARIOS = ROOT / 'scenarios'
MODELS.mkdir(exist_ok=True)
SCENARIOS.mkdir(exist_ok=True)
ALGEBRA = (MODELS / 'algebra.pvl').read_text()
PROFILES = ['Compatible', 'Weak', 'StrongerSVN', 'ConflictMeasurement',
            'ConflictSigner', 'ConflictProduct', 'ConflictTCB', 'ConflictAttester',
            'RejectPeerTCB', 'NoAssignments', 'PermissiveRpeTCB']

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
        entries = [req(j, weak=True, **({'s':f'exact(s{owner})'} if j == owner else {})) for j in range(1,n+1)]
    elif profile == 'StrongerSVN':
        entries[0] = req(1, v='V2')
    elif profile == 'ConflictMeasurement': entries[0] = req(1, m='exact(mBad)')
    elif profile == 'ConflictSigner': entries[0] = req(1, s='exact(sBad)')
    elif profile == 'ConflictProduct': entries[0] = req(1, p='exact(prodB)')
    elif profile == 'ConflictTCB': entries[0] = req(1, t='OnlyOutdated')
    elif profile == 'ConflictAttester': entries[0] = req(1, a=f'Assign(P{n})')
    elif profile == 'RejectPeerTCB': rt[0] = 'OnlyOutdated'
    elif profile == 'NoAssignments': entries = [req(j, a='NoAtt') for j in range(1,n+1)]
    elif profile == 'PermissiveRpeTCB': rt = ['Both'] * n
    if scenario == 'wrong-attester': entries[0] = req(1, a='Assign(P2)')
    return 'pol(' + ', '.join([f'P{owner}', f'Members{n}'] + rt + entries) + ')'

def schema(n, scenario):
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
    result += '\nletfun joinstar(x: polstar, y: polstar) =\n'
    for var in ['x','y']:
        result += f"  let mkstar({', '.join(f'{var}t{i}: tcbreq' for i in range(1,n+1))}, {', '.join(f'{var}e{i}: entry' for i in range(1,n+1))}) = {var} in\n"
    for j in range(1,n+1):
        result += f'  let jt{j} = jointcb(xt{j}, yt{j}) in\n'
        result += f'  let je{j} = joinentry(xe{j}, ye{j}) in\n'
    result += '  mkstar(' + ', '.join([f'jt{i}' for i in range(1,n+1)] + [f'je{i}' for i in range(1,n+1)]) + ').\n'
    for pr in PROFILES: result += f'const {pr}: profile [data].\n'
    result += '\n(* Explicit finite policy domain for the adversarial owner; see policy-catalog.json. *)\n'
    result += 'fun choosePolicy(profile): policy\n'
    result += '\notherwise '.join(('reduc ' if k==0 else '')+f'choosePolicy({pr}) = {policy(n,n,pr,scenario)}' for k,pr in enumerate(PROFILES)) + '.\n'
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
event PolicySent(party, party, policy).
event PolicyAuthenticated(party, party, policy).
event PolicyAccepted(party, party, policy).
event PoliciesComplete(party).
event FullJoin(party, polstar).
event ConfirmationSent(party, party, bitstring).
event ConfirmationAuthenticated(party, party, bitstring).
event ConfirmationAccepted(party, party, bitstring).
event Confirm(party, polstar).
event QuoteProduced(pkey, nonce, identity, tcbstatus).
event ChallengeSent(party, pkey, nonce).
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

def auxiliary(n, no_confirm=False):
    s = '''
(* A1: accepted policies were actually sent by that RPE to this recipient. *)
query a: party, b: party, r: policy;
  event(PolicyAccepted(a,b,r)) ==> event(PolicySent(b,a,r)).
(* A2: the all-Quote gate precedes policy dissemination. *)
query a: party, b: party, r: policy;
  event(PolicySent(a,b,r)) ==> event(QuotesComplete(a)).
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
    if n == 2:
        s += '''
(* A4: evidence, request, Stage 2 completion, and certificate payload binding. *)
query a: party, e: entity, kr: pkey, ke: pkey, n: nonce, id: identity, t: tcbstatus, x: polstar, body: bitstring;
  event(CertIssued(a,e,kr,ke,n,id,t,x,body)) ==>
    event(Confirm(a,x)) && event(ChallengeSent(a,ke,n)) && event(QuoteProduced(ke,n,id,t)) && body = hcert(ke,kr,hstar(x)).
'''
    return s

def reachability(n):
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
    return s

ATTEST = '''
(* Stage 3: shared verifier, invoked only after this RPE's Confirm event. *)
let attest(a: party, e: entity, skR: skey, pistar: polstar, c: entry, pkAK: pkey) =
  in(net, pkE: pkey);
  new challenge: nonce;
  event ChallengeSent(a,pkE,challenge);
  out(net, challenge);
  in(net, qe: bitstring);
  let teeQuote(actual: identity, status: tcbstatus, binding: bitstring) = checksign(qe,pkAK) in
  if binding = hchal(challenge,pkE) then
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

def role(n, i, scenario='', no_confirm=False):
    peers = [j for j in range(1,n+1) if j != i]
    s = f'\n(* RPE_{i}: required peers are the fixed Members{n} configuration minus self. *)\n'
    s += f'let rpe{i}(akR: skey, pkAKR: pkey, pkAKE: pkey) =\n'
    if i==n:
        fixed = {'conflict-measurement':'ConflictMeasurement','conflict-signer':'ConflictSigner',
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
        if i==n and j==1 and scenario in ('missing-policy','duplicate-policy'): continue
        payload = policy(n,n,'Weak') if i==n and j==1 and scenario=='policy-hash-mismatch' else f'rho{i}'
        s += f'  event PolicySent(P{i},P{j},{payload});\n'
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
    s += f';\n  attest(P{i},E{i},sk{i},pistar,starEntry{i}(pistar),pkAKE).\n' if n==2 else '.\n'
    return s

def scenario_queries(n, scenario):
    # A reachable preceding gate guards against a trivial dead model.
    if scenario in ('missing-quote','bad-rpe-tcb','bad-rpe-code'):
        return 'query r: policy; event(PolicyDeclared(P1,r)).\nquery event(QuotesComplete(P1)).\n'
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
    return '''query x: polstar; event(Confirm(P1,x)).
query kr: pkey, ke: pkey, n: nonce, id: identity, t: tcbstatus, x: polstar, body: bitstring;
  event(CertIssued(P1,E1,kr,ke,n,id,t,x,body)).
query ke: pkey, n: nonce, id: identity, t: tcbstatus;
  event(QuoteProduced(ke,n,id,t)).
'''

def model(n, kind='primary', scenario='', no_confirm=False):
    head = f'''(* SRAS revision 20261027; N={n}; kind={kind}; scenario={scenario or 'none'}.
 * SINGLE static initialization with exactly N protected RPE roles.
 * The adversary chooses the last owner's policy from 11 documented profiles.
 * All network sends/receives are public and adversary-controlled.
 * This file is generated by generate_models.py; original models remain intact.
 *)\n'''
    text = head + ALGEBRA + schema(n,scenario) + CRYPTO
    if kind=='primary': text += PRIMARY + (ISSUANCE if n==2 else '')
    elif kind=='auxiliary': text += auxiliary(n,no_confirm)
    elif kind=='reachability': text += reachability(n)
    else: text += scenario_queries(n,scenario)
    if n==2: text += ATTEST + instance(scenario)
    text += ''.join(role(n,i,scenario,no_confirm) for i in range(1,n+1))
    text += '''
process
  new akRPE: skey;
  new akTEE: skey;
  new akADV: skey;
  out(net,(pk(akRPE),pk(akTEE),pk(akADV),akADV));
  ('''
    text += ' |\n   '.join(f'rpe{i}(akRPE,pk(akRPE),pk(akTEE))' for i in range(1,n+1))
    if n==2: text += ' |\n   !instance(akTEE)'
    text += ')\n'
    return text

def main():
    catalog = {}
    for n in [2,3]:
        catalog[f'N{n}'] = {pr:policy(n,n,pr) for pr in PROFILES}
        for kind in ['primary','auxiliary','reachability']:
            (MODELS/f'sras-n{n}-{kind}.pv').write_text(model(n,kind))
        for kind in ['primary','reachability']:
            (MODELS/f'sras-n{n}-no-confirm-{kind}.pv').write_text(model(n,kind,no_confirm=True))
    (MODELS/'policy-catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')
    stage2 = ['missing-quote','bad-rpe-code','bad-rpe-tcb','missing-policy','duplicate-policy',
              'policy-hash-mismatch','missing-confirmation','confirmation-mismatch',
              'conflict-measurement','conflict-signer','conflict-product','conflict-tcb','conflict-attester','reject-peer-tcb']
    stage3 = ['bad-measurement','bad-signer','bad-product','bad-svn','bad-tcb','revoked-tcb','invalid-tcb','wrong-attester','wrong-challenge']
    for scenario in stage2:
        (SCENARIOS/f'n3-{scenario}.pv').write_text(model(3,'regression',scenario))
    for scenario in stage3:
        (SCENARIOS/f'n2-{scenario}.pv').write_text(model(2,'regression',scenario))
    print('Generated primary, auxiliary, reachability, single-change no-confirm, and regression models.')

if __name__ == '__main__': main()
