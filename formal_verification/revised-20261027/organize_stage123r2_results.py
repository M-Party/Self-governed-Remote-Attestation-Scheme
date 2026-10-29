#!/usr/bin/env python3
"""Audit and organize the completed bounded Stage 1-3 experiment.

Reads existing verifier evidence; does not run ProVerif. Regenerates sources
in a temporary directory to check reproducibility without overwriting logs.
The old stage123 reports remain a record of the preceding revision.
"""
import collections
import contextlib
import copy
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import generate_models as g
import stage123_complete as v
import stage123_supplement as s

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / 'reports'
BASE = '3766338d5301d543434a57fdcb3aea037aea512a'
BASE_GENERATOR_SHA256 = '961b66946b7f49e92783537edbadd4baeb29096ea6bb7748507bf0516d90ba15'
NAMES = ('Authorization', 'Agreement', 'Authenticity', 'Completeness', 'Issuance')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, value):
    (REPORTS / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def csv_file(name, rows):
    with (REPORTS / name).open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def nonquery(source):
    text = re.sub(r'\(\*.*?\*\)', '', source, flags=re.S)
    text = re.sub(r'^query\b.*?\.', '', text, flags=re.M | re.S)
    return sha(re.sub(r'\s+', ' ', text).strip().encode())


def profile_coverage():
    """A concrete slice demonstrates the limit; it is not a coverage estimate."""
    base = s.constraints(v.policy(1))
    details = []
    successful = set()
    for name in g.EXTENDED_PROFILES:
        term = s.constraints(v.policy(3, name))
        try:
            output = g.merge_star(3, base, term)
            successful.add(output)
            result = g.render(output)
            svn = [entry[1][3] for entry in output[1][3:]]
        except ValueError:
            result, svn = None, None
        details.append(dict(profile=name, policy=v.policy(3, name),
                            compatible_join=result is not None,
                            normalized_join=result, normalized_minimum_SVN=svn))

    # Keep every field of P3 Compatible fixed except its three minimum SVNs.
    # Self/signature/attester constraints are unchanged by this enumeration.
    svn_slice = []
    for minima in itertools.product(('V0', 'V1', 'V2'), repeat=3):
        fields = list(s.constraints(v.policy(3))[1])
        for j, minimum in enumerate(minima):
            entry = list(fields[j + 3][1])
            entry[3] = minimum
            fields[j + 3] = ('Req', tuple(entry))
        output = g.merge_star(3, base, ('mkstar', tuple(fields)))
        svn_slice.append(dict(input_minimum_SVN=minima,
                              normalized_minimum_SVN=[e[1][3] for e in output[1][3:]],
                              normalized_join=g.render(output)))
    possible = {tuple(x['normalized_minimum_SVN']) for x in svn_slice}
    covered = {tuple(x['normalized_minimum_SVN']) for x in details if x['compatible_join']}
    assert len(possible) == 8 and len(covered) == 3
    assert len(successful) == 3
    answer = dict(
        domain='12 complete P3 profiles, two fixed honest policies; no cross-profile field construction',
        principal_field_types=['measurement', 'signer', 'product', 'minimum SVN', 'TCB acceptance set', 'attester'],
        represented_semantics=['compatible concrete constraints', 'peer wildcards with concrete self signer',
                               'stronger SVN on E1 or E2', 'exact-value conflicts',
                               'disjoint TCB sets', 'attester conflicts',
                               'unspecified peer attester', 'redundant/weaker input'],
        profiles=details,
        successful_catalog_profiles=sum(x['compatible_join'] for x in details),
        distinct_successful_catalog_joins=len(successful),
        SVN_slice=dict(description='Only P3 minimum SVNs vary; all other fields are Compatible. Each input is admissible under the general field syntax.',
                       input_combinations=len(svn_slice), distinct_successful_join_vectors=sorted(possible),
                       vectors_covered_by_catalog=sorted(covered), missing_vectors=sorted(possible - covered),
                       enumeration=svn_slice),
        interpretation='This explicit slice refutes exhaustive field-combination coverage. The 3/8 count is not an estimate of total policy-domain coverage.',
        recommended_wording='12 个预设 profile 覆盖主要 policy 字段类型及通配符、相容、强化和冲突等代表性语义情形；该有限目录不穷尽字段自由组合。')
    save('stage123r2-profile-coverage.json', answer)
    csv_file('stage123r2-profile-coverage.csv', [
        dict(profile=x['profile'], compatible_join=x['compatible_join'],
             normalized_minimum_SVN=' / '.join(x['normalized_minimum_SVN'] or []),
             policy=x['policy'], normalized_join=x['normalized_join']) for x in details])
    (REPORTS / 'stage123r2-profile-coverage.txt').write_text(
        '12-profile 覆盖范围\n\n' + answer['recommended_wording'] + '\n\n'
        '六类主要约束：measurement、signer、product、最低 SVN、TCB 接受集合、attester。\n'
        '12 项是完整策略配置，不是六类字段的任意组合器。主模型没有开放目录间拼接。\n'
        '6 项可与固定诚实配置成功 join，6 项冲突；成功输入归一化后只有 3 种不同结果。\n\n'
        '可复核的遗漏：固定其他字段，仅让 P3 对 E1/E2/E3 的最低 SVN 各取 V0/V1/V2，\n'
        '原字段语法得到 27 个合法输入；与诚实方 (V1,V1,V1) 聚合后，得到 8 种成功结果。\n'
        '12 项目录覆盖其中 3 种：(V1,V1,V1)、(V2,V1,V1)、(V1,V2,V1)。\n'
        '未覆盖只提高 E3、同时提高 E1/E2，以及其他同时强化的结果。\n'
        '3/8 只是这一具体 SVN 切片的统计，不能当作整个策略空间的覆盖率。\n'
        '因此不能据此写“基本覆盖 policy 字段自由组合”，也未证明它们是完备等价类。\n\n'
        '本统计不增加主模型 profile、不改变输入域，也不替代新的安全证明。\n'
        '逐项目录与枚举依据见同名 JSON/CSV；通用 ProVerif join 对照见两项代数模型。\n')
    return answer


def audit(result, metadata):
    checks = {}
    def check(name, value):
        checks[name] = bool(value)

    check('current_results_complete', not result['issues'] and result['current_unresolved_queries'] == 0)
    check('current_source_integrity', result['source_and_log_integrity'])
    check('69_jobs_189_query_results', len(result['runs']) == 69 and len(result['current_results']) == 189)
    relative = 'formal_verification/revised-20261027/generate_models.py'
    # A delivered experiment archive has no Git database. Include the pinned
    # baseline source so the same audit works after an independent extraction.
    try:
        baseline = subprocess.run(['git', 'show', BASE + ':' + relative], cwd=ROOT,
                                  capture_output=True, check=False)
        old_text = baseline.stdout.decode() if baseline.returncode == 0 else ''
    except FileNotFoundError:
        old_text = ''
    if not old_text:
        old_text = (ROOT / 'legacy/generate_models-3766338.py').read_text()
    check('pinned_baseline_generator_hash', sha(old_text.encode()) == BASE_GENERATOR_SHA256)
    old = {'__file__': str(ROOT / 'generate_models.py'), '__name__': 'baseline'}
    exec(compile(old_text, 'baseline-generator', 'exec'), old)
    check('original_eleven_profiles_retained', g.EXTENDED_PROFILES[:-1] == old['PROFILES'])
    check('baseline_Stage3_verifier_preserved', g.ATTEST == old['ATTEST'])
    check('baseline_four_query_definitions_preserved', g.PRIMARY == old['PRIMARY'] and g.ISSUANCE == old['ISSUANCE'])
    check('historical_N2_N3_defaults_preserved', g.model(2) == old['model'](2) and g.model(3) == old['model'](3))
    before = g.constraints_term(3, g.policy(3, 3))
    expected = list(before[1])
    entry = list(expected[4][1]); entry[3] = 'V2'; expected[4] = ('Req', tuple(entry))
    check('twelfth_profile_only_changes_E2_SVN', g.constraints_term(3, g.policy(3, 3, 'StrongerSVNE2')) == ('mkstar', tuple(expected)))
    source = v.model()
    check('root_entry_is_current_r2', (ROOT.parent / 'sras-n3.pv').read_text() == source)
    check('public_main_network', 'free net: channel.' in source)
    check('malicious_O3_key_public', 'pk(skO3),skO3' in source)
    check('one_shared_hash_no_nonce_key_type_barrier', source.count('fun H(bitstring):bitstring.') == 1 and 'type nonce.' not in source and 'type pkey.' not in source)
    check('explicit_serialized_SelfTEE', 'fun pol(party, entity, roster,' in source and 'policySelfTEE(pol(a, selfTEE,' in source)
    for i in (1, 2, 3):
        role = v.role(i)
        check(f'RPE{i}_actual_SelfRPE_and_SelfTEE_guard', f'policySelf(rho{i})=P{i} && policySelfTEE(rho{i})=E{i}' in role)
        check(f'RPE{i}_same_key_policy_across_stages', role.count(f'new sk{i}:skey') == 1 and f'H((pk{i},H(policyBytes(rho{i}))))' in role and f'attest(P{i},E{i},sk{i},pistar' in role)
        check(f'RPE{i}_same_initial_Evidence_quote_payload_shape', f'rpeQuote(mRPE,Good,H((pk{i},requested)))' in role and f'rpeQuote(mRPE,Good,H((pk{i},H(policyBytes(rho{i})))))' in role)
        marker, end = f'  let q{i} = sign(', f'  event Confirm(P{i},pistar)'
        old_role, inherited = old['role'](3, i), g.stage123_role(i)
        check(f'RPE{i}_baseline_Stage2_checks_preserved', old_role[old_role.index(marker):old_role.index(end)+len(end)] == inherited[inherited.index(marker):inherited.index(end)+len(end)])

    rows = result['current_results']
    public = [r for r in result['runs'] if r['category'] in (*NAMES, 'auxiliary', 'reachability')]
    fingerprints = {r['job']: nonquery((ROOT / r['source']).read_text()) for r in public}
    check('22_public_models_same_nonquery_process_domain_corruption', len(public) == 22 and len(set(fingerprints.values())) == 1)
    check('five_primary_proved', sum(r['category'] in NAMES and r['result'] == 'proved' for r in rows) == 5)
    check('fourteen_auxiliary_proved', sum(r['category'] == 'auxiliary' and r['result'] == 'proved' for r in rows) == 14)
    check('three_joint_witnesses_reconstructed', sum(r['category'] == 'reachability' and r['result'] == 'reachable' and r['trace_reconstructed'] for r in rows) == 3)
    for run in result['runs']:
        directory = ROOT / 'results' / run['run'] / run['job']
        check('snapshot_' + run['job'], (directory / 'model.pv').read_bytes() == (ROOT / run['source']).read_bytes() and sha((directory / 'model.pv').read_bytes()) == run['sha256'])
        check('output_' + run['job'], sha((directory / 'output.log').read_bytes()) == run['log_sha256'] and run['parse_exit'] == run['exit'] == 0)
    by_job = collections.defaultdict(list)
    for row in rows:
        by_job[row['model']].append(row)
    for job, meta in metadata.items():
        actual = by_job[job]
        expected = ['reachable' if value else 'unreachable' for value in meta['expected_reachability']]
        check('expected_' + job, [r['result'] for r in actual] == expected)
        check('positive_trace_' + job, all(r['trace_reconstructed'] for r in actual if r['result'] == 'reachable'))
        if meta['actual_stage1_all_three']:
            fixture = (ROOT / meta['source']).read_text()
            for i in (1, 2, 3):
                accepted = f'event AuthorizationAccepted(P{i},pk{i},rho{i},ownerKey,selfSigner);'
                check(f'{job}_real_authorization{i}', accepted + f'\n    out(ready{i},P{i});' in fixture and f'let owner{i}(pkAKR:bitstring)' in fixture and f'sign((candidate,H(policyBytes(rho))),skO{i})' in fixture)
            check(job + '_private_control_label', 'CONTROL FIXTURE' in fixture and 'free net: channel [private].' in fixture)
    with tempfile.TemporaryDirectory(prefix='sras-r2-reproduce-', dir='/tmp') as temporary:
        folder = Path(temporary)
        for part in ('models', 'scenarios', 'queries', 'reports'):
            (folder / part).mkdir()
        shutil.copyfile(ROOT / 'models/stage123r2-report-inputs.json', folder / 'models/stage123r2-report-inputs.json')
        old_v, old_s = v.ROOT, s.ROOT
        try:
            v.ROOT = s.ROOT = folder
            with contextlib.redirect_stdout(io.StringIO()):
                v.main(); s.main()
            for run in result['runs']:
                check('regenerated_' + run['job'], (folder / run['source']).read_bytes() == (ROOT / run['source']).read_bytes())
        finally:
            v.ROOT, s.ROOT = old_v, old_s
    failed = [key for key, value in checks.items() if not value]
    assert not failed, failed
    answer = dict(baseline=BASE, baseline_generator_sha256=sha(old_text.encode()), checks=checks,
                  full_public_process_nonquery_sha256=fingerprints,
                  nature='Source/evidence audit, not additional ProVerif security queries',
                  scope=dict(policy='12 complete P3 profiles + two fixed honest policies; private pol constructor and public factories',
                             honest_configuration='Fixed Compatible constraints for P1/P2; Self RPE/TEE metadata differs',
                             corruption='O3 signing key public; O1/O2 and all RPE private keys protected',
                             SelfTEE='Serialized independent policy field, checked against the configured Ei in Stage1',
                             sessions='One initialization, three protected RPEs, common static membership',
                             quote='Stage1 and Stage2 share quote constructor, hardware key and H(key,bytes); Stage3 retains baseline separate hardware-key/teeQuote abstraction',
                             controls='29 private controlled schedules/inputs, including four Evidence-prefix tests with all three real authorizations; not replacements for public-network proofs',
                             exclusions='General field combinations, arbitrary honest configuration/corruption/N, repeated initialization, TLS and real collateral implementation'))
    save('stage123r2-source-audit.json', answer)
    return answer


def executed_witnesses(result):
    catalog = {g.render(g.parse_term(v.policy(3, name))): name for name in g.EXTENDED_PROFILES}
    witnesses = []
    for row in result['current_results']:
        if row['category'] != 'reachability':
            continue
        lines = (ROOT / row['log']).read_text().splitlines()
        executed = [(i, line) for i, line in enumerate(lines, 1) if line.startswith('The event AuthorizationAccepted(P3,')]
        assert executed
        lineno, line = executed[-1]
        start = line.index('pol('); end = start + 4; depth = 1
        while depth:
            if line[end] == '(': depth += 1
            if line[end] == ')': depth -= 1
            end += 1
        policy = line[start:end]
        witnesses.append(dict(model=row['model'], actual_P3_profile=catalog[g.render(g.parse_term(policy))],
                              actual_P3_policy=policy, log=row['log'], executed_event_line=lineno,
                              elapsed_seconds=row['elapsed_seconds']))
    assert {w['actual_P3_profile'] for w in witnesses} == {'PermissiveRpeTCB', 'StrongerSVNE2', 'Weak'}
    save('stage123r2-executed-witnesses.json', witnesses)
    return witnesses


def coverage(result, metadata, witnesses):
    previous = json.loads((ROOT / 'models/stage123r2-report-inputs.json').read_text())
    rows = copy.deepcopy(previous['coverage'])
    by_id = {r['编号']: r for r in rows}
    for row in rows:
        for key in ('核对结论', '证据', '未覆盖或待补'):
            row[key] = row[key].replace('stage123-', 'stage123r2-')
    def update(code, assessment, evidence, boundary='', status='已覆盖（限定当前模型与所列证据层级）'):
        row = by_id[code]
        row.update(当前覆盖=status, 核对结论=assessment, 证据=evidence, 未覆盖或待补=boundary)
    update('O01', '实际三方 Stage1–3，五主性质、14辅助及三种三方联合执行。', 'sras-n3-stage123r2-primary.pv；stage123r2-results.json')
    update('D03', '五类策略冲突均重建真实三方授权及 P1 PoliciesComplete 前序，FullJoin 不可达；RejectPeerTCB 单独检查。', 'control-conflict-*；control-reject-peer-tcb；两项 join 对照模型', '限定当前目录及明确列出的控制配置。')
    update('D04', '主模型实际验证 concrete self-signer、指纹、Self RPE/TEE 及 own attester；局部测试分别证明前序可达和拒绝。', '16个局部Stage1模型；auth-nonconcrete-signer/fingerprint-mismatch/wrong-self/wrong-self-tee/wrong-attester', '主目录并未开放任意不合法 own 字段组合；这些目录外负例是明确标记的控制输入。', '已覆盖检查与局部负例；主策略域按后续指令收窄')
    update('D05', '列出21个聚合字段，加上Self RPE、Self TEE、Members；分别描述语法与主目录实际取值。', 'stage123r2-field-domains.csv；stage123r2-profile-coverage.json', '主目录不开放字段笛卡尔积，详见D01/D02。')
    update('S105', 'policy现在序列化独立SelfTEE字段；实际比较policySelf=Pi及policySelfTEE=Ei。', 'stage123_complete.py:self_tee；auth-wrong-self-tee', '角色配置Pi/Ei仍固定；只篡改SelfTEE的局部输入在签名/hash通过后被拒绝。')
    update('S202', '保留实际签名、代码/TCB、key/hash绑定与peer key去重；补齐三方真实授权后的早期Quote检查。', 'A01/A02；missing-quote/duplicate-quote/bad-rpe-code/bad-rpe-tcb', '四个Quote控制模型保留精确检查前缀，省略后续不相关流程；不冒充完整私有全流程实验。')
    update('S206', 'Stage2使用已授权状态和RPE认证策略，不重验owner签名；具体signer冲突与peer wildcard各有当前证据。', 'authorized-signer-peer-conflict；reachability-weak', 'signer冲突控制配置的诚实peer对E3期望改为O1指纹；主配置未改。')
    update('S302', '实际实例验签、key/挑战绑定、六类appraisal守卫保持；11项当前坏输入控制实验覆盖前序与拒绝。', 'Issuance；A11；11个实例控制模型', '控制实例/接收端输入与故障性质分别列在control-expectations中。')
    update('R01', '三个公开网络联合查询各自重建同一条包含三方授权、Confirm及CertIssued的轨迹。', 'stage123r2-executed-witnesses.json', '实际P3分别为PermissiveRpeTCB、StrongerSVNE2和Weak；不声称每个profile均有成功执行。')
    update('T03', 'Self RPE、独立SelfTEE、本方attester及concrete self-signer分别有实际检查前序与拒绝证据。', 'auth-wrong-self/wrong-self-tee/wrong-attester/nonconcrete-signer', '局部控制负例不等同于主目录允许任意字段组合。')
    update('T04', 'P3以实际O3 key和H(pk(skO3))合法自授权；诚实peers对E3期望H(pk(skO1))。三方授权及PoliciesComplete可达，FullJoin不可达。', 'n3-stage123r2-control-authorized-signer-peer-conflict；control-tables', '为触发指定冲突，单独改变控制配置中诚实peer对E3的signer期望；主五性质配置保持原样。')
    update('T05', '同一公开主过程的联合查询将实际P3已授权policy约束为Weak，三方授权、确认及签发共同可达。', 'sras-n3-stage123r2-reachability-weak；executed-witnesses.json', 'Weak自身signer具体、对peers signer为Any；只约束查询，不限制过程输入。')
    update('T06', '真实三方授权后给P1交付有效P2 Evidence，扣留P3所有Quote交付。EvidenceChecked(P1,P2)可达、QuotesComplete(P1)不可达。', 'control-missing-quote', '私有确定交付与精确Evidence检查前缀；初始Quote服务保留，但不向P1交付可替代的P3 Quote。')
    update('T07', '将真实P2 Quote以P3外层标签再交付；三方真实授权及首个peer检查可达，重复包接收可达，全员Quote完成不可达。', 'control-duplicate-quote', '确定交付顺序的私有前缀测试；没有伪造硬件签名。')
    update('T08', '缺失/重复policy均从三方真实授权继续；QuotesComplete及接受有效P2 policy可达，PoliciesComplete不可达；重复包接收另有可达查询。', 'control-missing-policy/duplicate-policy', '完整Stage2–3体、私有交付控制。')
    update('T09', '缺失、重复、已认证但hash不匹配的确认均有FullJoin及有效P2确认前序，Confirm(P1)不可达。', 'control-missing-confirmation/duplicate-confirmation/confirmation-mismatch', '错误hash签名由受保护发送端故障注入；不声称正常网络攻击者可产生该签名。')
    update('T10', '请求真实P3初始Quote承诺Weak的hash，再交付实际授权Compatible的真实policy签名。QuotesComplete、PolicyAuthenticated可达，policy hash检查拒绝。', 'control-policy-hash-mismatch；ControlInitialHashRequested可达', '使用现有初始Quote请求能力和相同载荷；没有修改受保护RPE的policy发送内容。')
    update('T11', '五类策略冲突均有真实三方授权、PoliciesComplete可达及FullJoin不可达；控制专门化与通用PV join逐项对照。', 'control-conflict-measurement/signer/product/tcb/attester；join-stage123r2-control-tables', '语法合法输入限定列出的目录；一般自由组合仍未证明。')
    update('T12', '11项坏实例输入均在三方真实授权及P1共识确认后检查签名、绑定或appraisal拒绝，并分别确认接收/验签/QuoteVerified前序。', 'control-bad-*/revoked-tcb/invalid-tcb/wrong-attester/wrong-challenge/wrong-instance-key/invalid-signature', 'bad-rpe-code/tcb另外属于早期Quote前缀与硬件故障测试。')
    update('T13', '29个三方控制场景和16个局部Stage1测试均核对指定前序；所有正向可达结果有实际重建轨迹。', 'stage123r2-control-expectations.json；stage123r2-results-table.csv', '4个Quote场景为三方真实授权后的检查前缀；25个保留完整Stage2–3体。局部控制不替代公开网络主证明。')
    update('A02', '当前69作业189条确定结果，未决0；开发阶段状态另有摘要。', 'stage123r2-results.json；stage123r2-development-summary.json', '未选中开发尝试的原始文件留存本地，未计入或上传为当前结果；摘要不代替其原始证据。')
    update('A03', '5主查询、14辅助、3联合见证的非查询过程摘要一致；策略域及攻击者配置相同。', 'stage123r2-source-audit.json')
    update('V01', '给出基线到当前的源码差异；说明真实授权、Stage3、共享hash、独立SelfTEE和后续有限策略约定。', 'diffs/*-stage123r2.diff；stage123r2-SUMMARY.txt', '11项未替换为一般组合器，而按后续指令增加到12项；这一范围变化单独列明。')
    update('V02', '独立源码、固定基线、报告输入、生成和运行脚本、环境、命令及hash均已收录。', 'stage123r2-REPRODUCE.txt；各选中结果目录；SHA256SUMS.stage123r2.public.txt')
    update('V04', '当前69作业保存完整文字输出、冻结源、前序及联合执行轨迹；公开联合见证有DOT/PDF。', 'stage123r2-current-selection.json及各作业output.log/command/time/exit', '私有控制关闭绘图但保留文字轨迹；未选中的开发尝试只公开状态摘要，原始材料留在本地。')
    update('V06', '当前模型、原始日志、查询、三条联合执行轨迹和复现材料直接收录到仓库。', 'stage123r2-current-selection.json；stage123r2-REPRODUCE.txt；SHA256SUMS.stage123r2.public.txt', '本地完整压缩包继续保留；镜像、压缩包及其解压副本不重复提交。')
    by_id['V06']['后续直接指令'] = '按本次要求提交当前结果，排除镜像、交付副本和无关文件。'
    # Replace stale witness/count references in otherwise unchanged assessments.
    for row in rows:
        row['核对结论'] = row['核对结论'].replace('两个联合见证', '三个联合见证')
        row['证据'] = row['证据'].replace('两个联合见证', '三个联合见证')
    evidence = []
    for run in result['runs']:
        job = run['job']
        level = ('public-full-Stage123' if run['category'] in (*NAMES, 'auxiliary', 'reachability')
                 else metadata[job].get('process_extent', metadata[job]['nature']))
        evidence.append(dict(**run, evidence_level=level, details=metadata.get(job)))
    report = dict(instructions=previous['instructions'], instructions_sha256=previous['instructions_sha256'],
                  baseline=BASE, current_primary_sha256=sha(v.model().encode()),
                  verdict='Current evidence covers the targeted checks at their stated level in the later-authorized twelve-profile domain. Optional ablation was not rerun. Source, selected logs and traces are published directly; delivery archives are retained locally.',
                  current_model_jobs=69, current_query_results=189, executed_witnesses=witnesses,
                  coverage=rows, evidence=evidence,
                  scope_note='12 profiles are representative cases, not exhaustive or established near-complete field-combination coverage. Four early Quote controls use precise prefixes after three real authorizations.')
    save('stage123r2-second-instructions-coverage.json', report)
    csv_file('stage123r2-second-instructions-coverage.csv', rows)
    text = ['第二份说明：补齐后的覆盖对照（Stage123 r2，2026-10-28）',
            '原先列出的专项缺口现已补齐。范围按后续指令固定为12个完整profile，未恢复原文的一般字段组合。',
            '69个当前作业／189条确定结果；层级：5主性质＋14辅助＋3公开联合可达＋29控制场景79查询＋17局部/目录模型86查询＋控制表对照2查询。',
            '29个控制场景中：25个保留完整Stage2–3体；4个保留三方真实授权与精确Evidence检查前缀。',
            '16个局部Stage1模型是检查守卫的控制实验；另1个模型对照12项目录join。不得把控制测试数当作主性质数。',
            '一般策略组合、任意诚实配置/参与方数量/腐化组合不在此次结论内。12-profile不能写成基本覆盖自由组合。',
            '可选消融未重跑；当前原始证据直接收录仓库，不重复提交本地压缩包。论文附件未修改。', '']
    for row in rows:
        text += [f"{row['编号']} | {row['当前覆盖']}",
                 f"原说明第{row['说明起始行']}行：{row['原要求摘录']}",
                 '核对：' + row['核对结论'], '证据：' + row['证据']]
        if row['未覆盖或待补']: text.append('范围/解释：' + row['未覆盖或待补'])
        if row['后续直接指令']: text.append('后续指令：' + row['后续直接指令'])
        text.append('')
    (REPORTS / 'stage123r2-second-instructions-coverage.txt').write_text('\n'.join(text) + '\n')
    csv_file('stage123r2-field-domains.csv', previous['field_domains'])
    return report


def development_inventory(selection):
    # A published checkout deliberately contains only the selected runs.
    # Read the recorded development summary rather than deriving a different
    # history from whichever local prototype files happen to be present.
    inputs = json.loads((ROOT / 'models/stage123r2-report-inputs.json').read_text())
    assert sum(map(len, selection.values())) == 69
    save('stage123r2-development-summary.json', inputs['development_summary'])


def main():
    result = json.loads((REPORTS / 'stage123r2-results.json').read_text())
    metadata = json.loads((REPORTS / 'stage123r2-control-expectations.json').read_text())
    selection = json.loads((REPORTS / 'stage123r2-current-selection.json').read_text())
    audit_result = audit(result, metadata)
    profiles = profile_coverage()
    witnesses = executed_witnesses(result)
    development_inventory(selection)
    coverage(result, metadata, witnesses)
    main_rows = [r for r in result['current_results'] if r['category'] in NAMES]
    timings = {r['category']: r['elapsed_seconds'] for r in main_rows}
    print(json.dumps(dict(jobs=len(result['runs']), queries=len(result['current_results']),
                          source_checks=len(audit_result['checks']), main_seconds=timings,
                          witnesses=[w['actual_P3_profile'] for w in witnesses],
                          catalog_join_outcomes=profiles['distinct_successful_catalog_joins']), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
