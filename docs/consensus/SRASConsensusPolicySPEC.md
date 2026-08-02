# SRAS 共识策略实现 SPEC

> 版本：v1.0（对应论文修订稿 Definition 1 / Definition 2 定稿语义）
> 目标读者：实现工程师 / Codex
> 范围：在现有 SRAS 原型（Gramine LibOS + Intel SGX，Hyperledger Fabric 互证网络）中，实现新版 Expectation Policy 数据模型、共识策略在线 join、以及与 join 语义一致的验证逻辑，并为评估重跑提供埋点。

---

## 1. 背景与目标

现有原型已实现：Quote Verification Tool（`authorizing_rpe()` / `get_collateral()` / `passing_expectation()`）、Authentication Service（`generate_quote()` / `verify_evidence_quote()` / `issue_tee_certificate()` / `verify_tee_certificate()`）、TEE Instance APIs（`generate_tee_evidence()` / `get_tee_certificate()`）。

本次新增/改造：

1. **新版 Expectation Policy 数据模型**（四分量：TCB 指派 τ、身份约束 ι、认证关系 β）；
2. **在线共识形成**：互证后交换完整策略，本地执行确定性 join 函数 F 计算共识策略 π\* 及其哈希 H(π\*)；
3. **验证逻辑对齐**：RPE 互证检查、TEE 实例认证 `Attest(RPE, E, π*)` 全部按新语义执行；
4. **冲突处理**：join 失败（⊥）时产出结构化冲突报告，协议 abort；
5. **评估埋点**：各阶段计时，支持 Table IV / VII / VIII 重跑。

非目标（future work，不在本 SPEC 内）：SRAS-FT 冗余多 RPE 指派、故障恢复、形式化验证。

---

## 2. 数据模型

### 2.1 Expectation Policy（YAML）

每个参与方 P_i 声明一份策略 ρ_i，包含四个段。参考结构（即论文 Listing 1 新结构，ρ_1 示例）：

```yaml
TCB Entries:                        # τ 的值域：命名 TCB 级别库
  - id: tcb-1
    data: <collateral>              # Intel TCB Info + QE Identity，含 tcbEvaluationDataNumber
    min_status: UpToDate            # 枚举：UpToDate | ConfigurationNeeded | OutOfDate
  - id: tcb-2
    data: <collateral>
    min_status: UpToDate

Trusted Entities:                   # RPE 的 τ 指派（身份为全局固定 pin，不序列化）
  - entity: RPE-1
    tcb_allowed: [tcb-1]
  - entity: RPE-2
    tcb_allowed: [tcb-2]

TEE Instances:                      # 实例的 ι 约束 + τ 指派
  - entity: E1
    MRENCLAVE: <32-byte hex>        # 精确值
    MRSIGNER_ALLOW_ANY: True        # 通配 *
    ISVPRODID_ALLOW_ANY: True
    ISVSVN_ALLOW_ANY: True
    tcb_allowed: [tcb-1]
  - entity: E2
    MRENCLAVE_ALLOW_ANY: True
    MRSIGNER: <32-byte hex>
    ISVPRODID: 42
    ISVSVN_MINIMUM: 3               # 阈值 ≥3
    tcb_allowed: [tcb-2]

Attesting TEE:                      # β：纯认证关系，无级别字段
  - id: attesting-1
    RPE: RPE-1
    TEE: E1
  - id: attesting-2
    RPE: RPE-2
    TEE: E2
```

约束：

- `Attesting TEE` 条目**不得**携带 `tcb_allowed`（级别指派只出现在 `Trusted Entities` / `TEE Instances`）。
- 每个 TEE 实例的四个身份字段（MRENCLAVE / MRSIGNER / ISVPRODID / ISVSVN）恰好各出现一次，形式三选一：精确值、`<FIELD>_ALLOW_ANY: True`、（仅 ISVSVN）`ISVSVN_MINIMUM: <uint16>`。
- 自有实体（本方的 RPE 与实例）的约束即 ι^self；对他人实体的约束即 ι^j。解析时按实体归属自动拆分，无需在 YAML 中显式标注。

### 2.2 内存表示（建议）

```text
Policy {
  tcb_entries:   Map<EntryId, TcbEntry>,            // TcbEntry { collateral: Bytes, min_status: Status }
  tcb_assign:    Map<EntityId, EntryId>,            // τ：Trusted Entities ∪ TEE Instances 的 tcb_allowed
  identity:      Map<InstanceId, IdConstraint>,     // ι：IdConstraint = (m, s, p, v)
  attesting:     Set<(RpeId, InstanceId)>,          // β
}
Field  = Any | Exact(Bytes)                          // MRENCLAVE / MRSIGNER / ISVPRODID
SvnField = Any | Min(uint16)                         // ISVSVN
Status = OutOfDate | ConfigurationNeeded | UpToDate  // 线性序：OutOfDate ≺ ConfigurationNeeded ≺ UpToDate
```

### 2.3 满足关系（id ⊧ c）

实例身份 `id = (m, s, p, v)` 满足约束 `c = (cm, cs, cp, cv)`，当且仅当逐字段成立：

- `cm = Any ∨ cm = Exact(m)`；`cs`、`cp` 同理；
- `cv = Any ∨ (cv = Min(k) ∧ v ≥ k)`。

强度序：`Exact ≻ Any`；`Min(k1) ≻ Min(k2) ⇔ k1 ≥ k2`。约束越强，接受集越小。

---

## 3. 规范化与哈希（确定性基石）

H(ρ) 与 F 的确定性依赖**规范化序列化**，所有 RPE 必须对相同输入产出逐位相同的字节流。

规则（`canonicalize_policy`）：

1. **TCB 条目内容寻址**：解析后把每个 TCB 条目的显示名（tcb-1 等）替换为内容哈希 `entry_id = "tcb-" + SHA384(collateral ‖ min_status)[:16]`，并同步改写所有 `tcb_allowed` 引用。显示名仅用于人工阅读，不进入规范化形式。这消除跨策略同名不同内容的歧义。
2. Map 按键名字典序排列；数组按元素规范化字节序排序；整数十进制无填充；字节串小写 hex；UTF-8 编码；无时间戳、无随机字段。
3. `hash_policy(ρ) = SHA384(canonicalize(ρ))`，与 Evidence Quote 中 `H(PK_rpe ∥ H(ρ))` 的计算方式保持一致。

---

## 4. Join 语义（函数 F）

`compute_consensus({ρ_1, …, ρ_n})`：先两两归约 `join_policies(ρ_a, ρ_b)`（⊔ 是最小上界，满足结合律、交换律，归约顺序不影响结果），任一分量产生 ⊥ 则整体返回 `JoinError`。

### 4.1 身份约束 ι（逐实例、逐字段）

对同一实例的约束集合（各方的 ι^self 与 ι^j）逐字段取 ⊔：

```
Any   ⊔ x          = x
Exact(a) ⊔ Exact(b) = Exact(a)   if a == b
                    = ⊥          if a != b        // ⊥ 来源 1：身份精确值冲突
Min(k1) ⊔ Min(k2)  = Min(max(k1, k2))
```

实例只在一方策略中出现时，直接采用该方约束。

### 4.2 TCB 指派 τ（逐实体）

对同一实体的两个指派，先解析为 `(collateral, min_status)`，再取**较高阈值**：

```
stronger(t1, t2): 先比 min_status（线性序），平手比 collateral.tcbEvaluationDataNumber，取大者
```

**τ 的 join 永不产生 ⊥**（阈值语义，总能取高）。TCB 条目不达标属于验证阶段失败，不属于协商失败（见 §7）。

### 4.3 认证关系 β（集合并）

```
β* = β_a ∪ β_b
冲突检查：若同一 TEE 实例在 β* 中关联了两个不同的 RPE → ⊥   // ⊥ 来源 2：认证者指派冲突
```

### 4.4 TCB 条目库合并

`entries* = entries_a ∪ entries_b`（内容寻址后同 id 即同内容，天然可并）。τ 取高后被淘汰的条目仍保留在库中（无害），或可选择做引用回收，二者不影响 H(π\*)——**选定一种并在 SPEC 测试中固定**。

### 4.5 输出

```
π* = (entries*, tcb_assign*, identity*, attesting*)
H(π*) = SHA384(canonicalize(π*))
```

性质（必须成立，纳入测试）：对任意 i，π\* ⪰ ρ_i（no silent downgrade）；实例 E 被接纳 ⟺ 满足所有参与方对 E 的约束（explicit weakest link）。

### 4.6 Join 伪代码

```python
def join_policies(a: Policy, b: Policy) -> Policy | JoinError:
    entries = a.entries | b.entries                      # 内容寻址 union
    assign, identity, attesting = {}, {}, set()

    for e in all_entities(a, b):
        r = [p.tcb_assign.get(e) for p in (a, b) if e in p.tcb_assign]
        assign[e] = r[0] if len(r) == 1 else stronger(*[resolve(p.entries, x) for p, x in zip((a,b), r)]).id

    for inst in all_instances(a, b):
        cons = [p.identity[inst] for p in (a, b) if inst in p.identity]
        joined = fold(join_constraint, cons)             # 任一字段冲突 → JoinError("identity", inst, field, v1, v2)
        if joined is ⊥: return JoinError(...)
        identity[inst] = joined

    attesting = a.attesting | b.attesting
    for inst in instances_of(attesting):
        rpes = {r for (r, i) in attesting if i == inst}
        if len(rpes) > 1: return JoinError("attester", inst, sorted(rpes))

    return Policy(entries, assign, identity, attesting)
```

---

## 5. 验证算法

### 5.1 RPE 互证（`verify_evidence_quote`，VI 阶段）

对收到的每个 peer RPE Evidence Quote `(Quote, PK_rpe, H(ρ_peer))`，按本方策略 ρ_i 执行：

1. **身份 pin（ι 的 RPE 部分）**：Quote 的 MRENCLAVE == 本方 RPE 的 MRENCLAVE（公开 RPE 代码，固定值，不读策略）。
2. **TCB 检查（τ）**：用 ρ_i 中 `tcb_assign[RPE_peer]` 指向条目的**钉住的 collateral**（不是从 PCS 实时拉取）调用 QVL 推导 TCB status，要求 `status ≥ min_status`。
3. **策略绑定**：Quote report data 中的 `H(PK_rpe ∥ H(ρ_peer))` 与随附值一致。

任一失败 → 拒绝该 peer，互证失败。

### 5.2 策略交换与共识形成（新增，`exchange_policies` / `compute_consensus`）

1. 互证全部通过后，经认证信道（Fabric 网络）交换完整策略。**完整策略只在互证过的 RPE 之间交换；其他参与方只见到哈希**。
2. 对收到的每个 ρ_j：规范化后校验 `SHA384(canonical(ρ_j)) == quote 中绑定的 H(ρ_j)`。
3. `π* = compute_consensus({ρ_j} ∪ {ρ_self})`；失败 → 输出冲突报告并 abort（§7）。
4. 本地计算 `H(π*)`；由于 F 对规范化输入确定，所有 RPE 逐位一致（可经信道互换 H(π\*) 做一致性确认，可选）。

### 5.3 TEE 实例认证（`Attest(RPE_k, E, π*)`，VII 阶段）

RPE_k 收到本派对内实例 E 的 Quote（report data 绑定 `H(PK_E)`）后：

1. **β 指派**：`(RPE_k, E) ∈ π*.attesting`，否则拒绝（非指定认证者）。
2. **τ 级别**：用 `π*.tcb_assign[E]` 条目钉住的 collateral 推导 status，`≥ min_status`。
3. **π\*[E] 身份**：E 的 (MRENCLAVE, MRSIGNER, ISVPRODID, ISVSVN) ⊧ `π*.identity[E]`（§2.3）。

三项全过 → `issue_tee_certificate()` 签发证书 `(PK_E, PK_rpe, nonce, RPE 签名)`。

### 5.4 证书验证（信任建立，现有逻辑）

对端实例证书经本方指定 RPE 验证：用互证阶段记录的 peer `PK_rpe` 验签 RPE Verification Report，并检查 nonce 新鲜性。证书仅在当前协作内有效，协作变更即轮换。

---

## 6. API 清单（Authentication Service 新增/调整）

| 函数 | 说明 | 状态 |
|---|---|---|
| `generate_quote()` | report data 绑定 `H(PK_rpe ∥ H(ρ))` | 现有，对齐哈希算法 SHA-384 |
| `verify_evidence_quote()` | §5.1 三步检查 | 改造 |
| `exchange_policies()` | 经 Fabric 认证信道收发完整策略 | **新增** |
| `canonicalize_policy(ρ)` / `hash_policy(ρ)` | §3 | **新增** |
| `compute_consensus({ρ_j})` / `join_policies(a,b)` | §4，含冲突报告 | **新增** |
| `attest_instance(E_quote)` | §5.3 三分量检查（β + τ + π\*[E]） | 改造 |
| `issue_tee_certificate()` / `verify_tee_certificate()` | 现有 | 不变 |
| `get_collateral()` | 配置期获取 collateral 并**写入 TCB Entries 钉住**（含 tcbEvaluationDataNumber） | 改造 |

---

## 7. 错误处理：⊥ 与 Abort

- **⊥ 仅两个来源**：身份精确值冲突（§4.1）、认证者指派冲突（§4.3）。实现中不得引入第三个。
- join 返回 `JoinError { component, entity, field?, value_a, value_b }`，协议 abort，冲突报告呈现给参与方用于线下调和（reconcile 后重启协商）。
- **TCB 不达标不是 ⊥**：协商照常成功，验证阶段（§5.1.2 / §5.3.2）拒绝，表现为 attestation 失败而非 negotiation abort。两层语义必须在代码与日志中区分。
- 策略哈希不匹配（quote 绑定值 ≠ 收悉策略哈希）→ 按策略伪造攻击处理，互证失败并记录。

---

## 8. 协议流程（端到端）

```
1. 配置期（Quote Verification Tool）
   get_collateral() → 配置 ρ_i（TCB Entries 钉 collateral）→ authorizing_rpe() 验证 RPE
   → passing_expectation()  provision ρ_i 给 RPE_i
2. 互证（Mutual Attestation）
   RPE_i 生成 Evidence Quote → 交换 → §5.1 验证
3. 共识形成
   §5.2：交换策略 → 哈希校验 → compute_consensus → π* / H(π*)（或 abort）
4. 实例认证
   各 RPE 对本报实例执行 §5.3 → 签发证书
5. 信任建立
   实例间 RA-TLS 双向证书验证 → 安全信道
```

---

## 9. 测试与验收标准

### 9.1 单元测试（join 规则矩阵）

- ι：`Any⊔Exact`、`Exact⊔Exact`（同/异 → ⊥）、`Min⊔Min` 取 max、Any 全组合；
- τ：status 三档两两取高、平级按 tcbEvaluationDataNumber 取高、跨内容同名条目经内容寻址后正确合并；
- β：并集、同实例同 RPE 幂等、同实例不同 RPE → ⊥；
- 性质：π\* ⪰ ρ_i（随机策略对）；E 被接纳 ⟺ 满足所有方约束。

### 9.2 确定性测试

打乱输入策略顺序、YAML 键序、数组顺序，`canonicalize` 输出与 H(π\*) 逐位一致。

### 9.3 集成测试（两方银行/厂商用例）

- ρ_1 = 论文 Listing 1；ρ_2：E2 自有承诺 `(m2, s2, 42, ≥3)`，tcb-2 同义条目，attesting-2 同指 RPE-2；
- 期望 π\*：`π*[E2] = (m2, s2, 42, ≥3)`，`τ*(E2) = tcb-2` 等价条目，`attesting* ⊇ {(RPE-2,E2)}`；
- 冲突注入：把 ρ_2 中 E2 的 MRENCLAVE 承诺改为不同值 → join 返回 identity 冲突 `JoinError`；
- SGX 端到端：授权 → 互证 → 共识 → E1/E2 认证 → RA-TLS 互通。

### 9.4 评估埋点

在阶段边界打点并输出 CSV（参与方数 N ∈ {1,2,4,6,8,10}，实例数 M ∈ {1..10}）：

- `t_auth`（授权）、`t_quote`（Evidence Quote 生成/交换）、`t_exchange`（策略交换）、`t_join`（compute_consensus）、`t_attest`（单实例认证）、`t_cert`（签发/验证）；
- join 开销单列（预期微秒~毫秒级），互证总时延 = 原口径 + exchange + join，用于 Table IV / Fig 6 重跑；Case Study 两个场景（Table VIII）按原口径复测。

---

## 10. 实现约束与注意事项

1. **collateral 一律使用策略内钉住版本**，禁止验证时实时拉取 Intel PCS（否则破坏确定性与"期望不变则行为不变"）。
2. join 是纯本地计算，不得引入网络 I/O 或系统时间。
3. 哈希统一 SHA-384，签名 ECDSA/SECP384R1（与现有原型一致）。
4. 与现有代码同语言同风格（Gramine enclave 侧的 Authentication Service）；`JoinError` 需可序列化，便于跨 enclave 传输与日志记录。
5. 日志区分三层事件：`negotiation_abort`（⊥）、`verification_failure`（TCB/身份/指派不符）、`hash_mismatch`（策略伪造嫌疑），供安全分析章节与审计（XII-C）引用。
