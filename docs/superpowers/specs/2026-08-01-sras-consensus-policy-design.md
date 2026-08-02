# SRAS Consensus Policy（π\*）实现设计

> 日期：2026-08-01  
> 依据：`docs/consensus/SRASConsensusPolicySPEC.md` + 与用户对齐的工程约束  
> 状态：实现中（核心 join / Stage2 / 证书扩展已落地）

---

## 1. 目标与非目标

### 1.1 目标

1. 在现有 JSON 策略形态上对齐 SPEC 四分量语义（τ / ι / β）。
2. Stage2：**先互证 Evidence Quote，再交换完整 ρ，本地 join 得 π\***。
3. Phase3 实例认证按 π\* 执行（β + τ + ι）。
4. Stage4（CE 换证 / RPE 验证书）比对证书中的 `H(π*)`，确认各方共识一致。
5. 功能测试可用不同 ρ_i；评估测试可各方 ρ 相同（join ≈ 恒等）。
6. 提供 join 单测与阶段埋点。

### 1.2 非目标

- SRAS-FT 冗余、recovery、FT 传播（本轮不改）。
- `cust_qeid_allowed` 进入 join。
- enclave 内直接解析 YAML。
- Stage2 为 `H(π*)` 另开 RPE↔RPE 等齐轮（一致性放 Stage4 证书）。

---

## 2. 已拍板决策摘要

| 项 | 决定 |
|----|------|
| 协议顺序 | 先互证，后交换 ρ，再 join |
| 策略格式 | JSON；**保留旧键名** |
| `job` | 纯 β：仅 `id` + `rpe` + `ce`；**禁止** `tcb_allowed` |
| 原 `job.tcb_allowed` | 挪到对应 **`ce[].tcb_allowed`** |
| `rpe` | 即 Trusted Entities（含 `tcb_allowed`）；不另拆表 |
| `connection` | 业务拓扑；引用改为 **ce id**；不参与 join / Attest |
| `tcb_allowed` | **单值指派**（数组形态可保留，但 `len == 1`，对应 SPEC `Map<EntityId, EntryId>`） |
| TCB FMSPC 约束 | **策略输入合法性**：同一实体（rpe/ce）所引用 TCB Entry 的 FMSPC 必须相同；跨方 join 时若两边指派不同 FMSPC → 视为非法输入 / `JoinError`（或拒绝该策略），不得用 `tcbEvaluationDataNumber` 跨 FMSPC 比强弱 |
| τ stronger | 仅在 **同一 FMSPC** 内：先比 `min_status`，平手比 `tcbEvaluationDataNumber`；内容寻址后 id 相同则合并 |
| report_data / Evidence Quote | Evidence Quote 显式带 `policy_hash=H(ρ_i)`；**去掉** PK_e。**report_data（64B）**：`SHA384(PK_s ‖ H(ρ_i))`（48B）再零填充至 64B，完整绑进 quote（修复原 96B 截断只验策略哈希前 16B 的问题）。验 peer 用信封 `PK_s`+`policy_hash` 重建，不用本地策略哈希 |
| qeid | 评估沿用现逻辑；不进 join |
| 策略交换 | 复用现有 quote 信道（P2P/Fabric） |
| `H(π*)` 一致性 | **Stage4**：写入 CE 证书扩展 / Verification Report 新字段后比对 |
| Stage2 不为 `H(π*)` 另开等齐轮 | 本地算完只存储；避免加重 `phase2_exchange` |
| `min_status` | collateral 验 Quote 后取 status 与 `min_status` 比；**第一期：status < min_status 仍接受**（打日志，便于 debug） |
| 评估 | 各方 policy 可相同 |

---

## 3. 策略 JSON 语义（旧键名）

```text
tcb[]           TCB Entries：id, data(钉住 collateral), min_status, **fmspc（必填，用于合法性/stronger）**
rpe[]           Trusted Entities + 工程字段：id, tcb_allowed（**恰好 1 个 id**）, qeid_allowed, ca_signing_key_cert, ...
rpe_info        全局 RPE 代码 pin（沿用）
ce[]            TEE Instances：身份约束 ι + tcb_allowed（**恰好 1 个 id**）+（可选）qeid_allowed
job[]           Attesting TEE / β：id, rpe, ce   ← 无 tcb_allowed
connection[]    server/clients 引用 ce id
```

### 3.1 完整示例（ρ_i）

```json
{
  "session_id": "uuid-collab-001",
  "description": "party expectation policy",
  "rpe_info": {
    "mrenclave": "<hex>",
    "mrsigner": "<hex>",
    "isv_prod_id": "0",
    "isv_svn": "0"
  },
  "tcb": [
    {
      "id": "tcb-1",
      "fmspc": "fmspc-1",
      "min_status": "UpToDate",
      "data": "<pinned collateral>"
    },
    {
      "id": "tcb-2",
      "min_status": "UpToDate",
      "data": "<pinned collateral>"
    }
  ],
  "rpe": [
    {
      "id": "rpe-1",
      "tcb_allowed": ["tcb-1"],
      "qeid_allowed": ["feea1a922f97aee4d98e431a1068761a"],
      "ca_signing_key_cert": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    },
    {
      "id": "rpe-2",
      "tcb_allowed": ["tcb-2"],
      "qeid_allowed": ["feea1a922f97aee4d98e431a1068761a"],
      "ca_signing_key_cert": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ],
  "ce": [
    {
      "id": "ce-1",
      "mrenclave": "<hex>",
      "mrsigner_allow_any": true,
      "isvprodid_allow_any": true,
      "isvsvn_allow_any": true,
      "tcb_allowed": ["tcb-1"],
      "qeid_allowed": ["feea1a922f97aee4d98e431a1068761a"]
    },
    {
      "id": "ce-2",
      "mrenclave": "<hex>",
      "mrsigner": "<hex>",
      "isv_prod_id": "42",
      "isvsvn_minimum": 3,
      "tcb_allowed": ["tcb-2"]
    }
  ],
  "job": [
    { "id": "job-1", "rpe": "rpe-1", "ce": "ce-1" },
    { "id": "job-2", "rpe": "rpe-2", "ce": "ce-2" }
  ],
  "connection": [
    {
      "id": "connection-1",
      "server": "ce-1",
      "clients": ["ce-2"]
    }
  ]
}
```

> **注：** `tcb_allowed` 仅为单元素数组（如 `["tcb-1"]`）。跨策略 join 时，同一 `rpe-1`/`ce-1` 所引用 Entry 的 `fmspc` 必须一致。

---

## 4. 协议流程

```
Phase1  RPO → 本方 RPE 下发 ρ_i（可含多方条目 = 本方期望）
Phase2a 交换 Evidence Quote（含 quote、PK_s、policy_hash=H(ρ_i)；不含 PK_e）
        → 用 peer 的 PK_s + 信封 policy_hash 重建 report_data 并验 quote body
Phase2b 互证通过 → 复用 quote 信道交换完整 ρ
        → 校验 SHA384(ρ_j) == Evidence Quote 中的 policy_hash
        → π*, H(π*) = compute_consensus(S)；JoinError → negotiation_abort
        → 本地持久化 π* / H(π*)（Stage2 不互发 H(π*) 等齐）
Phase3  Attest(E)：β=(local_rpe,E)∈π*.job；τ / ι 来自 π*.ce
        → 签发证书，扩展字段写入 H(π*)
Phase4  CE 换证；验证方 RPE 验证书时：
        → 验签 + nonce 等现有逻辑
        → 比较证书中 H(π*) 与本地 H(π*)；不一致则拒绝
```

### 4.1 为何 Stage4 比对 `H(π*)`

- 评估显示 Stage2 瓶颈是 `phase2_exchange`（等齐），再开一轮 RPE↔RPE 等齐会叠加等待。
- 确定性 join 保证「该一致」；Stage4 证书携带 `H(π*)` 让对端观测到一致。
- 代价：不一致发现晚于发证；接受该取舍。

---

## 5. Join / 规范化（纯本地）

### 5.0 TCB 指派约束（v2 定稿）

1. **单值**：每个 `rpe`/`ce` 的 `tcb_allowed` 必须恰好一个 EntryId（JSON 可用单元素数组）。
2. **同 FMSPC**：解析/join 前校验——同一实体在各 ρ 中的 TCB 指派必须属于同一 `fmspc`；违反则拒绝策略或 `JoinError(tcb_fmspc, entity, ...)`，**禁止**跨 FMSPC 用 `tcbEvaluationDataNumber` 比较。
3. **stronger（仅同 FMSPC）**：`min_status` 线性序取高；平手比 `collateral.tcbEvaluationDataNumber` 取大；内容寻址后相同 Entry 则合并。


新建 `RPE/relying_party_enclave/consensus_policy.py`：

- `canonicalize_policy` / `hash_policy`（SHA-384）
- TCB 内容寻址：`entry_id = "tcb-" + SHA384(collateral ‖ min_status)[:16]`，改写引用
- `join_policies` / `compute_consensus`
  - ι：字段 ⊔（Exact 冲突 → ⊥）
  - τ：`tcb_allowed` 单值；先校验各方指派 **FMSPC 相同**（不同则非法/`JoinError`）；同 FMSPC 下取较高 `min_status`，平手比 `tcbEvaluationDataNumber`
  - β：`job` 并集；同一 `ce` 对应多个不同 `rpe` → ⊥
- `JoinError { component, entity, field?, value_a, value_b }`
- `connection` / `qeid` / 工程-only 字段：不参与 join 核心；canonicalize 共识视图剔除非共识字段（实现时固定并单测锁定）

日志三层：`negotiation_abort` / `verification_failure` / `hash_mismatch`。

---

## 6. 验证语义

### 6.1 Phase2 互证（按 ρ_i）与 Evidence Quote

**Evidence Quote JSON（新）：**

```json
{
  "quote": "<base64 SGX quote>",
  "rpe_public_signing_key": "<PEM PK_s>",
  "policy_hash": "<hex or raw bytes encoding of H(ρ_i)>"
}
```

- **不再包含** `rpe_public_encryption_key`（PK_e）。
- `policy_hash` 必须与写入 quote report_data 的策略哈希一致。

**report_data 绑定（64 字节，修复截断）：**

```text
Hρ     = SHA384(ρ_i)                         # 48 bytes；同时写入 Evidence Quote.policy_hash
inner  = SHA384(PK_s ‖ Hρ)                   # 48 bytes；PK_s 为 PEM 字符串字节，‖ 为拼接
report_data = inner ‖ 0x00 * 16              # pad 到 SGX report_data 64 bytes
```

说明：旧实现 `SHA384(keys)‖SHA384(ρ)` = 96B，SGX/C++ 只保留前 64B，策略哈希仅前 16B 进 quote。新布局用单次 SHA384 把 **完整** `H(ρ)` 与 `PK_s` 绑进 48B digest，再 pad 到 64B。

**验证 peer：**

1. DCAP `teeVerifyQuote`（钉住 collateral）。
2. 用 Evidence Quote 中的 `PK_s` + `policy_hash` 按上式重建 `report_data`，做 `sgxVerifyQuoteBody`（**禁止**用本地 `H(ρ_local)`）。
3. 身份 pin（MRENCLAVE 等）按现有/ρ_i 规则。
4. 互证后再收完整 ρ_j，检查 `SHA384(ρ_j) == policy_hash`，失败记 `hash_mismatch`。

`min_status`：QVL/collateral 验 Quote 得到 status 后与策略 `min_status` 比较；**第一期 status < min_status 仍 accept**，打告警日志便于 debug。后续可改为硬失败。

### 6.2 Phase3 Attest（按 π\*）

1. β：`(local_rpe, ce_id) ∈ π*.job`
2. τ：`π*.ce[ce_id].tcb_allowed` → 钉住 collateral + min_status 规则（同上 debug 策略）
3. ι：实例测量 ⊧ `π*.ce[ce_id]` 身份约束

### 6.3 Stage4 证书

- `generate_ce_certificate`（或 Verification Report）新增扩展 OID/字段：`consensus_policy_hash` = `H(π*)`
- `verify_ce_certificate`：在现有验签后比较该字段与验证方本地 `H(π*)`

---

## 7. 代码落点

| 模块 | 改动 |
|------|------|
| `consensus_policy.py` | 新建：canonicalize / join / hash / JoinError |
| `policies.py` + `RPO/policies.json.template` | 新语义；job 无 tcb；ce 带 tcb_allowed；connection→ce |
| `setup_multi_party.py` | 生成符合新语义的 policies；支持同 ρ 评估与异 ρ 功能用例 |
| `grpc_client` + P2P/Fabric | `sendPolicy` / `queryPolicyByIds`（仿 quote） |
| `rpe.py` Phase2 | Evidence Quote 加 `policy_hash`、去 PK_e；report_data=`SHA384(PK_s‖H(ρ))‖pad16`；验 peer 用信封重建；互证后 exchange + join；埋点 `t_exchange` / `t_join` |
| `rpe.py` Phase3 | Attest 读 π\*；签发带 `H(π*)` |
| `certificate.py` | 扩展字段读写 |
| `tests/test_consensus_policy.py` | SPEC §9.1–9.2 矩阵 |
| FT / `ft_control.py` | 本轮不动 |

---

## 8. 实现顺序

1. `consensus_policy` + 单测
2. 模板与 `policies.py` 解析迁移
3. 策略交换 API（复用 quote 信道）
4. Stage2 接入 exchange + join + 本地存 π\*
5. Phase3 Attest + 证书写 `H(π*)`
6. Stage4 验证书比 `H(π*)`
7. setup / 埋点 / 功能与评估用例

---

## 9. 测试与验收

- 单元：ι/τ/β join 矩阵；顺序无关确定性；两类 ⊥ only
- 功能：两方不同 ρ → 期望 π\*；冲突注入 → `JoinError`
- 评估：各方相同 ρ；Stage2 时延 = 原口径 + ρ exchange + join（无额外 H 等齐轮）
- Stage4：证书携带的 `H(π*)` 一致则过；故意改本地 π\* 则拒绝

---

## 10. 用户最终确认项（已并入上文）

1. 证书挂 `H(π*)`：扩展 / Verification Report 新字段  
2. `min_status`：比较但第一期不达标仍接受 + 日志  
3. `connection`：直接引用 ce id  
