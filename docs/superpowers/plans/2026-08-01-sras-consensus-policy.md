# SRAS Consensus Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 JSON 策略键名上实现 SPEC 四分量 join（τ/ι/β），Stage2 先互证再交换 ρ 得 π\*，Stage4 证书携带并比对 `H(π*)`。

**Architecture:** 纯本地 `consensus_policy.py` 负责 canonicalize / join / hash；`policies.py` 适配新语义（`job` 无 tcb，`ce.tcb_allowed` 单值，`connection` 引 ce id）；Phase2 改造 Evidence Quote（`policy_hash`、新 report_data）并在 quote 信道上交换完整 ρ；证书扩展挂 `H(π*)`。FT 本轮不改。

**Tech Stack:** Python 3、SHA-384、现有 gRPC quote 信道（P2P/Fabric）、cryptography x509

**Spec:** `docs/superpowers/specs/2026-08-01-sras-consensus-policy-design.md`  
**SPEC:** `docs/consensus/SRASConsensusPolicySPEC.md`

---

## File map

| Path | Role |
|------|------|
| `RPE/relying_party_enclave/consensus_policy.py` | **Create:** canonicalize / hash / join / JoinError / report_data helpers |
| `tests/test_consensus_policy.py` | **Create:** SPEC §9.1–9.2 + FMSPC/单值约束 |
| `RPE/relying_party_enclave/policies.py` | CE tcb 从 `ce[]`；job 纯 β；connection→ce |
| `RPO/policies.json.template` | 新语义模板 |
| `RPE/relying_party_enclave/grpc_client.py` + P2P/Fabric | `sendPolicy` / `queryPolicyByIds`（仿 quote） |
| `RPE/relying_party_enclave/rpe.py` | Phase2 Evidence Quote + exchange + join；Phase3 用 π\*；埋点 |
| `RPE/relying_party_enclave/certificate.py` | 扩展写/读 `consensus_policy_hash` |
| setup / multi-party 生成脚本 | 同 ρ 评估 / 异 ρ 功能用例（若触及） |

---

### Task 1: ✅ `consensus_policy` 核心 + 单测

**Files:**
- Create: `RPE/relying_party_enclave/consensus_policy.py`
- Create: `tests/test_consensus_policy.py`

- [ ] **Step 1: 写失败单测**（ι Any⊔Exact / Exact 冲突 ⊥；τ status+evalNumber 同 FMSPC；跨 FMSPC → JoinError；`tcb_allowed` len≠1 非法；β 同 CE 双 RPE ⊥；顺序无关确定性；report_data 64B）
- [ ] **Step 2: 实现最小通过代码**
  - `JoinError` 可序列化
  - `canonicalize_policy` / `hash_policy`（SHA-384）
  - TCB 内容寻址；改写引用
  - `tcbEvaluationDataNumber`：优先条目字段，否则尝试解析 `data` JSON，否则 0
  - `join_policies` / `compute_consensus`
  - `build_evidence_report_data(pk_s_pem, policy_hash_bytes)` → `SHA384(PK_s‖Hρ)‖0x00*16`
  - 合法性：`tcb_allowed` 恰好 1；实体指派同 FMSPC
- [ ] **Step 3: 跑通** `python -m pytest tests/test_consensus_policy.py -q`
- [ ] **Step 4: 不自动 commit**（除非用户要求）

---

### Task 2: ✅ 策略模板与 `policies.py` 适配

**Files:**
- Modify: `RPO/policies.json.template`
- Modify: `RPE/relying_party_enclave/policies.py`

- [ ] 模板：`job` 去掉 `tcb_allowed`；`ce` 加单值 `tcb_allowed` + tcb `min_status`；`rpe.tcb_allowed` 单值；`connection` 引 ce id
- [ ] `getCETCBINFO` / `getCETcbIds` / `getAllCEinfo` 等改为读 `ce[].tcb_allowed`
- [ ] `getCorrespondingJobs`：connection 按 ce id 解析，再映射到 job
- [ ] 兼容旧 `job.tcb_allowed`：警告并回退（过渡）
- [ ] 跑现有相关单测确认无回归

---

### Task 3: ✅ 策略交换 API（复用 quote 信道）

**Files:**
- Modify: `performance/p2p_quote_exchange.py`
- Modify: `RPE/relying_party_enclave/grpc_client.py`
- Fabric 路径对齐（若评估仍用）

- [ ] `sendPolicy` / `queryPolicyByIds`：P2P 独立 policies map；优先复用现有 RPC 信封或仿 SendQuote 载荷
- [ ] 冒烟：两节点收发

---

### Task 4: ✅ Stage2 Evidence Quote + exchange + join

**Files:**
- Modify: `RPE/relying_party_enclave/rpe.py`

- [ ] Evidence Quote：加 `policy_hash`；去掉 PK_e；验 peer 用信封重建 report_data
- [ ] 新 64B report_data；FT 路径本轮最小适配以保持可运行
- [ ] 互证后 exchange ρ → hash 校验 → `compute_consensus` → 存 π\* / H(π*)
- [ ] JoinError → `negotiation_abort`；埋点 `t_exchange` / `t_join`

---

### Task 5: ✅ Phase3 Attest + Stage4 证书 `H(π*)`

**Files:**
- Modify: `certificate.py`, `rpe.py`

- [ ] 证书扩展写入 `consensus_policy_hash`
- [ ] 验证时比对本地 H(π*)
- [ ] Phase3 Attest 读 π\*

---

### Task 6: ✅ (setup/tests; full e2e SGX pending env) setup / 验收

- [ ] 同 ρ 评估可跑；异 ρ / 冲突用例
- [ ] 更新 design 文档状态

## 约束备忘

- `tcb_allowed` 单值；同实体同 FMSPC
- Stage2 不另开 H(π*) 等齐轮；FT 本轮不动
- **不要自动 git commit**，除非用户明确要求
