# Q1：SRAS-FT 认证开销验证

## 研究问题

**Q1: What is the attestation overhead introduced by SRAS-FT?**

比较原 SRAS 与 SRAS-FT：在 TEE 证书签发（`generate_ce_certificate`）之前，增加 **state propagation** 与 **echo verification** 后，总延迟增加多少。

---

## 实验设计

| 组别 | RPE 配置 | 发证前额外步骤 | 对比指标 |
|------|----------|----------------|----------|
| **Baseline（原 SRAS）** | `ft.enabled = false` | 无 FT propagation | `auth_total` |
| **SRAS-FT** | `ft.enabled = true`，配置 peer | state propagation + echo quorum | `auth_total`、`ft_state_propagation`、breakdown 各列 |

两组使用 **相同的 party 数量、P2P 传输、CE 数量**，仅 FT 开关不同。建议各跑 **≥5 次 CE 认证** 取平均。

---

## 前置条件

1. 已在 SGX 机器上完成 RPE / RPO / CE 的 **build**（含 SRAS-FT 代码）。
2. 各 party 的 **collaterals**、**QEID** 已按主 README 配置。
3. 本机 loopback 多 party 测试时，推荐 **P2P** 作为 Phase 2 quote 交换通道（无需 Fabric 网络）。

---

## 一、环境搭建

### 1. Build（每个 party 只需 build 一次模板）

```bash
cd RPE && ./startup.sh build
cd ../RPO && ./startup.sh build
cd ../CE  && ./startup.sh build
```

### 2. 生成多 party 目录

**SRAS-FT 组**（开启 FT）：

```bash
python3 performance/setup_multi_party.py \
  --num-parties 5 \
  --transport p2p \
  --p2p-port 51051 \
  --ft-enabled
```

**Baseline 组**（关闭 FT，去掉 `--ft-enabled`）：

```bash
python3 performance/setup_multi_party.py \
  --num-parties 5 \
  --transport p2p \
  --p2p-port 51051
```

会生成 `RPO_party*`、`RPE_party*`、`fabric_client_party*`（P2P 模式下 fabric client 不参与 Phase 2，但目录仍会创建）及对应的 `policies-N.json`。

### 3. 配置 CE（连到发证 RPE，默认 RPE_party1 / 端口 4455）

```bash
python3 performance/setup_multi_ce.py \
  --num-ces 3 \
  --rpe-address 127.0.0.1 \
  --rpe-port 4455
```

生成 `CE_party1` … `CE_party3`，均向 **rpe-1** 申请证书。

---

## 二、启动顺序（重要）

按以下顺序启动，并 **等待所有 RPE 完成 Phase 1 + Phase 2** 后再触发 CE 认证：

```bash
# 终端 1：P2P quote 交换
python3 performance/start_multi_p2p.py --num-parties 5 --base-port 51051

# 终端 2：RPO
python3 performance/start_multi_rpo.py --num-parties 5

# 终端 3：RPE（会阻塞运行）
python3 performance/start_multi_rpe.py --num-parties 5
```

**就绪检查**（以 RPE_party1 为例）：

```bash
grep -E "Phase two|quorum|Phase 3|pre_init_ready" RPE_party1/logs/rpe_party1.log | tail -20
```

确认 5 个 RPE 均完成 Phase 2、进入 Phase 3 待命后再继续。

> **常见坑**：RPE / P2P 未完全就绪时 CE 连上，会出现 `quorum not reached`、`DEADLINE_EXCEEDED`、CE 侧 `Invalid certificate length: 0` 并多次重试。务必等 Phase 2 完成。

---

## 三、采集性能数据

### 1. 先启动采集脚本（`--repeat` 模式）

在 **触发 CE 认证之前** 启动，脚本会阻塞等待新增认证条数：

```bash
# SRAS-FT 组示例
python3 performance/phase3_performance_test.py \
  --repeat 5 \
  --perf-dir performance_data/q1_ft_n5 \
  --rpe-dir RPE_party1
```

```bash
# Baseline 组示例（换输出目录）
python3 performance/phase3_performance_test.py \
  --repeat 5 \
  --perf-dir performance_data/q1_baseline_n5 \
  --rpe-dir RPE_party1
```

**`--repeat N` 语义**：

- 累计采集 **N 次新的 CE 认证**（不论一次启动几个 CE）。
- **不清空** RPE 历史 perf 数据；启动时记录 `baseline_count`，等总条数达到 `baseline_count + N` 后，只取新增的 N 条写入报告。
- 默认读取 `RPE_party1/performance_data/rpe_phase3_perf_rpe-1.json`；可用 `--rpe-dir` 指定发证 RPE。

### 2. 再触发 CE 认证

另开终端：

```bash
python3 performance/start_multi_ce.py --num-parties 3
```

或手动进入各 `CE_party*` 执行 `./startup.sh start`。每完成一次向 RPE1 的成功认证，发证 RPE 的 perf JSON 会追加一条记录。

采集脚本凑满 N 条后自动退出，并生成报告。

---

## 四、输出报告

报告写在 `--perf-dir` 下：

| 文件 | 说明 |
|------|------|
| `state_update_report.txt` | 人类可读摘要 + breakdown 表 |
| `state_update_report.csv` | 表格数据 |
| `state_update_report.xlsx` | Excel（需 `openpyxl`） |
| `state_update_report.json` | 完整原始数据 |

### Breakdown 表列说明

每行 = 一次 CE 认证：

| 列名 | 含义 |
|------|------|
| `counter` | FT attestation counter |
| `ce_id` | CE 标识 |
| `bottleneck_peer` | 本次认证中 `rpc + verify_echo` 最大的 peer（同源取值，避免混用不同 peer 的 MAX） |
| `auth_total` | 单次认证总耗时（含 quote 验证、FT、发证） |
| `quote_verify` | CE DCAP quote 验证（`stage3_native_quote_verification`，FT 之前） |
| `rpc(incl.remote.veri+record)` | 向 bottleneck peer 发 `StateUpdate` 的 gRPC 往返（**含**网络 + 远端处理） |
| `remote.veri+record` | 远端 `verify_state_signature + record_state`（**已包含在 rpc 列内**，不可与 rpc 相加） |
| `verify_echo` | RPC 返回后，本端验证 echo 签名（与 rpc **串行**，在 rpc 之外） |

### 计时边界（发证 RPE 侧）

```
ce_auth_start
  ├─ perform_handshake + verify_peer     → quote_verify
  ├─ get_ce_info + verify_ce_body      → policy（通常接近 0）
  ├─ propagate_attestation_state()       → ft_state_propagation / breakdown
  │     ├─ local sign state + echo
  │     ├─ rpc(incl.remote.veri+record)  → 对每个 peer 并行，取 bottleneck
  │     └─ verify_echo                   → RPC 返回后本端验 echo
  ├─ generate_ce_certificate()         → 计入 auth_total，未单独列
  └─ send_ce_cert()
ce_auth_end                              → auth_total
```

### Q1 结论怎么算

- **FT 额外开销（墙钟）**：对比两组 `ft_state_propagation_duration` 平均值；Baseline 组该值应为 0 或不存在。
- **FT 额外开销（占 auth_total）**：`avg(ft_state_propagation) / avg(auth_total)`（仅 FT 组）。
- **细分**：看 breakdown 中 `rpc(incl.remote.veri+record)` 与 `verify_echo` 的 avg/min/max。

---

## 五、对比 Baseline 与 SRAS-FT

1. 分别跑完 Baseline 与 FT 两组，得到 `performance_data/q1_baseline_n5/` 与 `performance_data/q1_ft_n5/`。
2. 对比两目录下 `state_update_report.txt` 的 Summary，或 Excel/CSV 中的 `auth_total`、`quote_verify` 等列。
3. **FT overhead ≈ FT 组 `auth_total` 均值 − Baseline 组 `auth_total` 均值**（两组 CE 数量、party 数、网络条件应一致）。

如需保留原始 perf 快照以便事后重算，可复制发证 RPE 的 perf 文件：

```bash
cp RPE_party1/performance_data/rpe_phase3_perf_rpe-1.json \
   performance_data/q1_ft_n5/rpe_phase3_perf_snapshot.json
```

---

## 六、故障排查

| 现象 | 可能原因 | 处理 |
|------|----------|------|
| CE 多次失败后才成功 | FT quorum 未凑够，RPE 拒绝发证 | 确认 5 个 RPE Phase 2 完成；查 `RPE_party1/logs/rpe_party1.log` 是否有 `quorum reached` |
| `DEADLINE_EXCEEDED` | 某 peer FT gRPC 超时（默认 3s） | 查对应 `RPE_party*/logs/` 是否有 `StateUpdate accepted` |
| `invalid echo: signature verification failed` | peer 公钥与签名密钥不一致 | 重新 setup + 完整跑 Phase 2，勿混用旧 `RPE_party*` 目录 |
| 采集脚本超时 | CE 认证次数不足 | 多启动几次 CE，或增大 `--repeat` 前确认 CE 能连上 RPE |
| breakdown 列为 N/A | perf JSON 无 `ft_state_propagation_timings` | 确认 RPE 为 FT 开启版本且本次认证走了 propagation |

---

## 七、停止服务

```bash
python3 performance/start_multi_ce.py --num-parties 3    # Ctrl+C 停 CE
python3 performance/start_multi_rpe.py --num-parties 5 --stop
python3 performance/start_multi_rpo.py --num-parties 5 --stop
python3 performance/start_multi_p2p.py --num-parties 5 --stop
```

---

## 相关脚本

| 脚本 | 作用 |
|------|------|
| `setup_multi_party.py` | 复制并配置多 party RPO/RPE（`--ft-enabled` 控制 FT） |
| `setup_multi_ce.py` | 复制并配置多 CE |
| `start_multi_p2p.py` | 启动 P2P quote 交换 |
| `start_multi_rpo.py` | 启动多 RPO |
| `start_multi_rpe.py` | 启动多 RPE |
| `start_multi_ce.py` | 启动多 CE |
| `phase3_performance_test.py` | Phase 3 性能测试；Q1 使用 `--repeat` 模式 |
| `q2_ft_recovery_test.py` | Q2 recovery 采集 + 报告（合并原 `ft_recovery_report.py`） |

原始 perf 数据来源：`RPE_party1/performance_data/rpe_phase3_perf_rpe-1.json`（由 `RPE/relying_party_enclave/rpe.py` 写入）。

---

# Q2：Failed RPE Recovery 延迟验证

## 研究问题

**Q2: How efficiently can SRAS-FT recover a failed RPE?**

测 RPE crash/restart 后，recovering RPE 执行 Recovery query → Evidence Quote 验证 → Signed state 验证 → 选最大 ACj → 重新广播 Quote 的总耗时。

堆叠柱图字段（毫秒）：

`recovery_query` | `evidence_quote_verification` | `signed_state_verification` | `counter_selection` | `new_quote_generation` + `new_quote_broadcast`

## 前置条件

1. 多 party FT 环境已跑通，且 **已做过若干次 CE 认证**（peer 通过 `StateUpdate` 记录了 failed RPE 的 state）。
2. 待恢复 RPE 上存在 **`expt_cache.json`**（首次正常 startup 后写入）。
3. **不要用** `start_multi_rpe.py --stop` 模拟 crash——它会删除 `expt_cache.json`。

## 采集（`--repeat` 模式）

先启动采集脚本，再对每个 repeat 执行一次 kill + restart：

```bash
python3 performance/q2_ft_recovery_test.py \
  --repeat 3 \
  --rpe-dir RPE_party1 \
  --perf-dir performance_data/q2_n5 \
  --label n5
```

对每个 repeat：

```bash
# 模拟 crash（示例：按 RPE_party1 端口 kill，勿用 start_multi_rpe --stop）
kill $(lsof -ti :4455)

# 重启 recovering RPE（自动执行 recovery 并写 perf JSON）
cd RPE_party1 && ./startup.sh start
```

脚本会：

- 监视 `RPE_party1/performance_data/rpe_ft_recovery_perf_*.json` 的内容变化
- 每次新 recovery 快照到 `performance_data/q2_n5/recovery_runs/run_XXXX.json`
- 凑满 N 次后生成报告

## 输出

| 文件 | 说明 |
|------|------|
| `recovery_runs/run_*.json` | 每次 recovery 快照 |
| `q2_recovery_session.json` | 本次采集元数据 + 原始结果 |
| `q2_ft_recovery_report.{txt,csv,json}` | 汇总（avg over N runs） |

## 仅生成报告

对比不同 N（2/4/8）时，从已有目录汇总：

```bash
python3 performance/q2_ft_recovery_test.py \
  --input n3=RPE_party1/performance_data \
  --input n5=RPE_party5/performance_data \
  --output-dir performance_data/q2
```

或从已采集的 `--perf-dir`：

```bash
python3 performance/q2_ft_recovery_test.py \
  --report-only \
  --perf-dir performance_data/q2_n5 \
  --label n5
```

## 指标说明

- `new_quote_broadcast_ms`：仅计 **非阻塞** 发起 `EvidenceUpdate` 广播，不等 peer 确认。
- `evidence_quote_verification_ms` / `signed_state_verification_ms`：对 quorum 内各有效 response **求和**，非单 peer max。

原始 perf 写入：`RPE_partyX/performance_data/rpe_ft_recovery_perf_{rpe_id}.json`（每次 recovery **覆盖**；采集脚本负责快照留存）。
