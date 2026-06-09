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

测 RPE crash/restart 后，recovering RPE 在 **RecoveryQuery quorum 达成且 counter 选中** 的耗时（`recovery_success_ms` / `total_recovery_ms`）。

**Q2 主指标（毫秒）**：`recovery_success_ms`（不含 warmup、quorum 后慢 peer 等待、new quote、EvidenceUpdate dispatch）

**辅助 / 诊断**：

| 字段 | 含义 |
|------|------|
| `warmup_elapsed_ms` | Recovery 前 FT Ping 预热 |
| `full_query_collection_ms` | RecoveryQuery 全线程结束（可能晚于 quorum） |
| `evidence_quote_verification_ms` | quorum 内各 response 的 Phase2 quote 验签 **求和** |
| `signed_state_verification_ms` | quorum 内 signed_state 验签 **求和** |
| `counter_selection_ms` | 选 max counter |
| `new_quote_generation_ms` | **recovery 之后**，不计入 Q2 |
| `new_quote_broadcast_ms` | **recovery 之后** 非阻塞 dispatch，不计入 Q2 |

## 前置条件

1. 已完成 **build + setup**（5 方 FT + P2P 示例见上文「一、环境搭建」）。
2. P2P / RPO / **全部 RPE** 已启动，且 5 个 RPE 均完成 Phase 2（见上文「二、启动顺序」就绪检查）。
3. **已做过若干次 CE 认证**（peer 通过 `StateUpdate` 记录了 failed RPE 的 state）：

```bash
python3 performance/setup_multi_ce.py --num-ces 3 --rpe-address 127.0.0.1 --rpe-port 4455
python3 performance/start_multi_ce.py --num-ces 3
```

4. 待恢复 RPE（默认 `RPE_party1` / `rpe-1`）上存在 **`expt_cache.json`**：

```bash
ls RPE_party1/performance_data/expt_cache.json
# 或 RPE_party1/collaterals/expt_cache.json
```

5. **不要用** `start_multi_rpe.py --stop` 模拟 crash——它会删除 `expt_cache.json`。

默认端口（`setup_multi_party.py` 默认 `--base-rpe-port 4455`）：

| Party | 目录 | RPE ID | RA-TLS 端口（CE 连接） |
|-------|------|--------|------------------------|
| 1 | `RPE_party1` | rpe-1 | **4455** |
| 2 | `RPE_party2` | rpe-2 | 4456 |
| 3 | `RPE_party3` | rpe-3 | 4457 |
| 4 | `RPE_party4` | rpe-4 | 4458 |
| 5 | `RPE_party5` | rpe-5 | 4459 |

FT control 端口（`--ft-base-port 56001`）：party *i* → `56000 + i`。

---

## 完整测试流程（5 方 FT 示例）

在仓库根目录执行（下文以 `SRAS` 为根目录）。

**终端 1–3**：环境与 Q1 相同，保持 P2P / RPO / `start_multi_rpe.py --num-parties 5` 运行（**不要** `--stop`）。

**终端 4**：先启动 Q2 采集（会阻塞等待 N 次 recovery）：

```bash
cd SRAS

python3 performance/q2_ft_recovery_test.py \
  --repeat 3 \
  --rpe-dir RPE_party1 \
  --perf-dir performance_data/q2_n5 \
  --label n5
```

**对每个 repeat**（共 3 次），在 **终端 5** 模拟 crash 并单独重启 recovering RPE：

```bash
cd SRAS

# 1) 确认 rpe-1 正在监听 4455（可选）
lsof -i :4455

# 2) 模拟 crash：只杀 rpe-1 的 RA-TLS 进程，勿用 start_multi_rpe --stop
#    若 lsof 无输出，说明 rpe-1 已不在运行，可直接执行下面的 restart
kill $(lsof -ti :4455)

# 若普通 kill 无效，再试：
# kill -9 $(lsof -ti :4455)

# 3) 单独重启 recovering RPE（启动后会自动跑 FT recovery 并写 perf JSON）
cd RPE_party1
./startup.sh start
```

等价写法（显式 `gramine-sgx`）：

```bash
cd SRAS/RPE_party1
gramine-sgx python relying_party_enclave/rpe.py
```

说明：

- 其余 party（`RPE_party2`…`5`）继续由 **终端 3** 的 `start_multi_rpe.py` 保持在线，**不要** 整体停掉。
- 每次 restart 成功后，日志中应出现 `====== SRAS-FT recovery QUORUM OK` 与 `====== SRAS-FT RECOVERY TIMING SUMMARY`。
- **终端 4** 采集脚本检测到新的 `rpe_ft_recovery_perf_rpe-1.json` 后会打印 `Captured recovery run …`。
- 凑满 `--repeat 3` 后，终端 4 自动生成报告并退出。

---

## 仅重新生成报告（已测完、不重跑 recovery）

```bash
cd SRAS

python3 performance/q2_ft_recovery_test.py \
  --report-only \
  --perf-dir performance_data/q2_n5 \
  --label n5

cat performance_data/q2_n5/q2_ft_recovery_report.txt
```

对比不同 N（例如 n3 vs n5）：

```bash
python3 performance/q2_ft_recovery_test.py \
  --input n3=performance_data/q2_n3 \
  --input n5=performance_data/q2_n5 \
  --output-dir performance_data/q2_compare
```

---

## 输出文件

| 文件 | 说明 |
|------|------|
| `recovery_runs/run_*.json` | 每次 recovery 快照 |
| `q2_recovery_session.json` | 本次采集元数据 + 原始结果 |
| `q2_ft_recovery_runs.csv` | **每次 run 全字段 + 最后一行 AVG** |
| `q2_ft_recovery_report.txt` | 可读报告（含 All runs 表 + 按 label 汇总） |
| `q2_ft_recovery_report.csv` | 按 label 的平均汇总 |
| `q2_ft_recovery_report.json` | `summary` + `runs` + `detail_with_avg` |

报告 **All runs** 表：每一行是一次 recovery；**最后一行 `AVG`** 为各列平均值。Q2 主指标看 **`Recovery Success`** 列（= `recovery_success_ms`）。

---

## 指标说明

- **Q2 答案**：`Recovery Success` / `recovery_success_ms` / perf JSON 里的 `total_recovery_ms`（三者相同）。
- **不含**：`warmup_elapsed_ms`、`full_query_collection_ms`（quorum 后慢 peer）、`new_quote_generation_ms`、`new_quote_broadcast_ms`。
- `full_query_collection_ms` 可能远大于 `recovery_success_ms`（quorum 后仍在等慢 peer 验 DCAP）。
- `new_quote_broadcast_ms`：仅非阻塞 dispatch；peer DCAP 验新 quote 推迟到 CE 连接时。
- `evidence_quote_verification_ms` / `signed_state_verification_ms`：quorum 内各 response 耗时 **求和**，不是墙钟堆叠。

原始 perf 写入：`RPE_partyX/performance_data/rpe_ft_recovery_perf_{rpe_id}.json`（每次 recovery **覆盖**；采集脚本负责快照到 `recovery_runs/`）。
