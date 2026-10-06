# 科研计算溯源与发布系统

在科技战略协作基础服务之上，提供**科研计算全链路溯源、离线事件准入、不可变发布快照与数据撤回影响分析**。
计算科学平台把 AI 生成的候选材料交给实验团队前，系统可以回答三个问题：

1. **这份结果是用哪一版数据、哪份授权、什么模型参数、哪套工作流、在什么环境下、用什么种子算出来的？**
   —— 内容寻址制品 + 逐节点哈希事件链，从结果制品反向复原完整版本组合。
2. **离线节点补交的事件可不可信？**
   —— 按本地序列与哈希链准入；哈希不符、前驱缺失、时钟倒退一律先进隔离区，不污染谱系。
3. **历史发布能否被追溯和标记，而不是被抹掉？**
   —— 发布快照一经引用不可覆盖；数据撤回或校准失效会生成新的影响分析、标记历史发布、
   阻断不合规的后续发布，历史快照始终可复原。

## 目录

- `src/science_strategy_foundation/`
  - `provenance.py`：溯源核心——离线事件准入、隔离区裁定、谱系闭包、发布快照、撤回与影响分析；
  - `nodeclient.py`：离线算力节点本地事件日志（JSONL 持久化、本地序列与哈希链、恢复后补交）；
  - `service.py` / `storage.py` / `audit.py` / `api.py`：主体权限、SQLite 事务、审计链、HTTP 边界；
  - `acceptance.py`：覆盖完整故事线的离线端到端验收。
- `tests/`：48 个单元/接口/验收测试。

## 谱系模型

```
数据集版本(artifact, 授权, 校准) ─┐
模型配置(参数, 权重 artifact) ──┼─► 工作流运行(环境指纹, 随机种子, 有序步骤)
上游制品 ───────────────────────┘                    │
                                          输出制品（候选材料结果）
                                          人工判定（批准/复核/驳回）
```

- **制品内容寻址**：`artifact_id = sha256(字节内容)`，模型权重、数据集内容、结果输出一律不可伪装。
- **事件链**：每个算力节点维护独立的 `(node_id, seq)` 单调序列，事件携带 `previous_hash`，
  准入时重算 `event_hash`；任意篡改都会断链。
- **人工判定**：可挂在 run、run_step 或 artifact 上，与计算谱系一起固化。

## 离线准入与隔离区

节点在断网期间用 `LocalEventLog` 持续记录，恢复后按序补交：

| 异常 | 处置 |
| --- | --- |
| 事件哈希重算不符（载荷被篡改） | 隔离 `hash_mismatch`，内容类异常禁止强制接受 |
| 内容与 `artifact_id` 不符 | 隔离 `hash_mismatch`（内容寻址失败） |
| 序列缺口 / 前驱哈希不衔接 | 隔离 `predecessor_missing` / `chain_break`，缺口补齐后 `rescan` 自动放行 |
| 事件时间早于链尾 | 隔离 `clock_regression`，诚信/管理员查明原因后可附理由强制接受或驳回 |
| 引用了不存在的制品/模型/环境/工作流 | 隔离 `reference_missing` |
| 同一事件重复上传 | 幂等返回原回执；同 id 不同内容则隔离 |

所有隔离、自动放行、人工裁定都会写入全局审计链。

## 发布与撤回

- 发布前对结果制品做**全上游合规闭包检查**：授权是否允许公开、数据集是否撤回、
  是否存在撤回/校准通告、模型校准是否有效，任一不满足即阻断并返回具体原因。
- 发布生成不可变快照：全部运行、环境指纹、种子、模型参数、数据集版本与授权、
  制品清单、人工判定，整体计算 `snapshot_hash`；重复发布会被拒绝。
- 数据集撤回（`withdraw`）或校准失效（`invalidate-calibration`）会：
  1. 正向追踪所有受影响制品、运行与**已发布快照**；
  2. 生成新的影响分析并给历史发布打状态标记（不删除、不覆盖）；
  3. 此后任何引用该上游的新发布一律阻断。

## 角色与可见性

- **研究人员**（operator/reviewer/admin）：从 `/results/{artifact_id}` 复原完整版本组合；
  只能读取授权范围内的数据集内容，非数据制品同组织可见。
- **数据权利人**：通过授权（`/license-grants`）只看见被授权数据集版本的制品，
  引用快照时未授权制品被剔除，谱系结构不暴露越权哈希。
- **科研诚信人员**（auditor/admin）：可见全部制品，可正向追踪异常来源、
  查看影响分析、验证事件链、裁定隔离区。

## 环境与测试

- Linux，Python 3.11+，仅使用标准库与 SQLite。

```bash
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m science_strategy_foundation.acceptance
```

验收成功时输出一行 `status` 为 `ok` 的 JSON（含候选制品哈希、谱系运行数、
影响分析数、隔离总数与快照哈希），退出码为 `0`。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m science_strategy_foundation.api \
  --database provenance.sqlite3 --host 127.0.0.1 --port 8080
```

写入与溯源接口通过 `X-Actor-Id` 标识操作者。主要接口：

- 节点/授权：`POST /nodes`、`GET /nodes`、`POST /license-grants`
- 离线准入：`POST /ingest`、`POST /ingest-batch`
- 隔离区：`GET /quarantine`、`POST /quarantine/adjudicate`、`POST /quarantine/rescan`
- 谱系复原：`GET /results/{artifact_id}`、`GET /trace/backward`、`GET /trace/forward`、
  `GET /artifacts/{id}`、`GET /lineage/verify`、`GET /lineage/events`
- 发布：`POST /releases`、`POST /releases/{id}/publish`、`GET /releases`、
  `GET /references/{release_id}`
- 撤回与影响：`POST /datasets/withdraw`、`POST /datasets/invalidate-calibration`、
  `GET /impact-analyses[/{id}]`

服务重启后 SQLite 中的谱系、隔离记录、发布快照、审计历史全部保留。
