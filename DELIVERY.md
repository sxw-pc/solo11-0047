# 交付说明 · 慢查解剖台

交付日期：2026-11-14  
项目：`slowquery-autopsy` / 慢查解剖台  
Python 要求：3.10+  
状态：**实现完成，49 项测试全部通过，示例报告已生成**

## 1. 交付内容

- 完整可运行源码，采用 `src/` 布局。
- 合成 fixtures：4 个日志文件、5 个执行计划、1 个表结构快照。
- 三份声明式配置：流水线、归一化规则、计划审计规则。
- 49 项 pytest 测试：单元测试 + 端到端流水线 + 本地 HTTP 冒烟测试。
- `Makefile`：`test`、`run`、`serve`、`diff`、`validate`、`fixtures`。
- 示例输出：`reports/batch-bf0f825b4eb270c13682/`，含 Markdown、JSON 与 25 个静态 HTML 页面。
- 文档：本文件、[README.md](README.md)、[COMPLIANCE.md](COMPLIANCE.md)。

SQLite 台账 `data/ledger.sqlite3` 是运行时生成物，不随交付提交；首次 `make run` 会自动创建，`make serve` 需要先执行 `run`。示例报告保留在 `reports/` 供直接查看。

## 2. 环境与安装

实际验证环境：Windows 11，Python 3.13.15，pytest 8.3.5，PyYAML 6.0.2，Jinja2 3.1.6。

```bash
python -m pip install ".[dev]"
```

本执行环境未安装 GNU make（`make: command not found`），因此本次验证使用 Makefile 中对应命令的直接形式：

```bash
PYTHONPATH=src python -m slowquery_autopsy <command>
```

`Makefile` 已提交并设置 `export PYTHONPATH := src`；在具备 GNU make 的 Linux/macOS/Windows 开发环境中，可直接使用 `make test`、`make run`、`make serve`、`make diff`、`make validate`。

另已在隔离 venv 中验证非可编辑安装：

```text
$ python -m pip wheel . --no-deps --no-build-isolation
slowquery_autopsy-1.0.0-py3-none-any.whl

$ (venv) pip install --no-deps .
$ slowquery-autopsy --version
slowquery-autopsy 1.0.0
template dir present: cluster.html.j2, detail.html.j2, index.html.j2
```

## 3. 实际命令输出

### 3.1 测试

```text
$ python -m pytest
.................................................                        [100%]
64 passed
```

说明：全局安装的 `pytest-asyncio` 插件会打印一条未设置 fixture loop scope 的弃用提示。项目自身不依赖 `pytest-asyncio`，该提示不影响测试结果。测试过程中本地服务使用回环地址，不访问外部网络。

### 3.2 首次完整批处理与幂等重跑

```text
$ PYTHONPATH=src python -m slowquery_autopsy run --config configs/pipeline.yaml
batch batch-bf0f825b4eb270c13682: inserted
queries=20 clusters=4 plans=5 findings=14 high=9 suppressed=0 unparsed=3
markdown: reports/batch-bf0f825b4eb270c13682/report.md
json: reports/batch-bf0f825b4eb270c13682/report.json
html_index: reports/batch-bf0f825b4eb270c13682/html/index.html

$ PYTHONPATH=src python -m slowquery_autopsy run --config configs/pipeline.yaml
batch batch-bf0f825b4eb270c13682: already existed (idempotent no-op)
queries=20 clusters=4 plans=5 findings=14 high=9 suppressed=0 unparsed=3
...
```

- 输入哈希与配置哈希完全相同时，`batch_id` 不变，台账不重复写入。
- 将项目整体复制到另一绝对路径后，上述批次的 ID 仍为 `batch-bf0f825b4eb270c13682`，说明批次 ID 不依赖绝对路径。
- 连续两次生成全部 27 个报告文件，逐文件 SHA-256 校验一致：“27 files unchanged”。

### 3.3 配置与输入校验

```text
$ PYTHONPATH=src python -m slowquery_autopsy validate --config configs/pipeline.yaml
VALID .../configs/pipeline.yaml
inputs=4 queries=20 clusters=4 plans=5 findings=14 unparsed=3
note: unparsed fixtures/logs/malformed_lines.log:1: line outside a slow-log block
note: unparsed fixtures/logs/malformed_lines.log:9: missing # Query_time metadata
note: unparsed fixtures/logs/pg_log_01.log:5: missing CSV field 'statement' at index 8
```

退出码 `0`。三条 note 是 fixtures 中故意保留的坏行，用于验证“未解析行带文件/行号披露”。

### 3.4 单批次与 diff 边界

账本中只有一个批次时，默认 diff 会明确失败而不是伪造结果：

```text
$ PYTHONPATH=src python -m slowquery_autopsy diff --config configs/pipeline.yaml
error: need two batches or an explicit --base
exit=2
```

在临时副本中追加一条合成慢查后，第二批次和 diff 均正常：

```text
== run 1 ==
batch batch-bf0f825b4eb270c13682: inserted
queries=20 clusters=4 plans=5 findings=14 high=9 suppressed=0 unparsed=3
exit 0

== run 2 ==
batch batch-85ecafebc34cd39f84cd: inserted
queries=21 clusters=5 plans=5 findings=16 high=10 unparsed=3
exit 0

== diff ==
{
  "counts": {
    "disappeared_clusters": 0,
    "disappeared_high_findings": 0,
    "new_clusters": 1,
    "new_high_findings": 1
  },
  ...
  "clusters": {
    "new": [{
      "cluster_id": "aead15b6cc0366e0",
      "query_count": 1,
      "total_duration_ms": 5200.0,
      "sample_sql": "SELECT COUNT(*) FROM order_items WHERE product_id = 77;"
    }]
  }
}
exit 0
```

该演示在系统临时目录完成，未修改仓库 fixtures。

### 3.5 本地只读服务

`tests/test_server_smoke.py` 实际启动 `ThreadingHTTPServer`，绑定端口 `0`（操作系统分配回环端口），并验证：

- 绑定地址为 `127.0.0.1`；拒绝 `0.0.0.0`。
- `/healthz` 返回 `200`、`readonly: true`、CSP `default-src 'none'`。
- 批次、簇、发现、query 详情路由均返回 `200`。
- 未知路径返回 `404`；`POST` 返回 `405`；`HEAD` 返回 `200` 且无响应体。
- 页面不包含外部 URL/CDN 引用。
- 台账以 `mode=ro` + `PRAGMA query_only = ON` 打开，写操作被拒绝。

启动命令（先执行 `run` 生成台账）：

```bash
PYTHONPATH=src python -m slowquery_autopsy serve --config configs/pipeline.yaml
# serve: http://127.0.0.1:5000 (read-only, loopback only)
```

### 3.6 静态编译

```text
$ python -m compileall -q src tests scripts
compile_all_ok
```

## 4. Python 行数

统计口径：`src tests scripts` 下全部 `.py` 文件，含测试和脚本，不含空行过滤。

| 范围 | 行数 |
|---|---:|
| 应用源码 `src/` | 3410 |
| 测试 `tests/` | 897 |
| 生成脚本 `scripts/` | 180 |
| **合计** | **4487** |

单文件最大为 `src/slowquery_autopsy/models.py` 的 293 行，全部文件均 ≤300 行。

### 4.1 应用模块

| 文件 | 行数 | 职责 |
|---|---:|---|
| `src/slowquery_autopsy/__init__.py` | 4 | 版本与项目常量 |
| `src/slowquery_autopsy/__main__.py` | 5 | `python -m` 入口 |
| `analysis/__init__.py` | 1 | 包标记 |
| `analysis/cost.py` | 97 | 成本向量、阈值规则 |
| `analysis/diff.py` | 65 | 批次集合差异 |
| `analysis/fingerprint.py` | 85 | 指纹、nearest-rank、聚类 |
| `analysis/normalize.py` | 154 | 声明式归一化与分词 |
| `analysis/plan_audit.py` | 206 | 五类计划审计检查 |
| `analysis/risk_rules.py` | 91 | 统一 finding、覆盖与规则目录 |
| `cli.py` | 198 | run/serve/diff/validate |
| `config.py` | 273 | YAML 加载、路径解析与校验 |
| `ingest/__init__.py` | 1 | 包标记 |
| `ingest/log_parser.py` | 256 | MySQL slow log / PostgreSQL CSV |
| `ingest/plan_parser.py` | 226 | JSON 与文本计划 |
| `ingest/schema_loader.py` | 100 | 表结构快照读取 |
| `models.py` | 293 | 数据模型、严重级别与排序 |
| `pipeline.py` | 212 | 编排、哈希、持久化、校验 |
| `report/__init__.py` | 47 | 报告入口 |
| `report/html_report.py` | 117 | 静态 HTML 渲染 |
| `report/json_report.py` | 55 | JSON 报告 |
| `report/markdown_report.py` | 200 | Markdown 报告 |
| `server/__init__.py` | 1 | 包标记 |
| `server/app.py` | 268 | 回环只读 HTTP 服务 |
| `store/__init__.py` | 1 | 包标记 |
| `store/ledger.py` | 278 | SQLite 写入/只读访问 |
| `store/schema.py` | 74 | 台账 DDL |
| `util/__init__.py` | 1 | 包标记 |
| `util/hashing.py` | 58 | SHA-256、稳定 ID、文件哈希 |
| `util/timefmt.py` | 48 | UTC 时间格式 |

### 4.2 测试模块

| 文件 | 用例数 | 行数 |
|---|---:|---:|
| `tests/conftest.py` | — | 39 |
| `tests/test_cost.py` | 4 | 85 |
| `tests/test_fingerprint.py` | 4 | 70 |
| `tests/test_ledger.py` | 5 | 69 |
| `tests/test_log_parser.py` | 5 | 91 |
| `tests/test_normalize.py` | 5 | 71 |
| `tests/test_pipeline_e2e.py` | 3 | 87 |
| `tests/test_plan_audit.py` | 6 | 100 |
| `tests/test_plan_parser.py` | 5 | 69 |
| `tests/test_reports.py` | 5 | 82 |
| `tests/test_risk_rules.py` | 5 | 67 |
| `tests/test_server_smoke.py` | 2 | 67 |
| **合计** | **49** | **897** |

覆盖点：

- 日志块解析、CSV 字段映射、编码探测、坏行定位。
- 归一化等价性、规则顺序、指纹稳定性、nearest-rank 与簇排序。
- 成本规则算子/阈值/最小次数。
- JSON/文本计划树、节点路径、嵌套循环、损坏计划。
- 五类计划审计规则及规则关闭/覆盖。
- finding ID 稳定性、去重、排序、严重级别覆盖。
- SQLite 表结构、幂等批次、只读拒绝、baseline/comparison。
- Markdown/JSON/HTML 内容与确定性、本地资产、无外部链接。
- 端到端 run → append 新日志 → run → diff → validate。
- 回环绑定、CSP、路由、404、405、HEAD、POST 拒绝。

## 5. 示例报告

批次 `batch-bf0f825b4eb270c13682` 的输入统计：

| 指标 | 数量 |
|---|---:|
| 输入文件 | 4 |
| 解析慢查 | 20 |
| 参与聚类 | 18 |
| 排除语句（SET/SHOW） | 2 |
| 指纹簇 | 4 |
| 计划 / 计划节点 | 5 / 8 |
| 发现 / high 及以上 | 14 / 9 |
| 未解析行 | 3 |
| 未关联计划 | 1 |

输出文件共 27 个：

```text
reports/batch-bf0f825b4eb270c13682/
├── report.md                  # 14,094 bytes
├── report.json                # 51,677 bytes
└── html/
    ├── index.html
    ├── cluster-<fingerprint>.html   # 4 个
    └── query-<query_id>.html        # 20 个
```

严重级别分布：critical=0，high=9，medium=5，low=0，info=0。规则触发明细可在 `report.md` 的“规则触发表”中查看。

## 6. 离线与安全检查

- 仓库源码与文档中的 URL 只出现回环地址 `127.0.0.1`；没有外部域名、CDN 或远程 API。
- 源码没有 `urllib.request`、`requests`、`http.client`（仅测试用本地回环客户端）等外部访问逻辑；服务器只用于本地展示。
- 日志、计划、表结构读取为只读；服务端台账使用 SQLite `mode=ro` 和 `query_only`。
- HTTP 服务仅绑定 `127.0.0.1`，拒绝其他 host；写方法与未知路径有明确处理。
- fixtures、配置和报告样例均为合成数据，无 `password`/`token`/密钥/证书/真实公司名/真实域名/真实 IP。
- 报告不包含运行时间戳，连续执行生成相同正文；批次的创建时间仅保存在台账中，用于审计。

## 7. 已知限制与后续建议

1. 规则为静态启发式，无法理解业务语义、数据倾斜、缓存与参数绑定；finding 必须人工复核。
2. 表行数和索引来自快照，不是实时统计；不支持自动收集数据库元数据。
3. 文本计划仅覆盖 PostgreSQL 缩进格式的常见算子；JSON 计划聚焦 MySQL 常见结构。
4. 不支持压缩日志、二进制日志、MySQL 传统表格 EXPLAIN 或所有数据库方言。
5. 指纹归一化可能合并语义不同但结构相同的 SQL；差异应通过样本 SQL 和计划人工确认。
6. `SET`/`SHOW`/`USE` 默认排除出聚类，但仍保留在报告和台账中。
7. diff 是批次集合差异，不提供统计显著性、趋势或性能基准。
8. 本地 HTTP 服务无认证；必须保持回环绑定，禁止反向代理或端口转发暴露。
9. 发现基线通过 `baseline add/list/remove` 子命令或 `risk.baselines` 配置管理；基线只按规则 ID / SQL 指纹匹配，抑制后仅生效级别降为 info，原始级别与 finding 身份保持不变。命名批次基线仍由 `Ledger.set_baseline`/`get_baseline` 提供，diff 比较记录会自动写入 `comparisons`。
10. 报告包含原始 SQL、用户、客户端和数据库名，应按内部敏感数据管理。

## 8. 最终检查清单

- [x] F1 MySQL slow log + PostgreSQL CSV 解析。
- [x] F2 未解析行带文件、行号、原因和片段。
- [x] F3 声明式归一化与可关闭规则。
- [x] F4 确定性指纹聚类、P50/P95、放大、锁等待、耗时占比。
- [x] F5 可解释成本归因（actual/threshold/query_count/cluster）。
- [x] F6 JSON + 文本计划解析与五类审计规则。
- [x] F7 统一 finding，稳定 ID，启用/禁用/级别覆盖。
- [x] F8 SQLite 幂等批次、发现基线豁免（原始/生效级别分离）、comparison。
- [x] 确定性 Markdown / JSON / HTML 报告。
- [x] 仅回环、只读、GET/HEAD 本地服务。
- [x] `run` / `serve` / `diff` / `validate` CLI 与 Makefile。
- [x] README、COMPLIANCE、DELIVERY、合成 fixtures 与示例报告。
- [x] 64 项测试通过（新增基线抑制、身份稳定、重复批次幂等、未登记不误伤、旧台账迁移）。
