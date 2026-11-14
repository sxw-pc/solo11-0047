# 慢查解剖台 · slowquery-autopsy

> 面向小型 DBA / 后端团队的**离线**慢查询日志与执行计划审计台。  
> 输入本地日志、计划快照和表结构快照，输出可复现的指纹簇、成本证据、规则发现和静态报告。

## 1. 定位与边界

**它是：**

- 一个面向 MySQL slow log 和 PostgreSQL CSV 慢查询导出的本地批处理工具。
- 一个把“慢 SQL → 归一化 → 指纹聚类 → 成本归因 → 计划审计 → 风险发现”串成固定管线的工具。
- 一个可重复、可解释、可 diff 的审计记录器；每条发现都带规则 ID、证据 JSON 和建议。
- 一个只监听回环地址、只读展示本地台账的小型 HTTP 查看器。

**它不是：**

- 不是 APM、实时监控或数据库代理；不连接任何数据库，不执行 SQL，不采集线上指标。
- 不自动创建索引、不生成改写后的业务 SQL、不修改日志或计划文件。
- 不替代 DBA 的最终判断。所有规则都是静态启发式，必须结合数据分布、事务语义和业务目标复核。
- 不提供用户认证、多租户隔离或公网部署能力。HTTP 服务仅面向本机单用户。

## 2. 离线与合规承诺

- **完全离线**：运行期不发起网络请求，不做 DNS 解析，不读取 CDN、字体、图片或远程 API。HTML 报告的样式内联，模板与依赖全部在本地。
- **只监听回环**：`serve` 只允许绑定 `127.0.0.1`，默认端口 `5000`；HTTP 只接受 `GET`/`HEAD`，写方法统一返回 `405`。
- **只读分析**：日志、计划、表结构快照以只读方式读取；服务读取 SQLite 台账时使用 `mode=ro` URI。只有流水线会写入数据目录下自己的 `ledger.sqlite3`。
- **仅分析授权数据**：只能分析本人所有或已获得明确授权的日志与计划。使用前请确认授权范围，详见 [COMPLIANCE.md](COMPLIANCE.md)。
- **无密钥与真实标识**：仓库内全部示例为合成数据，不包含真实密钥、token、密码、公司名、真实域名或真实 IP；仅出现回环地址 `127.0.0.1`。

## 3. 快速开始

环境要求：Python 3.10+，依赖 `PyYAML`、`Jinja2`；测试依赖 `pytest`。

```bash
python -m pip install ".[dev]"

# 全部测试
make test

# 完整批处理：解析、归一化、聚类、计划审计、写台账、生成三种报告
make run

# 只读本地查看器（先执行 make run）
make serve
```

Windows 未安装 GNU make 时，使用等价命令：

```powershell
python -m pip install ".[dev]"
python -m pytest
$env:PYTHONPATH = "src"
python -m slowquery_autopsy run --config configs/pipeline.yaml
python -m slowquery_autopsy serve --config configs/pipeline.yaml
```

也可以不安装包，直接在仓库根目录设置 `PYTHONPATH=src` 后执行 `python -m slowquery_autopsy ...`。默认配置为 `configs/pipeline.yaml`。

首次 `run` 的预期输出（批次 ID 由配置和输入内容决定）：

```text
batch batch-bf0f825b4eb270c13682: inserted
queries=20 clusters=4 plans=5 findings=14 high=9 unparsed=3
markdown: reports/batch-bf0f825b4eb270c13682/report.md
json: reports/batch-bf0f825b4eb270c13682/report.json
html_index: reports/batch-bf0f825b4eb270c13682/html/index.html
```

再次用完全相同的输入执行 `run`，会以同一 `batch_id` 幂等跳过台账写入，并重新生成确定性的报告：

```text
batch batch-bf0f825b4eb270c13682: already existed (idempotent no-op)
```

生成物：

- `reports/<batch_id>/report.md`：人读报告。
- `reports/<batch_id>/report.json`：机器可读完整结果。
- `reports/<batch_id>/html/index.html`：离线 HTML；同目录还有簇页和 query 详情页。
- `data/ledger.sqlite3`：本地 SQLite 台账；可用 `make serve` 浏览。

`make diff` 需要台账中至少有两次不同输入的批次；只有一次时 CLI 会明确报错并退出，不会伪造比较结果。

## 4. 目录结构

```text
.
├── README.md
├── COMPLIANCE.md
├── DELIVERY.md
├── Makefile
├── pyproject.toml
├── configs/
│   ├── pipeline.yaml              # 输入、路径、成本规则、报告选项
│   ├── fingerprint_rules.yaml     # 有顺序的归一化规则
│   └── plan_audit_rules.yaml      # 五类计划审计规则
├── fixtures/
│   ├── logs/                      # 合成 MySQL / PostgreSQL 日志与坏行
│   ├── plans/                     # JSON 与文本执行计划快照
│   └── schema_snapshot.json       # 合成表结构、行数与索引
├── scripts/gen_fixtures.py        # 确定性重建合成 fixtures
├── src/slowquery_autopsy/
│   ├── cli.py                     # run / serve / diff / trace / validate
│   ├── config.py                  # 配置加载与校验
│   ├── pipeline.py                # 批次编排、输入哈希、持久化
│   ├── models.py                  # 数据模型与严重级别排序
│   ├── ingest/                    # 日志、计划、表结构解析
│   ├── analysis/                  # 归一化、指纹、成本、规则、diff、跨批次追踪
│   ├── store/                     # SQLite DDL 与台账读写
│   ├── report/                    # Markdown / JSON / HTML 报告
│   ├── server/                    # 仅回环的只读 HTTP 服务
│   └── util/                      # 哈希与时间工具
├── tests/                         # 单元测试 + 端到端测试
└── reports/                       # 生成的示例报告
```

## 5. 配置说明

所有路径字段相对于 `paths.root` 解析；`paths.root` 本身相对于**配置文件所在目录**解析。因此默认的 `configs/pipeline.yaml` 使用 `root: ..` 指向仓库根目录。修改路径后建议先运行 `validate`。

### 5.1 `paths` 与 `project`

| 字段 | 必填 | 含义 |
|---|---|---|
| `paths.root` | 否 | 路径根目录，默认 `.`，相对配置文件目录 |
| `paths.ledger` | 否 | SQLite 台账路径，默认 `data/ledger.sqlite3` |
| `paths.reports` | 否 | 报告输出目录，默认 `reports` |
| `project.name` | 否 | 报告中的项目标识 |

### 5.2 `inputs`、`formats`

| 字段 | 必填 | 含义 |
|---|---|---|
| `inputs[].path` | 是 | 日志文件路径 |
| `inputs[].format` | 是 | 必须指向 `formats` 中的一个键 |
| `inputs[].encoding` | 否 | `auto`（默认）、`utf-8`、`utf-8-sig`、`gbk` |
| `formats.<name>.type` | 是 | `mysql_slow` 或 `postgres_csv` |
| `formats.<name>.delimiter` | 否 | CSV 分隔符，默认 `,` |
| `formats.<name>.quotechar` | 否 | CSV 引号，默认 `"` |
| `formats.<name>.header` | 否 | CSV 是否有表头，默认 `false` |
| `formats.<name>.fields` | 否 | 列名到 0-based 列下标的映射 |

CSV 可用字段：`timestamp`、`user`、`database`、`duration_sec`、`lock_sec`、`rows_sent`、`rows_examined`、`client`、`statement`。默认映射为 `0..8`，与 `fixtures/logs/pg_log_01.log` 一致。

### 5.3 `fingerprint`

| 字段 | 必填 | 含义 |
|---|---|---|
| `rules_file` | 是 | 归一化规则 YAML |
| `excluded_statement_prefixes` | 否 | 不参与聚类的语句前缀，默认 `SET`、`SHOW`、`USE` |
| `quantile` | 否 | 目前仅支持 `nearest_rank` |

### 5.4 `cost.rules[]`

| 字段 | 必填 | 含义 |
|---|---|---|
| `id` | 是 | 稳定规则 ID |
| `title` / `description` / `recommendation` | `title` 必填 | 展示文案，可含 `{actual}`、`{threshold}`、`{cluster_id}` 等占位符 |
| `metric` | 是 | `amplification`、`avg_duration_ms`、`p95_duration_ms`、`lock_ratio`、`total_duration_ms`、`projected_ms_per_1k_calls`、`query_count` |
| `operator` | 是 | `gt`、`gte`、`lt`、`lte`、`eq` |
| `threshold` | 是 | 比较阈值 |
| `min_count` | 否 | 簇内最少查询次数，默认 `0` |
| `severity` | 是 | `critical` / `high` / `medium` / `low` / `info` |
| `enabled` | 否 | 默认 `true` |

### 5.5 `plan`、`risk`、`reports`

| 字段 | 必填 | 含义 |
|---|---|---|
| `plan.schema_file` | 是 | 表结构快照 JSON |
| `plan.rules_file` | 是 | 计划审计规则 YAML |
| `plan.files` | 否 | 要解析的计划文件列表 |
| `plan.links` | 否 | 计划路径/文件名 → 指纹；优先于计划文件内嵌指纹 |
| `risk.overrides.<RULE_ID>.enabled` | 否 | 关闭某条规则 |
| `risk.overrides.<RULE_ID>.severity` | 否 | 覆盖严重级别 |
| `risk.fail_on_severity` | 否 | `run` 的非零退出阈值；设置 `high` 会同时拦截 high 与 critical |
| `risk.diff_fail_on_new_high` | 否 | 等价于为每次 diff 启用 `--fail-on-new-high` |
| `reports.formats` | 否 | `markdown`、`json`、`html` 的任意子集 |
| `reports.top_clusters` | 否 | Markdown 展示的簇数量，默认 `8` |
| `reports.unparsed_preview` | 否 | 未解析行预览数，默认 `10` |
| `reports.excluded_preview` | 否 | 排除语句预览数，默认 `10` |

规则覆盖示例：

```yaml
risk:
  overrides:
    COST-AMP-001:
      enabled: false
    PLAN-FULLSCAN-001:
      severity: medium
  fail_on_severity: [high]
```

## 6. 支持的日志与计划格式

### 6.1 MySQL slow log

按块解析 `# Time`、`# User@Host`、`# Schema`、`# Query_time` / `# Lock_time` / `# Rows_sent` / `# Rows_examined`，忽略 `SET timestamp=...`，直到空行结束一条 SQL。示例：

```text
# Time: 2026-01-10T10:00:00Z
# User@Host: svc_app[svc_app] @ node-a [synthetic]  Id: 101
# Schema: shopdemo
# Query_time: 2.310000  Lock_time: 0.010000 Rows_sent: 20  Rows_examined: 200000
SET timestamp=1768039200;
SELECT *
FROM orders
WHERE customer_id = 42
  AND status = 'PAID'
ORDER BY created_at DESC
LIMIT 20;
```

缺失元数据、块外散行、无法解析的时长等不会被静默丢弃：报告会给出文件名、行号、原因和原文片段。

### 6.2 PostgreSQL CSV

默认无表头，9 列依次为时间戳、用户、数据库、耗时秒、锁等待秒、返回行数、扫描行数、客户端、SQL 文本：

```text
2026-01-10T12:00:00Z,svc_report,shopdemo,2.450,0.010,20,215000,node-d,SELECT * FROM orders WHERE customer_id = 501;
```

列映射可通过 `formats.<name>.fields` 调整；引号、逗号与跨字段文本遵循标准 CSV 规则。

### 6.3 执行计划

- **MySQL JSON EXPLAIN**：读取 `query_block`、`table`、`nested_loop`、`cost_info`，以及表节点的 `table_name`、`access_type`、`key`、`rows_examined_per_scan`、`filtered`、`attached_condition`、`possible_keys`、`using_filesort`、`using_temporary`。
- **PostgreSQL 缩进文本计划**：根据缩进建立节点路径，识别 `Seq Scan`、`Index Scan`、`Nested Loop`、`Sort`、`Limit` 等算子，以及 `Filter`、`Index Cond`、`Join Filter`。
- **关联方式**：`plan.links` 显式关联优先；否则读取计划中的 `fingerprint` 字段或文本计划首行 `-- slowquery fingerprint: ...`。未匹配的计划会在“未关联计划”中列出，不会消失。
- 单个计划解析失败会记录为未关联计划及错误原因，不中断其他计划；`validate` 会把这类错误作为校验失败返回。

`fixtures/plans/full_scan.json` 是最小 JSON 示例；`fixtures/plans/text_ok_plan.txt` 是最小文本示例。仓库内 `full_scan.json` 与 `ok_plan.json` 故意关联同一指纹，用于说明“同一查询的不同计划快照”。

## 7. 指纹、聚类与成本口径

1. 读取 `fingerprint_rules.yaml` 中 `enabled: true` 的规则，按文件顺序应用：去注释、字符串/数字字面量占位、折叠 `IN` 列表、归一化 `LIMIT`、压缩空白与标点、关键词大写。`regex_sub` 可用于增加自定义规则，无需改 Python。
2. 归一化后重新分词，得到有序结构 token 序列。
3. `fingerprint = SHA-256(归一化文本 + \x1e + 空格连接的有序 token)[:16]`。
4. 相同指纹的慢查进入同一簇；前缀命中 `SET`/`SHOW`/`USE` 的语句被排除，不进入簇，但保留在报告的排除清单中。
5. 簇按 `-总耗时, 指纹` 排序，保证相同输入稳定。
6. 分位数采用 nearest-rank：排序后取第 `ceil(q*n)` 个值，不做插值。
7. 扫描放大倍数 = 簇内扫描行总数 / `max(返回行总数, 1)`；锁等待占比 = 簇内锁等待时间总和 / 总耗时。
8. 每千次调用耗时 = 平均耗时 × 1000（毫秒）。

这些口径都是“基于本次日志快照”的统计，不是数据库内部的真实执行成本。

## 8. 规则目录

默认启用四条成本规则和五条计划规则。规则 ID 是稳定接口；关闭规则请只用配置覆盖，不要改历史 ID。

| 规则 ID | 类别 | 默认级别 | 含义 | 主要证据 |
|---|---|---|---|---|
| `COST-AMP-001` | 成本 | high | 扫描/返回放大倍数超阈值 | 放大倍数、阈值、次数、簇 ID |
| `COST-AVG-001` | 成本 | high | 簇平均耗时超阈值 | 平均耗时、阈值、次数 |
| `COST-P95-001` | 成本 | medium | 簇 P95 耗时超阈值 | P95、阈值、nearest-rank 口径 |
| `COST-LOCK-001` | 成本 | medium | 锁等待占执行时间比例超阈值 | 锁等待占比、阈值 |
| `PLAN-FULLSCAN-001` | 计划 | high | 大表 `ALL` 全表扫描 | 表、行数、access_type、节点路径 |
| `PLAN-FUNC-001` | 计划 | high | 索引列被函数包裹 | 表达式、函数、列、索引状态 |
| `PLAN-CAST-001` | 计划 | high | 数值列与字符串字面量比较 | 列类型、字面量、表、节点路径 |
| `PLAN-NL-INNER-001` | 计划 | high | 嵌套循环内层节点无可用索引 | 表、行数、内层位置、节点路径 |
| `PLAN-SORT-001` | 计划 | medium | 大结果集文件排序/临时表 | 行数、using_filesort、using_temporary |

统一的 finding 引擎会做三件事：按 `rule_id + target + evidence` 生成稳定的 `finding_id`；按 `risk.overrides` 应用开关和级别；按严重级别、规则 ID、finding ID 排序并去重。每条发现同时保留 `category`、`cluster_id`、`plan_file`、`node_path`、`evidence` 和 `recommendation`。

## 9. SQLite 台账

台账包含以下表：

| 表 | 内容 |
|---|---|
| `schema_meta` | schema 版本 |
| `batches` | 批次、配置哈希、输入哈希、创建时间、摘要 JSON |
| `log_files` | 每个输入文件的编码、行数、解析/未解析/排除计数 |
| `slow_queries` | 单条慢查、归一化 SQL、指纹、簇、成本向量 |
| `clusters` | 簇统计、分位数、放大倍数、锁等待占比、耗时占比 |
| `plans` / `plan_nodes` | 计划快照与展平节点 |
| `findings` | 统一发现与证据 JSON |
| `unparsed_lines` | 文件、行号、原文、原因 |
| `baselines` | 命名基线（Python `Ledger` API） |
| `comparisons` | diff 结果与时间 |
| `fingerprint_sources` | 每个批次中每个指纹的查询次数与来源文件（跨批次追踪的覆盖依据） |
| `traces` | `trace` 结果、批次序列与时间 |

`batch_id = stable_id("batch", config_hash, input_hash, length=20)`。`config_hash` 包含流水线配置及两份规则文件的哈希；`input_hash` 使用相对展示路径、格式和文件字节，不含绝对路径或 mtime，因此同一目录布局复制到其他位置仍得到相同批次。相同配置 + 相同输入重复运行不会产生新批次；输入或规则变化才会形成新批次。

`--now` 只覆盖台账和 comparison 的时间戳，不进入报告正文。服务端通过 `sqlite3.connect("file:...?mode=ro", uri=True)` 打开台账，并用 `PRAGMA query_only` 兜底。

## 10. 报告与 JSON 结构

Markdown 报告固定包含：概览、TOP 指纹簇、高扫描放大清单、计划审计、诊断发现明细、规则触发表、未解析日志、未关联计划、排除语句、输入文件、口径与边界。

JSON 报告的顶层键稳定为：

```text
schema_version, report_type, metadata,
summary, file_stats, clusters, queries, plans, findings,
unparsed, excluded_statements
```

- `metadata`：`project`、`batch_id`、`config_hash`、`input_hash`。
- `summary`：计数、耗时、严重级别计数、规则目录、计划关联、报告选项、未解析预览。
- `clusters[]`：`cluster_id`、样本/归一化 SQL、耗时统计、P50/P95、扫描/返回、放大倍数、锁等待占比、耗时占比、成本向量。
- `queries[]`：来源文件与行号、用户、客户端、数据库、原始 SQL、归一化 SQL、指纹、单条成本向量、是否排除。
- `findings[]`：`finding_id`、`rule_id`、级别、类别、目标、描述、证据、建议。
- `unparsed[]`：文件、行号、原因、片段；`excluded_statements[]` 单独保存元数据语句。

HTML 报告使用 Jinja2 自动转义和相对链接，仅包含内联 CSS，没有远程脚本、外部字体、外链图片或 CDN。索引页提供批次统计、簇列表和发现列表入口，簇页可继续进入 query 详情。

## 11. 批次对比与 CI

```bash
# 先对新输入执行 run，再比较最近两个批次
PYTHONPATH=src python -m slowquery_autopsy diff --config configs/pipeline.yaml

# 显式指定批次，并在出现新的 high/critical finding 时失败
PYTHONPATH=src python -m slowquery_autopsy diff \
  --config configs/pipeline.yaml \
  --base batch-<旧> --head batch-<新> \
  --fail-on-new-high \
  --output reports/diff.json
```

默认 `base` 是第二新的批次，`head` 是最新批次。输出包含新增/消失的簇、新增/消失的 high/critical 发现及计数，并把结果写入 `comparisons`。退出码约定：

- `0`：命令成功；未触发失败策略。
- `1`：`run` 发现达到 `risk.fail_on_severity`，或 diff 在启用失败策略时发现新的 high/critical。
- `2`：配置、输入、解析、台账或参数错误。

把 `diff --fail-on-new-high`（或 `risk.diff_fail_on_new_high: true`）放进 CI 即可阻止“新出现的高危模式”在无人审阅时合入。比较是**集合差异**，不是性能基准；同一个问题的证据值变化会产生新的 finding ID，这是有意的可追溯行为。

### 11.1 跨批次指纹追踪 `trace`

`diff` 是两批集合差异。`trace` 针对台账中的若干历史批次，串出某个指纹在每一批的查询次数、P95 以及该指纹上 high/critical 发现的出现情况：

```bash
# 最近两个批次（按台账时间正序）
PYTHONPATH=src python -m slowquery_autopsy trace --config configs/pipeline.yaml

# 指定批次，顺序即输出顺序
PYTHONPATH=src python -m slowquery_autopsy trace --config configs/pipeline.yaml \
  --batch batch-<旧> --batch batch-<新> --output reports/trace.json

# 只看最近 N 批
PYTHONPATH=src python -m slowquery_autopsy trace --config configs/pipeline.yaml --last 5
```

输出 JSON 的顶层键为 `trace_type`、`schema_version`、`status_basis`、`status_legend`、`batches`、`fingerprints`、`counts`。每个指纹包含：

- `batches[]`：逐批的 `state`、`query_count`、`p95_duration_ms`、high/critical 发现数量、`high_finding_keys`、`high_finding_ids`、`missing_sources`、`coverage_known`。
- `first_seen_batch` / `last_seen_batch`：该指纹首次/最近被实际观测到的批次。
- `status`：`continuous`（连续出现）、`reappeared`（间断后重现）、`new`（首次出现后一直存在）、`disappeared`（最近一次覆盖它的批次中消失）、`single_batch`（只在一个覆盖批次中出现）。
- `high_findings.keys[]`：按 `rule_id + plan_file + node_path` 归并的发现，附各批次的 `finding_id` 与 `finding_ids_changed`。

**为什么不按 `finding_id` 比较**：`finding_id` 由 `rule_id + 目标 + evidence` 决定，`queries` 或 P95 变化就会产生新 ID。`trace` 的指纹身份就是 `fingerprint`（簇 ID），发现身份是规则与目标，因而同一持久问题在 evidence 变化时仍被串起来，同时保留每批的原始 `finding_id` 做溯源。

**逐批状态**：

| 状态 | 含义 |
|---|---|
| `observed` | 该批次有该指纹的簇。 |
| `absent` | 该批次采集了该指纹的全部已知来源文件（`log_files` 有记录），但没有产生该指纹。这才是真正消失。 |
| `not_collected` | 该批次没有采集全该指纹的已知来源，或台账无法证明其覆盖（旧版台账未回填）。这不能解读为“消失”，`missing_sources` 给出缺失来源。 |

持续性状态只使用 `observed`/`absent` 批次，因此 `not_collected` 的空洞不会伪造出一次消失。若某批只采到了该指纹的部分来源，也会保守地记为 `not_collected`。

`trace` 会以批次序列生成 `trace_id` 并写入 `traces` 表（幂等：同一批次序列与内容重复执行会覆盖同一条记录）；trace 文档本身不含运行时间，对同一批次集合可重复生成相同输出。若台账由 schema v1 升级而来，`trace` 会先调用 `Ledger.backfill_fingerprint_sources()` 从 `slow_queries` 回填 `fingerprint_sources`，使历史批次也能区分 `absent` 与 `not_collected`。

## 12. 校验、限制与维护

### 12.1 本地校验

```bash
make validate
# 等价：PYTHONPATH=src python -m slowquery_autopsy validate --config configs/pipeline.yaml
```

校验会读取配置、输入日志、规则、计划和表结构，不写台账、不生成报告，也不会连接数据库。它报告输入/计划/规则错误，并打印输入、查询、簇、计划、发现、未解析数量。预期对合成 fixtures 输出：

```text
VALID .../configs/pipeline.yaml
inputs=4 queries=20 clusters=4 plans=5 findings=14 unparsed=3
```

三条未解析行是故意注入的合成坏行，作为 note 打印。

### 12.2 已知限制

- 规则是静态启发式，不理解业务语义、数据分布或参数绑定；可能误报，也可能漏报。
- 表结构行数和索引来自快照，不是实时统计信息；全表扫描和嵌套循环判断以此为准。
- 文本计划解析依赖 PostgreSQL `EXPLAIN` 的缩进约定；非常规格式、并行计划细节和方言差异可能无法还原完整树结构。
- JSON 计划聚焦 MySQL `EXPLAIN FORMAT=JSON` 常见结构；不承诺覆盖所有版本字段。
- 只支持标准 MySQL slow log 块和位置列/命名字段 CSV；不直接读取压缩包、二进制日志或数据库系统表。
- 指纹规则是确定性的文本启发式：可能把业务上不同的字面量合并为同一个模式，也可能因格式差异分簇；应结合 SQL 样本复核。
- 日志中的无时区时间戳按 UTC 解释；若源库使用本地时区，请先确认台账展示时间是否满足审计要求。
- `SET`/`SHOW`/`USE` 默认作为元数据排除，不会出现在簇和成本统计中；如业务确实需要分析，应调整 `excluded_statement_prefixes`。
- diff 是批次集合差异，不提供统计显著性、时序趋势或容量预测。
- `trace` 的持续性只基于台账中实际存在、且可证明覆盖的批次；批次不连续时，`not_collected` 只表示“该批未采到该指纹的已知来源”，不代表线上是否出现。
- 本地 HTTP 服务没有认证，虽然强制回环绑定，仍不应通过端口转发、反向代理或隧道暴露给他人。
- 报告会保留原始 SQL、用户名、客户端和数据库名，应按内部敏感数据管理；仓库内 fixtures 全部为合成占位值。

### 12.3 重建合成 fixtures

```bash
make fixtures
```

生成脚本是确定性的：不会读取网络，不会修改仓库外文件。重建后应重新执行 `make run` 和 `make test`，确认指纹与示例报告同步。

### 12.4 许可

本仓库按“仅限已授权本地分析”的专有示例项目交付；具体使用边界见 [COMPLIANCE.md](COMPLIANCE.md)。第三方依赖保留各自许可。
