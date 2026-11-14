# 慢查解剖台 · 批次审计报告

> 项目：slowquery-autopsy · 批次 `batch-bf0f825b4eb270c13682`

## 1. 概览

- 批次 ID：`batch-bf0f825b4eb270c13682`
- 配置哈希：`c9cd1c9c1899cc59`
- 输入哈希：`80f40b08d5186227`
- 输入文件：4；解析慢查：20；参与聚类：18；排除：2
- 指纹簇：4；计划：5；未关联计划：1
- 发现：14；高危及以上：9；未解析行：3
- 严重级别：critical=0 · high=9 · medium=5 · low=0 · info=0
- 全部慢查总耗时：50350.000 ms；参与分析总耗时：49600.000 ms
- 分位数口径：nearest-rank（`ceil(q*n)`）；放大倍数 = 扫描行总数 / max(返回行总数, 1)

## 2. TOP 指纹簇

按总耗时降序，总耗时相同按指纹升序。

| # | 簇 ID | 次数 | 总耗时 ms | 平均 ms | P50 ms | P95 ms | 扫描/返回 | 总扫描行 | 耗时占比 |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | `b6b972a308926333` | 10 | 27050.000 | 2705.000 | 2660.000 | 3200.000 | 11275.00x | 2255000 | 54.54% |
| 2 | `af4b9db7cdc9c045` | 3 | 13200.000 | 4400.000 | 4400.000 | 4800.000 | 18200.00x | 2730000 | 26.61% |
| 3 | `c34301cef6431f5f` | 4 | 8450.000 | 2112.500 | 2050.000 | 2400.000 | 1640.62x | 525000 | 17.04% |
| 4 | `0be4b6b31b5181f8` | 1 | 900.000 | 900.000 | 900.000 | 900.000 | 100.00x | 100 | 1.81% |

### 高扫描放大清单（>100x）

| 簇 ID | 次数 | 放大倍数 | 样本 SQL |
|---|---:|---:|---|
| `b6b972a308926333` | 10 | 11275.00x | SELECT *<br>FROM orders<br>WHERE customer_id = 42<br>  AND status = 'PAID'<br>ORDER BY created_at DESC<br>LIMIT 20; |
| `af4b9db7cdc9c045` | 3 | 18200.00x | SELECT oi.order_id, SUM(oi.quantity) AS qty<br>FROM order_items oi<br>JOIN orders o ON o.id = oi.order_id<br>WHERE o.created_at >= '2026-01-02'<br>GROUP BY oi.order_id<br>ORDE |
| `c34301cef6431f5f` | 4 | 1640.62x | SELECT c.id, c.name, COUNT(o.id) AS order_count<br>FROM customers c<br>JOIN orders o ON o.customer_id = c.id<br>WHERE lower(c.region) = 'south'<br>GROUP BY c.id, c.name<br>ORD |

## 3. 计划审计发现

| 级别 | 规则 | 计划 | 节点 | 表 | 描述 |
|---|---|---|---|---|---|
| high | `PLAN-CAST-001` | fixtures/plans/bad_index.json | `0` | customers | 节点 0 将数值列 customers.id（bigint）与字符串字面量 '42' 比较。 |
| high | `PLAN-FULLSCAN-001` | fixtures/plans/nested_loop.json | `0.1` | order_items | 节点 0.1 对表 order_items（约 900000 行）使用 ALL 全表扫描。 |
| high | `PLAN-FULLSCAN-001` | fixtures/plans/full_scan.json | `0` | orders | 节点 0 对表 orders（约 500000 行）使用 ALL 全表扫描。 |
| high | `PLAN-FUNC-001` | fixtures/plans/bad_index.json | `0` | customers | 节点 0 的条件 lower(customers.region 包裹了已索引列 customers.region，可能导致普通索引失效。 |
| high | `PLAN-NL-INNER-001` | fixtures/plans/nested_loop.json | `0.1` | order_items | 嵌套循环内层节点 0.1 对 order_items（约 900000 行）逐行扫描且未使用索引。 |
| medium | `PLAN-SORT-001` | fixtures/plans/full_scan.json | `0` | — | 节点 0 在大结果集（500000 行）上执行文件排序或临时表操作。 |

## 4. 诊断发现明细

### [HIGH] `fnd-5ee30d7fa393e6cb` — 扫描放大高风险

- 类别：cost；规则：`COST-AMP-001`；簇：`b6b972a308926333`
- 计划/节点：— / —
- 说明：簇 b6b972a308926333 的扫描/返回放大倍数为 11275.0，超过阈值 100，出现 10 次。
- 证据：`{"actual":11275.0,"cluster_id":"b6b972a308926333","fingerprint":"b6b972a308926333","metric":"amplification","query_count":10,"threshold":100}`
- 建议：检查过滤字段选择性、索引覆盖与分页方式；扫描放大不等同于错误，需结合业务确认。

### [HIGH] `fnd-ef063fd05124e5b1` — 平均耗时偏高

- 类别：cost；规则：`COST-AVG-001`；簇：`af4b9db7cdc9c045`
- 计划/节点：— / —
- 说明：簇 af4b9db7cdc9c045 平均耗时 4400.0 ms，超过阈值 1000 ms。
- 证据：`{"actual":4400.0,"cluster_id":"af4b9db7cdc9c045","fingerprint":"af4b9db7cdc9c045","metric":"avg_duration_ms","query_count":3,"threshold":1000}`
- 建议：结合执行计划定位主要耗时算子，先验证索引与数据分布假设。

### [HIGH] `fnd-339006ef44ab5a76` — 平均耗时偏高

- 类别：cost；规则：`COST-AVG-001`；簇：`b6b972a308926333`
- 计划/节点：— / —
- 说明：簇 b6b972a308926333 平均耗时 2705.0 ms，超过阈值 1000 ms。
- 证据：`{"actual":2705.0,"cluster_id":"b6b972a308926333","fingerprint":"b6b972a308926333","metric":"avg_duration_ms","query_count":10,"threshold":1000}`
- 建议：结合执行计划定位主要耗时算子，先验证索引与数据分布假设。

### [HIGH] `fnd-cab8157138614f6e` — 平均耗时偏高

- 类别：cost；规则：`COST-AVG-001`；簇：`c34301cef6431f5f`
- 计划/节点：— / —
- 说明：簇 c34301cef6431f5f 平均耗时 2112.5 ms，超过阈值 1000 ms。
- 证据：`{"actual":2112.5,"cluster_id":"c34301cef6431f5f","fingerprint":"c34301cef6431f5f","metric":"avg_duration_ms","query_count":4,"threshold":1000}`
- 建议：结合执行计划定位主要耗时算子，先验证索引与数据分布假设。

### [HIGH] `fnd-f24b203f50898f73` — 隐式类型转换风险

- 类别：plan；规则：`PLAN-CAST-001`；簇：`c34301cef6431f5f`
- 计划/节点：`fixtures/plans/bad_index.json` / `0`
- 说明：节点 0 将数值列 customers.id（bigint）与字符串字面量 '42' 比较。
- 证据：`{"column":"id","column_type":"bigint","node_path":"0","plan_format":"json","quoted_literal":"42","rule_type":"implicit_type_cast","table":"customers"}`
- 建议：检查应用绑定参数类型，确保数值列使用数值类型参数。

### [HIGH] `fnd-ca78de08effdefda` — 大表全表扫描

- 类别：plan；规则：`PLAN-FULLSCAN-001`；簇：`af4b9db7cdc9c045`
- 计划/节点：`fixtures/plans/nested_loop.json` / `0.1`
- 说明：节点 0.1 对表 order_items（约 900000 行）使用 ALL 全表扫描。
- 证据：`{"access_type":"ALL","node_path":"0.1","plan_format":"json","rule_type":"full_scan_large_table","table":"order_items","table_rows":900000,"threshold":100000}`
- 建议：检查过滤条件与排序字段，评估补充组合索引；本工具不生成改写后的 SQL。

### [HIGH] `fnd-ba7b9091cbf8d7d9` — 大表全表扫描

- 类别：plan；规则：`PLAN-FULLSCAN-001`；簇：`b6b972a308926333`
- 计划/节点：`fixtures/plans/full_scan.json` / `0`
- 说明：节点 0 对表 orders（约 500000 行）使用 ALL 全表扫描。
- 证据：`{"access_type":"ALL","node_path":"0","plan_format":"json","rule_type":"full_scan_large_table","table":"orders","table_rows":500000,"threshold":100000}`
- 建议：检查过滤条件与排序字段，评估补充组合索引；本工具不生成改写后的 SQL。

### [HIGH] `fnd-cef91ad732333516` — 索引列被函数包裹

- 类别：plan；规则：`PLAN-FUNC-001`；簇：`c34301cef6431f5f`
- 计划/节点：`fixtures/plans/bad_index.json` / `0`
- 说明：节点 0 的条件 lower(customers.region 包裹了已索引列 customers.region，可能导致普通索引失效。
- 证据：`{"column":"region","expression":"lower(customers.region","function":"lower","index_wrapped":true,"node_path":"0","plan_format":"json","rule_type":"function_wrapped_index","table":"customers"}`
- 建议：核对表达式索引或改写条件；先在测试环境验证执行计划。

### [HIGH] `fnd-d01f6000b013e9c1` — 嵌套循环内层缺索引

- 类别：plan；规则：`PLAN-NL-INNER-001`；簇：`af4b9db7cdc9c045`
- 计划/节点：`fixtures/plans/nested_loop.json` / `0.1`
- 说明：嵌套循环内层节点 0.1 对 order_items（约 900000 行）逐行扫描且未使用索引。
- 证据：`{"access_type":"ALL","nested_loop_position":1,"node_path":"0.1","plan_format":"json","rule_type":"nested_loop_inner_missing_index","table":"order_items","table_rows":900000,"threshold":10000}`
- 建议：检查连接键上是否有可用索引，并确认连接顺序与统计信息。

### [MEDIUM] `fnd-89d35d365e84f626` — 锁等待占比偏高

- 类别：cost；规则：`COST-LOCK-001`；簇：`c34301cef6431f5f`
- 计划/节点：— / —
- 说明：簇 c34301cef6431f5f 锁等待时间占执行时间比例 0.402367，超过阈值 0.3。
- 证据：`{"actual":0.402367,"cluster_id":"c34301cef6431f5f","fingerprint":"c34301cef6431f5f","metric":"lock_ratio","query_count":4,"threshold":0.3}`
- 建议：检查事务边界、行锁竞争与批量更新提交粒度。

### [MEDIUM] `fnd-6a82c28a5c1eacf3` — P95 耗时偏高

- 类别：cost；规则：`COST-P95-001`；簇：`af4b9db7cdc9c045`
- 计划/节点：— / —
- 说明：簇 af4b9db7cdc9c045 的 P95 耗时为 4800.0 ms（nearest-rank 口径）。
- 证据：`{"actual":4800.0,"cluster_id":"af4b9db7cdc9c045","fingerprint":"af4b9db7cdc9c045","metric":"p95_duration_ms","query_count":3,"threshold":2000}`
- 建议：检查长尾样本的绑定变量、数据倾斜与锁等待情况。

### [MEDIUM] `fnd-387e46b4759e2c35` — P95 耗时偏高

- 类别：cost；规则：`COST-P95-001`；簇：`b6b972a308926333`
- 计划/节点：— / —
- 说明：簇 b6b972a308926333 的 P95 耗时为 3200.0 ms（nearest-rank 口径）。
- 证据：`{"actual":3200.0,"cluster_id":"b6b972a308926333","fingerprint":"b6b972a308926333","metric":"p95_duration_ms","query_count":10,"threshold":2000}`
- 建议：检查长尾样本的绑定变量、数据倾斜与锁等待情况。

### [MEDIUM] `fnd-c7fdf634a8f88dde` — P95 耗时偏高

- 类别：cost；规则：`COST-P95-001`；簇：`c34301cef6431f5f`
- 计划/节点：— / —
- 说明：簇 c34301cef6431f5f 的 P95 耗时为 2400.0 ms（nearest-rank 口径）。
- 证据：`{"actual":2400.0,"cluster_id":"c34301cef6431f5f","fingerprint":"c34301cef6431f5f","metric":"p95_duration_ms","query_count":4,"threshold":2000}`
- 建议：检查长尾样本的绑定变量、数据倾斜与锁等待情况。

### [MEDIUM] `fnd-53dab6baf777b805` — 大结果集排序/临时表

- 类别：plan；规则：`PLAN-SORT-001`；簇：`b6b972a308926333`
- 计划/节点：`fixtures/plans/full_scan.json` / `0`
- 说明：节点 0 在大结果集（500000 行）上执行文件排序或临时表操作。
- 证据：`{"node_path":"0","operation":"TABLE ACCESS","plan_format":"json","rows":500000,"rule_type":"sort_temp_large","threshold":50000,"using_filesort":true,"using_temporary":false}`
- 建议：评估排序字段索引与 LIMIT 下推，避免在超大中间结果上排序。

### 规则触发表

| finding_id | 规则 | 级别 | 类别 | 簇 |
|---|---|---|---|---|
| `fnd-5ee30d7fa393e6cb` | `COST-AMP-001` | high | cost | `b6b972a308926333` |
| `fnd-ef063fd05124e5b1` | `COST-AVG-001` | high | cost | `af4b9db7cdc9c045` |
| `fnd-339006ef44ab5a76` | `COST-AVG-001` | high | cost | `b6b972a308926333` |
| `fnd-cab8157138614f6e` | `COST-AVG-001` | high | cost | `c34301cef6431f5f` |
| `fnd-f24b203f50898f73` | `PLAN-CAST-001` | high | plan | `c34301cef6431f5f` |
| `fnd-ca78de08effdefda` | `PLAN-FULLSCAN-001` | high | plan | `af4b9db7cdc9c045` |
| `fnd-ba7b9091cbf8d7d9` | `PLAN-FULLSCAN-001` | high | plan | `b6b972a308926333` |
| `fnd-cef91ad732333516` | `PLAN-FUNC-001` | high | plan | `c34301cef6431f5f` |
| `fnd-d01f6000b013e9c1` | `PLAN-NL-INNER-001` | high | plan | `af4b9db7cdc9c045` |
| `fnd-89d35d365e84f626` | `COST-LOCK-001` | medium | cost | `c34301cef6431f5f` |
| `fnd-6a82c28a5c1eacf3` | `COST-P95-001` | medium | cost | `af4b9db7cdc9c045` |
| `fnd-387e46b4759e2c35` | `COST-P95-001` | medium | cost | `b6b972a308926333` |
| `fnd-c7fdf634a8f88dde` | `COST-P95-001` | medium | cost | `c34301cef6431f5f` |
| `fnd-53dab6baf777b805` | `PLAN-SORT-001` | medium | plan | `b6b972a308926333` |

## 5. 未解析日志

总计 3 条；以下最多列出 10 条。

| 文件 | 行号 | 原因 | 原始片段 |
|---|---:|---|---|
| fixtures/logs/malformed_lines.log | 1 | line outside a slow-log block | this synthetic line is intentionally outside any slow-log block |
| fixtures/logs/malformed_lines.log | 9 | missing # Query_time metadata | # Time: 2026-01-10T13:01:00Z # User@Host: svc_app[svc_app] @ node-f [synthetic] Id: 302 # Query_time: broken SELECT missing_metadata FROM ghost_table; |
| fixtures/logs/pg_log_01.log | 5 | missing CSV field 'statement' at index 8 | 2026-01-10T12:04:00Z,svc_report,shopdemo |

## 6. 未关联计划

| 计划文件 | 指纹 | 节点数 | 原因 |
|---|---|---:|---|
| fixtures/plans/text_ok_plan.txt | `deadbeefdeadbeef` | 2 | fingerprint did not match any cluster |

## 7. 排除的元数据语句

排除前缀：SET, SHOW, USE
共 2 条。

| 前缀 | 次数 | 示例位置 | SQL |
|---|---:|---|---|
| SET | 1 | fixtures/logs/mysql_slow_01.log:50 | SET SESSION long_query_time = 0.2; |
| SHOW | 1 | fixtures/logs/mysql_slow_01.log:57 | SHOW INDEX FROM orders; |

## 8. 输入文件

| 文件 | 格式 | 编码 | 行数 | 解析 | 未解析 | 排除 | SHA-256 |
|---|---|---|---:|---:|---:|---:|---|
| fixtures/logs/mysql_slow_01.log | mysql_slow | utf-8 | 63 | 6 | 0 | 2 | `025c664a7e5c6ec4…` |
| fixtures/logs/mysql_slow_02.log | mysql_slow | utf-8 | 112 | 9 | 0 | 0 | `917961b5ece6446f…` |
| fixtures/logs/pg_log_01.log | postgres_csv | utf-8 | 5 | 4 | 1 | 0 | `e8566b8af641e8aa…` |
| fixtures/logs/malformed_lines.log | mysql_slow | utf-8 | 13 | 1 | 2 | 0 | `16e7218481899e08…` |

## 9. 口径与边界

- 归一化规则（按顺序）：FP-COMMENTS, FP-STRINGS, FP-NUMBERS, FP-IN-LIST, FP-LIMIT, FP-WHITESPACE, FP-KEYWORDS
- 指纹 = SHA-256(归一化文本 + 有序结构 token 序列) 前 16 位十六进制。
- 分位数使用 nearest-rank，不做插值；同一输入与配置产生相同的正文。
- 扫描放大倍数与锁等待占比按簇内总量计算；每千次调用耗时为平均耗时 × 1000。
- 本报告只做静态文本分析，不连接数据库、不执行 SQL、不生成改写版本。
- 误报提示：合成 fixture 与规则阈值仅用于演示；真实结论需结合业务与执行环境复核。
