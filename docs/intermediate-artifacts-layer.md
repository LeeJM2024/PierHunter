# 中间产物层 README

## 定位

中间产物层是 ACCHunter 在最终报告中新增的一层结构化数据，用来保存扫描过程中的真实证据、阶段轨迹和引擎输出。

它不是一个独立文件夹，而是每份扫描报告 JSON 里的 `analysis_artifacts` 字段。

```text
storage/reports/*_vuln_report.json
  └── analysis_artifacts
```

## 生成位置

中间产物层由扫描器在生成最终报告时写入：

```text
engine/scanner.py
```

关键入口：

```text
ApkScanner.scan()
  └── report["analysis_artifacts"] = self._build_analysis_artifacts(report)
```

核心构建函数：

```text
ApkScanner._build_analysis_artifacts(report)
```

## 输出位置

扫描完成后，中间产物会随最终报告一起保存：

```text
storage/reports/<apk_name>_vuln_report.json
```

历史测试运行中的报告也可能包含同样结构：

```text
storage/test_runs/*/reports/*_vuln_report.json
```

前端通过报告接口读取：

```text
GET /api/report?task_id=<task_id>
```

全局大盘通过聚合接口读取真实报告数据：

```text
GET /api/dashboard/summary
```

生态参考情报通过独立接口读取：

```text
GET /api/ecosystem/summary
```

该接口用于全局感知模块的“生态参考情报”视角，不代表用户当前 APK 或本地扫描任务已经命中。

## 顶层结构

当前 `analysis_artifacts` 的结构如下：

```text
analysis_artifacts
├── schema_version
├── generated_at
├── analysis_started_at
├── analysis_finished_at
├── execution_trace
│   ├── stages
│   └── events
├── engines
│   ├── libhunter
│   ├── phunter
│   └── semantic_engine
├── evidence
│   ├── libraries
│   └── patches
├── intelligence
└── summary
```

## 字段说明

### `schema_version`

中间产物层的数据结构版本。

当前版本：

```text
1
```

后续如果字段含义发生不兼容变化，应提升版本号。

### `generated_at`

中间产物层生成时间，使用 UTC ISO 时间字符串。

### `analysis_started_at`

本次 APK 分析开始时间。

### `analysis_finished_at`

本次 APK 分析结束时间。

## 执行轨迹：`execution_trace`

`execution_trace` 用来记录扫描过程，而不是只记录最终结论。

### `execution_trace.stages`

阶段列表。当前主要有四个阶段：

```text
init        初始化分析任务
libhunter   LibHunter 第三方库识别
phunter     PHunter 漏洞补丁验证
report      汇总诊断报告
```

每个阶段一般包含：

```text
key
label
status
started_at
finished_at
summary
metrics
```

示例：

```json
{
  "key": "libhunter",
  "label": "LibHunter 第三方库识别",
  "status": "completed",
  "started_at": "2026-06-05T04:09:58.360Z",
  "finished_at": "2026-06-05T04:13:13.170Z",
  "summary": "成功提取 4 个组件特征",
  "metrics": {
    "detection_count": 4,
    "matched_cve_count": 9
  }
}
```

### `execution_trace.events`

事件列表。用于记录阶段开始、阶段结束等过程事件。

每个事件一般包含：

```text
time
type
stage
message
payload
```

当前常见事件类型：

```text
stage_started
stage_finished
```

前端执行轨迹面板可以优先读取 `stages`，需要更细过程时再读取 `events`。

## 引擎产物：`engines`

`engines` 保存底层分析引擎的真实执行结果。

### `engines.libhunter`

LibHunter 第三方库识别的执行产物。

常见字段：

```text
status
returncode
cmd
result_file
detection_count
stdout
stderr
```

含义：

- `status`：LibHunter 执行状态。
- `returncode`：进程返回码。
- `cmd`：实际执行的命令行参数。
- `result_file`：LibHunter 结果文件路径，如果当前没有独立结果文件则可能为 `null`。
- `detection_count`：识别出的组件数量。
- `stdout` / `stderr`：输出摘要，不保存无限长日志，只保留行数、摘录和截断标记。

### `engines.phunter`

PHunter 漏洞补丁验证的执行产物。

常见信息包括：

```text
raw_task_count
deduped_task_count
failed_count
max_concurrent
```

具体每个 CVE 的验证证据通常会挂在 `evidence.patches[*].evidence` 中。

### `engines.semantic_engine`

语义引擎占位与说明。

当前它不是独立 LLM 智能体，也不是一个单独运行的模型服务。它的含义是：当前语义证据来自确定性的 PHunter 补丁验证，后续 LLM 智能体只能在这些 evidence 边界内做规划、解释、异常诊断和复验建议。

当前常见字段：

```text
status
source
patch_evidence_count
note
```

## 证据包：`evidence`

`evidence` 是中间产物层最重要的部分。前端报告页、证据面板、Copilot 解释和后续智能层都应该优先从这里取数据。

### `evidence.libraries`

每个识别组件的证据摘要。

字段：

```text
library
version
similarity
target_class_count
target_classes_sample
matched_cve_count
```

含义：

- `library`：规范化后的组件名。
- `version`：识别出的版本。
- `similarity`：LibHunter 相似度。
- `target_class_count`：候选类数量。
- `target_classes_sample`：候选类样本，当前最多保留前 24 个。
- `matched_cve_count`：该组件关联到的 CVE 数量。

### `evidence.patches`

每个漏洞补丁验证任务的证据摘要。

字段：

```text
cve_id
library
status
pre_similarity
post_similarity
evidence
```

含义：

- `cve_id`：CVE 编号。
- `library`：关联组件。
- `status`：PHunter 识别出的补丁状态。
- `pre_similarity`：与漏洞版本补丁前样本的相似度。
- `post_similarity`：与修复版本补丁后样本的相似度。
- `evidence`：PHunter 详细证据，包括资源文件、候选类范围、补丁相关方法数、返回码、重试状态、stdout/stderr 摘要等。

常见 `status` 包括：

```text
PRESENT
NOT_PRESENT
PATCH_PRESENT
PATCH_NOT_PRESENT
DEAD_CODE
UNKNOWN
HUNG
ERROR
RESOURCE_LIMIT
```

## 聚合摘要：`summary`

`summary` 提供给前端和大盘快速展示使用。

当前字段：

```text
library_count
vulnerability_count
patch_status_counts
patch_evidence_count
target_class_count
```

含义：

- `library_count`：识别组件数量。
- `vulnerability_count`：漏洞记录数量。
- `patch_status_counts`：按补丁状态聚合的数量。
- `patch_evidence_count`：补丁证据链数量。
- `target_class_count`：候选类总数。

## 智能体占位：`intelligence`

`intelligence` 是为后续真实智能体 API 预留的输出位置。

当前它是本地占位实现，不调用真实 LLM，也不连接外部 API。它只根据 `used_libraries`、`vulnerabilities` 和 `analysis_artifacts.evidence` 生成结构化诊断，目的是先固定前后端合同。

生成位置：

```text
engine/intelligence.py
```

新扫描报告会自动写入：

```text
analysis_artifacts.intelligence
```

旧报告也可以通过占位 API 临时生成：

```text
POST /api/intelligence/analyze
```

请求可以传：

```json
{
  "task_id": "任务 ID"
}
```

也可以直接传报告对象：

```json
{
  "report": {}
}
```

当前占位输出包括：

```text
status
provider
model
input_contract
input_summary
library_overview
findings
evidence_gaps
recommended_actions
rerun_plan
api_placeholder
```

其中：

- `library_overview`：简要说明本次任务识别出的第三方库通常用于什么功能。
- `findings[*].library_context`：单条漏洞对应第三方库的用途说明。
- `findings[*].cve_context`：单条漏洞对应 CVE 的简要说明、影响版本样本和补丁资源文件名。

当前 `cve_context` 优先读取本地 `data/cve_kb.json` 中的影响版本和补丁资源字段。由于当前知识库没有自然语言漏洞描述，占位层会先生成简短说明；真实智能体 API 接入后可替换为更准确的漏洞成因、攻击影响和修复建议。

以后接真实智能体 API 时，优先替换 `engine/intelligence.py` 里的实现，并保持响应结构稳定。如果字段含义发生不兼容变化，再提升 `schema_version`。

## 前端消费位置

前端类型定义：

```text
frontend/src/types/contracts.ts
```

报告适配：

```text
frontend/src/services/adapters/reportAdapter.ts
```

报告页中间产物摘要：

```text
frontend/src/components/report/AnalysisTracePanel.tsx
```

证据面板和 Copilot 解释也应优先读取报告模型中的 evidence，而不是再自行从少量最终字段推导。

## 和最终报告字段的关系

旧报告字段仍然保留：

```text
apk_info
used_libraries
vulnerabilities
```

中间产物层是在这些字段旁边新增的增强数据：

```text
analysis_artifacts
```

这样做是为了保持向后兼容。旧前端或旧脚本仍可读取最终结果，新前端和智能层可以读取更完整的过程证据。

## 设计原则

中间产物层遵守三条原则：

1. 真实数据优先。
   没有后端证据支撑的数据，不应在前端伪造成真实统计。

2. 证据约束智能层。
   LLM 或 Copilot 只能基于 `analysis_artifacts.evidence`、`execution_trace` 和确定性引擎产物做解释与建议，不能凭空判断漏洞状态。

3. 保持向后兼容。
   原有 `apk_info`、`used_libraries`、`vulnerabilities` 不应被随意删除或改语义。新增能力优先挂在 `analysis_artifacts` 下。

## 后续扩展建议

可以继续补充的中间产物包括：

- PHunter Java 侧直接导出的 JSON evidence，而不是只保存 Python 封装摘要。
- 更细粒度的方法级、基本块级、调用链级证据。
- 每个 CVE 的复验计划、复验结果和人工确认记录。
- LLM 智能体输出的语义规约、异常诊断和下一轮验证策略。
- 前端全局大盘所需的长期任务趋势、历史组件风险分布和扫描耗时统计。

扩展时建议仍然放在 `analysis_artifacts` 下，并优先新增字段，避免破坏现有字段含义。
