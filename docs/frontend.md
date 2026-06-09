# ACCHunter 前端 README

## 定位

本前端是 ACCHunter 的用户操作台，负责 APK 上传、任务执行监控、漏洞报告展示、证据查看和全局态势大盘展示。

前端并不直接运行 LibHunter 或 PHunter。它通过后端 API、WebSocket 和报告 JSON 读取数据。

和中间产物层相关的核心字段是：

```text
report.analysis_artifacts
```

中间产物层的完整说明见：

```text
../docs/intermediate-artifacts-layer.md
```

## 启动命令

在不启动 Docker 前端开发服务器的情况下，可以直接运行 Vite：

```bash
cd /home/leejm/demo-docker/demo-main/frontend
npm run dev
```

默认地址：

```text
http://localhost:5173
```

生产构建：

```bash
cd /home/leejm/demo-docker/demo-main/frontend
npm run build
```

## 路由总览

当前前端有 5 个主界面：

```text
/                           首页 / 操作台
/task/new                   新建扫描任务
/task/:taskId/execution     执行监控
/report/:taskId             扫描报告
/global-dashboard           全局态势感知大盘
```

路由定义位置：

```text
src/App.tsx
```

## 界面与中间产物层对应关系

| 界面 | 路由 | 是否直接对应中间产物层 | 主要数据来源 |
| --- | --- | --- | --- |
| 首页 / 操作台 | `/` | 部分对应 | `/api/dashboard/summary`、本地任务状态、回退展示数据 |
| 新建扫描任务 | `/task/new` | 不直接对应 | `/api/upload`、`/api/analyze` |
| 执行监控 | `/task/:taskId/execution` | 间接对应 | `/api/task/:taskId`、`/api/logs` WebSocket、报告完成后跳转报告页 |
| 扫描报告 | `/report/:taskId` | 强对应 | `/api/report?task_id=...`，读取 `report.analysis_artifacts` |
| 全局态势感知大盘 | `/global-dashboard` | 部分对应 | `/api/dashboard/summary`，由后端聚合数据库任务和报告文件 |

结论：

```text
报告页是当前中间产物层最完整的消费界面。
首页和全局大盘使用后端聚合后的真实数据，但仍保留示例数据回退。
执行页当前主要展示实时运行状态，结构化中间产物要等报告生成后才完整出现。
新建任务页只是入口，不消费中间产物层。
```

## 1. 首页 / 操作台

路由：

```text
/
```

页面文件：

```text
src/routes/DashboardPage.tsx
```

主要组件：

```text
src/components/dashboard/DashboardHero.tsx
src/components/dashboard/RecentTasksPanel.tsx
```

主要功能：

- 展示任务总数、漏洞总记录、组件识别数。
- 展示最近任务入口。
- 提供进入全局态势大盘的入口。
- 提供最近报告入口。

数据来源：

```text
GET /api/dashboard/summary
```

中间产物层对应情况：

```text
部分对应。
```

首页不直接读取某一份报告的 `analysis_artifacts`，而是读取后端聚合后的 `/api/dashboard/summary`。这个 summary 的一部分数据来自历史报告里的真实字段，包括漏洞数量、组件数量、证据链数量等。

注意：

当前首页仍保留了示例数据回退。当后端 summary 不存在或任务数为 0 时，页面会用 `mockData` 中的示例值兜底，并打上标签“示例数据”，避免界面空白。

相关文件：

```text
src/components/dashboard/mockData.ts
```

## 2. 新建扫描任务

路由：

```text
/task/new
```

页面文件：

```text
src/routes/NewTaskPage.tsx
```

主要组件：

```text
src/components/upload/UploadDropzone.tsx
```

主要功能：

- 选择或拖拽 APK 文件。
- 上传 APK。
- 提交分析任务。
- 创建任务后跳转到执行监控页。

数据来源：

```text
POST /api/upload
POST /api/analyze
```

中间产物层对应情况：

```text
不直接对应。
```

这个页面发生在分析开始之前，所以没有 `analysis_artifacts`。它只负责创建任务，不展示分析证据。

## 3. 执行监控

路由：

```text
/task/:taskId/execution
```

页面文件：

```text
src/routes/ExecutionPage.tsx
```

主要组件：

```text
src/components/execution/ExecutionStatusPanel.tsx
src/components/execution/ScanProgress.tsx
src/components/common/StageBadge.tsx
```

主要功能：

- 展示任务阶段。
- 展示 WebSocket 连接状态。
- 展示扫描进度与日志条数。
- 报告完成后自动跳转到报告页。

数据来源：

```text
GET /api/task/:taskId
WebSocket /api/logs?task_id=<taskId>
GET /api/report?task_id=<taskId>
```

中间产物层对应情况：

```text
间接对应。
```

执行监控页展示的是任务运行中的实时状态。当前它主要依赖 WebSocket 日志、任务状态和前端状态机，不直接读取 `analysis_artifacts.execution_trace`。

真正结构化的阶段轨迹保存在报告生成后的：

```text
report.analysis_artifacts.execution_trace
```

这部分目前主要由报告页的 `AnalysisTracePanel` 展示。

注意：

当前执行页的扫描进度仍会根据日志和任务阶段进行前端估算。它不是完全由 `execution_trace.stages` 驱动。后续如果要让执行页也完全对应中间产物层，应让后端在任务运行过程中实时推送结构化 stage event，而不是只在最终报告中保存。

## 4. 扫描报告

路由：

```text
/report/:taskId
```

页面文件：

```text
src/routes/ReportPage.tsx
```

主要组件：

```text
src/components/report/ReportSummaryCards.tsx
src/components/report/AnalysisTracePanel.tsx
src/components/report/SbomGraph.tsx
src/components/report/LibrariesTable.tsx
src/components/report/VulnerabilityTable.tsx
src/components/report/EvidencePanel.tsx
src/components/report/CopilotPanel.tsx
```

主要功能：

- 展示 APK 基础信息。
- 展示报告摘要卡片。
- 展示中间产物摘要和执行轨迹。
- 展示 SBOM 拓扑图。
- 展示组件清单。
- 展示漏洞明细。
- 展示单个漏洞的补丁证据。
- 基于 evidence 生成 Copilot 解释文本。

数据来源：

```text
GET /api/report?task_id=<taskId>
```

中间产物层对应情况：

```text
强对应。
```

这是当前最完整消费中间产物层的界面。

### `AnalysisTracePanel`

文件：

```text
src/components/report/AnalysisTracePanel.tsx
```

读取字段：

```text
report.analysisArtifacts
report.analysisArtifacts.execution_trace.stages
report.analysisArtifacts.summary
```

展示内容：

- 补丁证据链数量。
- 候选类证据数量。
- 漏洞记录数量。
- 初始化、LibHunter、PHunter、报告汇总等阶段。
- 每个阶段的状态、耗时和摘要。

### `EvidencePanel`

文件：

```text
src/components/report/EvidencePanel.tsx
```

读取字段：

```text
vulnerability.evidence
vulnerability.preSimilarity
vulnerability.postSimilarity
```

这些字段来自后端报告中的：

```text
report.vulnerabilities[*].evidence
```

同时也会出现在：

```text
report.analysis_artifacts.evidence.patches[*].evidence
```

展示内容：

- Pre Similarity。
- Post Similarity。
- 补丁资源。
- PHunter 验证状态。
- 返回码。
- 重试状态。
- 补丁相关方法数量。
- 候选类范围。
- 原始调试字段。

### `CopilotPanel`

文件：

```text
src/components/report/CopilotPanel.tsx
src/hooks/useCopilotStream.ts
src/utils/copilot.ts
```

读取字段：

```text
selected vulnerability
report.usedLibraries
report.vulnerabilities
vulnerability.evidence
```

中间产物层对应情况：

```text
证据约束解释。
```

当前 Copilot 不是真实 LLM API，而是基于后端保存的 evidence 生成解释文本。它的定位是后续智能层的前端雏形：解释可以智能化，但必须受 evidence 约束。

### `SbomGraph`

文件：

```text
src/components/report/SbomGraph.tsx
```

读取字段：

```text
report.usedLibraries
report.vulnerabilities
```

中间产物层对应情况：

```text
部分对应。
```

SBOM 拓扑图主要使用最终报告字段 `used_libraries` 和 `vulnerabilities`，不是直接读取 `analysis_artifacts.evidence.libraries`。不过这些最终字段中的 `target_classes`、`evidence` 已经由后端中间产物逻辑补强。

## 5. 全局态势感知大盘

路由：

```text
/global-dashboard
```

页面文件：

```text
src/routes/GlobalDashboardPage.tsx
```

主要组件：

```text
src/components/dashboard/TaskTrendChart.tsx
src/components/dashboard/CveTopList.tsx
src/components/dashboard/LibrarySourceChart.tsx
```

主要功能：

- 展示总任务数。
- 展示总漏洞数。
- 展示总组件数。
- 展示任务状态趋势。
- 展示高风险 CVE TOP 榜。
- 展示组件分布图。

数据来源：

```text
GET /api/dashboard/summary
GET /api/ecosystem/summary
```

中间产物层对应情况：

```text
部分对应。
```

全局大盘不直接读取某一份报告的 `analysis_artifacts`，而是读取后端聚合结果。后端聚合会从数据库任务和报告文件中汇总真实数据。

聚合数据包括：

```text
task_stats
vulnerability_stats
library_stats
engine_stats
trend
```

其中 `engine_stats.patch_evidence_count`、`library_stats.target_class_count` 等字段与中间产物层有关。

全局大盘中的 CVE TOP 榜和第三方组件排行支持两个视角：

```text
本地扫描聚合
生态参考情报
```

`本地扫描聚合` 是默认视角，展示用户已经完成的扫描任务中真实命中的 CVE 和组件排行。

`生态参考情报` 展示互联网/开源生态中值得关注的 CVE 和 TPL 热度参考。该视角必须明确标注“不代表当前 APK 命中”，避免客户把生态风险误认为本地扫描结果。

注意：

当前全局大盘仍保留示例数据回退。当 summary 不存在或任务数为 0 时，页面会显示 `mockData` 中的示例数据，并标记为“示例数据”。这不是完整真实数据状态。

## 数据流

### 上传并创建任务

```text
NewTaskPage
  └── useTaskStore.uploadAndAnalyze()
      ├── POST /api/upload
      └── POST /api/analyze
```

### 监控执行

```text
ExecutionPage
  └── useTaskStore.connectExecution()
      ├── GET /api/task/:taskId
      ├── WebSocket /api/logs?task_id=<taskId>
      └── GET /api/report?task_id=<taskId>
```

### 加载报告

```text
ReportPage
  └── useTaskStore.ensureReport()
      └── GET /api/report?task_id=<taskId>
          └── reportAdapter
              └── ReportModel.analysisArtifacts
```

### 加载大盘

```text
DashboardPage / GlobalDashboardPage
  └── fetchDashboardSummary()
      └── GET /api/dashboard/summary
```

## 类型和适配层

后端原始合同：

```text
src/types/contracts.ts
```

前端领域模型：

```text
src/types/domain.ts
```

报告适配：

```text
src/services/adapters/reportAdapter.ts
```

API 客户端：

```text
src/services/api.ts
```

任务状态和本地持久化：

```text
src/store/taskStore.ts
```

## 哪些地方仍不是完整中间产物驱动

当前还有几处需要注意：

1. 首页和全局大盘仍保留 `mockData` 示例数据回退。
   有真实 summary 时会优先显示真实聚合；没有真实数据时会回退到展示值。

2. 执行页进度不是完全由结构化 `execution_trace` 驱动。
   当前运行时更多依赖 WebSocket 日志和前端估算。`execution_trace` 是最终报告里的结构化轨迹。

3. SBOM 拓扑图主要使用 `used_libraries` 和 `vulnerabilities`。
   它并不是直接画 `analysis_artifacts.evidence.libraries`，但使用的数据已经被后端证据层补强。

4. Copilot 当前不是外部 LLM。
   它是基于 evidence 的前端解释生成，用来模拟后续智能层的证据约束输出。

## 后续改进建议

为了让所有界面都完整对应中间产物层，可以继续做：

- 后端在 WebSocket 中推送结构化 stage event，让执行页直接使用 `execution_trace` 同构数据。
- 移除或明确隔离 `mockData`，避免示例数据和真实数据混淆。
- 让 SBOM 图直接读取 `analysis_artifacts.evidence.libraries` 中的候选类和证据数量。
- 给 Copilot 接入真实 LLM API，但要求输入必须来自 `analysis_artifacts.evidence`。
- 给每个界面增加“数据来源”标识，区分真实聚合、报告证据、运行日志和示例数据。
