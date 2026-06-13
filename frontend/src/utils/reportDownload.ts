import type { AnalysisArtifactsRaw } from "../types/contracts";
import type { ReportModel, UsedLibraryModel, VulnerabilityModel } from "../types/domain";
import { formatBytes, formatRatio } from "./format";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, fallback = "-"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(6);
  if (typeof value === "boolean") return value ? "是" : "否";
  return String(value);
}

function escapeHtml(value: unknown, fallback = "-"): string {
  return text(value, fallback)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(value: unknown): string {
  const raw = text(value, "");
  if (!raw) return "-";
  const timestamp = Date.parse(raw);
  if (!Number.isFinite(timestamp)) return raw;
  return new Date(timestamp).toLocaleString("zh-CN");
}

function publicStageLabel(stage: Record<string, unknown>): string {
  if (stage.key === "libhunter") return "库版本识别";
  if (stage.key === "phunter") return "补丁验证";
  const label = text(stage.label || stage.key, "未知阶段");
  const libraryBrandPattern = new RegExp(["Lib", "Hunter"].join("") + "\\s*", "gi");
  const patchBrandPattern = new RegExp(["P", "Hunter"].join("") + "\\s*", "gi");
  return label
    .replace(libraryBrandPattern, "")
    .replace(patchBrandPattern, "")
    .replace("第三方库识别", "库版本识别")
    .replace("组件识别", "库版本识别")
    .replace("漏洞补丁验证", "补丁验证")
    .trim() || "未知阶段";
}

function durationSeconds(startedAt: unknown, finishedAt: unknown): string {
  const started = Date.parse(text(startedAt, ""));
  const finished = Date.parse(text(finishedAt, ""));
  if (!Number.isFinite(started) || !Number.isFinite(finished)) return "-";
  return `${Math.max(Math.round((finished - started) / 1000), 0)}s`;
}

function stringList(value: unknown): string[] {
  return asArray(value).map((item) => text(item, "")).filter(Boolean);
}

function table(headers: string[], rows: unknown[][]): string {
  if (!rows.length) return `<p class="muted">暂无数据。</p>`;
  return `
    <table>
      <thead>
        <tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`).join("")}
      </tbody>
    </table>
  `;
}

function bullets(items: string[]): string {
  if (!items.length) return `<p class="muted">暂无数据。</p>`;
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function tagList(items: string[]): string {
  if (!items.length) return `<span class="muted">暂无</span>`;
  return `<div class="tags">${items.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>`;
}

function section(title: string, body: string): string {
  return `<section class="pdf-section avoid-break"><h2>${escapeHtml(title)}</h2>${body}</section>`;
}

function artifactsSummary(artifacts: AnalysisArtifactsRaw | null): string {
  const summary = asRecord(artifacts?.summary);
  const statusCounts = asRecord(summary.patch_status_counts);
  const statusText = Object.entries(statusCounts).map(([key, value]) => `${key}: ${text(value)}`).join(", ") || "-";

  return table(
    ["指标", "数值"],
    [
      ["生成时间", formatDate(artifacts?.generated_at)],
      ["分析开始时间", formatDate(artifacts?.analysis_started_at)],
      ["分析完成时间", formatDate(artifacts?.analysis_finished_at)],
      ["识别组件数", summary.library_count],
      ["漏洞记录数", summary.vulnerability_count],
      ["补丁证据链", summary.patch_evidence_count],
      ["候选类证据", summary.target_class_count],
      ["补丁状态分布", statusText],
    ],
  );
}

function stagesTable(artifacts: AnalysisArtifactsRaw | null): string {
  const stages = asArray(artifacts?.execution_trace?.stages)
    .map(asRecord)
    .filter((stage) => stage.key !== "init" && stage.label !== "初始化分析任务");

  return table(
    ["阶段", "状态", "耗时", "摘要"],
    stages.map((stage) => [
      publicStageLabel(stage),
      stage.status,
      durationSeconds(stage.started_at, stage.finished_at),
      stage.summary,
    ]),
  );
}

function librariesTable(libraries: UsedLibraryModel[]): string {
  return table(
    ["组件", "原始名称", "版本", "置信度", "漏洞数", "候选类数"],
    libraries.map((lib) => [
      lib.libraryName,
      lib.rawName,
      lib.version,
      `${(lib.confidence * 100).toFixed(1)}%`,
      lib.vulnerabilityCount,
      lib.targetClasses.length,
    ]),
  );
}

function vulnerabilitiesTable(vulnerabilities: VulnerabilityModel[]): string {
  return table(
    ["CVE", "组件", "补丁状态", "风险级别", "Pre Similarity", "Post Similarity", "结论"],
    vulnerabilities.map((vuln) => [
      vuln.cveId,
      vuln.library,
      `${vuln.status.label} (${vuln.status.rawStatus})`,
      vuln.status.severity.toUpperCase(),
      formatRatio(vuln.preSimilarity),
      formatRatio(vuln.postSimilarity),
      vuln.status.conclusion,
    ]),
  );
}

function cveVersionTimelineTable(report: ReportModel): string {
  const rows = (report.cveVersionTimeline || []).flatMap((timeline) =>
    timeline.cves.map((item) => [
      timeline.libraryName,
      timeline.detectedVersion,
      item.cveId,
      item.affectedFrom && item.affectedTo ? `${item.affectedFrom} - ${item.affectedTo}` : "影响范围待确认",
      item.fixedVersion || "-",
      item.currentAffected ? "当前版本受影响" : "未命中当前版本",
    ]),
  );

  return table(
    ["组件", "当前版本", "CVE", "影响版本范围", "修复版本", "当前状态"],
    rows,
  );
}

function patchEvidence(vulnerabilities: VulnerabilityModel[]): string {
  if (!vulnerabilities.length) return `<p class="muted">暂无补丁证据。</p>`;

  return vulnerabilities.map((vuln, index) => {
    const evidence = asRecord(vuln.evidence);
    const resources = asRecord(evidence.resources);
    const verification = asRecord(evidence.verification);
    const execution = asRecord(evidence.execution);

    return `
      <article class="evidence-card avoid-break">
        <h3>${index + 1}. ${escapeHtml(vuln.cveId)} @ ${escapeHtml(vuln.library)}</h3>
        ${table(
          ["字段", "内容"],
          [
            ["补丁判定", `${vuln.status.label} (${vuln.status.rawStatus})`],
            ["Pre Similarity", formatRatio(vuln.preSimilarity)],
            ["Post Similarity", formatRatio(vuln.postSimilarity)],
            ["Pre Patch", resources.pre_patch_artifact],
            ["Post Patch", resources.post_patch_artifact],
            ["Patch Diff", resources.patch_diff_artifact],
            ["补丁验证状态", verification.status],
            ["Return Code", verification.returncode],
            ["补丁相关方法数", verification.patch_related_method_count],
            ["重试", verification.retried],
            ["stdout 行数", asRecord(execution.stdout).line_count],
            ["stderr 行数", asRecord(execution.stderr).line_count],
          ],
        )}
      </article>
    `;
  }).join("");
}

function candidateEvidence(report: ReportModel): string {
  const libraryCards = report.usedLibraries.map((lib, index) => `
    <article class="evidence-card avoid-break">
      <h3>${index + 1}. ${escapeHtml(lib.libraryName)} ${escapeHtml(lib.version)}</h3>
      <p><strong>候选类总数：</strong>${lib.targetClasses.length}</p>
      ${tagList(lib.targetClasses.slice(0, 30))}
    </article>
  `).join("");

  const scopeRows = report.vulnerabilities.map((vuln) => {
    const targetScope = asRecord(asRecord(vuln.evidence).target_scope);
    return [
      vuln.cveId,
      vuln.library,
      text(targetScope.class_count, "0"),
      stringList(targetScope.classes_sample).slice(0, 8).join(", "),
    ];
  });

  return `
    ${libraryCards || `<p class="muted">暂无组件候选类证据。</p>`}
    <h3>漏洞验证候选范围</h3>
    ${table(["CVE", "组件", "候选类数量", "候选类样本"], scopeRows)}
  `;
}

function intelligenceReport(artifacts: AnalysisArtifactsRaw | null): string {
  const intelligence = asRecord(artifacts?.intelligence);
  if (!Object.keys(intelligence).length) return `<p class="muted">当前报告暂无智能层分析结果。</p>`;

  const fallback = asRecord(intelligence.fallback);
  const libraryOverview = asArray(intelligence.library_overview).map(asRecord);
  const findings = asArray(intelligence.findings).map(asRecord);
  const actions = stringList(intelligence.recommended_actions);
  const gaps = asArray(intelligence.evidence_gaps)
    .map(asRecord)
    .map((gap) => text(gap.message || gap.type, ""))
    .filter(Boolean);

  const findingCards = findings.map((finding, index) => {
    const libraryContext = asRecord(finding.library_context);
    const cveContext = asRecord(finding.cve_context);
    const evidenceRefs = asRecord(finding.evidence_refs);

    return `
      <article class="evidence-card avoid-break">
        <h3>${index + 1}. ${escapeHtml(finding.cve_id)} @ ${escapeHtml(finding.library)}</h3>
        <p><strong>优先级：</strong>${escapeHtml(finding.priority)}</p>
        <p><strong>置信度：</strong>${escapeHtml(finding.confidence)}</p>
        <p><strong>判断依据：</strong>${escapeHtml(finding.rationale)}</p>
        <p><strong>第三方库用途：</strong>${escapeHtml(libraryContext.purpose)}</p>
        <p><strong>CVE 说明：</strong>${escapeHtml(cveContext.summary)}</p>
        <p><strong>影响：</strong>${escapeHtml(cveContext.impact)}</p>
        <p><strong>修复建议：</strong>${escapeHtml(cveContext.fix_advice)}</p>
        <p><strong>证据引用：</strong>patch-related methods=${escapeHtml(evidenceRefs.patch_related_method_count)}，target classes=${escapeHtml(evidenceRefs.target_class_count)}，pre=${escapeHtml(evidenceRefs.pre_similarity)}，post=${escapeHtml(evidenceRefs.post_similarity)}</p>
      </article>
    `;
  }).join("");

  return `
    ${table(
      ["字段", "内容"],
      [
        ["Provider", intelligence.provider],
        ["Model", intelligence.model],
        ["Status", intelligence.status],
        ["生成时间", formatDate(intelligence.generated_at)],
        ["是否回退", fallback.used ? "是" : "否"],
        ["回退原因", fallback.reason],
        ["整体风险", intelligence.risk_level],
        ["总体摘要", intelligence.agent_summary],
      ],
    )}
    <h3>第三方库用途概览</h3>
    ${table(
      ["组件", "版本", "用途"],
      libraryOverview.map((item) => [item.name, item.version, item.purpose]),
    )}
    <h3>智能层漏洞分析</h3>
    ${findingCards || `<p class="muted">暂无智能层单项发现。</p>`}
    <h3>智能层处置建议</h3>
    ${bullets(actions)}
    <h3>证据缺口</h3>
    ${bullets(gaps)}
  `;
}

function rawEvidenceAppendix(artifacts: AnalysisArtifactsRaw | null): string {
  const evidence = asRecord(artifacts?.evidence);
  if (!Object.keys(evidence).length) return `<p class="muted">暂无原始 evidence 字段。</p>`;
  return `<pre>${escapeHtml(JSON.stringify(evidence, null, 2))}</pre>`;
}

function reportStyles(): string {
  return `
    <style>
      .pdf-report {
        width: 760px;
        box-sizing: border-box;
        background: #ffffff;
        color: #111827;
        font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", "Droid Sans Fallback", Arial, sans-serif;
        font-size: 12px;
        line-height: 1.65;
        padding: 32px;
      }
      .pdf-report h1 {
        margin: 0;
        color: #0f172a;
        font-size: 26px;
        line-height: 1.25;
      }
      .pdf-report h2 {
        margin: 26px 0 12px;
        padding-bottom: 6px;
        border-bottom: 2px solid #0f766e;
        color: #0f172a;
        font-size: 17px;
      }
      .pdf-report h3 {
        margin: 16px 0 8px;
        color: #164e63;
        font-size: 13px;
      }
      .pdf-report .subtitle {
        margin: 8px 0 0;
        color: #475569;
      }
      .pdf-report .summary-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 8px;
        margin-top: 18px;
      }
      .pdf-report .summary-card {
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        padding: 9px;
        background: #f8fafc;
      }
      .pdf-report .summary-card span {
        display: block;
        color: #64748b;
        font-size: 10px;
      }
      .pdf-report .summary-card strong {
        display: block;
        margin-top: 2px;
        color: #0f172a;
        font-size: 20px;
      }
      .pdf-report table {
        width: 100%;
        border-collapse: collapse;
        table-layout: fixed;
        margin: 8px 0 14px;
      }
      .pdf-report th,
      .pdf-report td {
        border: 1px solid #d7dee8;
        padding: 6px 7px;
        vertical-align: top;
        word-break: break-word;
      }
      .pdf-report th {
        background: #e2e8f0;
        color: #0f172a;
        font-weight: 700;
      }
      .pdf-report .evidence-card {
        border: 1px solid #d7dee8;
        border-radius: 8px;
        padding: 10px 12px;
        margin: 10px 0;
        background: #fbfdff;
      }
      .pdf-report .tags {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
        margin-top: 6px;
      }
      .pdf-report .tags span {
        border: 1px solid #bae6fd;
        border-radius: 4px;
        background: #f0f9ff;
        color: #075985;
        padding: 2px 5px;
        font-family: Consolas, "Courier New", monospace;
        font-size: 9px;
      }
      .pdf-report pre {
        max-height: 520px;
        overflow: hidden;
        white-space: pre-wrap;
        word-break: break-word;
        border: 1px solid #d7dee8;
        border-radius: 8px;
        background: #0f172a;
        color: #e2e8f0;
        padding: 10px;
        font-family: Consolas, "Courier New", monospace;
        font-size: 9px;
      }
      .pdf-report .muted {
        color: #64748b;
      }
      .pdf-report .avoid-break {
        break-inside: avoid;
        page-break-inside: avoid;
      }
      .pdf-report ul {
        margin: 6px 0 14px 18px;
        padding: 0;
      }
    </style>
  `;
}

function buildReportHtml(report: ReportModel): string {
  const artifacts = report.analysisArtifacts;
  return `
    ${reportStyles()}
    <article class="pdf-report">
      <h1>Android 第三方库漏洞检测报告</h1>
      <p class="subtitle">报告基于本次检测任务生成，包含真实中间产物、补丁验证证据与智能层分析结果。</p>

      <div class="summary-grid avoid-break">
        <div class="summary-card"><span>高风险</span><strong>${report.summary.highRisk}</strong></div>
        <div class="summary-card"><span>待复核</span><strong>${report.summary.mediumRisk}</strong></div>
        <div class="summary-card"><span>安全/已修复</span><strong>${report.summary.safeCount}</strong></div>
        <div class="summary-card"><span>不确定状态</span><strong>${report.summary.unknownCount}</strong></div>
        <div class="summary-card"><span>漏洞总数</span><strong>${report.summary.total}</strong></div>
      </div>

      ${section("报告信息", table(
        ["字段", "内容"],
        [
          ["检测时间", formatDate(artifacts?.analysis_finished_at || artifacts?.generated_at)],
          ["Task ID", report.taskId],
          ["报告路径", report.reportPath],
          ["APK 名称", report.apkInfo.name],
          ["APK SHA256", report.apkInfo.sha256],
          ["APK 大小", formatBytes(report.apkInfo.size)],
        ],
      ))}

      ${section("真实中间产物摘要", artifactsSummary(artifacts))}
      ${section("执行阶段", stagesTable(artifacts))}
      ${section("CVE 影响版本演进时间轴", cveVersionTimelineTable(report))}
      ${section("命中的库版本", librariesTable(report.usedLibraries))}
      ${section("漏洞明细", vulnerabilitiesTable(report.vulnerabilities))}
      ${section("补丁证据链", patchEvidence(report.vulnerabilities))}
      ${section("候选类证据", candidateEvidence(report))}
      ${section("智能层分析结果", intelligenceReport(artifacts))}
      ${section("原始中间产物 evidence 附录", rawEvidenceAppendix(artifacts))}
    </article>
  `;
}

async function waitForReportLayout(element: HTMLElement): Promise<void> {
  await Promise.resolve(document.fonts?.ready);
  await new Promise<void>((resolve) => {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => resolve());
    });
  });
  const rect = element.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) {
    throw new Error("PDF report layout is empty.");
  }
}

export async function downloadDetectionReport(report: ReportModel): Promise<void> {
  const { default: html2pdf } = await import("html2pdf.js");
  const container = document.createElement("div");
  container.innerHTML = buildReportHtml(report);
  container.style.position = "fixed";
  container.style.left = "0";
  container.style.top = "0";
  container.style.width = "820px";
  container.style.pointerEvents = "none";
  container.style.zIndex = "-1";
  container.style.background = "#ffffff";
  document.body.appendChild(container);

  const apkStem = report.apkInfo.name.replace(/\.[^.]+$/, "").replace(/[\\/:*?"<>|\s]+/g, "_") || "apk";
  const filename = `${apkStem}_检测报告.pdf`;
  const reportElement = container.querySelector(".pdf-report");

  try {
    if (!(reportElement instanceof HTMLElement)) {
      throw new Error("PDF report element is missing.");
    }
    await waitForReportLayout(reportElement);
    await html2pdf()
      .set({
        filename,
        margin: [8, 8, 10, 8],
        image: { type: "jpeg", quality: 0.98 },
        html2canvas: {
          scale: 2,
          useCORS: true,
          backgroundColor: "#ffffff",
          windowWidth: 820,
        },
        jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
        pagebreak: { mode: ["css", "legacy"] },
      })
      .from(reportElement)
      .save();
  } finally {
    container.remove();
  }
}
