import type { ReportModel, VulnerabilityModel } from "../types/domain";
import { formatRatio } from "./format";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function valueText(value: unknown, fallback = "-"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item)).filter(Boolean);
}

function statusGuidance(vuln: VulnerabilityModel): string {
  if (vuln.status.normalizedStatus === "PATCH_NOT_PRESENT" || vuln.status.normalizedStatus === "PRESENT") {
    return "建议立即安排修复窗口，优先验证受影响调用链并制定热修复方案。";
  }
  if (vuln.status.normalizedStatus === "PATCH_PRESENT" || vuln.status.normalizedStatus === "NOT_PRESENT") {
    return "当前证据显示补丁生效，可作为修复完成项在答辩中展示。";
  }
  if (vuln.status.normalizedStatus === "DEAD_CODE") {
    return "该漏洞位于不可达代码路径，建议保留为低优先级技术债跟踪项。";
  }
  return "建议补充动态验证或人工复核，以降低误报和漏报风险。";
}

function findAgentFinding(vuln: VulnerabilityModel, report: ReportModel): Record<string, unknown> | null {
  const intelligence = asRecord(report.analysisArtifacts?.intelligence);
  const findings = asArray(intelligence.findings);
  const cveId = vuln.cveId.toUpperCase();
  const library = vuln.library.toLowerCase();
  for (const item of findings) {
    const finding = asRecord(item);
    const findingCve = valueText(finding.cve_id || finding.cveId || finding.id, "").toUpperCase();
    const findingLibrary = valueText(finding.library || finding.library_name || finding.component, "").toLowerCase();
    if (findingCve === cveId && (!findingLibrary || findingLibrary === library || findingLibrary.includes(library) || library.includes(findingLibrary))) {
      return finding;
    }
  }
  return null;
}

function buildAgentNarrative(vuln: VulnerabilityModel, report: ReportModel): string | null {
  const intelligence = asRecord(report.analysisArtifacts?.intelligence);
  if (!Object.keys(intelligence).length) return null;

  const provider = valueText(intelligence.provider, "unknown-provider");
  const model = valueText(intelligence.model, "unknown-model");
  const status = valueText(intelligence.status, "unknown");
  const fallback = asRecord(intelligence.fallback);
  const fallbackUsed = Boolean(fallback.used);
  const finding = findAgentFinding(vuln, report);

  if (!finding && !intelligence.agent_summary && !intelligence.risk_level) return null;

  const libraryContext = asRecord(finding?.library_context);
  const cveContext = asRecord(finding?.cve_context);
  const evidenceRefs = asRecord(finding?.evidence_refs);
  const actions = stringList(intelligence.recommended_actions).slice(0, 4);
  const gaps = asArray(intelligence.evidence_gaps)
    .map((item) => asRecord(item))
    .map((item) => valueText(item.message || item.type, ""))
    .filter(Boolean)
    .slice(0, 3);

  return [
    `智能体来源：${provider} / ${model}（status=${status}${fallbackUsed ? "，已回退本地解释" : "，真实 API 输出"}）`,
    fallbackUsed && fallback.reason ? `回退原因：${valueText(fallback.reason)}` : "",
    `分析对象：${vuln.cveId} @ ${vuln.library}`,
    intelligence.agent_summary ? `总体摘要：${valueText(intelligence.agent_summary)}` : "",
    intelligence.risk_level ? `整体风险：${valueText(intelligence.risk_level)}` : "",
    finding ? `单项判断：${valueText(finding.rationale || finding.summary || finding.conclusion, "智能体未返回单项摘要。")}` : "",
    libraryContext.purpose ? `第三方库用途：${valueText(libraryContext.purpose)}` : "",
    cveContext.summary ? `CVE 说明：${valueText(cveContext.summary)}` : "",
    cveContext.impact ? `可能影响：${valueText(cveContext.impact)}` : "",
    cveContext.fix_advice ? `修复建议：${valueText(cveContext.fix_advice)}` : "",
    evidenceRefs.patch_related_method_count !== undefined
      ? `证据引用：patch-related methods=${valueText(evidenceRefs.patch_related_method_count)}，target classes=${valueText(evidenceRefs.target_class_count)}。`
      : "",
    actions.length ? `处置建议：\n${actions.map((item) => `- ${item}`).join("\n")}` : "",
    gaps.length ? `证据缺口：\n${gaps.map((item) => `- ${item}`).join("\n")}` : "",
  ].filter(Boolean).join("\n");
}

export function buildCopilotNarrative(vuln: VulnerabilityModel | null, report: ReportModel | null): string {
  if (!vuln || !report) {
    return "请选择一个漏洞条目，智能层将会基于当前证据包实时生成安全分析结论。";
  }

  const agentNarrative = buildAgentNarrative(vuln, report);
  if (agentNarrative) return agentNarrative;

  const evidence = asRecord(vuln.evidence);
  const verification = asRecord(evidence.verification);
  const resources = asRecord(evidence.resources);
  const targetScope = asRecord(evidence.target_scope);

  return [
    `分析对象：${vuln.cveId} @ ${vuln.library}`,
    `结论：${vuln.status.conclusion}`,
    `补丁判定：${vuln.status.label}（原始状态 ${String(vuln.status.rawStatus || "UNKNOWN")}）`,
    `证据：Pre Similarity ${formatRatio(vuln.preSimilarity)}，Post Similarity ${formatRatio(vuln.postSimilarity)}。`,
    `确定性证据：PHunter=${valueText(verification.status)}，patch-related methods=${valueText(verification.patch_related_method_count)}，returncode=${valueText(verification.returncode)}。`,
    `分析范围：${valueText(targetScope.class_count, "0")} 个候选类，来源=${valueText(targetScope.source, "LibHunter target_classes")}。`,
    `补丁资源：pre=${valueText(resources.pre_patch_artifact)}，post=${valueText(resources.post_patch_artifact)}，diff=${valueText(resources.patch_diff_artifact)}。`,
    `风险级别：${vuln.status.severity.toUpperCase()}，可达性：${vuln.status.isReachable ? "可达" : "不可达"}。`,
    `处置建议：${statusGuidance(vuln)}`,
    `报告上下文：当前 APK 共识别 ${report.usedLibraries.length} 个组件，漏洞记录 ${report.vulnerabilities.length} 条。`,
    "提示：当前解释基于后端保存的确定性中间产物生成；后续 LLM 智能体应只在这些证据边界内提出语义规约和复验策略。",
  ].join("\n");
}

export async function* streamCopilotText(text: string): AsyncGenerator<string> {
  const chunks = text.split("\n");
  for (const line of chunks) {
    for (const char of line + "\n") {
      await new Promise((resolve) => setTimeout(resolve, 12));
      yield char;
    }
    await new Promise((resolve) => setTimeout(resolve, 90));
  }
}
