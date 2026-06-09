import { AlertTriangle, ExternalLink, Flame, Shield, TrendingUp, Zap } from "lucide-react";

import { mockTopCves, mockVulnerabilityStats } from "./mockData";
import type { DashboardSummaryRaw, EcosystemSummaryRaw } from "../../types/contracts";
import type { SeverityLevel } from "../../types/domain";

interface CveItem {
  id: string;
  name: string;
  severity: SeverityLevel;
  affectedLibraries: number;
  trend: "up" | "down" | "stable";
  description: string;
  cwe?: string;
  cvssScore?: number | null;
  publishedDate?: string;
}

const ECOSYSTEM_DISPLAY_LIMIT = 15;

export function CveTopList({ summary, ecosystemSummary, mode }: { summary: DashboardSummaryRaw | null; ecosystemSummary?: EcosystemSummaryRaw | null; mode?: "local" | "ecosystem" }): JSX.Element {
  const isEcosystem = mode === "ecosystem";
  const displayLimit = ecosystemSummary?.display_limit ?? ECOSYSTEM_DISPLAY_LIMIT;
  const hasRealCves = Boolean(summary && summary.vulnerability_stats.top_cves.length > 0);
  const topCves: CveItem[] = hasRealCves
    ? summary!.vulnerability_stats.top_cves.map((item) => ({
        id: item.id,
        name: item.id,
        severity: normalizeSeverity(item.severity),
        affectedLibraries: item.count,
        trend: "stable",
        description: "来源于已完成扫描报告的真实聚合结果。",
      }))
    : mockTopCves;

  const ecosystemCves: CveItem[] = (ecosystemSummary?.cve_top || []).slice(0, displayLimit).map((item) => ({
    id: item.id,
    name: item.title || item.id,
    severity: normalizeSeverity(item.severity),
    affectedLibraries: item.rank_score,
    trend: "stable",
    description: `${item.summary || ""} ${item.impact || ""}`.trim() || "生态参考情报，不代表当前 APK 已命中。",
    cvssScore: item.cvss_score,
  }));

  const displayCves = isEcosystem && ecosystemCves.length > 0 ? ecosystemCves : topCves;

  const stats = hasRealCves
    ? summary!.vulnerability_stats
    : {
        ...mockVulnerabilityStats,
        info: 0,
        by_status: {},
        top_cves: [],
      };

  const ecosystemSeverityStats = ecosystemCves.reduce(
    (acc, item) => {
      acc[item.severity] += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<SeverityLevel, number>,
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Flame className="h-4 w-4 text-rose-500" />
          <h3 className="text-sm font-semibold text-white">高风险 CVE TOP 榜</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Zap className="h-3 w-3 text-amber-500" />
          <span className="font-medium text-amber-400">{isEcosystem ? "生态参考" : hasRealCves ? "真实聚合" : "示例数据"}</span>
          <span className="font-medium text-slate-300">{isEcosystem ? ecosystemSummary?.total_cve_count ?? ecosystemCves.length : stats.total}</span>
          <span className="text-slate-400">{isEcosystem ? `全量 CVE，前端展示 Top ${displayLimit}` : "漏洞"}</span>
        </div>
      </div>

      {isEcosystem && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-xs leading-5 text-amber-100">
          生态参考情报，不代表当前 APK 已命中。后端基于 data/cve_kb.json 全量计算，当前仅展示排序后的 Top {displayLimit}。
        </div>
      )}

      <div className="space-y-3">
        {displayCves.map((cve, index) => (
          <div
            key={cve.id}
            className={`rounded-lg border border-slate-700/40 p-3 transition-all hover:scale-[1.01] hover:bg-slate-800/30 ${severityBg(cve.severity)}`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className={`text-xs font-bold ${severityColor(cve.severity)}`}>{severityLabel(cve.severity)}</span>
                  <span className="rounded bg-slate-900/50 px-1.5 py-0.5 font-mono text-xs text-slate-300">{cve.id}</span>
                  {cve.trend !== "stable" && <TrendingUp className={`h-3 w-3 ${cve.trend === "up" ? "text-rose-500" : "rotate-180 text-emerald-500"}`} />}
                  <div className="ml-auto flex items-center gap-1">
                    <span className="text-xs text-slate-400">{isEcosystem ? "CVSS" : hasRealCves ? "COUNT" : "CVSS"}</span>
                    <span className={`rounded bg-slate-900/50 px-1.5 py-0.5 text-xs font-bold ${scoreColor(cve.cvssScore ?? cve.affectedLibraries)}`}>
                      {isEcosystem ? (cve.cvssScore == null ? "—" : cve.cvssScore.toFixed(1)) : hasRealCves ? cve.affectedLibraries : cve.cvssScore?.toFixed(1)}
                    </span>
                  </div>
                </div>

                <h4 className="mb-1 truncate text-sm font-bold text-white">{cve.name}</h4>
                <p className="mb-2 text-xs leading-relaxed text-slate-400">{cve.description}</p>

                <div className="flex flex-wrap items-center gap-3">
                  <div className="flex items-center gap-1">
                    <Shield className="h-3 w-3 text-slate-500" />
                    <span className="text-xs text-slate-400">
                      {isEcosystem ? "生态评分" : "命中次数"} <span className="font-medium text-slate-300">{cve.affectedLibraries}</span>
                    </span>
                  </div>
                  {cve.cwe && <span className="text-xs text-slate-400">{cve.cwe}</span>}
                  {cve.publishedDate && <span className="text-xs text-slate-500">{cve.publishedDate}</span>}
                </div>

                {cve.severity === "critical" && (
                  <div className="mt-2 flex items-center gap-2 rounded border border-rose-500/20 bg-rose-500/10 p-2">
                    <AlertTriangle className="h-3 w-3 animate-pulse text-rose-500" />
                    <span className="text-xs font-bold text-rose-400">需要优先进入补丁验证与影响面确认。</span>
                  </div>
                )}
              </div>

              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2 ${severityRing(cve.severity)} ${severityBg(cve.severity)}`}>
                <span className={`text-lg font-black ${severityColor(cve.severity)}`}>{index + 1}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="mb-2 grid grid-cols-4 gap-2">
          <Metric label="严重" value={isEcosystem ? ecosystemSeverityStats.critical : stats.critical} className="text-rose-500" />
          <Metric label="高危" value={isEcosystem ? ecosystemSeverityStats.high : stats.high} className="text-orange-500" />
          <Metric label="中危" value={isEcosystem ? ecosystemSeverityStats.medium : stats.medium} className="text-amber-500" />
          <Metric label="低危" value={isEcosystem ? ecosystemSeverityStats.low : stats.low} className="text-emerald-500" />
        </div>
        <div className="flex items-center justify-between border-t border-slate-700/40 pt-2">
          <span className="text-xs text-slate-400">
            {isEcosystem ? "生态参考情报，不代表当前 APK 已命中" : <>基于 <span className="font-medium text-slate-300">{hasRealCves ? summary!.task_stats.completed_tasks : 1185}</span> 个任务分析</>}
          </span>
          <span className="inline-flex items-center gap-1 text-xs text-slate-400">
            <ExternalLink className="h-3 w-3" />
            威胁情报视图
          </span>
        </div>
      </div>

      <div className="text-center text-xs text-slate-500">
        来源：{isEcosystem ? ecosystemSummary?.methodology || "生态参考情报" : hasRealCves ? "后端已保存扫描报告" : "示例数据，等待真实 CVE 聚合"}
      </div>
    </div>
  );
}

function normalizeSeverity(value: string): SeverityLevel {
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") return value;
  if (value === "unknown") return "info";
  return "info";
}

function severityLabel(severity: SeverityLevel): string {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" }[severity];
}

function severityColor(severity: SeverityLevel): string {
  return { critical: "text-rose-500", high: "text-orange-500", medium: "text-amber-500", low: "text-emerald-500", info: "text-slate-400" }[severity];
}

function severityBg(severity: SeverityLevel): string {
  return { critical: "bg-rose-500/10", high: "bg-orange-500/10", medium: "bg-amber-500/10", low: "bg-emerald-500/10", info: "bg-slate-500/10" }[severity];
}

function severityRing(severity: SeverityLevel): string {
  return severity === "critical" ? "border-rose-500/50" : "border-slate-700/50";
}

function scoreColor(score: number): string {
  if (score >= 9) return "text-rose-400";
  if (score >= 7) return "text-orange-400";
  if (score >= 4) return "text-amber-400";
  return "text-emerald-400";
}

function Metric({ label, value, className }: { label: string; value: number; className: string }): JSX.Element {
  return (
    <div className="text-center">
      <div className={`text-xl font-bold ${className}`}>{value}</div>
      <div className="text-xs text-slate-400">{label}</div>
    </div>
  );
}
