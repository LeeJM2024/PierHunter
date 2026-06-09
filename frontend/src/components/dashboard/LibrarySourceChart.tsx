import { Layers, PieChart, Shield, Zap } from "lucide-react";

import { mockComponentRiskData, mockLibrarySourceData, mockTotalLibraries } from "./mockData";
import type { DashboardSummaryRaw, EcosystemSummaryRaw } from "../../types/contracts";

const ECOSYSTEM_DISPLAY_LIMIT = 15;

export function LibrarySourceChart({ summary, ecosystemSummary, mode }: { summary: DashboardSummaryRaw | null; ecosystemSummary?: EcosystemSummaryRaw | null; mode?: "local" | "ecosystem" }): JSX.Element {
  if (mode === "ecosystem") {
    return <EcosystemLibraryChart ecosystemSummary={ecosystemSummary} />;
  }

  const hasRealLibraries = Boolean(summary && summary.library_stats.top_libraries.length > 0);

  if (!hasRealLibraries) {
    return <MockLibrarySourceChart />;
  }

  const topLibraries = summary!.library_stats.top_libraries;
  const totalLibraries = summary!.library_stats.total_libraries;
  const maxCount = Math.max(...topLibraries.map((item) => item.count), 1);

  return (
    <div className="space-y-4">
      <Header mode="真实聚合" total={totalLibraries} title="识别组件分布" />

      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-4">
        <div className="grid grid-cols-3 gap-3">
          <Metric label="唯一组件" value={summary!.library_stats.unique_libraries} className="text-cyan-400" />
          <Metric label="候选类证据" value={summary!.library_stats.target_class_count} className="text-violet-400" />
          <Metric label="补丁证据链" value={summary!.engine_stats.patch_evidence_count} className="text-emerald-400" />
        </div>
      </div>

      <div className="space-y-2">
        {topLibraries.map((lib) => {
          const ratio = Math.max((lib.count / maxCount) * 100, 4);
          const risky = lib.vulnerability_count > 0;
          return (
            <div key={lib.name} className="rounded-lg border border-slate-700/40 bg-slate-800/25 p-3">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-white">{lib.name}</div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-slate-400">
                    <Shield className={`h-3 w-3 ${risky ? "text-rose-400" : "text-emerald-400"}`} />
                    <span>漏洞关联 {lib.vulnerability_count}</span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-slate-100">{lib.count}</div>
                  <div className="text-xs text-slate-500">命中</div>
                </div>
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-700/50">
                <div className={`h-full ${risky ? "bg-rose-500" : "bg-cyan-500"}`} style={{ width: `${ratio}%` }} />
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-center text-xs text-slate-500">
        来源：后端报告中的 used_libraries、target_classes 与漏洞关联结果
      </div>
    </div>
  );
}

function EcosystemLibraryChart({ ecosystemSummary }: { ecosystemSummary?: EcosystemSummaryRaw | null }): JSX.Element {
  const displayLimit = ecosystemSummary?.display_limit ?? ECOSYSTEM_DISPLAY_LIMIT;
  const libraries = (ecosystemSummary?.tpl_top || []).slice(0, displayLimit);
  const maxScore = Math.max(...libraries.map((item) => item.rank_score), 1);

  return (
    <div className="space-y-4">
      <Header mode="生态参考" total={ecosystemSummary?.total_library_count ?? libraries.length} title="生态 TPL 热度" />

      <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-xs leading-5 text-amber-100">
        生态参考情报，不代表当前 APK 已命中。后端基于 data/cve_kb.json 全量计算，当前仅展示排序后的 Top {displayLimit}。
      </div>

      <div className="space-y-2">
        {libraries.map((lib) => {
          const ratio = Math.max((lib.rank_score / maxScore) * 100, 5);
          return (
            <div key={lib.name} className="rounded-lg border border-slate-700/40 bg-slate-800/25 p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="truncate text-sm font-semibold text-white">{lib.display_name || lib.name}</div>
                    <span className="rounded bg-slate-900/60 px-1.5 py-0.5 text-[10px] text-cyan-200">{lib.ecosystem}</span>
                    <span className="rounded bg-slate-900/60 px-1.5 py-0.5 text-[10px] text-slate-300">CVE {lib.cve_count}</span>
                    <span className="rounded bg-slate-900/60 px-1.5 py-0.5 text-[10px] text-rose-200">高危 {lib.high_risk_cve_count}</span>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">{lib.description}</p>
                  <p className="mt-1 text-xs text-slate-500">常见用途：{lib.common_usage}</p>
                  {lib.security_focus && <p className="mt-1 text-xs text-slate-500">安全关注：{lib.security_focus}</p>}
                  {lib.notable_cves.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {lib.notable_cves.map((cve) => (
                        <span key={cve} className="rounded border border-rose-500/20 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[10px] text-rose-200">
                          {cve}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-amber-300">{lib.rank_score}</div>
                  <div className="text-xs text-slate-500">评分</div>
                </div>
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-700/50">
                <div className="h-full bg-amber-400" style={{ width: `${ratio}%` }} />
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-center text-xs text-slate-500">
        来源：{ecosystemSummary?.methodology || "生态参考情报"}
      </div>
    </div>
  );
}

function MockLibrarySourceChart(): JSX.Element {
  return (
    <div className="space-y-4">
      <Header mode="示例数据" total={mockTotalLibraries} title="组件来源占比图" />

      <div className="flex items-center gap-5">
        <div className="relative h-32 w-32 shrink-0 rounded-full bg-[conic-gradient(#3b82f6_0_49%,#8b5cf6_49%_69%,#10b981_69%_86%,#f59e0b_86%_96%,#64748b_96%_100%)] shadow-lg shadow-cyan-500/10">
          <div className="absolute inset-5 rounded-full bg-slate-950" />
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-bold text-white">{mockTotalLibraries}</span>
            <span className="text-xs text-slate-400">组件</span>
          </div>
        </div>

        <div className="flex-1 space-y-2">
          {mockLibrarySourceData.map((source) => (
            <div key={source.name} className="rounded-lg border border-slate-700/40 bg-slate-800/25 p-2.5">
              <div className="mb-1 flex items-center justify-between">
                <div className="flex min-w-0 items-center gap-2">
                  <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${source.color}`} />
                  <span className="truncate text-sm text-white">{source.name}</span>
                </div>
                <span className="text-xs font-bold text-slate-300">{source.percentage}%</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-slate-700/50">
                <div className={`h-full ${source.color}`} style={{ width: `${source.percentage}%` }} />
              </div>
              <p className="mt-1 text-xs text-slate-500">{source.description}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-xs font-medium text-slate-300">高风险组件分布</div>
          <div className="text-xs text-slate-500">TOP 8</div>
        </div>
        <div className="space-y-2">
          {mockComponentRiskData.map((component) => (
            <div key={component.name} className="flex items-center justify-between">
              <div className="flex min-w-0 items-center gap-2">
                <span className={`h-2 w-2 shrink-0 rounded-full ${riskColor(component.riskLevel)}`} />
                <span className="truncate text-xs text-slate-300">{component.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-700/50">
                  <div className={`h-full ${riskColor(component.riskLevel)}`} style={{ width: `${Math.min((component.count / 60) * 100, 100)}%` }} />
                </div>
                <span className="w-6 text-right text-xs font-medium text-slate-300">{component.count}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="mb-3 grid grid-cols-2 gap-3">
          <div className="text-center">
            <div className="text-lg font-bold text-emerald-500">59%</div>
            <div className="text-xs text-slate-400">官方源占比</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-rose-500">9%</div>
            <div className="text-xs text-slate-400">风险组件</div>
          </div>
        </div>
        <div className="text-xs text-slate-400">
          建议：优先使用 Maven Central 和私有仓库，减少遗留仓库依赖，定期更新高风险组件。
        </div>
      </div>

      <div className="text-center text-xs text-slate-500">
        来源：示例数据；后续可由中间产物记录组件仓库、包名解析与来源证据。
      </div>
    </div>
  );
}

function Header({ title, mode, total }: { title: string; mode: string; total: number }): JSX.Element {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <PieChart className="h-4 w-4 text-cyan-500" />
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      <div className="flex items-center gap-2 text-xs">
        <Zap className="h-3 w-3 text-amber-500" />
        <span className="font-medium text-amber-400">{mode}</span>
        <Layers className="h-3 w-3 text-slate-500" />
        <span className="font-medium text-slate-300">{total}</span>
        <span className="text-slate-400">组件记录</span>
      </div>
    </div>
  );
}

function riskColor(riskLevel: "critical" | "high" | "medium" | "low"): string {
  return {
    critical: "bg-rose-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-emerald-500",
  }[riskLevel];
}

function Metric({ label, value, className }: { label: string; value: number; className: string }): JSX.Element {
  return (
    <div className="text-center">
      <div className={`text-xl font-bold ${className}`}>{value}</div>
      <div className="text-xs text-slate-400">{label}</div>
    </div>
  );
}
