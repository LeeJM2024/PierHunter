import { Activity, ArrowLeft, Globe, Layers3, Shield, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { CveTopList } from "../components/dashboard/CveTopList";
import { LibrarySourceChart } from "../components/dashboard/LibrarySourceChart";
import { mockTaskStats, mockTotalLibraries, mockVulnerabilityStats } from "../components/dashboard/mockData";
import { TaskTrendChart } from "../components/dashboard/TaskTrendChart";
import { fetchDashboardSummary, fetchEcosystemSummary } from "../services/api";
import type { DashboardSummaryRaw, EcosystemSummaryRaw } from "../types/contracts";

type IntelMode = "local" | "ecosystem";

export function GlobalDashboardPage(): JSX.Element {
  const [summary, setSummary] = useState<DashboardSummaryRaw | null>(null);
  const [ecosystemSummary, setEcosystemSummary] = useState<EcosystemSummaryRaw | null>(null);
  const [intelMode, setIntelMode] = useState<IntelMode>("local");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stopped = false;
    void fetchDashboardSummary()
      .then((payload) => {
        if (!stopped) setSummary(payload);
      })
      .catch((err) => {
        if (!stopped) setError(err instanceof Error ? err.message : "大盘数据加载失败");
      });
    return () => {
      stopped = true;
    };
  }, []);

  useEffect(() => {
    let stopped = false;
    void fetchEcosystemSummary()
      .then((payload) => {
        if (!stopped) setEcosystemSummary(payload);
      })
      .catch(() => {
        if (!stopped) setEcosystemSummary(null);
      });
    return () => {
      stopped = true;
    };
  }, []);

  const hasRealSummary = Boolean(summary && summary.task_stats.total_tasks > 0);
  const taskStats = summary?.task_stats;
  const vulnerabilityStats = summary?.vulnerability_stats;
  const libraryStats = summary?.library_stats;

  const totalTasks = hasRealSummary ? taskStats!.total_tasks : mockTaskStats.totalTasks;
  const completedTasks = hasRealSummary ? taskStats!.completed_tasks : mockTaskStats.completedTasks;
  const failedTasks = hasRealSummary ? taskStats!.failed_tasks : mockTaskStats.failedTasks;
  const totalVulns = hasRealSummary ? vulnerabilityStats!.total : mockVulnerabilityStats.total;
  const criticalVulns = hasRealSummary ? vulnerabilityStats!.critical : mockVulnerabilityStats.critical;
  const totalLibraries = hasRealSummary ? libraryStats!.total_libraries : mockTotalLibraries;
  const uniqueLibraries = hasRealSummary ? libraryStats!.unique_libraries : 505;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/" className="inline-flex items-center gap-2 rounded-lg border border-slate-700/50 bg-slate-800/30 px-4 py-2 text-sm text-slate-300 transition-all hover:scale-[1.02] hover:border-slate-600 hover:bg-slate-800/50 hover:text-white">
            <ArrowLeft className="h-4 w-4" />
            返回操作台
          </Link>
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-cyan-500" />
            <h1 className="text-xl font-bold text-white">全局态势感知大盘</h1>
            <span className="ml-2 rounded-full bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-400">
              {intelMode === "ecosystem" ? "生态参考" : hasRealSummary ? "真实聚合" : "示例数据"}
            </span>
          </div>
        </div>
        <div className="text-xs text-slate-400">
          最后更新：{summary?.generated_at ? new Date(summary.generated_at).toLocaleString("zh-CN") : error || "等待后端连接"}
        </div>
      </div>

      <div className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-3">
        <TopCard icon={<Activity className="h-5 w-5 text-cyan-500" />} label="总任务数" value={totalTasks} badge={`+${taskStats?.daily_avg ?? mockTaskStats.dailyAvg}/天`}>
          完成 {completedTasks.toLocaleString()}，失败 {failedTasks}
        </TopCard>
        <TopCard icon={<Shield className="h-5 w-5 text-rose-500" />} label="总漏洞数" value={totalVulns} badge={`${criticalVulns} 严重`}>
          高危 {vulnerabilityStats?.high ?? mockVulnerabilityStats.high}，中危 {vulnerabilityStats?.medium ?? mockVulnerabilityStats.medium}，低危 {vulnerabilityStats?.low ?? mockVulnerabilityStats.low}
        </TopCard>
        <TopCard icon={<Layers3 className="h-5 w-5 text-emerald-500" />} label="总组件数" value={totalLibraries} badge={`${uniqueLibraries} 唯一组件`}>
          组件识别与来源统计当前可用示例数据，真实数据可逐步覆盖。
        </TopCard>
      </div>

      <div className="mb-8 rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm">
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/10">
              <Activity className="h-4 w-4 text-cyan-500" />
            </div>
            <h2 className="text-lg font-semibold text-white">任务状态趋势图</h2>
          </div>
          <div className="text-sm text-slate-400">
            最近 7 天，成功率 {taskStats?.success_rate ?? 96}%
          </div>
        </div>
        <div className="rounded-lg bg-slate-900/50 p-4">
          <TaskTrendChart summary={summary} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
        <PanelFrame
          icon={<Shield className="h-4 w-4 text-rose-500" />}
          title="高风险 CVE TOP 榜"
          right={intelMode === "ecosystem" ? "生态参考情报" : hasRealSummary ? "真实报告聚合" : "示例数据"}
          controls={<IntelModeSwitch value={intelMode} onChange={setIntelMode} />}
        >
          <CveTopList summary={summary} ecosystemSummary={ecosystemSummary} mode={intelMode} />
        </PanelFrame>
        <PanelFrame
          icon={<Layers3 className="h-4 w-4 text-emerald-500" />}
          title={intelMode === "ecosystem" ? "生态 TPL 使用热度" : "第三方组件使用次数排行"}
          right={intelMode === "ecosystem" ? `${ecosystemSummary?.tpl_top.length ?? 0} 情报项` : `${totalLibraries} 组件记录`}
          controls={<IntelModeSwitch value={intelMode} onChange={setIntelMode} />}
        >
          <LibrarySourceChart summary={summary} ecosystemSummary={ecosystemSummary} mode={intelMode} />
        </PanelFrame>
      </div>

      <div className="mt-8 text-center">
        <div className="inline-flex items-center gap-2 rounded-full bg-slate-900/50 px-4 py-2 text-xs text-slate-500">
          <Zap className="h-3 w-3 text-amber-500" />
          <span>{intelMode === "ecosystem" ? "生态参考不代表当前 APK 命中；当前 APK 风险请以本地扫描聚合为准" : "真实数据优先；缺失字段显示示例数据，等待中间产物层补齐"}</span>
          <Zap className="h-3 w-3 text-amber-500" />
        </div>
      </div>
    </div>
  );
}

function TopCard({ icon, label, value, badge, children }: { icon: JSX.Element; label: string; value: number; badge: string; children: ReactNode }): JSX.Element {
  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm transition-all hover:scale-[1.02] hover:bg-slate-800/40">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-950/50">{icon}</div>
          <div>
            <div className="text-sm text-slate-400">{label}</div>
            <div className="text-3xl font-bold text-white">{value.toLocaleString()}</div>
          </div>
        </div>
        <div className="rounded-full bg-emerald-500/10 px-2 py-1 text-xs text-emerald-500">{badge}</div>
      </div>
      <div className="text-xs text-slate-400">{children}</div>
    </div>
  );
}

function IntelModeSwitch({ value, onChange }: { value: IntelMode; onChange: (mode: IntelMode) => void }): JSX.Element {
  return (
    <div className="inline-flex rounded-lg border border-slate-700/60 bg-slate-950/70 p-1">
      {[
        { key: "local" as const, label: "本地扫描聚合" },
        { key: "ecosystem" as const, label: "生态参考情报" },
      ].map((item) => (
        <button
          key={item.key}
          type="button"
          onClick={() => onChange(item.key)}
          className={`rounded-md px-3 py-1.5 text-xs font-medium transition ${value === item.key ? "bg-cyan-500/20 text-cyan-200 shadow-sm" : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-200"}`}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

function PanelFrame({ icon, title, right, controls, children }: { icon: JSX.Element; title: string; right: string; controls?: ReactNode; children: ReactNode }): JSX.Element {
  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-950/50">{icon}</div>
          <h2 className="text-lg font-semibold text-white">{title}</h2>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-3">
          {controls}
          <div className="text-sm text-slate-400">{right}</div>
        </div>
      </div>
      <div className="rounded-lg bg-slate-900/50 p-4">{children}</div>
    </div>
  );
}
