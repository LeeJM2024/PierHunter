import { Activity, BarChart3, Globe, Layers3, Shield, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { Panel } from "../components/common/Panel";
import { DashboardHero } from "../components/dashboard/DashboardHero";
import { mockTaskStats, mockTotalLibraries, mockVulnerabilityStats } from "../components/dashboard/mockData";
import { RecentTasksPanel } from "../components/dashboard/RecentTasksPanel";
import { fetchDashboardSummary } from "../services/api";
import { useTaskStore } from "../store/taskStore";
import type { DashboardSummaryRaw } from "../types/contracts";

export function DashboardPage(): JSX.Element {
  const historyTaskIds = useTaskStore((state) => state.historyTaskIds);
  const reportsByTask = useTaskStore((state) => state.reportsByTask);
  const lastTaskId = useTaskStore((state) => state.lastTaskId);
  const clearTaskHistory = useTaskStore((state) => state.clearTaskHistory);
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummaryRaw | null>(null);

  useEffect(() => {
    let stopped = false;
    void fetchDashboardSummary()
      .then((summary) => {
        if (!stopped) setDashboardSummary(summary);
      })
      .catch(() => {
        if (!stopped) setDashboardSummary(null);
      });
    return () => {
      stopped = true;
    };
  }, []);

  const reports = Object.values(reportsByTask);
  const localVulns = reports.reduce((sum, report) => sum + report.vulnerabilities.length, 0);
  const localLibraries = reports.reduce((sum, report) => sum + report.usedLibraries.length, 0);
  const hasRealSummary = Boolean(dashboardSummary && dashboardSummary.task_stats.total_tasks > 0);

  const totalTasks = hasRealSummary ? dashboardSummary!.task_stats.total_tasks : Math.max(historyTaskIds.length, mockTaskStats.totalTasks);
  const totalVulns = hasRealSummary ? dashboardSummary!.vulnerability_stats.total : Math.max(localVulns, mockVulnerabilityStats.total);
  const totalLibraries = hasRealSummary ? dashboardSummary!.library_stats.total_libraries : Math.max(localLibraries, mockTotalLibraries);

  return (
    <div className="space-y-6">
      <DashboardHero summary={dashboardSummary} />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Panel title="任务总数" right={<Activity className="h-4 w-4 text-cyan-400" />} className="rounded-xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-md transition-all hover:scale-[1.02] hover:bg-white/10">
          <p className="font-mono text-3xl font-bold text-cyan-300">{totalTasks.toLocaleString()}</p>
        </Panel>

        <Panel title="漏洞总记录" right={<Shield className="h-4 w-4 text-rose-400" />} className="rounded-xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-md transition-all hover:scale-[1.02] hover:bg-white/10">
          <p className="font-mono text-3xl font-bold text-rose-400">{totalVulns.toLocaleString()}</p>
        </Panel>

        <Panel title="组件识别数" right={<Layers3 className="h-4 w-4 text-emerald-400" />} className="rounded-xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-md transition-all hover:scale-[1.02] hover:bg-white/10">
          <p className="font-mono text-3xl font-bold text-emerald-400">{totalLibraries.toLocaleString()}</p>
        </Panel>

        <Panel title="报告入口" right={<BarChart3 className="h-4 w-4 text-violet-400" />} className="rounded-xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-md transition-all hover:scale-[1.02] hover:bg-white/10">
          {lastTaskId ? (
            <Link to={`/report/${lastTaskId}`} className="inline-flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-4 py-2.5 text-sm text-violet-300 transition-all hover:scale-[1.05] hover:border-violet-500/50 hover:bg-violet-500/20">
              打开最近报告
            </Link>
          ) : (
            <p className="text-sm text-slate-500">暂无本地报告，统计卡当前显示示例数据。</p>
          )}
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <RecentTasksPanel historyTaskIds={historyTaskIds} onClear={clearTaskHistory} />

        <div className="relative group">
          <Link
            to="/global-dashboard"
            className="block rounded-xl border border-slate-700/40 bg-gradient-to-br from-slate-900/80 to-slate-800/60 p-8 backdrop-blur-sm transition-all hover:scale-[1.02] hover:bg-slate-800/70 hover:shadow-[0_20px_60px_rgba(6,182,212,0.3)]"
          >
            <div className="flex flex-col items-center space-y-4 text-center">
              <div className="relative">
                <div className="absolute inset-0 animate-pulse rounded-full bg-cyan-500/20 blur-xl" />
                <div className="relative flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg">
                  <Globe className="h-8 w-8 text-white" />
                </div>
              </div>
              <div>
                <h3 className="mb-2 text-xl font-bold text-white">全局态势感知大盘</h3>
                <div className="mb-3 flex items-center justify-center gap-2">
                  <Zap className="h-3 w-3 animate-pulse text-amber-500" />
                  <span className="text-sm font-medium text-amber-400">{hasRealSummary ? "真实聚合已接入" : "当前为示例数据"}</span>
                  <Zap className="h-3 w-3 animate-pulse text-amber-500" />
                </div>
              </div>
              <div className="inline-flex items-center gap-2 text-sm font-medium text-cyan-400">
                <span>进入全屏大屏</span>
                <div className="flex h-4 w-4 items-center justify-center rounded-full bg-cyan-500/20">
                  <div className="h-2 w-2 rounded-full bg-cyan-500" />
                </div>
              </div>
            </div>
          </Link>
          <div className="absolute -right-2 -top-2 h-4 w-4 rounded-full bg-cyan-500/30 blur-sm transition-colors group-hover:bg-cyan-500/50" />
          <div className="absolute -bottom-2 -left-2 h-4 w-4 rounded-full bg-blue-500/30 blur-sm transition-colors group-hover:bg-blue-500/50" />
        </div>
      </div>
    </div>
  );
}
