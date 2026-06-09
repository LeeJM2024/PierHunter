import {
  Activity,
  ArrowRight,
  BarChart3,
  Bug,
  Code,
  Cpu,
  Database,
  FileCode,
  GitBranch,
  Layers,
  Network,
  Radar,
  Shield,
  Zap,
} from "lucide-react";
import { Link } from "react-router-dom";

import { mockTaskStats, mockVulnerabilityStats, mockTotalLibraries } from "./mockData";
import { Panel } from "../common/Panel";
import type { DashboardSummaryRaw } from "../../types/contracts";

export function DashboardHero({ summary }: { summary: DashboardSummaryRaw | null }): JSX.Element {
  const hasRealSummary = Boolean(summary && summary.task_stats.total_tasks > 0);
  const stats = {
    totalApks: hasRealSummary ? summary!.task_stats.completed_tasks : mockTaskStats.completedTasks,
    highRiskVulns: hasRealSummary ? summary!.vulnerability_stats.high : mockVulnerabilityStats.high,
    recoveredFunctions: hasRealSummary ? summary!.library_stats.target_class_count : 386,
    totalTasks: hasRealSummary ? summary!.task_stats.total_tasks : mockTaskStats.totalTasks,
    criticalCves: hasRealSummary ? summary!.vulnerability_stats.critical : mockVulnerabilityStats.critical,
    analyzedLibraries: hasRealSummary ? summary!.library_stats.total_libraries : mockTotalLibraries,
    semanticMatches: hasRealSummary ? summary!.engine_stats.semantic_matches : 214,
    patchEvidence: hasRealSummary ? summary!.engine_stats.patch_evidence_count : 128,
    successRate: hasRealSummary ? summary!.task_stats.success_rate : 96,
    avgScanSeconds: hasRealSummary ? Math.round(summary!.task_stats.avg_scan_seconds) : mockTaskStats.avgScanSeconds,
    unknownResults: hasRealSummary ? summary!.engine_stats.unknown_results : 17,
  };

  return (
    <Panel className="border border-slate-800/30 bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 shadow-2xl">
      <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="flex flex-col gap-5">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-4xl font-bold leading-tight tracking-tight lg:text-5xl">
              <span className="bg-gradient-to-r from-slate-100 via-emerald-200 to-cyan-200 bg-clip-text text-transparent">
                Android 漏洞自动验证平台
              </span>
            </h1>
            <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-300">
              {hasRealSummary ? "真实数据" : "示例数据"}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <HeroStat icon={<Database className="h-5 w-5 text-cyan-400" />} title="历史检测 APK 数" value={stats.totalApks} color="text-cyan-400" className="from-cyan-500/10 to-blue-500/10 border-cyan-500/20" />
            <HeroStat icon={<Shield className="h-5 w-5 text-rose-400" />} title="拦截供应链漏洞" value={stats.highRiskVulns} color="text-rose-400" className="from-rose-500/10 to-pink-500/10 border-rose-500/20" />
            <HeroStat icon={<Code className="h-5 w-5 text-emerald-400" />} title="找回内联函数数" value={stats.recoveredFunctions} color="text-emerald-400" className="from-emerald-500/10 to-green-500/10 border-emerald-500/20" />
            <HeroStat icon={<GitBranch className="h-5 w-5 text-violet-400" />} title="语义匹配成功" value={stats.semanticMatches} color="text-violet-400" className="from-violet-500/10 to-purple-500/10 border-violet-500/20" />
          </div>

          <div className="flex flex-wrap gap-3">
            <Link
              to="/task/new"
              className="group inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3.5 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 transition-all hover:scale-[1.02] hover:shadow-xl hover:shadow-emerald-500/30"
            >
              <Zap className="h-4 w-4 transition-transform group-hover:rotate-12" />
              开始新任务
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </Link>
            <Link
              to="/global-dashboard"
              className="group inline-flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-5 py-3.5 text-sm font-semibold text-emerald-400 transition-all hover:scale-[1.02] hover:border-emerald-500/50 hover:bg-emerald-500/20"
            >
              <Radar className="h-4 w-4 transition-transform group-hover:rotate-45" />
              全局态势感知
            </Link>
            <div className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/50 px-4 py-3.5 text-sm text-slate-300">
              <BarChart3 className="h-4 w-4 text-cyan-400" />
              实时威胁监控
            </div>
          </div>
        </div>

        <div className="space-y-5">
          <div className="rounded-xl border border-slate-800/50 bg-gradient-to-br from-slate-900/60 to-slate-950/60 p-4 backdrop-blur-sm">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
                <Cpu className="h-4 w-4 text-emerald-400" />
                引擎性能指标
              </h3>
              <div className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" />
            </div>
            <div className="space-y-2.5">
              <EngineMetric label="任务完成率" value={`${stats.successRate}%`} color="text-emerald-400" />
              <EngineMetric label="平均扫描耗时" value={`${stats.avgScanSeconds}s`} color="text-cyan-400" />
              <EngineMetric label="语义相似度记录" value={String(stats.semanticMatches)} color="text-emerald-400" />
              <EngineMetric label="待复核结果" value={String(stats.unknownResults)} color="text-amber-400" />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <SmallMetric icon={<Layers className="h-3.5 w-3.5 text-blue-400" />} title="分析组件" value={stats.analyzedLibraries} desc="第三方库" color="text-blue-400" />
            <SmallMetric icon={<Bug className="h-3.5 w-3.5 text-rose-400" />} title="严重 CVE" value={stats.criticalCves} desc="CVSS 9.0+" color="text-rose-400" />
            <SmallMetric icon={<FileCode className="h-3.5 w-3.5 text-violet-400" />} title="补丁证据链" value={stats.patchEvidence} desc="语义适配" color="text-violet-400" />
            <SmallMetric icon={<Network className="h-3.5 w-3.5 text-amber-400" />} title="总任务数" value={stats.totalTasks} desc="历史记录" color="text-amber-400" />
          </div>
        </div>
      </div>

      <div className="mt-8 border-t border-slate-800/50 pt-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            <StatusPill icon={<Activity className="h-3 w-3" />} label="引擎" value={hasRealSummary ? "已接入" : "待接入真实任务"} color="text-emerald-400" />
            <StatusPill icon={<Radar className="h-3 w-3" />} label="数据层" value={hasRealSummary ? "真实聚合" : "示例数据"} color="text-cyan-400" />
          </div>
          <div className="text-xs text-slate-500">v2.4.1</div>
        </div>
      </div>
    </Panel>
  );
}

function HeroStat({ icon, title, value, color, className }: { icon: JSX.Element; title: string; value: number; color: string; className: string }): JSX.Element {
  return (
    <div className={`rounded-xl border bg-gradient-to-br p-5 backdrop-blur-sm transition-all hover:scale-[1.02] ${className}`}>
      <div className="mb-2 flex items-center gap-2">
        {icon}
        <span className="text-sm text-slate-400">{title}</span>
      </div>
      <div className={`font-mono text-3xl font-bold ${color}`}>{value.toLocaleString()}</div>
      <div className="mt-3 h-px w-full bg-gradient-to-r from-transparent via-current to-transparent opacity-20" />
    </div>
  );
}

function EngineMetric({ label, value, color }: { label: string; value: string; color: string }): JSX.Element {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-slate-400">{label}</span>
      <span className={`font-mono text-sm font-bold ${color}`}>{value}</span>
    </div>
  );
}

function SmallMetric({ icon, title, value, desc, color }: { icon: JSX.Element; title: string; value: number; desc: string; color: string }): JSX.Element {
  return (
    <div className="rounded-xl border border-slate-800/40 bg-slate-900/40 p-3 backdrop-blur-sm transition-all hover:scale-[1.02] hover:bg-slate-800/50">
      <div className="mb-1 flex items-center gap-1.5">
        {icon}
        <span className="text-[11px] font-medium text-white">{title}</span>
      </div>
      <div className={`font-mono text-lg font-bold leading-none ${color}`}>{value.toLocaleString()}</div>
      <div className="mt-0.5 text-[11px] text-slate-400">{desc}</div>
    </div>
  );
}

function StatusPill({ icon, label, value, color }: { icon: JSX.Element; label: string; value: string; color: string }): JSX.Element {
  return (
    <div className="flex items-center gap-2">
      <div className={`flex items-center gap-1 ${color}`}>
        <div className="h-2 w-2 animate-pulse rounded-full bg-current" />
        {icon}
      </div>
      <span className="text-xs text-slate-400">
        {label} <span className={`font-medium ${color}`}>{value}</span>
      </span>
    </div>
  );
}
