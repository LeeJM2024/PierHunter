import { Calendar, LineChart, TrendingDown, TrendingUp, Zap } from "lucide-react";

import { mockSuccessRate, mockTaskTrendData } from "./mockData";
import type { DashboardSummaryRaw } from "../../types/contracts";

interface TrendPoint {
  day: string;
  completed: number;
  failed: number;
  scanning: number;
  queued: number;
  total: number;
}

export function TaskTrendChart({ summary }: { summary: DashboardSummaryRaw | null }): JSX.Element {
  const hasRealTrend = Boolean(summary && summary.trend.length > 0 && summary.task_stats.total_tasks > 0);
  const trendData: TrendPoint[] = hasRealTrend ? summary!.trend : mockTaskTrendData;
  const totalScanning = trendData.reduce((sum, day) => sum + day.scanning, 0);
  const totalQueued = trendData.reduce((sum, day) => sum + day.queued, 0);
  const totalTasks = trendData.reduce((sum, day) => sum + day.total, 0);
  const totalCompleted = trendData.reduce((sum, day) => sum + day.completed, 0);
  const totalFailed = trendData.reduce((sum, day) => sum + day.failed, 0);
  const successRate = hasRealTrend ? summary!.task_stats.success_rate : mockSuccessRate;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <LineChart className="h-4 w-4 text-cyan-500" />
          <h3 className="text-sm font-semibold text-white">任务状态趋势图</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Zap className="h-3 w-3 text-amber-500" />
          <span className="font-medium text-amber-400">{hasRealTrend ? "真实聚合" : "示例数据"}</span>
          <Calendar className="h-3 w-3 text-slate-500" />
          <span className="text-slate-400">最近 7 天</span>
        </div>
      </div>

      <div className="space-y-3">
        {trendData.map((dayData) => (
          <div key={dayData.day} className="flex items-center justify-between rounded-lg p-2 transition-colors hover:bg-slate-800/20">
            <span className="w-14 text-xs text-slate-400">{dayData.day}</span>
            <div className="flex flex-1 items-center gap-1">
              {Array.from({ length: Math.min(Math.ceil(dayData.completed / 8), 16) }).map((_, i) => (
                <div key={`completed-${i}`} className="h-2 w-2 rounded-full bg-emerald-500/80" />
              ))}
              {Array.from({ length: Math.min(dayData.failed, 4) }).map((_, i) => (
                <div key={`failed-${i}`} className="h-2 w-2 rounded-full bg-rose-500/80" />
              ))}
              {Array.from({ length: Math.min(dayData.scanning, 6) }).map((_, i) => (
                <div key={`scanning-${i}`} className="h-2 w-2 animate-pulse rounded-full bg-amber-500/80" />
              ))}
              {Array.from({ length: Math.min(dayData.queued, 4) }).map((_, i) => (
                <div key={`queued-${i}`} className="h-2 w-2 rounded-full bg-cyan-500/70" />
              ))}
            </div>
            <div className="text-right">
              <span className="text-xs font-semibold text-white">{dayData.total}</span>
              <div className="text-xs text-slate-500">任务</div>
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="mb-2 grid grid-cols-4 gap-3">
          <Metric label="完成" value={totalCompleted} className="text-emerald-500" />
          <Metric label="失败" value={totalFailed} className="text-rose-500" />
          <Metric label="进行中" value={totalScanning} className="text-amber-500" />
          <Metric label="排队" value={totalQueued} className="text-cyan-500" />
        </div>

        <div className="flex items-center justify-between border-t border-slate-700/40 pt-2">
          <div className="text-xs text-slate-400">
            总计 <span className="font-medium text-slate-300">{totalTasks}</span> 任务
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">成功率</span>
            <span className={`text-sm font-bold ${successRate >= 95 ? "text-emerald-500" : "text-amber-500"}`}>
              {successRate}%
            </span>
            {successRate >= 95 ? <TrendingUp className="h-3 w-3 text-emerald-500" /> : <TrendingDown className="h-3 w-3 text-amber-500" />}
          </div>
        </div>
      </div>

      <div className="text-center text-xs text-slate-500">
        来源：{hasRealTrend ? "后端任务数据库与已保存报告" : "示例数据，等待真实任务沉淀"}
      </div>
    </div>
  );
}

function Metric({ label, value, className }: { label: string; value: number; className: string }): JSX.Element {
  return (
    <div className="text-center">
      <div className={`text-lg font-bold ${className}`}>{value}</div>
      <div className="text-xs text-slate-400">{label}</div>
    </div>
  );
}
