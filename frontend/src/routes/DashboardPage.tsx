import { Activity, BarChart3, Layers3, Shield, Globe, Zap } from "lucide-react";
import { Link } from "react-router-dom";

import { DashboardHero } from "../components/dashboard/DashboardHero";
import { RecentTasksPanel } from "../components/dashboard/RecentTasksPanel";
import { Panel } from "../components/common/Panel";
import { useTaskStore } from "../store/taskStore";

export function DashboardPage(): JSX.Element {
  const historyTaskIds = useTaskStore((state) => state.historyTaskIds);
  const reportsByTask = useTaskStore((state) => state.reportsByTask);
  const lastTaskId = useTaskStore((state) => state.lastTaskId);

  const reports = Object.values(reportsByTask);
  const totalVulns = reports.reduce((sum, report) => sum + report.vulnerabilities.length, 0);
  const totalLibraries = reports.reduce((sum, report) => sum + report.usedLibraries.length, 0);

  return (
    <div className="space-y-6">
      <DashboardHero />

      {/* 玻璃拟物化数据卡片 */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Panel className="bg-white/5 backdrop-blur-md border border-white/10 rounded-xl shadow-2xl hover:bg-white/10 transition-all duration-300 hover:scale-[1.02] hover:shadow-[0_20px_60px_rgba(6,182,212,0.3)]" title="任务总数" right={<Activity className="h-4 w-4 text-cyan-400" />}>
          <p className="text-3xl font-bold text-cyan-300 font-mono">{historyTaskIds.length}</p>
        </Panel>

        <Panel className="bg-white/5 backdrop-blur-md border border-white/10 rounded-xl shadow-2xl hover:bg-white/10 transition-all duration-300 hover:scale-[1.02] hover:shadow-[0_20px_60px_rgba(239,68,68,0.3)]" title="漏洞总记录" right={<Shield className="h-4 w-4 text-rose-400" />}>
          <p className="text-3xl font-bold text-rose-400 font-mono">{totalVulns}</p>
        </Panel>

        <Panel className="bg-white/5 backdrop-blur-md border border-white/10 rounded-xl shadow-2xl hover:bg-white/10 transition-all duration-300 hover:scale-[1.02] hover:shadow-[0_20px_60px_rgba(16,185,129,0.3)]" title="组件识别数" right={<Layers3 className="h-4 w-4 text-emerald-400" />}>
          <p className="text-3xl font-bold text-emerald-400 font-mono">{totalLibraries}</p>
        </Panel>

        <Panel className="bg-white/5 backdrop-blur-md border border-white/10 rounded-xl shadow-2xl hover:bg-white/10 transition-all duration-300 hover:scale-[1.02] hover:shadow-[0_20px_60px_rgba(139,92,246,0.3)]" title="展示入口" right={<BarChart3 className="h-4 w-4 text-violet-400" />}>
          {lastTaskId ? (
            <Link
              to={`/report/${lastTaskId}`}
              className="group inline-flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-4 py-2.5 text-sm text-violet-300 hover:border-violet-500/50 hover:bg-violet-500/20 transition-all duration-300 hover:scale-[1.05]"
            >
              <span>打开最近报告</span>
              <div className="h-4 w-4 rounded-full bg-violet-500/20 flex items-center justify-center transition-transform group-hover:rotate-90">
                <div className="h-2 w-2 rounded-full bg-violet-500"></div>
              </div>
            </Link>
          ) : (
            <p className="text-sm text-slate-500">暂无报告</p>
          )}
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <RecentTasksPanel historyTaskIds={historyTaskIds} />

        <div className="space-y-6">
          {/* 科技感入口按钮 */}
          <div className="relative group">
            <Link
              to="/global-dashboard"
              className="block rounded-xl border border-slate-700/40 bg-gradient-to-br from-slate-900/80 to-slate-800/60 p-8 backdrop-blur-sm hover:bg-slate-800/70 transition-all hover:scale-[1.02] hover:shadow-[0_20px_60px_rgba(6,182,212,0.3)]"
            >
              <div className="flex flex-col items-center text-center space-y-4">
                {/* 发光动画效果 */}
                <div className="relative">
                  <div className="absolute inset-0 bg-cyan-500/20 blur-xl rounded-full animate-pulse"></div>
                  <div className="relative h-16 w-16 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg">
                    <Globe className="h-8 w-8 text-white" />
                  </div>
                </div>
                
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">
                    🌐 全局态势感知大盘
                  </h3>
                  <div className="flex items-center justify-center gap-2 mb-3">
                    <Zap className="h-3 w-3 text-amber-500 animate-pulse" />
                    <span className="text-sm text-amber-400 font-medium">答辩模式</span>
                    <Zap className="h-3 w-3 text-amber-500 animate-pulse" />
                  </div>
                </div>
                
                <div className="inline-flex items-center gap-2 text-cyan-400 text-sm font-medium">
                  <span>进入全屏大屏</span>
                  <div className="h-4 w-4 rounded-full bg-cyan-500/20 flex items-center justify-center">
                    <div className="h-2 w-2 rounded-full bg-cyan-500"></div>
                  </div>
                </div>
              </div>
            </Link>
            
            {/* 装饰性元素 */}
            <div className="absolute -top-2 -right-2 h-4 w-4 rounded-full bg-cyan-500/30 blur-sm group-hover:bg-cyan-500/50 transition-colors"></div>
            <div className="absolute -bottom-2 -left-2 h-4 w-4 rounded-full bg-blue-500/30 blur-sm group-hover:bg-blue-500/50 transition-colors"></div>
          </div>
          
        </div>
      </div>
    </div>
  );
}
