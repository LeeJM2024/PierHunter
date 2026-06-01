import { ArrowLeft, Globe, Activity, Shield, Layers3, Zap } from "lucide-react";
import { Link } from "react-router-dom";
import { TaskTrendChart } from "../components/dashboard/TaskTrendChart";
import { CveTopList } from "../components/dashboard/CveTopList";
import { LibrarySourceChart } from "../components/dashboard/LibrarySourceChart";
import { mockTaskStats, mockVulnerabilityStats, mockTotalLibraries } from "../components/dashboard/mockData";

export function GlobalDashboardPage(): JSX.Element {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6">
      {/* 顶部导航栏 */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <Link
            to="/"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700/50 bg-slate-800/30 px-4 py-2 text-sm text-slate-300 hover:border-slate-600 hover:bg-slate-800/50 hover:text-white transition-all hover:scale-[1.02]"
          >
            <ArrowLeft className="h-4 w-4" />
            返回操作台
          </Link>
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-cyan-500" />
            <h1 className="text-xl font-bold text-white">全局态势感知大盘</h1>
            <div className="flex items-center gap-1 ml-2">
              <Zap className="h-3 w-3 text-amber-500" />
              <span className="text-xs text-amber-400 font-medium bg-amber-500/10 px-2 py-0.5 rounded-full">
                答辩模式
              </span>
            </div>
          </div>
        </div>
        <div className="text-xs text-slate-400">
          最后更新: 刚刚
        </div>
      </div>

      {/* 核心统计数字 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm hover:bg-slate-800/40 transition-all hover:scale-[1.02]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-full bg-cyan-500/10 flex items-center justify-center">
                <Activity className="h-5 w-5 text-cyan-500" />
              </div>
              <div>
                <div className="text-sm text-slate-400">总任务数</div>
                <div className="text-3xl font-bold text-white">{mockTaskStats.totalTasks.toLocaleString()}</div>
              </div>
            </div>
            <div className="text-xs text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded-full">
              +{mockTaskStats.dailyAvg}/天
            </div>
          </div>
          <div className="text-xs text-slate-400">
            完成 {mockTaskStats.completedTasks.toLocaleString()} • 失败 {mockTaskStats.failedTasks}
          </div>
        </div>

        <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm hover:bg-slate-800/40 transition-all hover:scale-[1.02]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-full bg-rose-500/10 flex items-center justify-center">
                <Shield className="h-5 w-5 text-rose-500" />
              </div>
              <div>
                <div className="text-sm text-slate-400">总漏洞数</div>
                <div className="text-3xl font-bold text-white">{mockVulnerabilityStats.total.toLocaleString()}</div>
              </div>
            </div>
            <div className="text-xs text-rose-500 bg-rose-500/10 px-2 py-1 rounded-full">
              {mockVulnerabilityStats.critical} 严重
            </div>
          </div>
          <div className="text-xs text-slate-400">
            高危 {mockVulnerabilityStats.high} • 中危 {mockVulnerabilityStats.medium} • 低危 {mockVulnerabilityStats.low}
          </div>
        </div>

        <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm hover:bg-slate-800/40 transition-all hover:scale-[1.02]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-full bg-emerald-500/10 flex items-center justify-center">
                <Layers3 className="h-5 w-5 text-emerald-500" />
              </div>
              <div>
                <div className="text-sm text-slate-400">总组件数</div>
                <div className="text-3xl font-bold text-white">{mockTotalLibraries.toLocaleString()}</div>
              </div>
            </div>
            <div className="text-xs text-amber-500 bg-amber-500/10 px-2 py-1 rounded-full">
              500+ 分析
            </div>
          </div>
        </div>
      </div>

      {/* 任务状态趋势图 - 全宽 */}
      <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 mb-8 backdrop-blur-sm">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-full bg-cyan-500/10 flex items-center justify-center">
              <Activity className="h-4 w-4 text-cyan-500" />
            </div>
            <h2 className="text-lg font-semibold text-white">任务状态趋势图</h2>
          </div>
          <div className="text-sm text-slate-400">
            最近7天 • 成功率 {Math.round((mockTaskStats.completedTasks / mockTaskStats.totalTasks) * 100)}%
          </div>
        </div>
        <div className="p-4 bg-slate-900/50 rounded-lg">
          <TaskTrendChart />
        </div>
      </div>

      {/* 底部并排展示 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* CVE 榜单 */}
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-full bg-rose-500/10 flex items-center justify-center">
                <Shield className="h-4 w-4 text-rose-500" />
              </div>
              <h2 className="text-lg font-semibold text-white">高风险 CVE TOP 榜</h2>
            </div>
            <div className="text-sm text-slate-400">
              CVSS 9.0+
            </div>
          </div>
          <div className="p-4 bg-slate-900/50 rounded-lg">
            <CveTopList />
          </div>
        </div>

        {/* 组件占比图 */}
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-6 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-full bg-emerald-500/10 flex items-center justify-center">
                <Layers3 className="h-4 w-4 text-emerald-500" />
              </div>
              <h2 className="text-lg font-semibold text-white">组件来源占比图</h2>
            </div>
            <div className="text-sm text-slate-400">
              500+ 组件
            </div>
          </div>
          <div className="p-4 bg-slate-900/50 rounded-lg">
            <LibrarySourceChart />
          </div>
        </div>
      </div>

      {/* 底部说明 */}
      <div className="mt-8 text-center">
        <div className="inline-flex items-center gap-2 text-xs text-slate-500 bg-slate-900/50 px-4 py-2 rounded-full">
          <Zap className="h-3 w-3 text-amber-500" />
          <span>全局态势感知大盘 • 答辩演示模式 • 数据仅供参考</span>
          <Zap className="h-3 w-3 text-amber-500" />
        </div>
      </div>
    </div>
  );
}