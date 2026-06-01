import { ArrowRight, Radar, Database, Code, GitBranch, Zap, Layers, FileCode, Network, Bug, Shield, Activity, BarChart3, Cpu } from "lucide-react";
import { Link } from "react-router-dom";

import { Panel } from "../common/Panel";

export function DashboardHero(): JSX.Element {
  // 宏观数据 - 模拟后端数据库中的真实数据
  const macroStats = {
    totalApks: 1248, // 历史检测APK总数
    interceptedVulns: 287, // 拦截第三方库供应链漏洞数
    recoveredFunctions: 156, // 基于语义重组找回的内联函数数
    totalTasks: 1248, // 总任务数
    criticalCves: 42, // 严重CVE数量
    analyzedLibraries: 505, // 分析组件数
    semanticMatches: 89, // 语义匹配成功数
    patchEvidence: 67, // 补丁证据链数量
  };

  return (
    <Panel className="bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border border-slate-800/30 shadow-2xl">
      <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr]">
        {/* ===== 左侧区域 ===== */}
        <div className="flex flex-col gap-5">
          {/* 标题区 */}
          <h1 className="text-4xl font-bold leading-tight lg:text-5xl tracking-tight">
            <span className="bg-gradient-to-r from-slate-100 via-emerald-200 to-cyan-200 bg-clip-text text-transparent">Android 漏洞自动验证平台</span>
          </h1>

          {/* 宏观数据 - 2x2 大卡片 */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { 
                icon: <Database className="h-5 w-5 text-cyan-400" />, 
                title: "历史检测APK数", 
                value: macroStats.totalApks.toLocaleString(),
                color: "text-cyan-400",
                bg: "bg-gradient-to-br from-cyan-500/10 to-blue-500/10",
                border: "border-cyan-500/20"
              },
              { 
                icon: <Shield className="h-5 w-5 text-rose-400" />, 
                title: "拦截供应链漏洞", 
                value: macroStats.interceptedVulns.toLocaleString(),
                color: "text-rose-400",
                bg: "bg-gradient-to-br from-rose-500/10 to-pink-500/10",
                border: "border-rose-500/20"
              },
              { 
                icon: <Code className="h-5 w-5 text-emerald-400" />, 
                title: "找回内联函数数", 
                value: macroStats.recoveredFunctions.toLocaleString(),
                color: "text-emerald-400",
                bg: "bg-gradient-to-br from-emerald-500/10 to-green-500/10",
                border: "border-emerald-500/20"
              },
              { 
                icon: <GitBranch className="h-5 w-5 text-violet-400" />, 
                title: "语义匹配成功", 
                value: macroStats.semanticMatches.toLocaleString(),
                color: "text-violet-400",
                bg: "bg-gradient-to-br from-violet-500/10 to-purple-500/10",
                border: "border-violet-500/20"
              },
            ].map((stat) => (
              <div 
                key={stat.title}
                className={`rounded-xl ${stat.bg} ${stat.border} border backdrop-blur-sm p-5 transition-all duration-300 hover:scale-[1.02] hover:shadow-lg hover:shadow-current/10`}
              >
                <div className="flex items-center gap-2 mb-2">
                  {stat.icon}
                  <span className="text-sm text-slate-400">{stat.title}</span>
                </div>
                <div className={`text-3xl font-bold ${stat.color} font-mono`}>{stat.value}</div>
                <div className="h-px w-full bg-gradient-to-r from-transparent via-current to-transparent opacity-20 mt-3"></div>
              </div>
            ))}
          </div>

          {/* 操作按钮 */}
          <div className="flex flex-wrap gap-3">
            <Link
              to="/task/new"
              className="group inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3.5 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 transition-all duration-300 hover:scale-[1.02] hover:shadow-xl hover:shadow-emerald-500/30"
            >
              <Zap className="h-4 w-4 transition-transform group-hover:rotate-12" />
              开始新任务
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </Link>
            <Link
              to="/global-dashboard"
              className="group inline-flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-5 py-3.5 text-sm font-semibold text-emerald-400 transition-all duration-300 hover:border-emerald-500/50 hover:bg-emerald-500/20 hover:scale-[1.02]"
            >
              <Radar className="h-4 w-4 transition-transform group-hover:rotate-45" />
              全局态势感知
            </Link>
            <div className="group inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/50 px-4 py-3.5 text-sm text-slate-300 transition-all duration-300 hover:border-cyan-500/40 hover:bg-cyan-500/10 hover:scale-[1.02]">
              <BarChart3 className="h-4 w-4 text-cyan-400" />
              实时威胁监控
            </div>
          </div>
        </div>

        {/* ===== 右侧区域 ===== */}
        <div className="space-y-5">
          {/* 引擎性能指标 */}
          <div className="rounded-xl bg-gradient-to-br from-slate-900/60 to-slate-950/60 border border-slate-800/50 backdrop-blur-sm p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Cpu className="h-4 w-4 text-emerald-400" />
                引擎性能指标
              </h3>
              <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
            </div>
            
            <div className="space-y-2.5">
              {[
                { label: "LibHunter 跨内联匹配", value: "98.7%", color: "text-emerald-400", icon: "✓" },
                { label: "PHunter 切片分析精度", value: "95.2%", color: "text-cyan-400", icon: "✓" },
                { label: "语义重组成功率", value: "89.4%", color: "text-emerald-400", icon: "✓" },
                { label: "实时威胁检测延迟", value: "< 2.3s", color: "text-amber-400", icon: "⚡" },
              ].map((metric) => (
                <div key={metric.label} className="flex items-center justify-between group">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">{metric.icon}</span>
                    <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors">{metric.label}</span>
                  </div>
                  <span className={`text-sm font-bold ${metric.color} font-mono`}>{metric.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* 4个小指标卡片 */}
          <div className="grid grid-cols-2 gap-2.5">
            {[
              { 
                icon: <Layers className="h-3.5 w-3.5 text-blue-400" />, 
                title: "分析组件", 
                value: macroStats.analyzedLibraries,
                desc: "第三方库",
                color: "text-blue-400"
              },
              { 
                icon: <Bug className="h-3.5 w-3.5 text-rose-400" />, 
                title: "严重CVE", 
                value: macroStats.criticalCves,
                desc: "CVSS 9.0+",
                color: "text-rose-400"
              },
              { 
                icon: <FileCode className="h-3.5 w-3.5 text-violet-400" />, 
                title: "补丁证据链", 
                value: macroStats.patchEvidence,
                desc: "语义适配",
                color: "text-violet-400"
              },
              { 
                icon: <Network className="h-3.5 w-3.5 text-amber-400" />, 
                title: "总任务数", 
                value: macroStats.totalTasks,
                desc: "历史记录",
                color: "text-amber-400"
              },
            ].map((item) => (
              <div 
                key={item.title}
                className="rounded-xl bg-slate-900/40 border border-slate-800/40 backdrop-blur-sm p-3 transition-all duration-300 hover:bg-slate-800/50 hover:scale-[1.02] hover:shadow-md"
              >
                <div className="flex items-center gap-1.5 mb-1">
                  {item.icon}
                  <span className="text-[11px] font-medium text-white">{item.title}</span>
                </div>
                <div className={`text-lg font-bold ${item.color} font-mono leading-none`}>{item.value.toLocaleString()}</div>
                <div className="text-[11px] text-slate-400 mt-0.5">{item.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
      
      {/* 底部状态栏 */}
      <div className="mt-8 pt-5 border-t border-slate-800/50">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></div>
              <span className="text-xs text-slate-400">引擎 <span className="text-emerald-400 font-medium">运行中</span></span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-cyan-500 animate-pulse"></div>
              <span className="text-xs text-slate-400">WebSocket <span className="text-cyan-400 font-medium">已连接</span></span>
            </div>
          </div>
          <div className="text-xs text-slate-500">
            v2.4.1
          </div>
        </div>
      </div>
    </Panel>
  );
}
