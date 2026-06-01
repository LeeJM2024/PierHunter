import { Activity, Bot, FileBadge2, LayoutDashboard, ShieldCheck, UploadCloud, Terminal, Cpu } from "lucide-react";
import type { PropsWithChildren } from "react";
import { NavLink } from "react-router-dom";

import { useTaskStore } from "../../store/taskStore";

function NavItem({ to, label, icon }: { to: string; label: string; icon: JSX.Element }): JSX.Element {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200 ${
          isActive
            ? "bg-gradient-to-r from-emerald-500/20 to-cyan-500/20 text-emerald-300 border border-emerald-500/30 shadow-lg shadow-emerald-500/10"
            : "text-slate-400 hover:bg-slate-800/40 hover:text-slate-200 hover:border hover:border-slate-700/50"
        }`
      }
    >
      {icon}
      <span>{label}</span>
    </NavLink>
  );
}

export function AppShell({ children }: PropsWithChildren): JSX.Element {
  const currentTaskId = useTaskStore((state) => state.currentTaskId);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-950 to-black text-slate-200">
      {/* 顶部装饰性渐变条 */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 via-cyan-500 to-blue-500"></div>
      
      <header className="sticky top-0 z-40 border-b border-white/10 bg-slate-950/90 backdrop-blur-xl shadow-2xl">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-center gap-3">
            {/* 科技感Logo */}
            <div className="relative">
              <div className="absolute inset-0 bg-emerald-500/20 blur-xl rounded-xl"></div>
              <div className="relative rounded-xl bg-gradient-to-br from-slate-900 to-slate-950 p-2.5 border border-emerald-500/30 shadow-lg">
                <ShieldCheck className="h-5 w-5 text-emerald-400" />
              </div>
            </div>
            <div>
              <p className="text-base font-bold tracking-tight text-white bg-gradient-to-r from-emerald-300 to-cyan-300 bg-clip-text text-transparent">
                Android Security Operations Console
              </p>
            </div>
          </div>

          <nav className="flex flex-wrap items-center gap-2">
            <NavItem to="/" label="Dashboard" icon={<LayoutDashboard className="h-4 w-4" />} />
            <NavItem to="/task/new" label="新建任务" icon={<UploadCloud className="h-4 w-4" />} />
            {currentTaskId && (
              <>
                <NavItem
                  to={`/task/${currentTaskId}/execution`}
                  label="执行监控"
                  icon={<Activity className="h-4 w-4" />}
                />
                <NavItem to={`/report/${currentTaskId}`} label="报告" icon={<FileBadge2 className="h-4 w-4" />} />
              </>
            )}
            {/* 系统状态指示器 */}
            <div className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs">
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></div>
                <Cpu className="h-3 w-3 text-emerald-400" />
                <span className="text-emerald-300 font-medium">SYSTEM ACTIVE</span>
              </div>
            </div>
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl px-6 py-8">{children}</main>
      
      {/* 底部状态栏 */}
      <footer className="border-t border-white/10 bg-slate-950/80 backdrop-blur-xl py-3">
        <div className="mx-auto max-w-7xl px-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4 text-xs text-slate-500">
              <div className="flex items-center gap-1.5">
                <Terminal className="h-3 w-3" />
                <span className="font-mono">v2.4.1</span>
              </div>
              <div className="h-3 w-px bg-slate-700"></div>
              <div className="flex items-center gap-1.5">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
                <span>WebSocket Connected</span>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
