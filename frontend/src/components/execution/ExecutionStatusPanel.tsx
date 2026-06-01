import { AlertTriangle, RotateCcw, WifiOff } from "lucide-react";

import type { TaskStage, WsConnectionState } from "../../types/domain";
import { StageBadge } from "../common/StageBadge";

interface ExecutionStatusPanelProps {
  taskId: string;
  stage: TaskStage;
  wsState: WsConnectionState;
  isPollingFallback: boolean;
  errorMessage: string | null;
  onReconnect: () => void;
}

function wsLabel(wsState: WsConnectionState): { label: string; className: string; icon: JSX.Element } {
  switch (wsState) {
    case "CONNECTED":
      return { 
        label: "WS 已连接", 
        className: "text-emerald-300",
        icon: <div className="h-2 w-2 rounded-full bg-emerald-500/70 animate-subtle-pulse"></div>
      };
    case "CONNECTING":
      return { 
        label: "WS 连接中", 
        className: "text-amber-300",
        icon: <div className="h-2 w-2 rounded-full bg-amber-500/70 animate-pulse"></div>
      };
    case "RECONNECTING":
      return { 
        label: "WS 重连中", 
        className: "text-amber-300",
        icon: <div className="h-2 w-2 rounded-full bg-amber-500/70 animate-pulse"></div>
      };
    case "DEGRADED":
      return { 
        label: "降级模式", 
        className: "text-rose-300",
        icon: <div className="h-2 w-2 rounded-full bg-rose-500/70 animate-warning-pulse"></div>
      };
    case "FAILED":
      return { 
        label: "连接失败", 
        className: "text-rose-400",
        icon: <div className="h-2 w-2 rounded-full bg-rose-500/70 animate-danger-pulse"></div>
      };
    default:
      return { 
        label: "未连接", 
        className: "text-slate-400",
        icon: <div className="h-2 w-2 rounded-full bg-slate-500/50"></div>
      };
  }
}

export function ExecutionStatusPanel({
  taskId,
  stage,
  wsState,
  isPollingFallback,
  errorMessage,
  onReconnect,
}: ExecutionStatusPanelProps): JSX.Element {
  const ws = wsLabel(wsState);

  return (
    <div className="space-y-5 rounded-2xl bg-gradient-to-br from-slate-900/60 to-slate-950/60 backdrop-blur-md border border-slate-700/30 p-6 hover-lift transition-all">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-400 mb-1">当前任务</p>
          <p className="terminal-font text-sm text-white bg-slate-800/40 rounded px-2 py-1 inline-block">{taskId}</p>
        </div>
        <StageBadge stage={stage} />
      </div>

      <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 px-4 py-3 text-sm hover:bg-slate-800/40 transition-colors">
        <div className="flex items-center gap-2">
          {ws.icon}
          <p className={`font-medium ${ws.className}`}>{ws.label}</p>
        </div>
        {isPollingFallback && (
          <p className="mt-2 inline-flex items-center gap-2 text-xs text-slate-300">
            <WifiOff className="h-4 w-4" />
            WebSocket 重连失败，已启用短轮询拉取报告。
          </p>
        )}
      </div>

      {errorMessage && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/15 px-4 py-3 text-sm text-rose-300 animate-danger-pulse">
          <p className="inline-flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            {errorMessage}
          </p>
        </div>
      )}

      <button
        type="button"
        onClick={onReconnect}
        className="inline-flex items-center gap-2 rounded-xl border border-slate-700/40 bg-slate-800/30 px-5 py-3 text-sm text-slate-200 hover-lift transition-all hover:border-cyan-500/40 hover:bg-cyan-500/10 hover:text-white"
      >
        <RotateCcw className="h-4 w-4" />
        手动重连执行通道
      </button>
    </div>
  );
}
