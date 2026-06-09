import { useMemo } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Cpu,
  FileSearch,
  Loader2,
  ScanLine,
  Shield,
  ShieldAlert,
  WifiOff,
} from "lucide-react";

import type { LogEntry, TaskStage, WsConnectionState } from "../../types/domain";

// ============================================================
// 扫描阶段定义
// ============================================================
interface ScanPhase {
  key: string;
  label: string;
  icon: JSX.Element;
  startWeight: number; // 0-100
  endWeight: number; // 0-100
  keywords: string[]; // 匹配日志中的关键词
}

const SCAN_PHASES: ScanPhase[] = [
  {
    key: "init",
    label: "初始化分析任务",
    icon: <Cpu className="h-4 w-4" />,
    startWeight: 0,
    endWeight: 8,
    keywords: ["初始化分析任务"],
  },
  {
    key: "libhunter",
    label: "LibHunter 第三方库识别",
    icon: <FileSearch className="h-4 w-4" />,
    startWeight: 8,
    endWeight: 35,
    keywords: ["阶段一", "LibHunter", "识别第三方库", "组件特征", "组件识别"],
  },
  {
    key: "phunter",
    label: "PHunter 漏洞补丁验证",
    icon: <Shield className="h-4 w-4" />,
    startWeight: 35,
    endWeight: 85,
    keywords: ["阶段二", "PHunter", "补丁确诊", "漏洞情报", "并发校验", "验证"],
  },
  {
    key: "report",
    label: "汇总诊断报告",
    icon: <ScanLine className="h-4 w-4" />,
    startWeight: 85,
    endWeight: 98,
    keywords: ["阶段三", "汇总诊断报告"],
  },
  {
    key: "done",
    label: "扫描完成",
    icon: <CheckCircle2 className="h-4 w-4" />,
    startWeight: 98,
    endWeight: 100,
    keywords: ["Scan Completed", "扫描完成", "完成"],
  },
];

// ============================================================
// 从日志中提取当前阶段和进度信息
// ============================================================
interface ProgressInfo {
  currentPhase: ScanPhase | null;
  progress: number; // 0-100
  detailMessage: string;
  subProgress: string;
}

function extractProgress(logs: LogEntry[]): ProgressInfo {
  // 默认状态
  const result: ProgressInfo = {
    currentPhase: SCAN_PHASES[0],
    progress: 0,
    detailMessage: "等待引擎启动...",
    subProgress: "",
  };

  if (logs.length === 0) return result;

  // 从最新的日志往前找，确定当前阶段
  let latestPhaseIndex = -1;
  let latestPhaseLog: string | null = null;

  for (let i = logs.length - 1; i >= 0; i--) {
    const msg = logs[i].message;
    for (let p = SCAN_PHASES.length - 1; p >= 0; p--) {
      const phase = SCAN_PHASES[p];
      if (phase.keywords.some((kw) => msg.includes(kw))) {
        if (p > latestPhaseIndex) {
          latestPhaseIndex = p;
          latestPhaseLog = msg;
        }
        break;
      }
    }
  }

  // 如果找到了阶段，计算进度
  if (latestPhaseIndex >= 0) {
    const phase = SCAN_PHASES[latestPhaseIndex];
    result.currentPhase = phase;

    // 基础进度 = 当前阶段的起始权重
    let baseProgress = phase.startWeight;

    // 如果在当前阶段内，根据日志数量估算子进度
    const phaseLogs = logs.filter((log) =>
      phase.keywords.some((kw) => log.message.includes(kw)),
    );
    const subProgressRatio = Math.min(phaseLogs.length / 5, 1); // 每个阶段最多5个关键日志算100%
    const phaseRange = phase.endWeight - phase.startWeight;
    result.progress = Math.min(
      Math.round(baseProgress + phaseRange * subProgressRatio),
      phase.endWeight,
    );

    // 提取详细信息
    result.detailMessage = latestPhaseLog || phase.label;

    // 提取子进度信息（如 "3/10 个漏洞验证"）
    const countMatch = latestPhaseLog?.match(
      /(\d+)\s*\/\s*(\d+)|命中\s*(\d+)\s*个|成功提取\s*(\d+)\s*个/,
    );
    if (countMatch) {
      result.subProgress = countMatch[0];
    }
  }

  // 检查是否完成
  const hasDone = logs.some(
    (log) =>
      log.message.includes("Scan Completed") ||
      log.message.includes("扫描完成") ||
      log.message.includes("[DONE]"),
  );
  if (hasDone) {
    result.currentPhase = SCAN_PHASES[4];
    result.progress = 100;
    result.detailMessage = "扫描已完成，正在生成报告...";
  }

  // 检查是否失败
  const hasError = logs.some(
    (log) =>
      log.source === "stderr" ||
      log.source === "socket" ||
      log.message.includes("failed") ||
      log.message.includes("异常") ||
      log.message.includes("错误"),
  );
  if (hasError && latestPhaseIndex < 0) {
    result.detailMessage = "扫描过程出现异常";
  }

  return result;
}

// ============================================================
// 进度条组件
// ============================================================
function ProgressBar({
  progress,
  phase,
  isError,
  isDone,
}: {
  progress: number;
  phase: ScanPhase | null;
  isError: boolean;
  isDone: boolean;
}): JSX.Element {
  // 进度条颜色
  const barColor = isError
    ? "from-rose-500 to-rose-400"
    : isDone
      ? "from-emerald-500 to-emerald-400"
      : "from-cyan-500 via-blue-500 to-indigo-500";

  const glowColor = isError
    ? "shadow-rose-500/30"
    : isDone
      ? "shadow-emerald-500/30"
      : "shadow-cyan-500/30";

  return (
    <div className="space-y-2">
      {/* 进度数值 */}
      <div className="flex items-center justify-between text-xs">
        <span className="text-zinc-400">扫描进度</span>
        <span
          className={`font-mono font-bold tabular-nums ${
            isError
              ? "text-rose-400"
              : isDone
                ? "text-emerald-400"
                : "text-cyan-300"
          }`}
        >
          {progress}%
        </span>
      </div>

      {/* 进度条轨道 */}
      <div className="relative h-3 overflow-hidden rounded-full bg-zinc-800/80 ring-1 ring-zinc-700/50">
        {/* 背景光晕 */}
        <div
          className={`absolute inset-0 rounded-full bg-gradient-to-r ${barColor} opacity-5`}
        />

        {/* 填充条 */}
        <div
          className={`relative h-full rounded-full bg-gradient-to-r ${barColor} transition-all duration-700 ease-out ${glowColor}`}
          style={{
            width: `${Math.max(progress, 2)}%`,
            boxShadow: progress > 0 ? `0 0 12px rgba(var(--bar-glow), 0.3)` : "none",
          }}
        >
          {/* 进度条内的高光动画 */}
          {!isDone && !isError && progress < 100 && (
            <div className="absolute inset-0 overflow-hidden rounded-full">
              <div className="absolute inset-0 animate-shimmer bg-gradient-to-r from-transparent via-white/20 to-transparent" />
            </div>
          )}
        </div>

        {/* 进度标记点 */}
        {SCAN_PHASES.map((p) => {
          const pos = p.startWeight;
          const isActive = phase?.key === p.key;
          const isPast =
            SCAN_PHASES.indexOf(p) <
            (phase ? SCAN_PHASES.indexOf(phase) : -1);
          return (
            <div
              key={p.key}
              className="absolute top-1/2 -translate-y-1/2"
              style={{ left: `${pos}%` }}
            >
              <div
                className={`h-2 w-2 rounded-full border transition-all duration-300 ${
                  isPast || isActive
                    ? isError
                      ? "border-rose-400 bg-rose-400"
                      : "border-emerald-400 bg-emerald-400"
                    : "border-zinc-600 bg-zinc-800"
                }`}
              />
            </div>
          );
        })}
      </div>

      {/* 阶段标记 */}
      <div className="flex justify-between px-0.5">
        {SCAN_PHASES.slice(0, 4).map((p) => {
          const isActive = phase?.key === p.key;
          const isPast =
            SCAN_PHASES.indexOf(p) <
            (phase ? SCAN_PHASES.indexOf(phase) : -1);
          return (
            <div key={p.key} className="flex flex-col items-center gap-1">
              <div
                className={`text-[10px] font-medium transition-colors duration-300 ${
                  isPast || isActive
                    ? isError
                      ? "text-rose-400"
                      : "text-emerald-400"
                    : "text-zinc-600"
                }`}
              >
                {p.label.length > 6 ? p.label.slice(0, 6) + "…" : p.label}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ============================================================
// 当前阶段详情卡片
// ============================================================
function PhaseDetail({
  phase,
  detailMessage,
  subProgress,
  isError,
  isDone,
  logs,
}: {
  phase: ScanPhase | null;
  detailMessage: string;
  subProgress: string;
  isError: boolean;
  isDone: boolean;
  logs: LogEntry[];
}): JSX.Element {
  // 获取最近的几条关键日志
  const recentLogs = useMemo(() => {
    return logs
      .filter(
        (log) =>
          log.source !== "meta" &&
          !log.message.includes("[socket]") &&
          !log.message.includes("[system] 就绪"),
      )
      .slice(-5)
      .reverse();
  }, [logs]);

  return (
    <div className="space-y-3 rounded-xl border border-zinc-700/30 bg-zinc-800/30 p-4">
      {/* 当前操作标题 */}
      <div className="flex items-center gap-3">
        <div
          className={`flex h-9 w-9 items-center justify-center rounded-lg ${
            isError
              ? "bg-rose-500/20 text-rose-400"
              : isDone
                ? "bg-emerald-500/20 text-emerald-400"
                : "bg-cyan-500/20 text-cyan-400"
          }`}
        >
          {isError ? (
            <ShieldAlert className="h-5 w-5" />
          ) : isDone ? (
            <CheckCircle2 className="h-5 w-5" />
          ) : (
            phase?.icon || <Loader2 className="h-5 w-5 animate-spin" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-zinc-200 truncate">
            {phase?.label || "等待中"}
          </p>
          {subProgress && (
            <p className="text-xs text-zinc-500 mt-0.5">{subProgress}</p>
          )}
        </div>
        {!isDone && !isError && (
          <Loader2 className="h-4 w-4 animate-spin text-cyan-400 shrink-0" />
        )}
      </div>

      {/* 详细信息 */}
      <p className="text-xs text-zinc-400 leading-relaxed pl-0.5">
        {detailMessage}
      </p>

      {/* 最近日志 */}
      {recentLogs.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-zinc-700/20">
          <p className="text-[10px] font-medium text-zinc-500 uppercase tracking-wider">
            最近操作
          </p>
          {recentLogs.map((log) => (
            <div
              key={log.id}
              className="flex items-start gap-2 text-[11px] leading-relaxed"
            >
              <ChevronRight className="h-3 w-3 text-zinc-600 mt-0.5 shrink-0" />
              <span className="text-zinc-400 truncate">{log.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================
// 引擎状态指示器
// ============================================================
function EngineStatus({
  logs,
  isError,
}: {
  logs: LogEntry[];
  isError: boolean;
}): JSX.Element {
  const libHunterActive = logs.some(
    (log) =>
      log.message.includes("LibHunter") || log.message.includes("阶段一"),
  );
  const pHunterActive = logs.some(
    (log) =>
      log.message.includes("PHunter") || log.message.includes("阶段二"),
  );

  const engines = [
    {
      name: "LibHunter",
      active: libHunterActive,
      icon: <FileSearch className="h-3 w-3" />,
    },
    {
      name: "PHunter",
      active: pHunterActive,
      icon: <Shield className="h-3 w-3" />,
    },
    {
      name: "语义引擎",
      active: pHunterActive,
      icon: <Cpu className="h-3 w-3" />,
    },
  ];

  return (
    <div className="grid grid-cols-3 gap-2">
      {engines.map((engine) => (
        <div
          key={engine.name}
          className={`rounded-lg border p-2.5 transition-all duration-300 ${
            isError
              ? "border-rose-500/20 bg-rose-500/5"
              : engine.active
                ? "border-cyan-500/30 bg-cyan-500/10"
                : "border-zinc-700/30 bg-zinc-800/30"
          }`}
        >
          <div className="flex items-center gap-2 mb-1">
            <div
              className={`h-1.5 w-1.5 rounded-full ${
                isError
                  ? "bg-rose-400"
                  : engine.active
                    ? "bg-emerald-400 animate-pulse"
                    : "bg-zinc-600"
              }`}
            />
            <span
              className={`text-xs font-medium ${
                isError
                  ? "text-rose-300"
                  : engine.active
                    ? "text-zinc-200"
                    : "text-zinc-500"
              }`}
            >
              {engine.name}
            </span>
          </div>
          <div className="flex items-center gap-1">
            {engine.icon}
            <span className="text-[10px] text-zinc-500">
              {isError
                ? "异常"
                : engine.active
                  ? "运行中"
                  : "待命中"}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================================
// 主组件
// ============================================================
interface ScanProgressProps {
  logs: LogEntry[];
  taskStage: TaskStage;
  wsState: WsConnectionState;
  isPollingFallback: boolean;
  errorMessage: string | null;
}

export function ScanProgress({
  logs,
  taskStage,
  wsState,
  isPollingFallback,
  errorMessage,
}: ScanProgressProps): JSX.Element {
  const { currentPhase, progress, detailMessage, subProgress } =
    extractProgress(logs);

  const isError = taskStage === "FAILED" || errorMessage !== null;
  const isDone = taskStage === "REPORT_READY";
  const isWaiting = taskStage === "IDLE" || taskStage === "UPLOADING" || taskStage === "QUEUED";
  const isScanning = taskStage === "SCANNING";

  return (
    <div className="space-y-5">
      {/* 标题 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/20">
            <ScanLine className="h-4 w-4 text-cyan-400" />
          </div>
          <h3 className="text-sm font-semibold text-white">扫描进度</h3>
        </div>

        {/* 连接状态 */}
        <div className="flex items-center gap-2">
          {isPollingFallback ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-1 text-[10px] font-medium text-amber-400">
              <WifiOff className="h-3 w-3" />
              降级轮询
            </span>
          ) : wsState === "CONNECTED" ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2.5 py-1 text-[10px] font-medium text-emerald-400">
              <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              实时
            </span>
          ) : wsState === "CONNECTING" || wsState === "RECONNECTING" ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-1 text-[10px] font-medium text-amber-400">
              <Loader2 className="h-3 w-3 animate-spin" />
              连接中
            </span>
          ) : null}
        </div>
      </div>

      {/* 等待状态 */}
      {isWaiting && (
        <div className="flex flex-col items-center justify-center py-8 space-y-4">
          <div className="relative">
            <div className="h-16 w-16 rounded-full bg-zinc-800/50 border border-zinc-700/30 flex items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-cyan-400/70" />
            </div>
            <div className="absolute -inset-2 rounded-full border-2 border-dashed border-zinc-700/20 animate-spin-slow" />
          </div>
          <div className="text-center">
            <p className="text-sm text-zinc-300 font-medium">
              {taskStage === "UPLOADING"
                ? "正在上传 APK 文件..."
                : taskStage === "QUEUED"
                  ? "任务已排队，等待引擎启动..."
                  : "准备就绪，等待扫描开始"}
            </p>
            <p className="text-xs text-zinc-500 mt-1">
              {taskStage === "QUEUED" && "扫描引擎正在初始化"}
            </p>
          </div>
        </div>
      )}

      {/* 扫描中 / 已完成 / 失败 */}
      {(isScanning || isDone || isError) && (
        <>
          {/* 进度条 */}
          <ProgressBar
            progress={progress}
            phase={currentPhase}
            isError={isError}
            isDone={isDone}
          />

          {/* 当前阶段详情 */}
          <PhaseDetail
            phase={currentPhase}
            detailMessage={detailMessage}
            subProgress={subProgress}
            isError={isError}
            isDone={isDone}
            logs={logs}
          />

          {/* 引擎状态 */}
          <EngineStatus logs={logs} isError={isError} />

          {/* 错误信息 */}
          {errorMessage && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/15 px-4 py-3 text-sm text-rose-300">
              <p className="inline-flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                {errorMessage}
              </p>
            </div>
          )}

          {/* 完成状态 */}
          {isDone && (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
              <p className="inline-flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                扫描已完成，即将跳转到报告页面...
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
