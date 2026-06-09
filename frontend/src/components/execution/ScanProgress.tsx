import { AlertTriangle, CheckCircle2, Clock3, Cpu, FileSearch, Loader2, ScanLine, Shield, WifiOff } from "lucide-react";
import { useMemo } from "react";

import type { ScanEstimateRaw } from "../../types/contracts";
import type { LogEntry, TaskStage, WsConnectionState } from "../../types/domain";

interface ScanPhase {
  key: string;
  label: string;
  icon: JSX.Element;
  startWeight: number;
  endWeight: number;
  keywords: string[];
}

const SCAN_PHASES: ScanPhase[] = [
  {
    key: "init",
    label: "初始化",
    icon: <Cpu className="h-4 w-4" />,
    startWeight: 0,
    endWeight: 8,
    keywords: ["初始化", "init", "created"],
  },
  {
    key: "libhunter",
    label: "LibHunter 组件识别",
    icon: <FileSearch className="h-4 w-4" />,
    startWeight: 8,
    endWeight: 35,
    keywords: ["LibHunter", "第三方库", "组件识别", "library"],
  },
  {
    key: "phunter",
    label: "PHunter 补丁验证",
    icon: <Shield className="h-4 w-4" />,
    startWeight: 35,
    endWeight: 85,
    keywords: ["PHunter", "补丁", "漏洞", "验证", "patch", "CVE"],
  },
  {
    key: "report",
    label: "生成报告",
    icon: <ScanLine className="h-4 w-4" />,
    startWeight: 85,
    endWeight: 98,
    keywords: ["报告", "report", "summary"],
  },
  {
    key: "done",
    label: "扫描完成",
    icon: <CheckCircle2 className="h-4 w-4" />,
    startWeight: 98,
    endWeight: 100,
    keywords: ["done", "completed", "完成", "REPORT_READY"],
  },
];

interface ScanProgressProps {
  logs: LogEntry[];
  taskStage: TaskStage;
  wsState: WsConnectionState;
  isPollingFallback: boolean;
  errorMessage: string | null;
  uploadSize?: number | null;
  scanEstimate?: ScanEstimateRaw | null;
}

export function ScanProgress({
  logs,
  taskStage,
  wsState,
  isPollingFallback,
  errorMessage,
  uploadSize = null,
  scanEstimate = null,
}: ScanProgressProps): JSX.Element {
  const progress = useMemo(() => extractProgress(logs, taskStage), [logs, taskStage]);
  const estimate = useMemo(() => buildDisplayEstimate(scanEstimate, taskStage, progress.percent, uploadSize), [scanEstimate, taskStage, progress.percent, uploadSize]);
  const isError = taskStage === "FAILED" || errorMessage !== null;
  const isDone = taskStage === "REPORT_READY";

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/20">
            <ScanLine className="h-4 w-4 text-cyan-400" />
          </div>
          <h3 className="text-sm font-semibold text-white">扫描进度</h3>
        </div>
        <ConnectionBadge wsState={wsState} isPollingFallback={isPollingFallback} />
      </div>

      <EstimateCard estimate={estimate} isDone={isDone} isError={isError} />

      <ProgressBar phase={progress.phase} progress={progress.percent} isError={isError} isDone={isDone} />

      <div className="rounded-xl border border-zinc-700/30 bg-zinc-800/30 p-4">
        <div className="flex items-center gap-3">
          <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${isError ? "bg-rose-500/20 text-rose-400" : isDone ? "bg-emerald-500/20 text-emerald-400" : "bg-cyan-500/20 text-cyan-400"}`}>
            {isError ? <AlertTriangle className="h-5 w-5" /> : isDone ? <CheckCircle2 className="h-5 w-5" /> : progress.phase.icon}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-zinc-200">{progress.phase.label}</p>
          </div>
          {!isDone && !isError && <Loader2 className="h-4 w-4 shrink-0 animate-spin text-cyan-400" />}
        </div>
      </div>

      {errorMessage && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/15 px-4 py-3 text-sm text-rose-300">
          <p className="inline-flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            {errorMessage}
          </p>
        </div>
      )}

      {isDone && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
          <p className="inline-flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            扫描已完成。首次完成会自动打开报告；后续可点击左侧按钮查看。
          </p>
        </div>
      )}
    </div>
  );
}

interface TimeEstimate {
  totalMinutes: number;
  remainingMinutes: number;
  confidence: "low" | "medium" | "high";
  basis: string[];
  metrics: {
    apkSizeMb: number | null;
    dexCount: number | null;
    methodCount: number | null;
    classCount: number | null;
  };
  model: string;
  calibration: {
    sampleCount: number;
    multiplier: number;
  } | null;
}

function buildDisplayEstimate(scanEstimate: ScanEstimateRaw | null, taskStage: TaskStage, progress: number, uploadSize: number | null): TimeEstimate {
  const apkSizeMb = uploadSize ? uploadSize / 1024 / 1024 : null;
  if (scanEstimate) {
    const totalMinutes = Math.max(Math.ceil(scanEstimate.total_seconds / 60), scanEstimate.total_minutes || 1);
    return {
      totalMinutes,
      remainingMinutes: taskStage === "REPORT_READY" ? 0 : Math.max(Math.ceil(totalMinutes * (1 - Math.min(progress, 98) / 100)), 1),
      confidence: normalizeConfidence(scanEstimate.confidence),
      basis: scanEstimate.basis || [],
      model: scanEstimate.model || "dex-static-cost-v1",
      calibration: scanEstimate.calibration
        ? {
            sampleCount: scanEstimate.calibration.sample_count || 0,
            multiplier: scanEstimate.calibration.multiplier || 1,
          }
        : null,
      metrics: {
        apkSizeMb,
        dexCount: null,
        methodCount: null,
        classCount: null,
      },
    };
  }

  const total = apkSizeMb === null ? 12 : 8 + Math.min(Math.max(apkSizeMb * 0.9, 3), 30);
  const totalMinutes = Math.max(Math.round(total), 5);
  return {
    totalMinutes,
    remainingMinutes: taskStage === "REPORT_READY" ? 0 : Math.max(Math.ceil(totalMinutes * (1 - Math.min(progress, 98) / 100)), 1),
    confidence: "low",
    basis: apkSizeMb === null ? ["等待 APK 静态画像"] : [`APK ${formatNumber(apkSizeMb)} MB`, "等待 DEX 静态画像"],
    model: "size-fallback",
    calibration: null,
    metrics: {
      apkSizeMb,
      dexCount: null,
      methodCount: null,
      classCount: null,
    },
  };
}

function normalizeConfidence(value: string): "low" | "medium" | "high" {
  if (value === "high" || value === "medium" || value === "low") return value;
  return "medium";
}

function formatNumber(value: number): string {
  return value >= 10 ? value.toFixed(0) : value.toFixed(1);
}

function EstimateCard({ estimate, isDone, isError }: { estimate: TimeEstimate; isDone: boolean; isError: boolean }): JSX.Element {
  const confidenceText = estimate.confidence === "high" ? "高" : estimate.confidence === "medium" ? "中" : "低";
  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/15 text-cyan-300">
            <Clock3 className="h-5 w-5" />
          </div>
          <div>
            <p className="text-sm font-semibold text-cyan-100">预估耗时</p>
            <p className="mt-0.5 text-xs text-cyan-100/65">基于 DEX 静态复杂度与本机历史耗时校准</p>
          </div>
        </div>
        <div className="text-right">
          <p className={`text-2xl font-bold tabular-nums ${isError ? "text-rose-300" : isDone ? "text-emerald-300" : "text-cyan-200"}`}>
            {isDone ? "已完成" : `约 ${estimate.remainingMinutes} 分钟`}
          </p>
          <p className="mt-0.5 text-xs text-slate-400">
            总耗时约 {estimate.totalMinutes} 分钟 · 置信度 {confidenceText} · {estimate.model}
          </p>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {estimate.basis.slice(0, 4).map((item) => (
          <span key={item} className="rounded-full border border-cyan-400/15 bg-black/20 px-2.5 py-1 text-[11px] text-cyan-100/75">
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

function extractProgress(logs: LogEntry[], taskStage: TaskStage): { phase: ScanPhase; percent: number } {
  if (taskStage === "REPORT_READY") {
    return { phase: SCAN_PHASES[4], percent: 100 };
  }
  if (taskStage === "FAILED") {
    return { phase: SCAN_PHASES[Math.max(findPhaseIndex(logs), 0)], percent: Math.max(progressFromLogs(logs), 8) };
  }
  if (taskStage === "UPLOADING") {
    return { phase: SCAN_PHASES[0], percent: 2 };
  }
  if (taskStage === "QUEUED" || taskStage === "IDLE") {
    return { phase: SCAN_PHASES[0], percent: taskStage === "QUEUED" ? 4 : 0 };
  }

  const phaseIndex = Math.max(findPhaseIndex(logs), 0);
  const phase = SCAN_PHASES[phaseIndex];
  const percent = progressFromLogs(logs);
  return {
    phase,
    percent: Math.max(percent, phase.startWeight + 4),
  };
}

function findPhaseIndex(logs: LogEntry[]): number {
  for (let i = logs.length - 1; i >= 0; i -= 1) {
    const msg = logs[i].message.toLowerCase();
    for (let p = SCAN_PHASES.length - 1; p >= 0; p -= 1) {
      if (SCAN_PHASES[p].keywords.some((kw) => msg.includes(kw.toLowerCase()))) return p;
    }
  }
  return 0;
}

function progressFromLogs(logs: LogEntry[]): number {
  const phaseIndex = findPhaseIndex(logs);
  const phase = SCAN_PHASES[Math.max(phaseIndex, 0)];
  const phaseLogs = logs.filter((log) => phase.keywords.some((kw) => log.message.toLowerCase().includes(kw.toLowerCase()))).length;
  const ratio = Math.min(phaseLogs / 5, 1);
  return Math.min(Math.round(phase.startWeight + (phase.endWeight - phase.startWeight) * ratio), phase.endWeight);
}

function ProgressBar({ progress, phase, isError, isDone }: { progress: number; phase: ScanPhase; isError: boolean; isDone: boolean }): JSX.Element {
  const barColor = isError ? "from-rose-500 to-rose-400" : isDone ? "from-emerald-500 to-emerald-400" : "from-cyan-500 via-blue-500 to-indigo-500";

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs">
        <span className="text-zinc-400">扫描进度</span>
        <span className={`font-mono font-bold tabular-nums ${isError ? "text-rose-400" : isDone ? "text-emerald-400" : "text-cyan-300"}`}>{progress}%</span>
      </div>
      <div className="relative h-3 overflow-hidden rounded-full bg-zinc-800/80 ring-1 ring-zinc-700/50">
        <div className={`h-full rounded-full bg-gradient-to-r ${barColor} transition-all duration-700`} style={{ width: `${Math.max(progress, 2)}%` }}>
          {!isDone && !isError && progress < 100 && <div className="h-full animate-pulse bg-white/10" />}
        </div>
        {SCAN_PHASES.slice(0, 5).map((p) => (
          <span key={p.key} className={`absolute top-1/2 h-2 w-2 -translate-y-1/2 rounded-full border ${p.startWeight <= progress || p.key === phase.key ? "border-emerald-400 bg-emerald-400" : "border-zinc-600 bg-zinc-800"}`} style={{ left: `${p.startWeight}%` }} />
        ))}
      </div>
      <div className="grid grid-cols-5 text-center text-[10px] text-zinc-500">
        {SCAN_PHASES.map((p) => (
          <span key={p.key} className={p.key === phase.key ? "text-emerald-400" : ""}>{p.label}</span>
        ))}
      </div>
    </div>
  );
}

function ConnectionBadge({ wsState, isPollingFallback }: { wsState: WsConnectionState; isPollingFallback: boolean }): JSX.Element | null {
  if (isPollingFallback) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-1 text-[10px] font-medium text-amber-400">
        <WifiOff className="h-3 w-3" />
        降级轮询
      </span>
    );
  }
  if (wsState === "CONNECTED") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2.5 py-1 text-[10px] font-medium text-emerald-400">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
        实时
      </span>
    );
  }
  if (wsState === "CONNECTING" || wsState === "RECONNECTING") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-1 text-[10px] font-medium text-amber-400">
        <Loader2 className="h-3 w-3 animate-spin" />
        连接中
      </span>
    );
  }
  return null;
}
