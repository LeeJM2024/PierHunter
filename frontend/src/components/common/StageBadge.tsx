import type { TaskStage } from "../../types/domain";

const STAGE_THEME: Record<TaskStage, { label: string; className: string }> = {
  IDLE: {
    label: "待机",
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-all duration-200",
  },
  UPLOADING: {
    label: "上传中",
    className: "border-blue-500/30 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition-all duration-200 animate-pulse",
  },
  QUEUED: {
    label: "已排队",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-all duration-200",
  },
  SCANNING: {
    label: "扫描中",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-all duration-200 animate-pulse",
  },
  REPORT_READY: {
    label: "报告就绪",
    className: "border-emerald-500/50 bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 transition-all duration-200 shadow-lg shadow-emerald-500/20",
  },
  FAILED: {
    label: "高危",
    className: "border-rose-500/50 bg-rose-500/20 text-rose-400 hover:bg-rose-500/30 transition-all duration-200 animate-pulse shadow-lg shadow-rose-500/20",
  },
};

export function StageBadge({ stage }: { stage: TaskStage }): JSX.Element {
  const theme = STAGE_THEME[stage];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-3.5 py-1.5 text-xs font-bold ${theme.className}`}>
      {/* 状态指示点 */}
      <div className={`h-1.5 w-1.5 rounded-full ${
        stage === "FAILED" ? "bg-rose-400" :
        stage === "REPORT_READY" ? "bg-emerald-400" :
        stage === "SCANNING" ? "bg-emerald-400" :
        stage === "UPLOADING" ? "bg-blue-400" :
        stage === "QUEUED" ? "bg-amber-400" :
        "bg-cyan-400"
      }`}></div>
      {theme.label}
    </span>
  );
}
