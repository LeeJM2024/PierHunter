import type { TaskStage } from "../../types/domain";

const STAGE_THEME: Record<TaskStage, { label: string; className: string; dot: string }> = {
  IDLE: {
    label: "待机",
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-400",
    dot: "bg-cyan-400",
  },
  UPLOADING: {
    label: "上传中",
    className: "border-blue-500/30 bg-blue-500/10 text-blue-400 animate-pulse",
    dot: "bg-blue-400",
  },
  QUEUED: {
    label: "已排队",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-400",
    dot: "bg-amber-400",
  },
  SCANNING: {
    label: "扫描中",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 animate-pulse",
    dot: "bg-emerald-400",
  },
  REPORT_READY: {
    label: "报告就绪",
    className: "border-emerald-500/50 bg-emerald-500/20 text-emerald-400 shadow-lg shadow-emerald-500/20",
    dot: "bg-emerald-400",
  },
  FAILED: {
    label: "失败",
    className: "border-rose-500/50 bg-rose-500/20 text-rose-400 shadow-lg shadow-rose-500/20",
    dot: "bg-rose-400",
  },
};

export function StageBadge({ stage }: { stage: TaskStage }): JSX.Element {
  const theme = STAGE_THEME[stage];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-3.5 py-1.5 text-xs font-bold transition-all ${theme.className}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${theme.dot}`} />
      {theme.label}
    </span>
  );
}
