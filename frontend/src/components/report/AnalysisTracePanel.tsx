import { Activity, CheckCircle2, Clock, FileSearch, Shield } from "lucide-react";

import type { AnalysisArtifactsRaw, AnalysisStageRaw } from "../../types/contracts";

function stageIcon(key: string | undefined): JSX.Element {
  if (key === "libhunter") return <FileSearch className="h-4 w-4 text-cyan-300" />;
  if (key === "phunter") return <Shield className="h-4 w-4 text-emerald-300" />;
  if (key === "report") return <CheckCircle2 className="h-4 w-4 text-violet-300" />;
  return <Activity className="h-4 w-4 text-slate-300" />;
}

function durationSeconds(stage: AnalysisStageRaw): string {
  if (!stage.started_at || !stage.finished_at) return "-";
  const started = Date.parse(stage.started_at);
  const finished = Date.parse(stage.finished_at);
  if (!Number.isFinite(started) || !Number.isFinite(finished)) return "-";
  return `${Math.max(Math.round((finished - started) / 1000), 0)}s`;
}

function statusColor(status: string | undefined): string {
  if (status === "completed") return "text-emerald-300";
  if (status === "running") return "text-cyan-300";
  if (status === "partial") return "text-amber-300";
  if (status === "failed" || status === "hung") return "text-rose-300";
  return "text-slate-300";
}

export function AnalysisTracePanel({ artifacts }: { artifacts: AnalysisArtifactsRaw | null }): JSX.Element {
  const visibleStages = (artifacts?.execution_trace?.stages || []).filter((stage) => stage.key !== "init" && stage.label !== "初始化分析任务");
  const stages = visibleStages.slice(0, 4);
  const hiddenStageCount = Math.max(visibleStages.length - stages.length, 0);
  const summary = artifacts?.summary || {};

  return (
    <div className="h-full rounded-xl border border-slate-700/70 bg-slate-900/45 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-400">Analysis Artifacts</p>
          <p className="text-sm font-semibold text-slate-100">真实中间产物摘要</p>
        </div>
        <div className="inline-flex items-center gap-1 text-xs text-slate-400">
          <Clock className="h-3.5 w-3.5" />
          {artifacts?.generated_at ? new Date(artifacts.generated_at).toLocaleString("zh-CN") : "未生成"}
        </div>
      </div>

      <div className="mt-4 grid gap-2 text-xs sm:grid-cols-3 xl:grid-cols-1">
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <p className="text-slate-400">补丁证据链</p>
          <p className="mt-1 text-base font-semibold text-emerald-300">{String(summary.patch_evidence_count ?? 0)}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <p className="text-slate-400">候选类证据</p>
          <p className="mt-1 text-base font-semibold text-cyan-300">{String(summary.target_class_count ?? 0)}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <p className="text-slate-400">漏洞记录</p>
          <p className="mt-1 text-base font-semibold text-violet-300">{String(summary.vulnerability_count ?? 0)}</p>
        </div>
      </div>

      <div className="mt-4 space-y-2">
        {stages.length === 0 && <p className="text-xs text-slate-500">当前报告暂无结构化执行轨迹。</p>}
        {stages.map((stage) => (
          <div key={stage.key || stage.label} className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/55 p-2.5">
            <div className="mt-0.5">{stageIcon(stage.key)}</div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-medium text-slate-100">{stage.label || stage.key}</p>
                <span className={`font-mono ${statusColor(stage.status)}`}>{stage.status || "unknown"} · {durationSeconds(stage)}</span>
              </div>
              {stage.summary && <p className="mt-1 truncate text-slate-400">{stage.summary}</p>}
            </div>
          </div>
        ))}
        {hiddenStageCount > 0 && <p className="text-xs text-slate-500">其余 {hiddenStageCount} 个阶段已折叠。</p>}
      </div>
    </div>
  );
}
