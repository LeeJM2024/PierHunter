import { GaugeCircle } from "lucide-react";

import { PatchStatusBadge } from "../common/PatchStatusBadge";
import type { VulnerabilityModel } from "../../types/domain";
import { clamp01, formatRatio } from "../../utils/format";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function display(value: unknown, fallback = "-"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(6);
  if (typeof value === "boolean") return value ? "是" : "否";
  return String(value);
}

function SimilarityBar({ label, value, colorClass }: { label: string; value: number | null; colorClass: string }): JSX.Element {
  const ratio = clamp01(value);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-slate-300">
        <span>{label}</span>
        <span>{formatRatio(value)}</span>
      </div>
      <div className="h-2 rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${colorClass}`} style={{ width: `${ratio * 100}%` }} />
      </div>
    </div>
  );
}

export function EvidencePanel({ vulnerability }: { vulnerability: VulnerabilityModel | null }): JSX.Element {
  if (!vulnerability) {
    return (
      <div className="rounded-xl border border-slate-700/70 bg-slate-900/45 p-4 text-sm text-slate-400">
        选择漏洞后将在此展示补丁证据与结论。
      </div>
    );
  }

  const evidence = asRecord(vulnerability.evidence);
  const resources = asRecord(evidence.resources);
  const targetScope = asRecord(evidence.target_scope);
  const verification = asRecord(evidence.verification);
  const execution = asRecord(evidence.execution);
  const classSample = asArray(targetScope.classes_sample).map(String);

  return (
    <div className="rounded-xl border border-slate-700/70 bg-slate-900/45 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-400">Evidence Panel</p>
          <p className="text-sm font-semibold text-slate-100">{vulnerability.cveId}</p>
        </div>
        <PatchStatusBadge status={vulnerability.status} />
      </div>

      <div className="mt-4 space-y-3">
        <SimilarityBar label="Pre Similarity" value={vulnerability.preSimilarity} colorClass="bg-rose-500" />
        <SimilarityBar label="Post Similarity" value={vulnerability.postSimilarity} colorClass="bg-emerald-500" />
      </div>

      <div className="mt-4 grid gap-3 text-xs md:grid-cols-2">
        <div className="rounded-lg border border-slate-700/70 bg-slate-950/65 p-3">
          <p className="font-semibold text-slate-100">补丁资源</p>
          <p className="mt-2 text-slate-400">Pre: <span className="text-slate-200">{display(resources.pre_patch_artifact)}</span></p>
          <p className="mt-1 text-slate-400">Post: <span className="text-slate-200">{display(resources.post_patch_artifact)}</span></p>
          <p className="mt-1 text-slate-400">Diff: <span className="text-slate-200">{display(resources.patch_diff_artifact)}</span></p>
        </div>
        <div className="rounded-lg border border-slate-700/70 bg-slate-950/65 p-3">
          <p className="font-semibold text-slate-100">验证执行</p>
          <p className="mt-2 text-slate-400">PHunter 状态: <span className="text-slate-200">{display(verification.status)}</span></p>
          <p className="mt-1 text-slate-400">Return Code: <span className="text-slate-200">{display(verification.returncode)}</span></p>
          <p className="mt-1 text-slate-400">重试: <span className="text-slate-200">{display(verification.retried)}</span></p>
          <p className="mt-1 text-slate-400">补丁相关方法: <span className="text-slate-200">{display(verification.patch_related_method_count)}</span></p>
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-slate-700/70 bg-slate-950/65 p-3 text-xs">
        <div className="flex items-center justify-between gap-3">
          <p className="font-semibold text-slate-100">候选分析范围</p>
          <span className="text-slate-400">{display(targetScope.class_count, "0")} classes</span>
        </div>
        <div className="mt-2 flex max-h-24 flex-wrap gap-1 overflow-auto">
          {classSample.length === 0 ? (
            <span className="text-slate-500">暂无候选类样本</span>
          ) : (
            classSample.slice(0, 20).map((name) => (
              <span key={name} className="rounded border border-cyan-500/20 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] text-cyan-100">
                {name}
              </span>
            ))
          )}
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-slate-700/70 bg-slate-950/65 p-3 text-xs text-slate-200">
        <p className="inline-flex items-center gap-1 font-semibold text-slate-100">
          <GaugeCircle className="h-4 w-4 text-cyan-300" />
          一句话结论
        </p>
        <p className="mt-2 leading-6">{vulnerability.status.conclusion}</p>
      </div>

      <div className="mt-4 rounded-lg border border-slate-800 bg-black/50 p-3 text-xs text-slate-400">
        <p className="font-semibold text-slate-300">原始字段（调试）</p>
        <p className="mt-1">raw.status: {String(vulnerability.raw.status)}</p>
        <p>raw.pre_similarity: {String(vulnerability.raw.pre_similarity)}</p>
        <p>raw.post_similarity: {String(vulnerability.raw.post_similarity)}</p>
        <p>phunter.returncode: {display(verification.returncode)}</p>
        <p>stdout.lines: {display(asRecord(execution.stdout).line_count)}</p>
        <p>stderr.lines: {display(asRecord(execution.stderr).line_count)}</p>
      </div>
    </div>
  );
}
