import { Clock3, FileScan, Loader2, PlayCircle, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";

import { Panel } from "../common/Panel";

export function RecentTasksPanel({ historyTaskIds, onClear }: { historyTaskIds: string[]; onClear: () => Promise<void> }): JSX.Element {
  const [isClearing, setIsClearing] = useState(false);

  const handleClear = async () => {
    if (isClearing) return;
    setIsClearing(true);
    try {
      await onClear();
    } finally {
      setIsClearing(false);
    }
  };

  const right = historyTaskIds.length ? (
    <button
      type="button"
      onClick={() => void handleClear()}
      disabled={isClearing}
      className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-600/60 bg-slate-800/40 text-slate-300 transition hover:border-rose-400/50 hover:bg-rose-500/10 hover:text-rose-200"
      title="清除历史记录"
      aria-label="清除历史记录"
    >
      {isClearing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
    </button>
  ) : (
    <Clock3 className="h-4 w-4 text-slate-300" />
  );

  return (
    <Panel title="历史任务" right={right}>
      {historyTaskIds.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-600/70 bg-slate-950/45 px-4 py-5 text-sm text-slate-400">
          暂无历史任务
        </div>
      ) : (
        <div className="max-h-[228px] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent pr-1">
          <ul className="space-y-3">
            {historyTaskIds.map((taskId) => (
              <li
                key={taskId}
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-700/70 bg-slate-950/45 px-4 py-3"
              >
                <span className="inline-flex items-center gap-2 text-sm text-slate-200 truncate max-w-[180px]">
                  <FileScan className="h-4 w-4 text-cyan-300 flex-shrink-0" />
                  <span className="truncate">{taskId}</span>
                </span>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <Link
                    to={`/task/${taskId}/execution`}
                    className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/45 bg-cyan-500/10 px-2.5 py-1 text-xs text-cyan-100"
                  >
                    <PlayCircle className="h-3.5 w-3.5" />
                    执行页
                  </Link>
                  <Link
                    to={`/report/${taskId}`}
                    className="rounded-lg border border-slate-500/60 bg-slate-700/30 px-2.5 py-1 text-xs text-slate-100"
                  >
                    报告页
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}
