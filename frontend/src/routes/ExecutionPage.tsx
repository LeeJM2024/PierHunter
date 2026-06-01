import { ArrowRightCircle, FileText } from "lucide-react";
import { useEffect } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { ExecutionStatusPanel } from "../components/execution/ExecutionStatusPanel";
import { ScanProgress } from "../components/execution/ScanProgress";
import { Panel } from "../components/common/Panel";
import { StageBadge } from "../components/common/StageBadge";
import { useTaskBootstrap } from "../hooks/useTaskBootstrap";
import { useTaskStore } from "../store/taskStore";

export function ExecutionPage(): JSX.Element {
  const navigate = useNavigate();
  const params = useParams();
  const taskId = params.taskId;

  useTaskBootstrap(taskId);

  const logs = useTaskStore((state) => state.logs);
  const taskStage = useTaskStore((state) => state.taskStage);
  const wsState = useTaskStore((state) => state.wsState);
  const isPollingFallback = useTaskStore((state) => state.isPollingFallback);
  const errorMessage = useTaskStore((state) => state.errorMessage);
  const connectExecution = useTaskStore((state) => state.connectExecution);

  useEffect(() => {
    if (taskStage !== "REPORT_READY" || !taskId) return;
    const timer = window.setTimeout(() => {
      navigate(`/report/${taskId}`);
    }, 1200);
    return () => window.clearTimeout(timer);
  }, [taskStage, taskId, navigate]);

  if (!taskId) {
    return (
      <Panel title="执行监控">
        <p className="text-sm text-zinc-500">任务 ID 缺失，请先前往新建任务页。</p>
        <Link
          to="/task/new"
          className="mt-6 inline-flex items-center gap-2 rounded-xl border border-zinc-700/50 bg-zinc-800/40 px-5 py-3 text-sm text-zinc-200 transition-all hover:border-zinc-600/60 hover:bg-zinc-700/40 hover:text-white"
        >
          去新建任务
        </Link>
      </Panel>
    );
  }

  return (
    <div className="grid gap-8 xl:grid-cols-[0.36fr_0.64fr]">
      <div className="space-y-6">
        <ExecutionStatusPanel
          taskId={taskId}
          stage={taskStage}
          wsState={wsState}
          isPollingFallback={isPollingFallback}
          errorMessage={errorMessage}
          onReconnect={() => {
            void connectExecution(taskId);
          }}
        />

        <Panel title="流程状态">
          <div className="space-y-4 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-zinc-500">任务阶段</span>
              <StageBadge stage={taskStage} />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-500">日志条数</span>
              <span className="text-zinc-300">{logs.length}</span>
            </div>
          </div>
        </Panel>

        <div className="flex flex-wrap gap-3">
          <Link
            to={`/report/${taskId}`}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-700/50 bg-zinc-800/40 px-5 py-3 text-sm text-zinc-200 transition-all hover:border-zinc-600/60 hover:bg-zinc-700/40 hover:text-white"
          >
            <FileText className="h-4 w-4" />
            立即查看报告
          </Link>
          <button
            type="button"
            onClick={() => {
              void connectExecution(taskId);
            }}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-700/50 bg-zinc-800/40 px-5 py-3 text-sm text-zinc-200 transition-all hover:border-zinc-600/60 hover:bg-zinc-700/40 hover:text-white"
          >
            <ArrowRightCircle className="h-4 w-4" />
            重建监控连接
          </button>
        </div>
      </div>

      <Panel title="扫描进度" className="bg-zinc-900/50">
        <ScanProgress
          logs={logs}
          taskStage={taskStage}
          wsState={wsState}
          isPollingFallback={isPollingFallback}
          errorMessage={errorMessage}
        />
      </Panel>
    </div>
  );
}
