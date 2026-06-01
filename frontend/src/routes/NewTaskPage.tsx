import { Loader2, PlayCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Panel } from "../components/common/Panel";
import { UploadDropzone } from "../components/upload/UploadDropzone";
import { useTaskStore } from "../store/taskStore";
import { formatBytes } from "../utils/format";

export function NewTaskPage(): JSX.Element {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const uploadAndAnalyze = useTaskStore((state) => state.uploadAndAnalyze);
  const taskStage = useTaskStore((state) => state.taskStage);
  const uploadState = useTaskStore((state) => state.uploadState);
  const uploadContext = useTaskStore((state) => state.uploadContext);
  const errorMessage = useTaskStore((state) => state.errorMessage);

  const canStart = useMemo(() => {
    return Boolean(selectedFile) && uploadState !== "PENDING";
  }, [selectedFile, uploadState]);

  const startTask = async () => {
    if (!selectedFile) return;
    const taskId = await uploadAndAnalyze(selectedFile);
    navigate(`/task/${taskId}/execution`);
  };

  return (
    <div className="space-y-6">
      <Panel title="新建扫描任务">
        <UploadDropzone file={selectedFile} onFileSelect={setSelectedFile} disabled={uploadState === "PENDING"} />

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={!canStart}
            onClick={() => void startTask()}
            className="inline-flex items-center gap-2 rounded-xl bg-cyber-gradient px-5 py-3 font-semibold text-white shadow-cyber-glow transition-all hover:scale-[1.02] hover:shadow-[0_0_30px_rgba(16,185,129,0.6),0_0_60px_rgba(16,185,129,0.3)] disabled:cursor-not-allowed disabled:bg-zinc-800 disabled:text-zinc-500 disabled:shadow-none disabled:hover:scale-100"
          >
            {uploadState === "PENDING" ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
            上传并开始扫描
          </button>

          {selectedFile && <span className="text-sm text-zinc-500">{selectedFile.name} · {formatBytes(selectedFile.size)}</span>}
        </div>

        {uploadContext && (
          <div className="mt-4 rounded-xl border border-zinc-700/50 bg-zinc-800/40 px-4 py-3 text-sm text-zinc-300">
            已上传：{uploadContext.fileName}（{formatBytes(uploadContext.size)}）
          </div>
        )}

        {errorMessage && (
          <div className="mt-4 rounded-xl border border-zinc-700/50 bg-zinc-800/40 px-4 py-3 text-sm text-zinc-300">
            {errorMessage}
          </div>
        )}
      </Panel>
    </div>
  );
}
