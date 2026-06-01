import { FileArchive, UploadCloud } from "lucide-react";
import { useRef, useState } from "react";

import { formatBytes } from "../../utils/format";

interface UploadDropzoneProps {
  file: File | null;
  onFileSelect: (file: File) => void;
  disabled?: boolean;
}

export function UploadDropzone({ file, onFileSelect, disabled = false }: UploadDropzoneProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragging, setDragging] = useState(false);

  const chooseFile = (selected: File | null | undefined) => {
    if (!selected || disabled) return;
    onFileSelect(selected);
  };

  return (
    <div
      className={`relative rounded-2xl border-2 border-dashed p-8 transition backdrop-blur-sm ${
        dragging
          ? "border-cyan-500/50 bg-cyan-500/20"
          : "border-cyan-500/30 bg-cyan-500/10 hover:border-cyan-500/50 hover:bg-cyan-500/20"
      } ${disabled ? "opacity-70" : ""}`}
      onDragOver={(event) => {
        event.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        chooseFile(event.dataTransfer.files?.[0]);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk"
        className="hidden"
        onChange={(event) => chooseFile(event.target.files?.[0])}
      />

      <button
        type="button"
        disabled={disabled}
        className="absolute inset-0"
        onClick={() => inputRef.current?.click()}
        aria-label="select-apk"
      />

      <div className="pointer-events-none text-center">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30">
          <UploadCloud className="h-8 w-8 text-cyan-400" />
        </div>
        <p className="mt-4 text-base font-semibold text-white">拖拽 APK 或点击选择文件</p>
        <p className="mt-1.5 text-sm text-slate-400">支持 .apk 格式，单个文件上传</p>

        {file && (
          <div className="mx-auto mt-6 max-w-md rounded-xl border border-emerald-500/30 bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 backdrop-blur-sm px-4 py-3 text-left">
            <p className="inline-flex items-center gap-2 text-sm text-white">
              <FileArchive className="h-4 w-4 text-emerald-400" />
              {file.name}
            </p>
            <p className="mt-1 text-xs text-emerald-300/80">{formatBytes(file.size)}</p>
          </div>
        )}
      </div>
    </div>
  );
}
