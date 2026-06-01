import type { PropsWithChildren, ReactNode } from "react";

interface PanelProps extends PropsWithChildren {
  title?: ReactNode;
  right?: ReactNode;
  className?: string;
}

export function Panel({ title, right, className = "", children }: PanelProps): JSX.Element {
  return (
    <section className={`rounded-2xl bg-gradient-to-br from-slate-900/40 to-slate-950/40 backdrop-blur-md border border-slate-700/30 p-6 shadow-[0_8px_32px_rgba(0,0,0,0.3)] hover-lift transition-all ${className}`}>
      {(title || right) && (
        <header className="mb-6 flex items-center justify-between gap-4 border-b border-slate-700/30 pb-4">
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-1.5 rounded-full bg-cyan-500/70"></div>
            <div className="text-sm font-semibold tracking-wide text-white">{title}</div>
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}
