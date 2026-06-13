import { AlertTriangle, CheckCircle2, Crosshair, GitBranch, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { CveVersionTimelineItemModel, CveVersionTimelineModel } from "../../types/domain";

interface CveVersionTimelineProps {
  timelines?: CveVersionTimelineModel[];
}

function percent(index: number, total: number): number {
  if (total <= 1) return 50;
  return 4 + (index / (total - 1)) * 92;
}

type TimelineEventKind = "introduced" | "fixed";

interface TimelineEvent {
  version: string;
  kind: TimelineEventKind;
  cveId: string;
}

interface PositionedTimelineEvent extends TimelineEvent {
  nodeX: number;
  labelLeft: number;
  labelTop: number;
}

const EVENT_LABEL_WIDTH = 176;
const EVENT_LABEL_GAP = 16;
const EVENT_BASE_TOP = 150;
const EVENT_ROW_HEIGHT = 38;

function versionState(version: string, timeline: CveVersionTimelineModel): {
  isCurrent: boolean;
  isAffected: boolean;
  isFixed: boolean;
} {
  return {
    isCurrent: version === timeline.detectedVersion,
    isAffected: timeline.cves.some((item) => item.affectedVersions.includes(version)),
    isFixed: timeline.cves.some((item) => item.fixedVersion === version),
  };
}

function nodeClass(version: string, timeline: CveVersionTimelineModel): string {
  const isCurrent = version === timeline.detectedVersion;
  const isAffected = timeline.cves.some((item) => item.affectedVersions.includes(version));
  const isFixed = timeline.cves.some((item) => item.fixedVersion === version);

  if (isCurrent && isAffected) return "border-cyan-100 bg-cyan-400 text-slate-950 ring-4 ring-rose-400/30 shadow-[0_0_22px_rgba(34,211,238,0.5)]";
  if (isCurrent) return "border-cyan-200 bg-cyan-500 text-slate-950 shadow-[0_0_18px_rgba(34,211,238,0.42)]";
  if (isFixed) return "border-emerald-300 bg-emerald-500/75 text-slate-950";
  if (isAffected) return "border-amber-200 bg-amber-400/80 text-slate-950";
  return "border-slate-600 bg-slate-900 text-slate-300";
}

function VersionMarker({ version, timeline }: { version: string; timeline: CveVersionTimelineModel }): JSX.Element {
  const { isCurrent, isAffected, isFixed } = versionState(version, timeline);

  if (isCurrent) {
    return (
      <div className={`grid h-6 w-6 place-items-center rounded-full border-2 ${nodeClass(version, timeline)}`}>
        <div className="h-2.5 w-2.5 rounded-full bg-slate-950/80" />
      </div>
    );
  }

  if (isFixed) {
    return (
      <div className="relative h-5 w-5">
        <div className="absolute inset-0 bg-emerald-400/85 shadow-[0_0_14px_rgba(52,211,153,0.28)] [clip-path:polygon(25%_5%,75%_5%,100%_50%,75%_95%,25%_95%,0_50%)]" />
        <CheckCircle2 className="absolute left-1/2 top-1/2 h-3 w-3 -translate-x-1/2 -translate-y-1/2 text-slate-950/85" />
      </div>
    );
  }

  if (isAffected) {
    return (
      <div className="relative h-5 w-5">
        <div className="absolute inset-1 rotate-45 rounded-[4px] border border-amber-100/80 bg-amber-400/85 shadow-[0_0_12px_rgba(251,191,36,0.18)]" />
        <div className="absolute left-1/2 top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-slate-950/70" />
      </div>
    );
  }

  return (
    <div className="grid h-4 w-4 place-items-center rounded-full border border-slate-500/70 bg-slate-800 shadow-[0_0_8px_rgba(148,163,184,0.12)]">
      <div className="h-1.5 w-1.5 rounded-full bg-slate-400/80" />
    </div>
  );
}

function rangeLabel(item: CveVersionTimelineItemModel): string {
  if (item.knowledgeStatus !== "matched" || !item.affectedFrom || !item.affectedTo) return "影响范围待确认";
  const fixed = item.fixedVersion ? `，修复于 ${item.fixedVersion}` : "";
  return `影响 ${item.affectedFrom} - ${item.affectedTo}${fixed}`;
}

function compareVersions(a: string, b: string): number {
  const left = a.split(/[._+-]/).map((part) => Number(part));
  const right = b.split(/[._+-]/).map((part) => Number(part));
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (left[index] || 0) - (right[index] || 0);
    if (diff !== 0) return diff;
  }
  return a.localeCompare(b);
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(value, max));
}

function timelineEvents(items: CveVersionTimelineItemModel[]): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  for (const item of items) {
    if (item.affectedFrom) {
      events.push({ version: item.affectedFrom, cveId: item.cveId, kind: "introduced" });
    }
    if (item.fixedVersion) {
      events.push({ version: item.fixedVersion, cveId: item.cveId, kind: "fixed" });
    }
  }

  return events.sort((a, b) => {
    const versionDiff = compareVersions(a.version, b.version);
    if (versionDiff !== 0) return versionDiff;
    if (a.kind !== b.kind) return a.kind === "introduced" ? -1 : 1;
    return a.cveId.localeCompare(b.cveId);
  });
}

function positionedTimelineEvents(events: TimelineEvent[], versions: string[], chartWidth: number): PositionedTimelineEvent[] {
  const laneRightEdges: number[] = [];
  const positioned: PositionedTimelineEvent[] = [];

  for (const event of events) {
    const versionIndex = versions.indexOf(event.version);
    if (versionIndex < 0) continue;

    const nodeX = (percent(versionIndex, versions.length) / 100) * chartWidth;
    const preferredLeft = clamp(nodeX - EVENT_LABEL_WIDTH / 2, 0, chartWidth - EVENT_LABEL_WIDTH);
    let lane = 0;
    while (laneRightEdges[lane] !== undefined && preferredLeft < laneRightEdges[lane] + EVENT_LABEL_GAP) {
      lane += 1;
    }
    laneRightEdges[lane] = preferredLeft + EVENT_LABEL_WIDTH;
    positioned.push({
      ...event,
      nodeX,
      labelLeft: preferredLeft,
      labelTop: EVENT_BASE_TOP + lane * EVENT_ROW_HEIGHT,
    });
  }

  return positioned;
}

function TimelineCard({ timeline }: { timeline: CveVersionTimelineModel }): JSX.Element {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const versions = timeline.versions.length > 0 ? timeline.versions : [timeline.detectedVersion];
  const currentIndex = versions.indexOf(timeline.detectedVersion);
  const matchedCves = timeline.cves.filter((item) => item.knowledgeStatus === "matched");
  const affectedNow = timeline.cves.filter((item) => item.currentAffected).length;
  const events = timelineEvents(matchedCves);
  const chartWidth = Math.max(1040, versions.length * 52);
  const positionedEvents = positionedTimelineEvents(events, versions, chartWidth);
  const maxEventTop = positionedEvents.reduce((max, event) => Math.max(max, event.labelTop), EVENT_BASE_TOP);
  const chartHeight = Math.max(300, maxEventTop + 74);
  const fixVersions = matchedCves
    .filter((item) => item.currentAffected && item.fixedVersion)
    .map((item) => item.fixedVersion as string)
    .sort(compareVersions);
  const nextFixVersion = fixVersions.length > 0 ? fixVersions[fixVersions.length - 1] : null;

  useEffect(() => {
    const container = scrollRef.current;
    if (!container || currentIndex < 0) return;
    const currentX = (percent(currentIndex, versions.length) / 100) * chartWidth;
    const maxScrollLeft = Math.max(chartWidth - container.clientWidth, 0);
    if (chartWidth <= container.clientWidth * 1.35) {
      container.scrollLeft = 0;
      return;
    }
    let nextScrollLeft = clamp(currentX - container.clientWidth / 2, 0, maxScrollLeft);

    for (let pass = 0; pass < 4; pass += 1) {
      const leftEdge = nextScrollLeft;
      const rightEdge = nextScrollLeft + container.clientWidth;
      const clippedLeft = positionedEvents.find((event) => event.labelLeft < leftEdge && event.labelLeft + EVENT_LABEL_WIDTH > leftEdge);
      if (clippedLeft) {
        nextScrollLeft = clamp(clippedLeft.labelLeft - 24, 0, maxScrollLeft);
        continue;
      }
      const clippedRight = positionedEvents.find((event) => event.labelLeft < rightEdge && event.labelLeft + EVENT_LABEL_WIDTH > rightEdge);
      if (clippedRight) {
        nextScrollLeft = clamp(clippedRight.labelLeft + EVENT_LABEL_WIDTH + 24 - container.clientWidth, 0, maxScrollLeft);
        continue;
      }
      break;
    }

    container.scrollLeft = nextScrollLeft;
  }, [chartWidth, currentIndex, positionedEvents, timeline.libraryName, versions.length]);

  return (
    <article className="rounded-xl border border-slate-700/70 bg-slate-950/55 p-4">
      <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold text-slate-100">{timeline.libraryName}</h3>
            <span className="rounded-full border border-cyan-300/35 bg-cyan-400/10 px-2 py-0.5 text-xs text-cyan-100">
              当前版本 {timeline.detectedVersion}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {affectedNow > 0 ? `当前版本命中 ${affectedNow} 个 CVE 影响区间` : "当前版本未落入已知影响区间"}
          </p>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 lg:min-w-[360px]">
          <div className={`rounded-lg border px-3 py-2 ${affectedNow > 0 ? "border-rose-300/45 bg-rose-500/10" : "border-emerald-300/35 bg-emerald-500/10"}`}>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Crosshair className="h-3.5 w-3.5 text-cyan-200" />
              当前命中版本
            </div>
            <p className="mt-1 font-mono text-lg font-semibold text-cyan-100">{timeline.detectedVersion}</p>
          </div>
          <div className="rounded-lg border border-slate-700/70 bg-slate-900/65 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ShieldAlert className="h-3.5 w-3.5 text-amber-200" />
              建议关注
            </div>
            <p className="mt-1 text-sm font-semibold text-slate-100">
              {nextFixVersion ? `至少升级到 ${nextFixVersion}` : `${timeline.cves.length} 个 CVE`}
            </p>
          </div>
        </div>
      </div>

      <div ref={scrollRef} className="mt-4 overflow-x-auto pb-2">
        <div className="relative" style={{ height: chartHeight, width: chartWidth }}>
          <div className="absolute left-[4%] right-[4%] top-[92px] h-px bg-slate-700" />
          {currentIndex >= 0 && (
            <div
              className="absolute bottom-4 top-0 w-px bg-cyan-300/75 shadow-[0_0_18px_rgba(34,211,238,0.6)]"
              style={{ left: `${percent(currentIndex, versions.length)}%` }}
            >
              <span className="absolute -left-14 top-2 whitespace-nowrap rounded-lg border border-cyan-300/55 bg-cyan-400/15 px-3 py-1 text-xs font-semibold text-cyan-50">
                当前使用 {timeline.detectedVersion}
              </span>
            </div>
          )}

          <svg className="pointer-events-none absolute inset-0 h-full w-full overflow-visible">
            {positionedEvents.map((event) => {
              const labelCenter = event.labelLeft + EVENT_LABEL_WIDTH / 2;
              const branchY = event.labelTop - 14;
              const stroke = event.kind === "introduced" ? "rgba(251,113,133,0.42)" : "rgba(52,211,153,0.42)";
              return (
                <path
                  key={`${timeline.libraryName}-${event.kind}-${event.version}-${event.cveId}-branch`}
                  d={`M ${event.nodeX} 108 V ${branchY} H ${labelCenter} V ${event.labelTop - 2}`}
                  fill="none"
                  stroke={stroke}
                  strokeWidth="1"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              );
            })}
          </svg>

          {positionedEvents.map((event) => (
            <div
              key={`${timeline.libraryName}-${event.kind}-${event.version}-${event.cveId}`}
              className={`absolute flex w-[176px] items-center gap-1 whitespace-nowrap rounded-md border px-2 py-1 text-[10px] font-semibold ${
                event.kind === "introduced"
                  ? "border-rose-300/45 bg-rose-500/10 text-rose-100"
                  : "border-emerald-300/45 bg-emerald-500/10 text-emerald-100"
              }`}
              style={{ left: event.labelLeft, top: event.labelTop }}
              title={`${event.version} ${event.kind === "introduced" ? "出现" : "修复"} ${event.cveId}`}
            >
              {event.kind === "introduced" ? <AlertTriangle className="h-3 w-3" /> : <CheckCircle2 className="h-3 w-3" />}
              <span>{event.kind === "introduced" ? "出现" : "修复"} {event.cveId}</span>
            </div>
          ))}

          {versions.map((version, index) => (
            <div
              key={`${timeline.libraryName}-${version}`}
              className="absolute top-[78px] flex -translate-x-1/2 flex-col items-center"
              style={{ left: `${percent(index, versions.length)}%` }}
            >
              <VersionMarker version={version} timeline={timeline} />
              <span className={`mt-2 whitespace-nowrap font-mono text-xs ${version === timeline.detectedVersion ? "font-semibold text-cyan-100" : "text-slate-300"}`}>
                {version}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
        {timeline.cves.map((item) => (
          <div
            key={`${timeline.libraryName}-${item.cveId}-detail`}
            className={`rounded-lg border p-2 text-xs ${
              item.currentAffected
                ? "border-rose-400/45 bg-rose-500/10"
                : "border-slate-700/70 bg-slate-900/60"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-semibold text-slate-100">{item.cveId}</span>
              <span className={item.currentAffected ? "text-rose-200" : "text-slate-400"}>
                {item.currentAffected ? "当前受影响" : "未命中当前版本"}
              </span>
            </div>
            <p className="mt-1 text-slate-400">{rangeLabel(item)}</p>
          </div>
        ))}
      </div>
    </article>
  );
}

export function CveVersionTimeline({ timelines }: CveVersionTimelineProps): JSX.Element {
  const visibleTimelines = useMemo(
    () => (timelines || []).filter((item) => item.cves.length > 0),
    [timelines],
  );
  const [selectedLibrary, setSelectedLibrary] = useState<string | null>(null);
  const activeTimeline = visibleTimelines.find((item) => item.libraryName === selectedLibrary) || visibleTimelines[0] || null;

  useEffect(() => {
    if (visibleTimelines.length === 0) {
      setSelectedLibrary(null);
      return;
    }
    if (!activeTimeline) {
      setSelectedLibrary(visibleTimelines[0].libraryName);
    }
  }, [activeTimeline, visibleTimelines]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-slate-300">
          按第三方库版本顺序标注 CVE 出现与修复节点，突出当前 APK 使用版本的位置。
        </p>
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-cyan-400" />当前版本</span>
          <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-rose-400" />CVE 出现</span>
          <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />CVE 修复</span>
        </div>
      </div>

      {visibleTimelines.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {visibleTimelines.map((timeline) => {
            const selected = activeTimeline?.libraryName === timeline.libraryName;
            const affectedNow = timeline.cves.filter((item) => item.currentAffected).length;
            return (
              <button
                key={`${timeline.libraryName}-${timeline.detectedVersion}`}
                type="button"
                onClick={() => setSelectedLibrary(timeline.libraryName)}
                className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition ${
                  selected
                    ? "border-cyan-300/70 bg-cyan-400/15 text-cyan-50 shadow-[0_0_18px_rgba(34,211,238,0.16)]"
                    : "border-slate-700 bg-slate-900/65 text-slate-300 hover:border-cyan-300/45 hover:text-cyan-100"
                }`}
              >
                <span>{timeline.libraryName}</span>
                <span className={affectedNow > 0 ? "text-rose-200" : "text-slate-500"}>
                  {affectedNow}/{timeline.cves.length}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {visibleTimelines.length === 0 && (
        <div className="rounded-xl border border-slate-700/70 bg-slate-950/45 px-4 py-6 text-sm text-slate-400">
          当前报告暂无可绘制的 CVE 版本影响范围。
        </div>
      )}

      {activeTimeline && <TimelineCard timeline={activeTimeline} />}

      {visibleTimelines.length > 0 && (
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <GitBranch className="h-3.5 w-3.5" />
          版本节点来自本地 CVE 知识库；红色标记表示该 CVE 首个受影响版本，绿色标记表示对应修复版本。
        </div>
      )}
    </div>
  );
}
