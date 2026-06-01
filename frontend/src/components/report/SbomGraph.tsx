import * as echarts from "echarts";
import { useEffect, useMemo, useRef } from "react";

import type { UsedLibraryModel } from "../../types/domain";

interface SbomGraphProps {
  apkName: string;
  libraries: UsedLibraryModel[];
  selectedLibraryId: string | null;
  onSelectLibrary: (libraryId: string) => void;
}

export function SbomGraph({ apkName, libraries, selectedLibraryId, onSelectLibrary }: SbomGraphProps): JSX.Element {
  const holderRef = useRef<HTMLDivElement | null>(null);

  const graphData = useMemo(() => {
    const centerId = "apk-center";
    const nodes = [
      {
        id: centerId,
        name: apkName,
        symbolSize: 72,
        category: 0,
        value: 0,
        itemStyle: {
          color: "rgba(14, 165, 233, 0.25)",
          borderColor: "rgba(56, 189, 248, 0.6)",
          borderWidth: 2,
          shadowColor: "rgba(56, 189, 248, 0.3)",
          shadowBlur: 12,
        },
        label: {
          color: "#e0f2fe",
          fontWeight: 600,
          fontSize: 14,
          backgroundColor: "rgba(14, 165, 233, 0.2)",
          padding: [4, 8],
          borderRadius: 4,
        },
      },
      ...libraries.map((lib) => {
        const risk = lib.vulnerabilityCount > 0;
        const isSelected = selectedLibraryId === lib.id;
        
        // 更柔和的颜色
        let color = "rgba(34, 197, 94, 0.25)"; // 安全 - 柔和的绿色
        let borderColor = "rgba(34, 197, 94, 0.6)";
        
        if (risk) {
          color = "rgba(249, 115, 22, 0.25)"; // 风险 - 柔和的橙色
          borderColor = "rgba(249, 115, 22, 0.6)";
        }
        
        if (isSelected) {
          color = "rgba(56, 189, 248, 0.35)"; // 选中 - 柔和的蓝色
          borderColor = "rgba(56, 189, 248, 0.8)";
        }
        
        return {
          id: lib.id,
          name: `${lib.artifact}\nv${lib.version}`,
          category: risk ? 1 : 2,
          symbolSize: Math.max(28, 28 + lib.vulnerabilityCount * 5),
          value: lib.vulnerabilityCount,
          itemStyle: {
            color,
            borderColor,
            borderWidth: isSelected ? 3 : 2,
            shadowColor: isSelected ? "rgba(56, 189, 248, 0.4)" : "transparent",
            shadowBlur: isSelected ? 16 : 0,
          },
          label: {
            color: risk ? "#fef3c7" : "#d1fae5",
            fontWeight: risk ? 500 : 400,
            fontSize: 11,
            backgroundColor: risk ? "rgba(249, 115, 22, 0.15)" : "rgba(34, 197, 94, 0.15)",
            padding: [3, 6],
            borderRadius: 3,
          },
        };
      }),
    ];

    const links = libraries.map((lib) => {
      const risk = lib.vulnerabilityCount > 0;
      return {
        source: centerId,
        target: lib.id,
        lineStyle: {
          color: risk ? "rgba(251, 113, 133, 0.5)" : "rgba(34, 197, 94, 0.4)",
          width: risk ? 1.5 : 1,
          opacity: 0.7,
          type: risk ? "solid" : "dashed",
          curveness: 0.2,
        },
        label: {
          show: true,
          formatter: risk ? `${lib.vulnerabilityCount} vuln` : "safe",
          color: risk ? "#fca5a5" : "#86efac",
          fontSize: 10,
          backgroundColor: risk ? "rgba(251, 113, 133, 0.1)" : "rgba(34, 197, 94, 0.1)",
          padding: [2, 4],
          borderRadius: 2,
        },
      };
    });

    return { nodes, links };
  }, [apkName, libraries, selectedLibraryId]);

  useEffect(() => {
    if (!holderRef.current) return;

    const chart = echarts.init(holderRef.current);
    chart.setOption({
      backgroundColor: "transparent",
      tooltip: {
        trigger: "item",
        backgroundColor: "rgba(15, 23, 42, 0.9)",
        borderColor: "rgba(148, 163, 184, 0.2)",
        borderWidth: 1,
        textStyle: {
          color: "#e2e8f0",
          fontSize: 12,
        },
        formatter: (params: any) => {
          if (params.dataType === 'node') {
            const data = params.data;
            if (data.id === 'apk-center') {
              return `<div style="font-weight:600;color:#38bdf8">${data.name}</div>`;
            }
            return `
              <div style="font-weight:600;color:${data.itemStyle.borderColor}">${data.name}</div>
              <div style="margin-top:4px;color:#94a3b8">漏洞数量: ${data.value}</div>
              <div style="margin-top:2px;color:#94a3b8">状态: ${data.category === 1 ? '⚠️ 风险' : '✅ 安全'}</div>
            `;
          }
          return '';
        },
      },
      series: [
        {
          type: "graph",
          layout: "force",
          roam: true,
          draggable: true,
          data: graphData.nodes,
          links: graphData.links,
          categories: [
            { 
              name: "APK",
              itemStyle: {
                color: "rgba(14, 165, 233, 0.25)",
              }
            },
            { 
              name: "Risk",
              itemStyle: {
                color: "rgba(249, 115, 22, 0.25)",
              }
            },
            { 
              name: "Safe",
              itemStyle: {
                color: "rgba(34, 197, 94, 0.25)",
              }
            },
          ],
          label: {
            show: true,
            position: "right",
            color: "#cbd5e1",
            fontSize: 11,
            formatter: (params: any) => {
              return params.data.name;
            },
          },
          lineStyle: {
            opacity: 0.7,
            curveness: 0.2,
          },
          force: {
            repulsion: 280,
            gravity: 0.05,
            edgeLength: [90, 160],
            friction: 0.8,
          },
          emphasis: {
            focus: "adjacency",
            lineStyle: {
              width: 3,
              opacity: 0.9,
            },
            itemStyle: {
              shadowBlur: 20,
              shadowColor: "rgba(255, 255, 255, 0.3)",
            },
          },
          animation: true,
          animationDuration: 1000,
          animationEasing: "cubicOut",
        },
      ],
    });

    chart.on("click", (params) => {
      const id = params.data && typeof params.data === "object" ? String((params.data as { id?: string }).id || "") : "";
      if (id && id !== "apk-center") {
        onSelectLibrary(id);
      }
    });

    // 悬停效果
    chart.on("mouseover", (params: any) => {
      if (params.dataType === 'node') {
        chart.dispatchAction({
          type: 'highlight',
          seriesIndex: 0,
          dataIndex: params.dataIndex,
        });
      }
    });

    chart.on("mouseout", (params: any) => {
      chart.dispatchAction({
        type: 'downplay',
        seriesIndex: 0,
        dataIndex: params.dataIndex,
      });
    });

    const resizeHandler = () => chart.resize();
    window.addEventListener("resize", resizeHandler);

    return () => {
      window.removeEventListener("resize", resizeHandler);
      chart.dispose();
    };
  }, [graphData, onSelectLibrary]);

  return (
    <div className="relative h-[360px] w-full overflow-hidden rounded-xl border border-slate-700/40 bg-gradient-to-br from-slate-900/50 to-slate-950/50 backdrop-blur-sm">
      <div ref={holderRef} className="absolute inset-0" />
      
      {/* 图例 */}
      <div className="absolute bottom-3 left-3 z-10 flex flex-wrap gap-2">
        <div className="flex items-center gap-1.5 rounded-lg bg-slate-900/80 px-2.5 py-1.5 text-xs backdrop-blur-sm">
          <div className="h-2.5 w-2.5 rounded-full bg-cyan-500/60"></div>
          <span className="text-slate-300">APK</span>
        </div>
        <div className="flex items-center gap-1.5 rounded-lg bg-slate-900/80 px-2.5 py-1.5 text-xs backdrop-blur-sm">
          <div className="h-2.5 w-2.5 rounded-full bg-emerald-500/60"></div>
          <span className="text-slate-300">安全组件</span>
        </div>
        <div className="flex items-center gap-1.5 rounded-lg bg-slate-900/80 px-2.5 py-1.5 text-xs backdrop-blur-sm">
          <div className="h-2.5 w-2.5 rounded-full bg-amber-500/60"></div>
          <span className="text-slate-300">风险组件</span>
        </div>
      </div>
      
      {/* 交互提示 */}
      <div className="absolute top-3 right-3 z-10">
        <div className="rounded-lg bg-slate-900/80 px-2.5 py-1.5 text-xs text-slate-400 backdrop-blur-sm">
          🖱️ 拖拽 · 缩放 · 点击
        </div>
      </div>
    </div>
  );
}
