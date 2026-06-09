import { Layers, PieChart, Zap } from "lucide-react";
import { mockLibrarySourceData, mockTotalLibraries, mockComponentRiskData } from "./mockData";

interface SourceData {
  name: string;
  count: number;
  percentage: number;
  color: string;
  icon: string;
  description: string;
}

export function LibrarySourceChart(): JSX.Element {
  const sourceData: SourceData[] = mockLibrarySourceData;
  const totalLibraries = mockTotalLibraries;
  
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <PieChart className="h-4 w-4 text-cyan-500" />
          <h3 className="text-sm font-semibold text-white">组件来源占比图</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Zap className="h-3 w-3 text-amber-500" />
          <span className="text-amber-400 font-medium">答辩模式</span>
          <Layers className="h-3 w-3 text-slate-500" />
          <span className="text-slate-300 font-medium">{totalLibraries}</span>
          <span className="text-slate-400">组件</span>
        </div>
      </div>
      
      {/* 饼图可视化 */}
      <div className="relative h-32 flex items-center justify-center">
        <div className="relative h-28 w-28">
          {/* 饼图扇形 */}
          <div className="absolute inset-0 rounded-full border-4 border-slate-800/50"></div>
          
          {(() => {
            let accumulatedPercentage = 0;
            return sourceData.map((source) => {
              const startAngle = (accumulatedPercentage / 100) * 360;
              const endAngle = ((accumulatedPercentage + source.percentage) / 100) * 360;
              accumulatedPercentage += source.percentage;
              
              const colorClass = source.color;
              const colorMap: Record<string, string> = {
                'bg-blue-500': '#3b82f6',
                'bg-purple-500': '#8b5cf6',
                'bg-emerald-500': '#10b981',
                'bg-amber-500': '#f59e0b',
                'bg-slate-500': '#64748b'
              };
              
              const colorValue = colorMap[colorClass] || '#3b82f6';
              
              const style = {
                background: `conic-gradient(
                  transparent 0deg ${startAngle}deg,
                  ${colorValue} ${startAngle}deg ${endAngle}deg,
                  transparent ${endAngle}deg 360deg
                )`
              } as React.CSSProperties;
              
              return (
                <div 
                  key={source.name}
                  className="absolute inset-0 rounded-full"
                  style={style}
                />
              );
            });
          })()}
          
          {/* 中心圆 */}
          <div className="absolute inset-5 rounded-full bg-slate-900/90 backdrop-blur-sm border border-slate-700/40 flex items-center justify-center shadow-lg">
            <div className="text-center">
              <div className="text-xl font-black text-white">{totalLibraries}</div>
              <div className="text-xs text-slate-400">组件</div>
            </div>
          </div>
        </div>
      </div>
      
      {/* 图例和数据 */}
      <div className="space-y-2">
        {sourceData.map((source) => (
          <div key={source.name} className="flex items-center justify-between p-2 rounded-lg hover:bg-slate-800/30 transition-all hover:scale-[1.01] group">
            <div className="flex items-center gap-3">
              <div className={`h-3 w-3 rounded-full ${source.color} group-hover:scale-125 transition-transform`}></div>
              <div className="flex items-center gap-2">
                <div className="text-lg">{source.icon}</div>
                <div>
                  <div className="text-sm font-medium text-white">{source.name}</div>
                  <div className="text-xs text-slate-400">{source.description}</div>
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm font-bold text-white">{source.count.toLocaleString()}</div>
              <div className="text-xs text-slate-400">{source.percentage}%</div>
            </div>
          </div>
        ))}
      </div>
      
      {/* 高风险组件统计 */}
      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="flex items-center justify-between mb-3">
          <div className="text-xs font-medium text-slate-300">高风险组件分布</div>
          <div className="text-xs text-slate-500">TOP 8</div>
        </div>
        
        <div className="space-y-2">
          {mockComponentRiskData.map((component) => (
            <div key={component.name} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className={`h-2 w-2 rounded-full ${
                  component.riskLevel === 'critical' ? 'bg-rose-500' :
                  component.riskLevel === 'high' ? 'bg-orange-500' :
                  component.riskLevel === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'
                }`}></div>
                <span className="text-xs text-slate-300">{component.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-1.5 w-16 bg-slate-700/50 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${
                      component.riskLevel === 'critical' ? 'bg-rose-500' :
                      component.riskLevel === 'high' ? 'bg-orange-500' :
                      component.riskLevel === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${(component.count / 60) * 100}%` }}
                  ></div>
                </div>
                <span className="text-xs font-medium text-slate-300 w-6 text-right">{component.count}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {/* 统计摘要 */}
      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div className="text-center">
            <div className="text-lg font-bold text-emerald-500">
              {sourceData[0].percentage + sourceData[3].percentage}%
            </div>
            <div className="text-xs text-slate-400">官方源占比</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-rose-500">
              {Math.round(sourceData[1].percentage * 0.3 + sourceData[4].percentage * 0.7)}%
            </div>
            <div className="text-xs text-slate-400">风险组件</div>
          </div>
        </div>
        
        <div className="text-xs text-slate-400">
          💡 建议：优先使用 Maven Central 和私有仓库，减少 JCenter 依赖，定期更新高风险组件
        </div>
      </div>
      
      <div className="text-xs text-slate-500 text-center">
        📊 包含 500+ 组件分析 • 覆盖 Android 主流依赖库 • 实时供应链风险评估
      </div>
    </div>
  );
}
