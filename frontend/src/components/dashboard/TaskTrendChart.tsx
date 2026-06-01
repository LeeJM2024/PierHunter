import { LineChart, TrendingUp, TrendingDown, Calendar, Zap } from "lucide-react";
import { mockTaskTrendData, mockTotalTasks, mockTotalCompleted, mockTotalFailed, mockSuccessRate } from "./mockData";

export function TaskTrendChart(): JSX.Element {
  const totalScanning = mockTaskTrendData.reduce((sum, day) => sum + day.scanning, 0);
  
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <LineChart className="h-4 w-4 text-cyan-500" />
          <h3 className="text-sm font-semibold text-white">任务状态趋势图</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Zap className="h-3 w-3 text-amber-500" />
          <span className="text-amber-400 font-medium">答辩模式</span>
          <Calendar className="h-3 w-3 text-slate-500" />
          <span className="text-slate-400">最近7天</span>
        </div>
      </div>
      
      <div className="space-y-3">
        {mockTaskTrendData.map((dayData, index) => (
          <div key={index} className="flex items-center justify-between group hover:bg-slate-800/20 p-2 rounded-lg transition-colors">
            <span className="text-xs text-slate-400 w-12">{dayData.day}</span>
            <div className="flex-1 flex items-center gap-1">
              {/* 完成的任务 - 大量绿色圆点 */}
              {Array.from({ length: Math.min(Math.floor(dayData.completed / 5), 15) }).map((_, i) => (
                <div key={`completed-${i}`} className="h-2 w-2 rounded-full bg-emerald-500/80 group-hover:bg-emerald-500 transition-colors"></div>
              ))}
              {dayData.completed > 75 && (
                <span className="text-xs text-emerald-400 font-medium">+{dayData.completed - 75}</span>
              )}
              {/* 失败的任务 - 少量红色圆点 */}
              {Array.from({ length: Math.min(dayData.failed, 3) }).map((_, i) => (
                <div key={`failed-${i}`} className="h-2 w-2 rounded-full bg-rose-500/80 group-hover:bg-rose-500 transition-colors"></div>
              ))}
              {/* 扫描中的任务 - 闪烁的黄色圆点 */}
              {Array.from({ length: Math.min(dayData.scanning, 5) }).map((_, i) => (
                <div key={`scanning-${i}`} className="h-2 w-2 rounded-full bg-amber-500/80 animate-pulse group-hover:bg-amber-500 transition-colors"></div>
              ))}
            </div>
            <div className="text-right">
              <span className="text-xs font-semibold text-white">{dayData.total}</span>
              <div className="text-xs text-slate-500">任务</div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="grid grid-cols-3 gap-3 mb-2">
          <div className="text-center">
            <div className="text-lg font-bold text-emerald-500">{mockTotalCompleted}</div>
            <div className="text-xs text-slate-400">完成</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-rose-500">{mockTotalFailed}</div>
            <div className="text-xs text-slate-400">失败</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-amber-500">{totalScanning}</div>
            <div className="text-xs text-slate-400">进行中</div>
          </div>
        </div>
        
        <div className="flex items-center justify-between pt-2 border-t border-slate-700/40">
          <div className="text-xs text-slate-400">
            总计 <span className="text-slate-300 font-medium">{mockTotalTasks}</span> 任务
          </div>
          <div className="flex items-center gap-2">
            <div className="text-xs text-slate-400">成功率</div>
            <div className={`text-sm font-bold ${mockSuccessRate >= 95 ? 'text-emerald-500' : 'text-amber-500'}`}>
              {mockSuccessRate}%
            </div>
            {mockSuccessRate >= 95 ? (
              <TrendingUp className="h-3 w-3 text-emerald-500" />
            ) : (
              <TrendingDown className="h-3 w-3 text-amber-500" />
            )}
          </div>
        </div>
      </div>
      
      <div className="text-xs text-slate-500 text-center">
        📈 数据每5分钟自动更新 • 峰值并发 48 任务 • 平均扫描时间 2分34秒
      </div>
    </div>
  );
}
