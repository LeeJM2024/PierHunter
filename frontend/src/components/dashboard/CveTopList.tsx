import { AlertTriangle, Flame, Shield, TrendingUp, Database, Zap, Skull, ExternalLink } from "lucide-react";
import { mockTopCves, mockVulnerabilityStats } from "./mockData";
import type { SeverityLevel } from "../../types/domain";

interface CveItem {
  id: string;
  name: string;
  severity: SeverityLevel;
  affectedLibraries: number;
  trend: 'up' | 'down' | 'stable';
  description: string;
  cwe: string;
  cvssScore: number;
  publishedDate: string;
}

export function CveTopList(): JSX.Element {
  const topCves: CveItem[] = mockTopCves;
  
  const getSeverityColor = (severity: SeverityLevel) => {
    switch (severity) {
      case 'critical': return 'text-rose-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-amber-500';
      case 'low': return 'text-emerald-500';
      case 'info': return 'text-slate-400';
      default: return 'text-slate-400';
    }
  };
  
  const getSeverityBg = (severity: SeverityLevel) => {
    switch (severity) {
      case 'critical': return 'bg-rose-500/10';
      case 'high': return 'bg-orange-500/10';
      case 'medium': return 'bg-amber-500/10';
      case 'low': return 'bg-emerald-500/10';
      case 'info': return 'bg-slate-500/10';
      default: return 'bg-slate-500/10';
    }
  };
  
  const getSeverityLabel = (severity: SeverityLevel) => {
    switch (severity) {
      case 'critical': return '严重';
      case 'high': return '高危';
      case 'medium': return '中危';
      case 'low': return '低危';
      case 'info': return '信息';
      default: return '未知';
    }
  };
  
  const getTrendIcon = (trend: 'up' | 'down' | 'stable') => {
    switch (trend) {
      case 'up': return <TrendingUp className="h-3 w-3 text-rose-500" />;
      case 'down': return <TrendingUp className="h-3 w-3 text-emerald-500 rotate-180" />;
      case 'stable': return <div className="h-3 w-3 text-slate-500">•</div>;
      default: return null;
    }
  };
  
  const getCvssColor = (score: number) => {
    if (score >= 9.0) return 'text-rose-500';
    if (score >= 7.0) return 'text-orange-500';
    if (score >= 4.0) return 'text-amber-500';
    return 'text-emerald-500';
  };
  
  const getCvssBg = (score: number) => {
    if (score >= 9.0) return 'bg-rose-500/20';
    if (score >= 7.0) return 'bg-orange-500/20';
    if (score >= 4.0) return 'bg-amber-500/20';
    return 'bg-emerald-500/20';
  };
  
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Flame className="h-4 w-4 text-rose-500" />
          <h3 className="text-sm font-semibold text-white">高风险 CVE TOP 榜</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Zap className="h-3 w-3 text-amber-500" />
          <span className="text-amber-400 font-medium">答辩模式</span>
          <Skull className="h-3 w-3 text-rose-500" />
          <span className="text-slate-300 font-medium">{mockVulnerabilityStats.total}</span>
          <span className="text-slate-400">漏洞</span>
        </div>
      </div>
      
      <div className="space-y-3">
        {topCves.map((cve, index) => (
          <div 
            key={cve.id} 
            className={`rounded-lg border ${getSeverityBg(cve.severity)} border-slate-700/40 p-3 hover:bg-slate-800/30 transition-all hover:scale-[1.01] hover:shadow-lg`}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-bold ${getSeverityColor(cve.severity)}`}>
                    {getSeverityLabel(cve.severity)}
                  </span>
                  <span className="text-xs font-mono text-slate-300 bg-slate-900/50 px-1.5 py-0.5 rounded">
                    {cve.id}
                  </span>
                  <div className="flex items-center gap-1">
                    {getTrendIcon(cve.trend)}
                  </div>
                  <div className="ml-auto flex items-center gap-1">
                    <span className="text-xs text-slate-400">CVSS</span>
                    <span className={`text-xs font-bold ${getCvssColor(cve.cvssScore)} bg-slate-900/50 px-1.5 py-0.5 rounded`}>
                      {cve.cvssScore.toFixed(1)}
                    </span>
                  </div>
                </div>
                <h4 className="text-sm font-bold text-white mb-1">{cve.name}</h4>
                <p className="text-xs text-slate-400 mb-2">{cve.description}</p>
                
                <div className="flex flex-wrap items-center gap-3">
                  <div className="flex items-center gap-1">
                    <Shield className="h-3 w-3 text-slate-500" />
                    <span className="text-xs text-slate-400">
                      影响组件: <span className="text-slate-300 font-medium">{cve.affectedLibraries}</span>
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-slate-400">CWE:</span>
                    <span className="text-xs text-slate-300 font-mono">{cve.cwe.split(':')[0]}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-slate-400">发布于:</span>
                    <span className="text-xs text-slate-300">{cve.publishedDate}</span>
                  </div>
                </div>
                
                {cve.severity === 'critical' && (
                  <div className="mt-2 flex items-center gap-2 p-2 rounded bg-rose-500/10 border border-rose-500/20">
                    <AlertTriangle className="h-3 w-3 text-rose-500 animate-pulse" />
                    <span className="text-xs text-rose-400 font-bold">⚠️ 需立即修复！影响范围极广</span>
                  </div>
                )}
              </div>
              <div className="flex items-center ml-3">
                <div className={`h-10 w-10 rounded-full flex items-center justify-center ${getSeverityBg(cve.severity)} border-2 ${cve.severity === 'critical' ? 'border-rose-500/50' : 'border-slate-700/50'}`}>
                  <span className={`text-lg font-black ${getSeverityColor(cve.severity)}`}>
                    {index + 1}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
        <div className="grid grid-cols-4 gap-2 mb-2">
          <div className="text-center">
            <div className="text-lg font-bold text-rose-500">{mockVulnerabilityStats.critical}</div>
            <div className="text-xs text-slate-400">严重</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-orange-500">{mockVulnerabilityStats.high}</div>
            <div className="text-xs text-slate-400">高危</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-amber-500">{mockVulnerabilityStats.medium}</div>
            <div className="text-xs text-slate-400">中危</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-emerald-500">{mockVulnerabilityStats.low}</div>
            <div className="text-xs text-slate-400">低危</div>
          </div>
        </div>
        
        <div className="flex items-center justify-between pt-2 border-t border-slate-700/40">
          <div className="text-xs text-slate-400">
            基于 <span className="text-slate-300 font-medium">1,248</span> 个任务分析
          </div>
          <div className="flex items-center gap-1 text-xs text-slate-400">
            <ExternalLink className="h-3 w-3" />
            <span>实时威胁情报</span>
          </div>
        </div>
      </div>
      
      <div className="text-xs text-slate-500 text-center">
        🔥 包含 Log4Shell、Text4Shell 等知名高危漏洞 • CVSS 评分 9.0+ • 影响组件 500+
      </div>
    </div>
  );
}