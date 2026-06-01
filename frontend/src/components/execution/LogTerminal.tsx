import { useEffect, useRef, useState } from "react";
import { Terminal, Maximize2, Minimize2, X, Square } from "lucide-react";

import type { LogEntry } from "../../types/domain";

// 打字机效果组件
function TypewriterText({ text, delay = 0 }: { text: string; delay?: number }) {
  const [displayText, setDisplayText] = useState("");
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    if (currentIndex < text.length) {
      const timeout = setTimeout(() => {
        setDisplayText(prev => prev + text[currentIndex]);
        setCurrentIndex(prev => prev + 1);
      }, 10 + delay);
      return () => clearTimeout(timeout);
    }
  }, [currentIndex, text, delay]);

  return <span>{displayText}</span>;
}

// 高亮关键特征提取的日志信息
function highlightKeyFeatures(message: string): JSX.Element {
  const keyPhrases = [
    "LibHunter",
    "PHunter",
    "跨内联匹配",
    "切片分析",
    "语义重组",
    "特征提取",
    "内联函数",
    "控制流图",
    "数据流分析",
    "符号执行",
    "漏洞验证",
    "补丁适配"
  ];
  
  let highlightedMessage = message;
  keyPhrases.forEach(phrase => {
    const regex = new RegExp(`(${phrase})`, 'gi');
    highlightedMessage = highlightedMessage.replace(regex, '█$1█');
  });
  
  const parts = highlightedMessage.split('█');
  return (
    <>
      {parts.map((part, index) => {
        const isHighlight = keyPhrases.some(phrase => 
          phrase.toLowerCase() === part.toLowerCase()
        );
        return isHighlight ? (
          <span key={index} className="text-yellow-400 font-bold bg-yellow-400/10 px-1 rounded">
            {part}
          </span>
        ) : (
          <span key={index}>{part}</span>
        );
      })}
    </>
  );
}

function colorBySource(source: LogEntry["source"]): string {
  if (source === "stderr") return "text-rose-400";
  if (source === "meta") return "text-cyan-300";
  if (source === "socket") return "text-soc-cyber-green";
  if (source === "system") return "text-amber-400";
  return "text-soc-cyber-green"; // 赛博绿
}

function getSourcePrefix(source: LogEntry["source"]): string {
  const prefixes: Record<string, string> = {
    stdout: "OUT",
    stderr: "ERR",
    meta: "META",
    socket: "SOCK",
    system: "SYS",
  };
  return prefixes[source] || "LOG";
}

export function LogTerminal({ logs }: { logs: LogEntry[] }): JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showTypewriter, setShowTypewriter] = useState(true);

  useEffect(() => {
    if (ref.current) {
      ref.current.scrollTop = ref.current.scrollHeight;
    }
  }, [logs]);

  // 模拟关键节点日志
  const criticalLogs = logs.filter(log => 
    log.message.includes("LibHunter") || 
    log.message.includes("PHunter") ||
    log.message.includes("跨内联") ||
    log.message.includes("切片分析")
  );

  return (
    <div className={`relative ${isFullscreen ? 'fixed inset-0 z-50 h-screen' : 'h-[520px]'} overflow-hidden rounded-xl border border-slate-800 bg-black/90 backdrop-blur-sm`}>
      {/* MacOS风格控制按钮 */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/90 px-4 py-2.5">
        <div className="flex items-center gap-3">
          <div className="flex gap-2">
            <button className="h-3 w-3 rounded-full bg-rose-500 hover:bg-rose-400 transition-colors flex items-center justify-center">
              <X className="h-2 w-2 text-black opacity-0 hover:opacity-100" />
            </button>
            <button className="h-3 w-3 rounded-full bg-amber-500 hover:bg-amber-400 transition-colors flex items-center justify-center">
              <Square className="h-2 w-2 text-black opacity-0 hover:opacity-100" />
            </button>
            <button 
              className="h-3 w-3 rounded-full bg-emerald-500 hover:bg-emerald-400 transition-colors flex items-center justify-center"
              onClick={() => setIsFullscreen(!isFullscreen)}
            >
              {isFullscreen ? (
                <Minimize2 className="h-2 w-2 text-black opacity-0 hover:opacity-100" />
              ) : (
                <Maximize2 className="h-2 w-2 text-black opacity-0 hover:opacity-100" />
              )}
            </button>
          </div>
          
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-slate-400" />
            <span className="font-mono text-xs font-medium text-slate-300">terminal — zsh</span>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
            <span className="font-mono text-xs text-slate-400">实时流式渲染</span>
          </div>
          <button 
            className="font-mono text-xs text-slate-400 hover:text-slate-300 transition-colors"
            onClick={() => setShowTypewriter(!showTypewriter)}
          >
            {showTypewriter ? "打字机: ON" : "打字机: OFF"}
          </button>
        </div>
      </div>
      
      {/* 终端内容 */}
      <div
        ref={ref}
        className={`font-mono ${isFullscreen ? 'h-[calc(100vh-48px)]' : 'h-[calc(520px-48px)]'} overflow-y-auto bg-black p-4 text-sm leading-relaxed`}
        style={{ 
          fontFamily: '"IBM Plex Mono", "JetBrains Mono", Consolas, monospace',
          fontSize: '0.875rem',
          lineHeight: '1.5'
        }}
      >
        {logs.length === 0 ? (
          <div className="flex h-full items-center justify-center">
            <div className="text-center">
              <div className="mb-4 text-5xl">🖥️</div>
              <p className="text-slate-400 text-sm mb-1">等待引擎启动...</p>
              <p className="text-slate-500 text-xs">连接 LibHunter & PHunter 分析引擎</p>
              <div className="mt-4 inline-flex items-center gap-2 rounded-lg bg-slate-900/50 px-3 py-1.5">
                <div className="h-1.5 w-1.5 rounded-full bg-soc-cyber-green animate-pulse"></div>
                <span className="text-xs text-slate-400">WebSocket 准备就绪</span>
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* 关键节点高亮区域 */}
            {criticalLogs.length > 0 && (
              <div className="mb-4 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3">
                <div className="flex items-center gap-2 mb-2">
                  <div className="h-2 w-2 rounded-full bg-yellow-500 animate-pulse"></div>
                  <span className="text-xs font-bold text-yellow-400">关键分析节点</span>
                  <span className="text-xs text-slate-400">({criticalLogs.length}个关键操作)</span>
                </div>
                {criticalLogs.slice(-3).map((log) => (
                  <div key={`critical-${log.id}`} className="mb-1 text-xs text-yellow-300">
                    ⚡ {highlightKeyFeatures(log.message)}
                  </div>
                ))}
              </div>
            )}
            
            {/* 日志流 */}
            {logs.map((entry, index) => (
              <div 
                key={entry.id} 
                className={`mb-1.5 break-words whitespace-pre-wrap rounded px-2 py-1.5 hover:bg-slate-900/50 transition-colors ${colorBySource(entry.source)} animate-terminal-fade`}
                style={{ animationDelay: `${index * 0.05}s` }}
              >
                <div className="flex items-start gap-2">
                  <span className="text-slate-500 shrink-0 text-xs font-bold mt-0.5">
                    [{getSourcePrefix(entry.source)}]
                  </span>
                  <span className="text-slate-600 text-xs font-mono mt-0.5">
                    {new Date(entry.timestamp).toLocaleTimeString('zh-CN', {
                      hour12: false,
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit'
                    })}
                  </span>
                  <span className="flex-1">
                    {showTypewriter && index === logs.length - 1 ? (
                      <TypewriterText text={entry.message} delay={index * 10} />
                    ) : (
                      highlightKeyFeatures(entry.message)
                    )}
                  </span>
                </div>
              </div>
            ))}
            
            {/* 终端提示符 */}
            <div className="mt-4 flex items-center gap-2">
              <span className="text-soc-cyber-green font-bold">➜</span>
              <span className="text-cyan-400 font-medium">~/demo-main/engine</span>
              <span className="text-slate-500">$</span>
              <span className="text-soc-cyber-green animate-pulse">█</span>
              <span className="text-slate-400 text-xs ml-2">
                {isFullscreen ? "全屏模式 • 按 ESC 退出" : "tail -f engine.log"}
              </span>
            </div>
            
            {/* 引擎状态指示器 */}
            <div className="mt-6 grid grid-cols-3 gap-3 text-xs">
              <div className="rounded border border-slate-800 bg-slate-900/50 p-2">
                <div className="flex items-center gap-2 mb-1">
                  <div className="h-1.5 w-1.5 rounded-full bg-soc-cyber-green animate-pulse"></div>
                  <span className="text-slate-300">LibHunter</span>
                </div>
                <div className="text-slate-400">跨内联匹配中</div>
              </div>
              <div className="rounded border border-slate-800 bg-slate-900/50 p-2">
                <div className="flex items-center gap-2 mb-1">
                  <div className="h-1.5 w-1.5 rounded-full bg-cyan-500 animate-pulse"></div>
                  <span className="text-slate-300">PHunter</span>
                </div>
                <div className="text-slate-400">切片分析运行</div>
              </div>
              <div className="rounded border border-slate-800 bg-slate-900/50 p-2">
                <div className="flex items-center gap-2 mb-1">
                  <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
                  <span className="text-slate-300">语义引擎</span>
                </div>
                <div className="text-slate-400">重组进行中</div>
              </div>
            </div>
          </>
        )}
      </div>
      
      {/* 状态栏 */}
      <div className="absolute bottom-0 left-0 right-0 border-t border-slate-800 bg-slate-950/90 px-4 py-1.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="font-mono text-xs text-slate-400">
              日志: <span className="text-slate-300">{logs.length}</span>
            </span>
            <span className="font-mono text-xs text-slate-400">
              关键节点: <span className="text-yellow-400">{criticalLogs.length}</span>
            </span>
            <span className="font-mono text-xs text-slate-400">
              最后更新: <span className="text-slate-300">
                {logs.length > 0 ? new Date(logs[logs.length - 1].timestamp).toLocaleTimeString() : '--:--:--'}
              </span>
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs text-slate-400">UTF-8</span>
            <span className="font-mono text-xs text-slate-400">•</span>
            <span className="font-mono text-xs text-slate-400">100%</span>
            <span className="font-mono text-xs text-slate-400">•</span>
            <span className="font-mono text-xs text-slate-400">zsh</span>
          </div>
        </div>
      </div>
    </div>
  );
}