// 答辩模式专用 Mock 数据
// 设计目标：数据量庞大、业务繁忙、极具视觉冲击力

// ========== 任务趋势图 Mock 数据 ==========
export const mockTaskTrendData = Array.from({ length: 7 }, (_, i) => {
  const date = new Date();
  date.setDate(date.getDate() - (6 - i));
  const dayStr = date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' });
  
  // 生成波动起伏的任务数据：每天几十到上百个任务
  const baseTasks = 60 + Math.floor(Math.random() * 40); // 60-100个基础任务
  const completed = baseTasks + Math.floor(Math.random() * 20); // 完成的任务数
  const failed = Math.floor(Math.random() * 5); // 少量失败
  const scanning = Math.floor(Math.random() * 15); // 扫描中的任务
  
  return {
    day: dayStr,
    completed,
    failed,
    scanning,
    total: completed + failed + scanning
  };
});

// 计算总计和成功率
export const mockTotalTasks = mockTaskTrendData.reduce((sum, day) => sum + day.total, 0);
export const mockTotalCompleted = mockTaskTrendData.reduce((sum, day) => sum + day.completed, 0);
export const mockTotalFailed = mockTaskTrendData.reduce((sum, day) => sum + day.failed, 0);
export const mockSuccessRate = Math.round((mockTotalCompleted / (mockTotalCompleted + mockTotalFailed)) * 100);

// ========== 高风险 CVE TOP 榜 Mock 数据 ==========
export const mockTopCves = [
  {
    id: "CVE-2021-44228",
    name: "Log4Shell 远程代码执行",
    severity: "critical" as const,
    affectedLibraries: 42,
    trend: "up" as const,
    description: "Apache Log4j2 远程代码执行漏洞，影响范围极广",
    cwe: "CWE-502: 反序列化不受信任的数据",
    cvssScore: 10.0,
    publishedDate: "2021-12-09"
  },
  {
    id: "CVE-2022-42889",
    name: "Text4Shell 代码注入",
    severity: "critical" as const,
    affectedLibraries: 28,
    trend: "up" as const,
    description: "Apache Commons Text 远程代码执行漏洞",
    cwe: "CWE-94: 代码注入",
    cvssScore: 9.8,
    publishedDate: "2022-10-13"
  },
  {
    id: "CVE-2017-18349",
    name: "Fastjson 反序列化",
    severity: "critical" as const,
    affectedLibraries: 35,
    trend: "stable" as const,
    description: "Fastjson 反序列化远程代码执行漏洞",
    cwe: "CWE-502: 反序列化不受信任的数据",
    cvssScore: 9.8,
    publishedDate: "2017-10-27"
  },
  {
    id: "CVE-2021-45046",
    name: "Log4j2 拒绝服务",
    severity: "high" as const,
    affectedLibraries: 19,
    trend: "down" as const,
    description: "Apache Log4j2 拒绝服务攻击漏洞",
    cwe: "CWE-400: 不受控制的资源消耗",
    cvssScore: 9.0,
    publishedDate: "2021-12-14"
  },
  {
    id: "CVE-2020-13935",
    name: "Apache Tomcat RCE",
    severity: "high" as const,
    affectedLibraries: 24,
    trend: "stable" as const,
    description: "Apache Tomcat 远程代码执行漏洞",
    cwe: "CWE-78: OS命令注入",
    cvssScore: 9.8,
    publishedDate: "2020-06-25"
  }
];

// ========== 组件来源占比图 Mock 数据 ==========
export const mockLibrarySourceData = [
  {
    name: "Maven Central",
    count: 245,
    percentage: 49,
    color: "bg-blue-500",
    icon: "🌐",
    description: "官方仓库，安全性较高"
  },
  {
    name: "JCenter",
    count: 98,
    percentage: 20,
    color: "bg-purple-500",
    icon: "📦",
    description: "历史遗留组件较多"
  },
  {
    name: "GitHub Releases",
    count: 85,
    percentage: 17,
    color: "bg-emerald-500",
    icon: "⬇️",
    description: "社区维护，更新频繁"
  },
  {
    name: "私有仓库",
    count: 52,
    percentage: 10,
    color: "bg-amber-500",
    icon: "🔒",
    description: "企业定制，风险可控"
  },
  {
    name: "其他来源",
    count: 25,
    percentage: 4,
    color: "bg-slate-500",
    icon: "❓",
    description: "未知或第三方源"
  }
];

export const mockTotalLibraries = mockLibrarySourceData.reduce((sum, source) => sum + source.count, 0);

// ========== 漏洞统计 Mock 数据 ==========
export const mockVulnerabilityStats = {
  total: 1287,
  critical: 42,
  high: 156,
  medium: 489,
  low: 600,
  byMonth: [
    { month: "1月", count: 98 },
    { month: "2月", count: 112 },
    { month: "3月", count: 145 },
    { month: "4月", count: 167 },
    { month: "5月", count: 189 },
    { month: "6月", count: 156 },
    { month: "7月", count: 134 },
    { month: "8月", count: 178 },
    { month: "9月", count: 195 },
    { month: "10月", count: 203 },
    { month: "11月", count: 187 },
    { month: "12月", count: 162 }
  ]
};

// ========== 任务统计 Mock 数据 ==========
export const mockTaskStats = {
  totalTasks: 1248,
  completedTasks: 1185,
  failedTasks: 63,
  avgScanTime: "2分34秒",
  peakConcurrency: 48,
  dailyAvg: 178
};

// ========== 组件风险分布 Mock 数据 ==========
export const mockComponentRiskData = [
  { name: "Apache Commons", riskLevel: "high", count: 42 },
  { name: "Google Guava", riskLevel: "medium", count: 38 },
  { name: "Spring Framework", riskLevel: "high", count: 56 },
  { name: "Log4j", riskLevel: "critical", count: 28 },
  { name: "Fastjson", riskLevel: "critical", count: 24 },
  { name: "Jackson", riskLevel: "medium", count: 32 },
  { name: "OkHttp", riskLevel: "low", count: 19 },
  { name: "Retrofit", riskLevel: "low", count: 15 }
];

// ========== 实时监控 Mock 数据 ==========
export const mockRealtimeStats = {
  activeScans: 12,
  queueLength: 8,
  avgResponseTime: "1.2秒",
  systemLoad: 78,
  memoryUsage: "4.2GB / 8GB",
  storageUsage: "1.8TB / 2TB"
};