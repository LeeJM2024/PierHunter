export const mockTaskTrendData = [
  { day: "05-29", completed: 68, failed: 2, scanning: 4, queued: 3, total: 77 },
  { day: "05-30", completed: 82, failed: 3, scanning: 6, queued: 2, total: 93 },
  { day: "05-31", completed: 74, failed: 1, scanning: 7, queued: 4, total: 86 },
  { day: "06-01", completed: 96, failed: 5, scanning: 8, queued: 3, total: 106 },
  { day: "06-02", completed: 88, failed: 2, scanning: 5, queued: 2, total: 97 },
  { day: "06-03", completed: 104, failed: 4, scanning: 9, queued: 5, total: 122 },
  { day: "06-04", completed: 91, failed: 3, scanning: 11, queued: 6, total: 111 },
];

export const mockTotalCompleted = mockTaskTrendData.reduce((sum, day) => sum + day.completed, 0);
export const mockTotalFailed = mockTaskTrendData.reduce((sum, day) => sum + day.failed, 0);
export const mockSuccessRate = Math.round(
  (mockTotalCompleted / Math.max(mockTotalCompleted + mockTotalFailed, 1)) * 100,
);

export const mockTopCves = [
  {
    id: "CVE-2021-44228",
    name: "Log4Shell 远程代码执行",
    severity: "critical" as const,
    affectedLibraries: 42,
    trend: "up" as const,
    description: "Apache Log4j2 远程代码执行漏洞，影响范围极广。",
    cwe: "CWE-502",
    cvssScore: 10.0,
    publishedDate: "2021-12-09",
  },
  {
    id: "CVE-2022-42889",
    name: "Text4Shell 代码注入",
    severity: "critical" as const,
    affectedLibraries: 28,
    trend: "up" as const,
    description: "Apache Commons Text 字符串插值导致的代码执行风险。",
    cwe: "CWE-94",
    cvssScore: 9.8,
    publishedDate: "2022-10-13",
  },
  {
    id: "CVE-2017-18349",
    name: "Fastjson 反序列化",
    severity: "critical" as const,
    affectedLibraries: 35,
    trend: "stable" as const,
    description: "Fastjson autoType 相关反序列化漏洞。",
    cwe: "CWE-502",
    cvssScore: 9.8,
    publishedDate: "2017-10-27",
  },
  {
    id: "CVE-2021-45046",
    name: "Log4j2 拒绝服务",
    severity: "high" as const,
    affectedLibraries: 19,
    trend: "down" as const,
    description: "Log4j2 特定配置下仍可能触发拒绝服务。",
    cwe: "CWE-400",
    cvssScore: 9.0,
    publishedDate: "2021-12-14",
  },
  {
    id: "CVE-2020-13935",
    name: "Apache Tomcat WebSocket 风险",
    severity: "high" as const,
    affectedLibraries: 24,
    trend: "stable" as const,
    description: "Tomcat WebSocket 处理链中的拒绝服务风险。",
    cwe: "CWE-400",
    cvssScore: 7.5,
    publishedDate: "2020-07-14",
  },
];

export const mockLibrarySourceData = [
  {
    name: "Maven Central",
    count: 245,
    percentage: 49,
    color: "bg-blue-500",
    description: "官方仓库，组件来源较稳定。",
  },
  {
    name: "JCenter",
    count: 98,
    percentage: 20,
    color: "bg-violet-500",
    description: "历史遗留组件较多。",
  },
  {
    name: "GitHub Releases",
    count: 85,
    percentage: 17,
    color: "bg-emerald-500",
    description: "社区维护，版本变化频繁。",
  },
  {
    name: "私有仓库",
    count: 52,
    percentage: 10,
    color: "bg-amber-500",
    description: "企业定制组件，需要结合证据确认。",
  },
  {
    name: "未知来源",
    count: 25,
    percentage: 4,
    color: "bg-slate-500",
    description: "无法从现有证据推断来源。",
  },
];

export const mockTotalLibraries = mockLibrarySourceData.reduce((sum, source) => sum + source.count, 0);

export const mockComponentRiskData = [
  { name: "Apache Commons", riskLevel: "high" as const, count: 42 },
  { name: "Google Guava", riskLevel: "medium" as const, count: 38 },
  { name: "Spring Framework", riskLevel: "high" as const, count: 56 },
  { name: "Log4j", riskLevel: "critical" as const, count: 28 },
  { name: "Fastjson", riskLevel: "critical" as const, count: 24 },
  { name: "Jackson", riskLevel: "medium" as const, count: 32 },
  { name: "OkHttp", riskLevel: "low" as const, count: 19 },
  { name: "Retrofit", riskLevel: "low" as const, count: 15 },
];

export const mockVulnerabilityStats = {
  total: 1287,
  critical: 42,
  high: 156,
  medium: 489,
  low: 600,
};

export const mockTaskStats = {
  totalTasks: 1248,
  completedTasks: 1185,
  failedTasks: 63,
  avgScanSeconds: 124,
  dailyAvg: 178,
};
