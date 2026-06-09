export type PatchStatusRaw =
  | "PRESENT"
  | "NOT_PRESENT"
  | "PATCH_PRESENT"
  | "PATCH_NOT_PRESENT"
  | "DEAD_CODE"
  | "UNKNOWN"
  | "HUNG"
  | "ERROR"
  | "RESOURCE_LIMIT"
  | string;

export interface UploadResponseRaw {
  message: string;
  filename: string;
  path: string;
  size: number;
  apk_profile?: ApkStaticProfileRaw;
  scan_estimate?: ScanEstimateRaw;
}

export interface ApkStaticProfileRaw {
  apk_size: number;
  dex_count: number;
  dex_compressed_size: number;
  dex_uncompressed_size: number;
  method_count: number;
  class_count: number;
  dex_files: Array<{
    name: string;
    compressed_size: number;
    uncompressed_size: number;
    method_count: number;
    class_count: number;
  }>;
}

export interface ScanEstimateRaw {
  total_seconds: number;
  total_minutes: number;
  confidence: "low" | "medium" | "high" | string;
  model: string;
  estimated_components: number;
  estimated_cves: number;
  stages: {
    init_seconds: number;
    libhunter_seconds: number;
    phunter_seconds: number;
    report_seconds: number;
  };
  basis: string[];
  calibration?: {
    sample_count: number;
    multiplier: number;
    updated_at?: string | null;
  };
}

export interface AnalyzeTaskRaw {
  task_id: string;
  apk_name: string;
  apk_path: string;
  status: string;
  celery_task_id?: string | null;
  report_path?: string | null;
  stdout_log_path?: string | null;
  stderr_log_path?: string | null;
  error?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface AnalyzeResponseRaw {
  message: string;
  task: AnalyzeTaskRaw;
}

export interface ApkInfoRaw {
  name?: string;
  sha256?: string;
  size?: number;
}

export interface UsedLibraryRaw {
  raw_name?: string;
  library_name?: string;
  version?: string;
  similarity?: number;
  target_classes?: string[];
  evidence?: Record<string, unknown>;
}

export interface VulnerabilityRaw {
  cve_id?: string;
  library?: string;
  status?: PatchStatusRaw;
  pre_similarity?: number | null;
  post_similarity?: number | null;
  evidence?: Record<string, unknown>;
}

export interface ReportRaw {
  apk_info?: ApkInfoRaw;
  used_libraries?: UsedLibraryRaw[];
  vulnerabilities?: VulnerabilityRaw[];
  analysis_artifacts?: AnalysisArtifactsRaw;
}

export interface ReportResponseRaw {
  task_id?: string | null;
  report_path?: string;
  report?: ReportRaw;
}

export interface AnalysisStageRaw {
  key?: string;
  label?: string;
  status?: string;
  started_at?: string | null;
  finished_at?: string | null;
  summary?: string;
  metrics?: Record<string, unknown>;
}

export interface AnalysisEventRaw {
  time?: string;
  type?: string;
  stage?: string | null;
  message?: string;
  payload?: Record<string, unknown>;
}

export interface AnalysisArtifactsRaw {
  schema_version?: number;
  generated_at?: string;
  analysis_started_at?: string;
  analysis_finished_at?: string | null;
  execution_trace?: {
    stages?: AnalysisStageRaw[];
    events?: AnalysisEventRaw[];
  };
  engines?: Record<string, unknown>;
  evidence?: {
    libraries?: Record<string, unknown>[];
    patches?: Record<string, unknown>[];
  };
  intelligence?: Record<string, unknown>;
  summary?: Record<string, unknown>;
}

export interface DashboardSummaryRaw {
  generated_at: string;
  task_stats: {
    total_tasks: number;
    completed_tasks: number;
    failed_tasks: number;
    running_tasks: number;
    queued_tasks: number;
    daily_avg: number;
    success_rate: number;
    avg_scan_seconds: number;
  };
  vulnerability_stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    by_status: Record<string, number>;
    top_cves: Array<{ id: string; count: number; severity: string }>;
  };
  library_stats: {
    total_libraries: number;
    unique_libraries: number;
    target_class_count: number;
    top_libraries: Array<{ name: string; count: number; vulnerability_count: number }>;
  };
  engine_stats: {
    patch_evidence_count: number;
    semantic_matches: number;
    resource_limited: number;
    unknown_results: number;
  };
  trend: Array<{
    day: string;
    completed: number;
    failed: number;
    scanning: number;
    queued: number;
    total: number;
  }>;
}

export interface EcosystemCveItemRaw {
  id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  cvss_vector?: string;
  rank_score: number;
  library_name: string;
  library_names?: string[];
  affected_packages: string[];
  affected_versions: string[];
  affected_version_count: number;
  patch_artifacts: {
    pre_patch_jar: string;
    post_patch_jar: string;
    patch_diff: string;
  };
  summary: string;
  impact: string;
  android_relevance: string;
  fix_advice: string;
  references: string[];
  source_basis?: string;
  published?: string;
  last_modified?: string;
  record_count?: number;
}

export interface EcosystemTplItemRaw {
  name: string;
  display_name: string;
  ecosystem: string;
  rank_score: number;
  cve_count: number;
  record_count?: number;
  high_risk_cve_count: number;
  affected_version_count: number;
  package_names: string[];
  usage_hint: string;
  description: string;
  common_usage: string;
  security_focus: string;
  notable_cves: string[];
  source_basis: string;
}

export interface EcosystemSummaryRaw {
  generated_at: string;
  source_label: string;
  scope: string;
  methodology: string;
  knowledge_base_version?: string;
  generated_by?: string;
  total_cve_count: number;
  total_cve_record_count?: number;
  total_library_count: number;
  display_limit: number;
  cve_top: EcosystemCveItemRaw[];
  tpl_top: EcosystemTplItemRaw[];
  disclaimer: string;
  warnings?: string[];
}

export interface WsMetaMessageRaw {
  type: "meta";
  task_id: string;
  apk_name: string;
  status: string;
}

export interface WsLogMessageRaw {
  type: "log";
  task_id: string;
  file?: string;
  message?: string;
}

export interface WsDoneMessageRaw {
  type: "done";
  task_id: string;
  status: "completed" | "failed" | string;
  error?: string | null;
  report_path?: string | null;
}

export interface WsErrorMessageRaw {
  type: "error";
  message: string;
  task_id?: string;
}

export type TaskLogMessageRaw =
  | WsMetaMessageRaw
  | WsLogMessageRaw
  | WsDoneMessageRaw
  | WsErrorMessageRaw;
