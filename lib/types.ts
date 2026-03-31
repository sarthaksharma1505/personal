export interface Threat {
  category: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  recommendation: string;
  references: string[];
}

export interface ComplianceIssue {
  regulation: string;
  section: string;
  requirement: string;
  status: "PASS" | "FAIL" | "WARNING" | "NOT_CHECKED";
  details: string;
}

export interface ScoreData {
  score: number;
  rating: string;
  breakdown?: Record<string, number>;
}

export interface CrawlStatsData {
  pages_fetched: number;
  pages_with_content: number;
  urls_discovered: number;
  errors: number;
  pages_list?: Array<{ url: string; title: string; status: number }>;
}

export interface AdaptiveInsight {
  type: "trend" | "anomaly" | "recommendation" | "learning";
  title: string;
  description: string;
  confidence: number;
  impact: "high" | "medium" | "low";
}

export interface ScanResult {
  report_metadata?: {
    tool: string;
    version: string;
    target_url: string;
    scan_date: string;
    scan_mode: string;
  };
  security_score: ScoreData;
  compliance_score: ScoreData;
  crawl_stats?: CrawlStatsData;
  scan_results: {
    url: string;
    hostname: string;
    http: Record<string, any>;
    ssl: Record<string, any>;
    dns: Record<string, any>;
    headers: Record<string, any>;
  };
  threats: Threat[];
  compliance: {
    issues: ComplianceIssue[];
    summary: Record<string, any>;
  };
  adaptive_insights?: AdaptiveInsight[];
}

export interface ScanHistoryEntry {
  url: string;
  timestamp: string;
  securityScore: number;
  complianceScore: number;
  threatCount: number;
}
