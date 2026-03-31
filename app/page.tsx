"use client";

import { useState, useCallback } from "react";
import { Header } from "@/components/Header";
import { ScanInput } from "@/components/ScanInput";
import { ScanProgress } from "@/components/ScanProgress";
import { ScoreCards } from "@/components/ScoreCards";
import { ThreatSummary } from "@/components/ThreatSummary";
import { ScanOverview } from "@/components/ScanOverview";
import { ThreatList } from "@/components/ThreatList";
import { ComplianceTable } from "@/components/ComplianceTable";
import { CrawlStats } from "@/components/CrawlStats";
import { AdaptiveInsights } from "@/components/AdaptiveInsights";
import { ExportBar } from "@/components/ExportBar";
import { ScanHistory } from "@/components/ScanHistory";
import type { ScanResult, ScanHistoryEntry } from "@/lib/types";

export default function Home() {
  const [scanning, setScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [activeTab, setActiveTab] = useState<"threats" | "compliance" | "overview">("threats");

  const handleScan = useCallback(async (url: string, maxPages: number, maxDepth: number) => {
    setScanning(true);
    setResult(null);
    setError(null);
    setScanProgress(0);

    const phases = [
      { msg: "Validating URL...", pct: 5 },
      { msg: "Deep crawling website pages...", pct: 15 },
      { msg: "Analyzing HTTP connectivity...", pct: 25 },
      { msg: "Checking SSL/TLS configuration...", pct: 35 },
      { msg: "Scanning DNS records...", pct: 45 },
      { msg: "Analyzing security headers...", pct: 55 },
      { msg: "Scanning page content...", pct: 65 },
      { msg: "Running threat analysis...", pct: 75 },
      { msg: "Checking regulatory compliance...", pct: 85 },
      { msg: "Running adaptive learning algorithm...", pct: 90 },
      { msg: "Generating report...", pct: 95 },
    ];

    let phaseIdx = 0;
    const phaseInterval = setInterval(() => {
      if (phaseIdx < phases.length) {
        setScanPhase(phases[phaseIdx].msg);
        setScanProgress(phases[phaseIdx].pct);
        phaseIdx++;
      }
    }, 2500);

    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, max_pages: maxPages, max_depth: maxDepth }),
      });

      clearInterval(phaseInterval);

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ detail: `Server error: ${resp.status}` }));
        throw new Error(errData.detail || `Scan failed (${resp.status})`);
      }

      const data = await resp.json();
      if (!data.success) {
        throw new Error(data.error || "Scan failed");
      }

      setScanProgress(100);
      setScanPhase("Scan complete!");

      const scanResult: ScanResult = data.data;
      setResult(scanResult);

      // Add to history
      const entry: ScanHistoryEntry = {
        url,
        timestamp: new Date().toISOString(),
        securityScore: scanResult.security_score?.score ?? 0,
        complianceScore: scanResult.compliance_score?.score ?? 0,
        threatCount: scanResult.threats?.length ?? 0,
      };
      setHistory((prev) => [entry, ...prev].slice(0, 10));
    } catch (err: any) {
      clearInterval(phaseInterval);
      setError(err.message || "An unknown error occurred");
    } finally {
      setScanning(false);
    }
  }, []);

  const handleHistoryClick = (entry: ScanHistoryEntry) => {
    // Re-scan the URL from history
    handleScan(entry.url, 50, 3);
  };

  return (
    <div className="min-h-screen bg-mesh">
      <Header />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Scan Input */}
        <ScanInput onScan={handleScan} disabled={scanning} />

        {/* Scan History */}
        {history.length > 0 && !scanning && !result && (
          <ScanHistory entries={history} onSelect={handleHistoryClick} />
        )}

        {/* Progress */}
        {scanning && (
          <ScanProgress phase={scanPhase} progress={scanProgress} />
        )}

        {/* Error */}
        {error && (
          <div className="glass rounded-xl p-6 border-red-500/30 border animate-fade-in">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <div>
                <p className="text-red-400 font-semibold">Scan Failed</p>
                <p className="text-red-300/80 text-sm">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {result && !scanning && (
          <div className="space-y-6 animate-fade-in">
            {/* Score Cards */}
            <ScoreCards
              securityScore={result.security_score}
              complianceScore={result.compliance_score}
            />

            {/* Adaptive Learning Insights */}
            {result.adaptive_insights && (
              <AdaptiveInsights insights={result.adaptive_insights} />
            )}

            {/* Threat Summary Bar */}
            <ThreatSummary threats={result.threats || []} />

            {/* Crawl Stats */}
            {result.crawl_stats && (
              <CrawlStats stats={result.crawl_stats} />
            )}

            {/* Tab Navigation */}
            <div className="flex gap-1 bg-cyber-950 rounded-lg p-1 border border-[#1e3a5f]">
              {(["threats", "compliance", "overview"] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`flex-1 py-2.5 px-4 rounded-md text-sm font-medium transition-all duration-200 ${
                    activeTab === tab
                      ? "bg-cyber-500/20 text-cyber-500 shadow-sm"
                      : "text-gray-400 hover:text-gray-200 hover:bg-white/5"
                  }`}
                >
                  {tab === "threats"
                    ? `Threats (${result.threats?.length || 0})`
                    : tab === "compliance"
                    ? "Compliance"
                    : "Scan Overview"}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="animate-fade-in">
              {activeTab === "threats" && (
                <ThreatList threats={result.threats || []} />
              )}
              {activeTab === "compliance" && (
                <ComplianceTable
                  issues={result.compliance?.issues || []}
                  breakdown={result.compliance_score?.breakdown || {}}
                />
              )}
              {activeTab === "overview" && (
                <ScanOverview scanResults={result.scan_results} />
              )}
            </div>

            {/* Export */}
            <ExportBar data={result} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1e3a5f] mt-16 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p className="text-xs text-gray-500">
            FinTech Threat Detection Agent v2.0 &mdash; AI-powered cybersecurity assessment.
            This is an automated external scan and does not replace a comprehensive penetration test.
          </p>
        </div>
      </footer>
    </div>
  );
}
