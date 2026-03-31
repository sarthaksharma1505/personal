"use client";

import { useState } from "react";
import { FileSearch, Globe, AlertCircle, ChevronDown, ChevronRight } from "lucide-react";
import type { CrawlStatsData } from "@/lib/types";

interface CrawlStatsProps {
  stats: CrawlStatsData;
}

export function CrawlStats({ stats }: CrawlStatsProps) {
  const [showPages, setShowPages] = useState(false);

  const metrics = [
    { icon: FileSearch, label: "Pages Fetched", value: stats.pages_fetched, color: "#00d4ff" },
    { icon: Globe, label: "Pages with Content", value: stats.pages_with_content, color: "#22c55e" },
    { icon: Globe, label: "URLs Discovered", value: stats.urls_discovered, color: "#a78bfa" },
    { icon: AlertCircle, label: "Errors", value: stats.errors, color: stats.errors > 0 ? "#ef4444" : "#6b7280" },
  ];

  return (
    <div className="glass rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-[#1e3a5f]/50 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-cyber-500">Deep Crawl Results</h3>
        {stats.pages_list && stats.pages_list.length > 0 && (
          <button
            onClick={() => setShowPages(!showPages)}
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-300 transition-colors"
          >
            View pages
            {showPages ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-[#1e3a5f]/30">
        {metrics.map((m) => (
          <div key={m.label} className="bg-[#111827] px-4 py-3 text-center">
            <m.icon className="w-4 h-4 mx-auto mb-1" style={{ color: m.color }} />
            <div className="text-lg font-bold text-white">{m.value}</div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">{m.label}</div>
          </div>
        ))}
      </div>

      {showPages && stats.pages_list && (
        <div className="border-t border-[#1e3a5f]/50 max-h-64 overflow-y-auto animate-fade-in">
          {stats.pages_list.map((page, i) => (
            <div
              key={i}
              className="flex items-center justify-between px-5 py-2 border-b border-[#1e3a5f]/20 hover:bg-white/[0.02]"
            >
              <div className="min-w-0 flex-1">
                <p className="text-xs text-gray-300 truncate font-mono">{page.url}</p>
                {page.title && (
                  <p className="text-[10px] text-gray-500 truncate">{page.title}</p>
                )}
              </div>
              <span
                className={`ml-3 text-xs font-medium ${
                  page.status === 200 ? "text-green-400" : "text-yellow-400"
                }`}
              >
                {page.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
