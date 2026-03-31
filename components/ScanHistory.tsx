"use client";

import { Clock, ArrowRight } from "lucide-react";
import type { ScanHistoryEntry } from "@/lib/types";

interface ScanHistoryProps {
  entries: ScanHistoryEntry[];
  onSelect: (entry: ScanHistoryEntry) => void;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

export function ScanHistory({ entries, onSelect }: ScanHistoryProps) {
  return (
    <div className="glass rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Clock className="w-4 h-4 text-gray-500" />
        <h3 className="text-sm font-medium text-gray-300">Recent Scans</h3>
      </div>
      <div className="space-y-2">
        {entries.map((entry, i) => (
          <button
            key={i}
            onClick={() => onSelect(entry)}
            className="w-full flex items-center justify-between px-4 py-3 rounded-lg hover:bg-white/5 transition-colors group"
          >
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: scoreColor(entry.securityScore) }} />
              <span className="text-sm text-gray-300 truncate">{entry.url}</span>
            </div>
            <div className="flex items-center gap-4 flex-shrink-0">
              <div className="flex items-center gap-2 text-xs">
                <span style={{ color: scoreColor(entry.securityScore) }}>{entry.securityScore}</span>
                <span className="text-gray-600">/</span>
                <span style={{ color: scoreColor(entry.complianceScore) }}>{entry.complianceScore}</span>
              </div>
              <span className="text-xs text-gray-500">
                {entry.threatCount} threats
              </span>
              <ArrowRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400 transition-colors" />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
