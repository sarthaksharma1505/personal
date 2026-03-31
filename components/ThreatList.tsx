"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, ShieldAlert, AlertTriangle, AlertCircle, Info, BookOpen } from "lucide-react";
import type { Threat } from "@/lib/types";

interface ThreatListProps {
  threats: Threat[];
}

const severityConfig = {
  CRITICAL: { color: "#ef4444", bg: "rgba(239,68,68,0.1)", border: "rgba(239,68,68,0.3)", icon: ShieldAlert },
  HIGH: { color: "#f97316", bg: "rgba(249,115,22,0.1)", border: "rgba(249,115,22,0.3)", icon: AlertTriangle },
  MEDIUM: { color: "#eab308", bg: "rgba(234,179,8,0.1)", border: "rgba(234,179,8,0.3)", icon: AlertCircle },
  LOW: { color: "#22d3ee", bg: "rgba(34,211,238,0.1)", border: "rgba(34,211,238,0.3)", icon: Info },
  INFO: { color: "#6b7280", bg: "rgba(107,114,128,0.1)", border: "rgba(107,114,128,0.3)", icon: Info },
};

function ThreatCard({ threat, index }: { threat: Threat; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const config = severityConfig[threat.severity] || severityConfig.INFO;
  const Icon = config.icon;

  return (
    <div
      className="stagger-item glass rounded-xl overflow-hidden transition-all duration-200 hover:border-opacity-50 cursor-pointer"
      style={{ borderLeftWidth: "3px", borderLeftColor: config.color }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="px-5 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
              style={{ backgroundColor: config.bg }}
            >
              <Icon className="w-4 h-4" style={{ color: config.color }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-white">
                  #{index + 1} {threat.title}
                </span>
                <span
                  className="px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                  style={{ backgroundColor: config.bg, color: config.color }}
                >
                  {threat.severity}
                </span>
              </div>
              <span className="text-xs text-gray-500 mt-0.5 block">{threat.category}</span>
            </div>
          </div>
          <div className="flex-shrink-0">
            {expanded ? (
              <ChevronDown className="w-4 h-4 text-gray-500" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-500" />
            )}
          </div>
        </div>

        {expanded && (
          <div className="mt-4 ml-11 space-y-3 animate-fade-in">
            <p className="text-sm text-gray-300 leading-relaxed">{threat.description}</p>

            <div className="flex items-start gap-2 p-3 rounded-lg bg-green-500/5 border border-green-500/10">
              <div className="w-5 h-5 rounded flex items-center justify-center bg-green-500/20 flex-shrink-0 mt-0.5">
                <svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-sm text-green-300/90">{threat.recommendation}</p>
            </div>

            {threat.references?.length > 0 && (
              <div className="flex items-start gap-2">
                <BookOpen className="w-3.5 h-3.5 text-gray-500 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-gray-500">
                  {threat.references.join(" | ")}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export function ThreatList({ threats }: ThreatListProps) {
  const [filter, setFilter] = useState<string>("ALL");

  const filtered =
    filter === "ALL"
      ? threats
      : threats.filter((t) => t.severity === filter);

  if (threats.length === 0) {
    return (
      <div className="glass rounded-xl p-12 text-center">
        <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mx-auto mb-4">
          <svg className="w-8 h-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <p className="text-green-400 font-semibold">No threats detected!</p>
        <p className="text-sm text-gray-500 mt-1">The scanned target appears to have good security posture.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Filter bar */}
      <div className="flex gap-2 overflow-x-auto pb-1">
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => {
          const count =
            sev === "ALL"
              ? threats.length
              : threats.filter((t) => t.severity === sev).length;
          const conf = sev !== "ALL" ? severityConfig[sev as keyof typeof severityConfig] : null;
          return (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all whitespace-nowrap ${
                filter === sev
                  ? "bg-cyber-500/20 text-cyber-400 border border-cyber-500/30"
                  : "text-gray-400 border border-transparent hover:bg-white/5"
              }`}
            >
              {sev === "ALL" ? "All" : sev.charAt(0) + sev.slice(1).toLowerCase()}{" "}
              <span className="opacity-60">({count})</span>
            </button>
          );
        })}
      </div>

      {/* Threat cards */}
      <div className="space-y-2">
        {filtered.map((threat, i) => (
          <ThreatCard key={i} threat={threat} index={threats.indexOf(threat)} />
        ))}
      </div>
    </div>
  );
}
