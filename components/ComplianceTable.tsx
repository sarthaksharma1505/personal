"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, CheckCircle2, XCircle, AlertTriangle, MinusCircle } from "lucide-react";
import type { ComplianceIssue } from "@/lib/types";

interface ComplianceTableProps {
  issues: ComplianceIssue[];
  breakdown: Record<string, number>;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

const statusConfig = {
  PASS: { icon: CheckCircle2, color: "#22c55e", label: "Pass" },
  FAIL: { icon: XCircle, color: "#ef4444", label: "Fail" },
  WARNING: { icon: AlertTriangle, color: "#eab308", label: "Warning" },
  NOT_CHECKED: { icon: MinusCircle, color: "#6b7280", label: "N/A" },
};

function RegulationGroup({
  regulation,
  issues,
  score,
  defaultOpen,
}: {
  regulation: string;
  issues: ComplianceIssue[];
  score?: number;
  defaultOpen: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultOpen);
  const passCount = issues.filter((i) => i.status === "PASS").length;
  const failCount = issues.filter((i) => i.status === "FAIL").length;
  const warnCount = issues.filter((i) => i.status === "WARNING").length;

  return (
    <div className="glass rounded-xl overflow-hidden stagger-item">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-3">
          {expanded ? (
            <ChevronDown className="w-4 h-4 text-gray-500" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-500" />
          )}
          <span className="text-sm font-semibold text-white">{regulation}</span>
          {score !== undefined && (
            <span
              className="px-2 py-0.5 rounded text-xs font-bold"
              style={{
                backgroundColor: scoreColor(score) + "20",
                color: scoreColor(score),
              }}
            >
              {score}%
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs">
          {passCount > 0 && (
            <span className="text-green-400">{passCount} pass</span>
          )}
          {failCount > 0 && (
            <span className="text-red-400">{failCount} fail</span>
          )}
          {warnCount > 0 && (
            <span className="text-yellow-400">{warnCount} warn</span>
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#1e3a5f]/50 animate-fade-in">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider">
                  <th className="text-left px-5 py-2.5 w-36">Section</th>
                  <th className="text-left px-5 py-2.5">Requirement</th>
                  <th className="text-center px-5 py-2.5 w-24">Status</th>
                  <th className="text-left px-5 py-2.5">Details</th>
                </tr>
              </thead>
              <tbody>
                {issues.map((issue, i) => {
                  const config =
                    statusConfig[issue.status] || statusConfig.NOT_CHECKED;
                  const StatusIcon = config.icon;
                  return (
                    <tr
                      key={i}
                      className="border-t border-[#1e3a5f]/30 hover:bg-white/[0.02] transition-colors"
                    >
                      <td className="px-5 py-3 text-xs text-gray-400">
                        {issue.section}
                      </td>
                      <td className="px-5 py-3 text-sm text-gray-200">
                        {issue.requirement}
                      </td>
                      <td className="px-5 py-3 text-center">
                        <div className="flex items-center justify-center gap-1">
                          <StatusIcon
                            className="w-4 h-4"
                            style={{ color: config.color }}
                          />
                          <span
                            className="text-xs font-medium"
                            style={{ color: config.color }}
                          >
                            {config.label}
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-500 max-w-xs">
                        {issue.details}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export function ComplianceTable({ issues, breakdown }: ComplianceTableProps) {
  // Group by regulation
  const grouped: Record<string, ComplianceIssue[]> = {};
  issues.forEach((issue) => {
    if (!grouped[issue.regulation]) grouped[issue.regulation] = [];
    grouped[issue.regulation].push(issue);
  });

  // Sort by score (worst first)
  const sorted = Object.entries(grouped).sort(([a], [b]) => {
    const aScore = breakdown[a] ?? 100;
    const bScore = breakdown[b] ?? 100;
    return aScore - bScore;
  });

  if (issues.length === 0) {
    return (
      <div className="glass rounded-xl p-12 text-center">
        <p className="text-gray-400">No compliance data available.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Summary bar */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(breakdown)
          .sort(([, a], [, b]) => a - b)
          .map(([reg, score]) => (
            <span
              key={reg}
              className="px-3 py-1.5 rounded-lg text-xs font-medium border"
              style={{
                backgroundColor: scoreColor(score) + "10",
                borderColor: scoreColor(score) + "30",
                color: scoreColor(score),
              }}
            >
              {reg}: {score}%
            </span>
          ))}
      </div>

      {/* Regulation groups */}
      {sorted.map(([regulation, regIssues], i) => (
        <RegulationGroup
          key={regulation}
          regulation={regulation}
          issues={regIssues}
          score={breakdown[regulation]}
          defaultOpen={i === 0}
        />
      ))}
    </div>
  );
}
