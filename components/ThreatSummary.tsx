"use client";

import { AlertTriangle, AlertCircle, Info, ShieldAlert } from "lucide-react";
import type { Threat } from "@/lib/types";

interface ThreatSummaryProps {
  threats: Threat[];
}

export function ThreatSummary({ threats }: ThreatSummaryProps) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  threats.forEach((t) => {
    if (t.severity in counts) counts[t.severity as keyof typeof counts]++;
  });

  const cards = [
    { label: "Critical", count: counts.CRITICAL, color: "#ef4444", bgColor: "rgba(239,68,68,0.1)", icon: ShieldAlert },
    { label: "High", count: counts.HIGH, color: "#f97316", bgColor: "rgba(249,115,22,0.1)", icon: AlertTriangle },
    { label: "Medium", count: counts.MEDIUM, color: "#eab308", bgColor: "rgba(234,179,8,0.1)", icon: AlertCircle },
    { label: "Low", count: counts.LOW, color: "#22d3ee", bgColor: "rgba(34,211,238,0.1)", icon: Info },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {cards.map((card) => (
        <div
          key={card.label}
          className="glass rounded-xl p-4 text-center glass-hover transition-all duration-200 cursor-default group"
          style={{ borderColor: card.count > 0 ? card.color + "30" : undefined }}
        >
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center mx-auto mb-2 transition-transform group-hover:scale-110"
            style={{ backgroundColor: card.bgColor }}
          >
            <card.icon className="w-4 h-4" style={{ color: card.color }} />
          </div>
          <div className="text-2xl font-bold" style={{ color: card.color }}>
            {card.count}
          </div>
          <div className="text-xs text-gray-400 uppercase tracking-wider mt-0.5">
            {card.label}
          </div>
        </div>
      ))}
    </div>
  );
}
