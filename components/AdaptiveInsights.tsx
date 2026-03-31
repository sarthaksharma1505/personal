"use client";

import { Brain, TrendingUp, AlertTriangle, Lightbulb, Cpu } from "lucide-react";
import type { AdaptiveInsight } from "@/lib/types";

interface AdaptiveInsightsProps {
  insights: AdaptiveInsight[];
}

const typeConfig = {
  trend: { icon: TrendingUp, color: "#a78bfa", label: "Trend" },
  anomaly: { icon: AlertTriangle, color: "#f97316", label: "Anomaly" },
  recommendation: { icon: Lightbulb, color: "#22c55e", label: "AI Recommendation" },
  learning: { icon: Cpu, color: "#00d4ff", label: "Learned Pattern" },
};

export function AdaptiveInsights({ insights }: AdaptiveInsightsProps) {
  if (!insights || insights.length === 0) return null;

  return (
    <div className="glass rounded-xl overflow-hidden glow-border">
      <div className="px-5 py-3 border-b border-[#1e3a5f]/50 flex items-center gap-2">
        <Brain className="w-4 h-4 text-purple-400" />
        <h3 className="text-sm font-semibold text-purple-300">Adaptive AI Insights</h3>
        <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
          Self-Learning
        </span>
      </div>

      <div className="p-4 space-y-3">
        {insights.map((insight, i) => {
          const config = typeConfig[insight.type] || typeConfig.learning;
          const Icon = config.icon;

          return (
            <div
              key={i}
              className="flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] border border-[#1e3a5f]/30 stagger-item"
            >
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ backgroundColor: config.color + "15" }}
              >
                <Icon className="w-4 h-4" style={{ color: config.color }} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white">{insight.title}</span>
                  <span
                    className="px-1.5 py-0.5 rounded text-[9px] font-medium uppercase"
                    style={{
                      backgroundColor: config.color + "15",
                      color: config.color,
                    }}
                  >
                    {config.label}
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">{insight.description}</p>
                <div className="flex items-center gap-3 mt-2">
                  <div className="flex items-center gap-1">
                    <span className="text-[10px] text-gray-500">Confidence:</span>
                    <div className="w-16 h-1 rounded-full bg-[#1e3a5f]">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${insight.confidence * 100}%`,
                          backgroundColor: config.color,
                        }}
                      />
                    </div>
                    <span className="text-[10px] text-gray-400">
                      {Math.round(insight.confidence * 100)}%
                    </span>
                  </div>
                  <span
                    className={`text-[10px] font-medium ${
                      insight.impact === "high"
                        ? "text-red-400"
                        : insight.impact === "medium"
                        ? "text-yellow-400"
                        : "text-green-400"
                    }`}
                  >
                    {insight.impact} impact
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
