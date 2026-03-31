"use client";

import { useEffect, useState } from "react";
import { Shield, FileCheck } from "lucide-react";
import type { ScoreData } from "@/lib/types";

interface ScoreCardsProps {
  securityScore: ScoreData;
  complianceScore: ScoreData;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

function ScoreRing({ score, label, icon: Icon, delay }: {
  score: number;
  label: string;
  icon: typeof Shield;
  delay: number;
}) {
  const [displayScore, setDisplayScore] = useState(0);
  const color = scoreColor(score);
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (circumference * displayScore) / 100;

  useEffect(() => {
    const timeout = setTimeout(() => {
      let current = 0;
      const interval = setInterval(() => {
        current += 1;
        if (current > score) {
          clearInterval(interval);
          return;
        }
        setDisplayScore(current);
      }, 15);
      return () => clearInterval(interval);
    }, delay);
    return () => clearTimeout(timeout);
  }, [score, delay]);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-32 h-32 sm:w-36 sm:h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50" cy="50" r="42"
            fill="none"
            stroke="#1e293b"
            strokeWidth="6"
          />
          <circle
            cx="50" cy="50" r="42"
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-100 ease-out"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl sm:text-4xl font-extrabold" style={{ color }}>{displayScore}</span>
          <span className="text-[10px] text-gray-400 uppercase tracking-wider">/100</span>
        </div>
      </div>
      <div className="flex items-center gap-1.5">
        <Icon className="w-4 h-4" style={{ color }} />
        <span className="text-sm font-medium text-gray-300">{label}</span>
      </div>
    </div>
  );
}

export function ScoreCards({ securityScore, complianceScore }: ScoreCardsProps) {
  const secRating = securityScore?.rating || "N/A";
  const compRating = complianceScore?.rating || "N/A";

  return (
    <div className="glass rounded-2xl p-6 sm:p-8 glow-border">
      <div className="flex flex-col sm:flex-row items-center justify-around gap-8">
        <div className="text-center space-y-2">
          <ScoreRing score={securityScore?.score ?? 0} label="Security Score" icon={Shield} delay={200} />
          <span
            className="inline-block px-3 py-1 rounded-full text-xs font-bold"
            style={{
              backgroundColor: scoreColor(securityScore?.score ?? 0) + "20",
              color: scoreColor(securityScore?.score ?? 0),
            }}
          >
            {secRating}
          </span>
        </div>

        {/* Divider */}
        <div className="hidden sm:block w-px h-36 bg-gradient-to-b from-transparent via-[#1e3a5f] to-transparent" />
        <div className="sm:hidden w-48 h-px bg-gradient-to-r from-transparent via-[#1e3a5f] to-transparent" />

        <div className="text-center space-y-2">
          <ScoreRing score={complianceScore?.score ?? 0} label="Compliance Score" icon={FileCheck} delay={400} />
          <span
            className="inline-block px-3 py-1 rounded-full text-xs font-bold"
            style={{
              backgroundColor: scoreColor(complianceScore?.score ?? 0) + "20",
              color: scoreColor(complianceScore?.score ?? 0),
            }}
          >
            {compRating}
          </span>
        </div>
      </div>
    </div>
  );
}
