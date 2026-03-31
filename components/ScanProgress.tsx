"use client";

import { Loader2 } from "lucide-react";

interface ScanProgressProps {
  phase: string;
  progress: number;
}

export function ScanProgress({ phase, progress }: ScanProgressProps) {
  return (
    <div className="glass rounded-2xl p-8 animate-fade-in">
      <div className="flex flex-col items-center gap-6">
        {/* Animated scanner */}
        <div className="relative w-24 h-24">
          <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="none"
              stroke="#1e3a5f"
              strokeWidth="4"
            />
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="none"
              stroke="#00d4ff"
              strokeWidth="4"
              strokeLinecap="round"
              strokeDasharray="264"
              strokeDashoffset={264 - (264 * progress) / 100}
              className="transition-all duration-700 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xl font-bold text-cyber-500">{progress}%</span>
          </div>
        </div>

        {/* Phase text */}
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center gap-2">
            <Loader2 className="w-4 h-4 text-cyber-500 animate-spin" />
            <span className="text-sm font-medium text-white">{phase}</span>
          </div>
          <p className="text-xs text-gray-500">
            Deep scanning all pages, analyzing security posture, and running AI threat detection...
          </p>
        </div>

        {/* Progress bar */}
        <div className="w-full max-w-md">
          <div className="h-1.5 bg-[#1e3a5f] rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyber-500 to-cyan-400 rounded-full transition-all duration-700 ease-out progress-pulse"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
