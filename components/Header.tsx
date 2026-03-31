"use client";

import { Shield, Activity, Zap } from "lucide-react";

export function Header() {
  return (
    <header className="relative overflow-hidden border-b border-[#1e3a5f]">
      {/* Animated background */}
      <div className="absolute inset-0 bg-gradient-to-r from-cyber-950 via-[#0d1b2a] to-cyber-950" />
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyber-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-64 h-64 bg-cyber-600/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-500/20 to-cyber-700/20 flex items-center justify-center border border-cyber-500/30 animate-glow">
                <Shield className="w-6 h-6 text-cyber-500" />
              </div>
              <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-green-400 border-2 border-cyber-950 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold gradient-text">
                FinTech Threat Detection Agent
              </h1>
              <p className="text-sm text-gray-400 flex items-center gap-2">
                <Activity className="w-3 h-3" />
                AI-Powered Security & Compliance Assessment
              </p>
            </div>
          </div>

          <div className="hidden sm:flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
              <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-xs text-green-400 font-medium">Adaptive AI Active</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-cyber-500/10 border border-cyber-500/20">
              <Zap className="w-3 h-3 text-cyber-400" />
              <span className="text-xs text-cyber-400 font-medium">v2.0</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
