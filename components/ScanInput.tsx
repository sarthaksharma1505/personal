"use client";

import { useState } from "react";
import { Search, Globe, Settings2, ChevronDown, ChevronUp } from "lucide-react";

interface ScanInputProps {
  onScan: (url: string, maxPages: number, maxDepth: number) => void;
  disabled: boolean;
}

export function ScanInput({ onScan, disabled }: ScanInputProps) {
  const [url, setUrl] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [maxPages, setMaxPages] = useState(50);
  const [maxDepth, setMaxDepth] = useState(3);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || disabled) return;
    onScan(url.trim(), maxPages, maxDepth);
  };

  const quickScans = [
    { label: "Paytm", url: "https://paytm.com" },
    { label: "Razorpay", url: "https://razorpay.com" },
    { label: "PhonePe", url: "https://phonepe.com" },
    { label: "Groww", url: "https://groww.in" },
  ];

  return (
    <div className="glass rounded-2xl p-6 sm:p-8 glow-border">
      <div className="text-center mb-6">
        <h2 className="text-lg font-semibold text-white mb-1">
          Scan a Fintech Product
        </h2>
        <p className="text-sm text-gray-400">
          Enter any fintech URL to detect security threats and check regulatory
          compliance (RBI, SEBI, DPDP, PCI DSS, GDPR)
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Main input row */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com or Play Store / App Store link"
              disabled={disabled}
              className="w-full pl-12 pr-4 py-3.5 rounded-xl bg-cyber-950 border border-[#1e3a5f] text-white placeholder-gray-500 focus:outline-none focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500/50 transition-all text-base disabled:opacity-50"
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSubmit(e);
              }}
            />
          </div>
          <button
            type="submit"
            disabled={disabled || !url.trim()}
            className="px-8 py-3.5 rounded-xl bg-gradient-to-r from-cyber-500 to-cyan-600 text-black font-bold text-base hover:from-cyber-400 hover:to-cyan-500 disabled:from-gray-600 disabled:to-gray-700 disabled:text-gray-400 disabled:cursor-not-allowed transition-all duration-200 shadow-lg shadow-cyber-500/20 hover:shadow-cyber-500/40 flex items-center gap-2 justify-center whitespace-nowrap"
          >
            <Search className="w-5 h-5" />
            Scan Now
          </button>
        </div>

        {/* Quick scan buttons */}
        <div className="flex flex-wrap gap-2 justify-center">
          <span className="text-xs text-gray-500 self-center mr-1">Quick scan:</span>
          {quickScans.map((qs) => (
            <button
              key={qs.url}
              type="button"
              onClick={() => {
                setUrl(qs.url);
                if (!disabled) onScan(qs.url, maxPages, maxDepth);
              }}
              disabled={disabled}
              className="px-3 py-1 rounded-lg bg-cyber-500/10 border border-cyber-500/20 text-xs text-cyber-400 hover:bg-cyber-500/20 hover:border-cyber-500/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {qs.label}
            </button>
          ))}
        </div>

        {/* Advanced options toggle */}
        <div className="pt-2 border-t border-[#1e3a5f]/50">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-xs text-gray-400 hover:text-gray-300 transition-colors mx-auto"
          >
            <Settings2 className="w-3.5 h-3.5" />
            Advanced Options
            {showAdvanced ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
          </button>

          {showAdvanced && (
            <div className="mt-4 flex flex-col sm:flex-row gap-4 justify-center animate-fade-in">
              <div className="flex items-center gap-3">
                <label className="text-sm text-gray-400 whitespace-nowrap">
                  Max Pages
                </label>
                <input
                  type="number"
                  value={maxPages}
                  onChange={(e) => setMaxPages(Number(e.target.value))}
                  min={1}
                  max={200}
                  className="w-20 px-3 py-2 rounded-lg bg-cyber-950 border border-[#1e3a5f] text-white text-sm focus:outline-none focus:border-cyber-500"
                />
              </div>
              <div className="flex items-center gap-3">
                <label className="text-sm text-gray-400 whitespace-nowrap">
                  Max Depth
                </label>
                <input
                  type="number"
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(Number(e.target.value))}
                  min={1}
                  max={5}
                  className="w-20 px-3 py-2 rounded-lg bg-cyber-950 border border-[#1e3a5f] text-white text-sm focus:outline-none focus:border-cyber-500"
                />
              </div>
            </div>
          )}
        </div>
      </form>
    </div>
  );
}
