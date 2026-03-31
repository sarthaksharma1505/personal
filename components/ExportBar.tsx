"use client";

import { Download, FileJson, ClipboardCopy } from "lucide-react";
import { useState } from "react";
import type { ScanResult } from "@/lib/types";

interface ExportBarProps {
  data: ScanResult;
}

export function ExportBar({ data }: ExportBarProps) {
  const [copied, setCopied] = useState(false);

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `threat-report-${new Date().toISOString().split("T")[0]}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="glass rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
      <div className="flex items-center gap-2">
        <FileJson className="w-4 h-4 text-gray-500" />
        <span className="text-sm text-gray-400">Export scan results</span>
      </div>
      <div className="flex gap-2">
        <button
          onClick={handleCopy}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 border border-[#1e3a5f] text-sm text-gray-300 hover:bg-white/10 transition-colors"
        >
          <ClipboardCopy className="w-4 h-4" />
          {copied ? "Copied!" : "Copy JSON"}
        </button>
        <button
          onClick={handleExportJSON}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-500/20 border border-cyber-500/30 text-sm text-cyber-400 hover:bg-cyber-500/30 transition-colors"
        >
          <Download className="w-4 h-4" />
          Download Report
        </button>
      </div>
    </div>
  );
}
