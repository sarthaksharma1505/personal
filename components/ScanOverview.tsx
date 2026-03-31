"use client";

import { Globe, Lock, Shield, Mail, Clock, Server } from "lucide-react";

interface ScanOverviewProps {
  scanResults: {
    http?: Record<string, any>;
    ssl?: Record<string, any>;
    dns?: Record<string, any>;
    headers?: Record<string, any>;
    hostname?: string;
  };
}

function StatusBadge({ pass, label }: { pass: boolean; label: string }) {
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs font-medium ${
        pass
          ? "bg-green-500/10 text-green-400 border border-green-500/20"
          : "bg-red-500/10 text-red-400 border border-red-500/20"
      }`}
    >
      {label}
    </span>
  );
}

export function ScanOverview({ scanResults }: ScanOverviewProps) {
  const http = scanResults?.http || {};
  const ssl = scanResults?.ssl || {};
  const dns = scanResults?.dns || {};
  const headers = scanResults?.headers || {};

  const checks = [
    {
      icon: Globe,
      label: "HTTP Status",
      status: http.reachable ? "Reachable" : "Unreachable",
      pass: !!http.reachable,
      detail: http.status_code ? `Status ${http.status_code}` : "N/A",
    },
    {
      icon: Lock,
      label: "HTTPS",
      status: http.uses_https ? "Encrypted" : "Plaintext",
      pass: !!http.uses_https,
      detail: http.uses_https ? "TLS encrypted connection" : "Data sent in plaintext",
    },
    {
      icon: Shield,
      label: "SSL/TLS",
      status: ssl.has_ssl ? "Active" : "None",
      pass: !!ssl.has_ssl,
      detail: ssl.protocol_version || "N/A",
    },
    {
      icon: Clock,
      label: "Response Time",
      status: http.response_time_ms ? `${http.response_time_ms}ms` : "N/A",
      pass: http.response_time_ms ? http.response_time_ms < 3000 : true,
      detail: http.response_time_ms && http.response_time_ms < 1000 ? "Fast" : http.response_time_ms && http.response_time_ms < 3000 ? "Average" : "Slow",
    },
    {
      icon: Mail,
      label: "SPF Record",
      status: dns.has_spf ? "Found" : "Missing",
      pass: !!dns.has_spf,
      detail: "Email spoofing protection",
    },
    {
      icon: Mail,
      label: "DMARC Record",
      status: dns.has_dmarc ? "Found" : "Missing",
      pass: !!dns.has_dmarc,
      detail: "Email authentication policy",
    },
  ];

  const presentHeaders = Object.keys(headers?.present || {});
  const missingHeaders = headers?.missing || [];

  return (
    <div className="space-y-4">
      {/* Infrastructure checks */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e3a5f]/50">
          <h3 className="text-sm font-semibold text-cyber-500">Infrastructure</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px bg-[#1e3a5f]/30">
          {checks.map((check) => (
            <div key={check.label} className="bg-[#111827] px-5 py-4 flex items-center gap-4">
              <div
                className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                  check.pass ? "bg-green-500/10" : "bg-red-500/10"
                }`}
              >
                <check.icon
                  className={`w-5 h-5 ${check.pass ? "text-green-400" : "text-red-400"}`}
                />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white">{check.label}</span>
                  <StatusBadge pass={check.pass} label={check.status} />
                </div>
                <p className="text-xs text-gray-500 mt-0.5">{check.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Security Headers */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e3a5f]/50 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-cyber-500">Security Headers</h3>
          <span className="text-xs text-gray-500">
            {presentHeaders.length}/{presentHeaders.length + missingHeaders.length} configured
          </span>
        </div>
        <div className="p-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {presentHeaders.map((h) => (
              <div key={h} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-500/5">
                <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
                <span className="text-xs text-green-300 font-mono">{h}</span>
              </div>
            ))}
            {missingHeaders.map((h: string) => (
              <div key={h} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/5">
                <div className="w-1.5 h-1.5 rounded-full bg-red-400" />
                <span className="text-xs text-red-300 font-mono">{h}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* SSL Certificate */}
      {ssl.certificate && Object.keys(ssl.certificate).length > 0 && (
        <div className="glass rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-[#1e3a5f]/50">
            <h3 className="text-sm font-semibold text-cyber-500">SSL Certificate</h3>
          </div>
          <div className="p-5 space-y-2">
            {ssl.certificate.subject_cn && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Subject</span>
                <span className="text-white font-mono text-xs">{ssl.certificate.subject_cn}</span>
              </div>
            )}
            {ssl.certificate.issuer_org && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Issuer</span>
                <span className="text-white">{ssl.certificate.issuer_org}</span>
              </div>
            )}
            {ssl.certificate.days_until_expiry !== undefined && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Expires in</span>
                <span
                  className={`font-medium ${
                    ssl.certificate.days_until_expiry > 30
                      ? "text-green-400"
                      : ssl.certificate.days_until_expiry > 0
                      ? "text-yellow-400"
                      : "text-red-400"
                  }`}
                >
                  {ssl.certificate.days_until_expiry} days
                </span>
              </div>
            )}
            {ssl.cipher_suite && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Cipher Suite</span>
                <span className="text-white font-mono text-xs">{ssl.cipher_suite}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
