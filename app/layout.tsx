import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "FinTech Threat Detection Agent",
  description:
    "AI-powered cybersecurity & compliance assessment for Indian fintech products. Scans for threats across RBI, SEBI, DPDP, PCI DSS, and GDPR regulations.",
  keywords: [
    "fintech security",
    "threat detection",
    "RBI compliance",
    "SEBI CSCRF",
    "DPDP Act",
    "cybersecurity",
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased font-sans">{children}</body>
    </html>
  );
}
