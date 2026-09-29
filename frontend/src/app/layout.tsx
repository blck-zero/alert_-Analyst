import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SentinelAI | SOC Analyst Platform",
  description: "AI-Powered SOC Alert Triage & Incident Correlation Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-[#0b0f19] text-gray-100 antialiased min-h-screen flex flex-col`}>
        <header className="sticky top-0 z-50 border-b border-gray-800 bg-[#0b0f19]/80 backdrop-blur-md">
          <div className="container mx-auto px-4 h-14 flex items-center justify-between">
            <div className="flex items-center gap-6">
              <a href="/" className="flex items-center gap-2 text-blue-500 font-bold text-lg tracking-wide">
                <span className="w-8 h-8 rounded bg-blue-500/20 flex items-center justify-center border border-blue-500/50">
                  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>
                </span>
                SentinelAI
              </a>
              <nav className="hidden md:flex items-center gap-4 text-sm font-medium text-gray-400">
                <a href="/" className="hover:text-white transition-colors">Dashboard</a>
                <a href="/incidents" className="hover:text-white transition-colors">Incidents</a>
                <a href="/alerts" className="hover:text-white transition-colors">Raw Alerts</a>
              </nav>
            </div>
            <div className="flex items-center gap-3">
              <div className="text-xs text-right hidden sm:block">
                <div className="text-gray-300">Tier-1 Analyst</div>
                <div className="text-gray-500">SOC Operations</div>
              </div>
              <div className="w-8 h-8 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center">
                <span className="text-xs font-medium">T1</span>
              </div>
            </div>
          </div>
        </header>
        <main className="flex-1 flex flex-col relative z-0">
          {children}
        </main>
      </body>
    </html>
  );
}
