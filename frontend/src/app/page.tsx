"use client";

import React, { useEffect, useState } from "react";
import { Activity, ShieldAlert, Users, Target, Play, BarChart3, AlertTriangle, ArrowRight, Loader2, Search } from "lucide-react";
import { api } from "@/lib/api";
import { RiskBadge } from "@/components/RiskBadge";
import { MitreBadge } from "@/components/MitreBadge";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";

export default function Dashboard() {
  const [metrics, setMetrics] = useState<any>(null);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [isTriaging, setIsTriaging] = useState(false);
  const [triageStatus, setTriageStatus] = useState<any>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [metricsData, incidentsData] = await Promise.all([
        api.getMetrics(),
        api.getIncidents()
      ]);
      setMetrics(metricsData);
      setIncidents(incidentsData);
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
    }
  };

  const handleRunTriage = async () => {
    setIsTriaging(true);
    try {
      const res = await api.runTriage();
      setTriageStatus(res);
      pollTriageStatus(res.run_id);
    } catch (error) {
      console.error("Failed to run triage:", error);
      setIsTriaging(false);
    }
  };

  const pollTriageStatus = (runId: string) => {
    const interval = setInterval(async () => {
      try {
        const res = await api.getTriageStatus(runId);
        setTriageStatus(res);
        if (res.status === "completed" || res.status === "failed") {
          clearInterval(interval);
          setIsTriaging(false);
          fetchDashboardData(); // Refresh data
        }
      } catch (error) {
        clearInterval(interval);
        setIsTriaging(false);
      }
    }, 1000);
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">SOC Analyst Dashboard</h1>
          <p className="text-gray-400">AI-Powered Alert Triage & Incident Correlation</p>
        </div>
        
        <button 
          onClick={handleRunTriage}
          disabled={isTriaging}
          className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium shadow-[0_0_20px_rgba(37,99,235,0.3)] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isTriaging ? (
            <><Loader2 className="w-5 h-5 animate-spin" /> Processing...</>
          ) : (
            <><Play className="w-5 h-5" /> Run AI Triage</>
          )}
        </button>
      </div>

      <AnimatePresence>
        {isTriaging && triageStatus && (
          <motion.div 
            initial={{ opacity: 0, height: 0, marginBottom: 0 }}
            animate={{ opacity: 1, height: 'auto', marginBottom: 32 }}
            exit={{ opacity: 0, height: 0, marginBottom: 0 }}
            className="overflow-hidden"
          >
            <div className="bg-[#111827] border border-blue-900/50 rounded-xl p-6 shadow-lg relative overflow-hidden">
              <div className="absolute top-0 left-0 h-1 bg-blue-500 transition-all duration-300 ease-out" style={{ width: `${triageStatus.progress_pct || 0}%` }} />
              
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-blue-400 flex items-center gap-2">
                  <Activity className="w-5 h-5" />
                  Analyzing Alerts
                </h3>
                <span className="text-sm font-mono bg-blue-500/10 text-blue-400 px-2 py-1 rounded">
                  {triageStatus.progress_pct}%
                </span>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div className="flex flex-col gap-1">
                  <span className="text-gray-500">Current Stage</span>
                  <span className="text-gray-200 capitalize font-medium">{triageStatus.current_stage?.replace('_', ' ') || 'Starting'}</span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-gray-500">Alerts Processed</span>
                  <span className="text-gray-200 font-medium">{triageStatus.total_alerts_input || 0}</span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-gray-500">Incidents Found</span>
                  <span className="text-gray-200 font-medium">{triageStatus.incidents_created || 0}</span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-gray-500">Status</span>
                  <span className="text-gray-200 font-medium capitalize">{triageStatus.status}</span>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <MetricCard title="Raw Alerts" value={metrics?.total_alerts?.toLocaleString() || "0"} icon={<Activity />} color="blue" />
        <MetricCard title="Incidents" value={metrics?.total_incidents?.toLocaleString() || "0"} icon={<Target />} color="purple" />
        <MetricCard title="Critical Incidents" value={metrics?.critical_incidents?.toLocaleString() || "0"} icon={<ShieldAlert />} color="red" />
        <MetricCard title="False Positive Rate" value={`${((metrics?.false_positive_rate || 0) * 100).toFixed(1)}%`} icon={<BarChart3 />} color="green" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Incidents */}
        <div className="lg:col-span-2 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-gray-100 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              Priority Incidents
            </h2>
            <Link href="/incidents" className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1">
              View all <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          
          <div className="flex flex-col gap-3">
            {incidents.slice(0, 5).map((incident) => (
              <IncidentCard key={incident.incident_id} incident={incident} />
            ))}
            
            {incidents.length === 0 && !isTriaging && (
              <div className="bg-[#111827] border border-gray-800 rounded-xl p-10 flex flex-col items-center justify-center text-center text-gray-500">
                <Search className="w-12 h-12 mb-4 opacity-20" />
                <p className="text-lg font-medium text-gray-400">No Incidents Found</p>
                <p className="max-w-sm mt-2">Run the AI Triage pipeline to analyze the raw security alerts and correlate them into incidents.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: AI Triage Reduction & MTTT */}
        <div className="flex flex-col gap-6">
          <div className="bg-[#111827] border border-gray-800 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-6">Alert Reduction</h3>
            
            <div className="relative">
              <div className="flex justify-between items-end mb-2">
                <div className="flex flex-col">
                  <span className="text-3xl font-bold text-gray-200">{metrics?.total_alerts?.toLocaleString() || "0"}</span>
                  <span className="text-xs text-gray-500 uppercase tracking-wider">Raw Alerts</span>
                </div>
                <ArrowRight className="w-5 h-5 text-gray-600 mb-2" />
                <div className="flex flex-col text-right">
                  <span className="text-3xl font-bold text-blue-400">{metrics?.total_incidents?.toLocaleString() || "0"}</span>
                  <span className="text-xs text-gray-500 uppercase tracking-wider">Incidents</span>
                </div>
              </div>
              
              <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden mt-4">
                <div 
                  className="h-full bg-blue-500 rounded-full" 
                  style={{ width: `${Math.max(2, (metrics?.total_incidents || 0) / Math.max(1, metrics?.total_alerts || 1) * 100)}%` }}
                />
              </div>
              <div className="mt-3 text-center text-sm font-medium text-green-400">
                {((metrics?.alert_reduction || 0) * 100).toFixed(1)}% reduction in noise
              </div>
            </div>
          </div>

          <div className="bg-[#111827] border border-gray-800 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Detection Performance</h3>
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Precision</span>
                <span className="font-mono font-medium">{((metrics?.precision || 0) * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${(metrics?.precision || 0) * 100}%` }} />
              </div>
              
              <div className="flex items-center justify-between mt-2">
                <span className="text-gray-400 text-sm">Recall</span>
                <span className="font-mono font-medium">{((metrics?.recall || 0) * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-purple-500 rounded-full" style={{ width: `${(metrics?.recall || 0) * 100}%` }} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ title, value, icon, color }: { title: string, value: string, icon: React.ReactNode, color: 'blue'|'purple'|'red'|'green' }) {
  const colorMap = {
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    purple: "text-purple-400 bg-purple-500/10 border-purple-500/20",
    red: "text-red-400 bg-red-500/10 border-red-500/20",
    green: "text-green-400 bg-green-500/10 border-green-500/20",
  };
  
  return (
    <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 flex items-center gap-4 hover:border-gray-700 transition-colors">
      <div className={`p-3 rounded-lg border ${colorMap[color]}`}>
        {icon}
      </div>
      <div>
        <p className="text-sm font-medium text-gray-400">{title}</p>
        <p className="text-2xl font-bold text-gray-100">{value}</p>
      </div>
    </div>
  );
}

function IncidentCard({ incident }: { incident: any }) {
  return (
    <Link href={`/incidents/${incident.incident_id}`}>
      <div className="bg-[#111827] border border-gray-800 hover:border-blue-500/50 hover:bg-[#151d2e] rounded-xl p-5 transition-all group cursor-pointer">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className="text-sm font-mono font-medium text-gray-400">{incident.incident_id}</span>
              <RiskBadge score={incident.risk_score} severity={incident.severity} />
              <MitreBadge techniqueId={incident.mitre_technique_id} techniqueName={incident.mitre_technique_name} />
            </div>
            <h3 className="text-lg font-semibold text-gray-200 group-hover:text-blue-400 transition-colors mb-2">
              {incident.title}
            </h3>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-gray-500">
              <span className="flex items-center gap-1.5"><Activity className="w-4 h-4" /> {incident.alert_count} Alerts</span>
              <span className="flex items-center gap-1.5"><Users className="w-4 h-4" /> {incident.affected_users?.length || 0} Users</span>
              <span className="flex items-center gap-1.5"><Target className="w-4 h-4" /> {incident.source_ips?.length || 0} IPs</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded-full bg-gray-800/50 flex items-center justify-center text-gray-500 group-hover:bg-blue-500/10 group-hover:text-blue-400 transition-colors shrink-0">
            <ArrowRight className="w-5 h-5" />
          </div>
        </div>
      </div>
    </Link>
  );
}
