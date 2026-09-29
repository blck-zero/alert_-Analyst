"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { RiskBadge } from "@/components/RiskBadge";
import { MitreBadge } from "@/components/MitreBadge";
import { AlertTriangle, Users, Target, Activity, ShieldCheck, ThumbsDown, Search, Share2, Clock, AlertCircle } from "lucide-react";
import Link from "next/link";

export default function IncidentDetail() {
  const { id } = useParams();
  const router = useRouter();
  const [incident, setIncident] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [reviewNotes, setReviewNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (id) {
      fetchIncident(id as string);
    }
  }, [id]);

  const fetchIncident = async (incidentId: string) => {
    try {
      const data = await api.getIncident(incidentId);
      setIncident(data);
    } catch (error) {
      console.error("Failed to fetch incident:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleReview = async (decision: string) => {
    setSubmitting(true);
    try {
      await api.reviewIncident(id as string, decision, reviewNotes);
      router.push("/");
    } catch (error) {
      console.error("Failed to submit review:", error);
      setSubmitting(false);
    }
  };

  if (loading) {
    return <div className="container mx-auto px-4 py-12 flex justify-center text-gray-500">Loading incident details...</div>;
  }

  if (!incident) {
    return <div className="container mx-auto px-4 py-12 flex justify-center text-red-500">Incident not found</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 mb-8">
        <div>
          <div className="flex items-center gap-3 mb-3">
            <span className="text-sm font-mono font-bold text-gray-400 bg-gray-800 px-2 py-1 rounded">{incident.incident_id}</span>
            <RiskBadge score={incident.risk_score} severity={incident.severity} className="text-sm px-3 py-1.5" />
            <MitreBadge techniqueId={incident.mitre_technique_id} techniqueName={incident.mitre_technique_name} />
          </div>
          <h1 className="text-2xl md:text-3xl font-bold text-white mb-2">{incident.title}</h1>
          <p className="text-gray-400 text-lg flex items-center gap-2">
            Status: <span className="uppercase text-gray-200 font-semibold tracking-wider text-sm">{incident.status}</span>
          </p>
        </div>
        
        <div className="flex items-center gap-4 bg-[#111827] border border-gray-800 rounded-xl p-4">
          <div className="flex flex-col items-center px-4 border-r border-gray-800">
            <span className="text-3xl font-bold text-blue-400">{incident.alert_count}</span>
            <span className="text-xs text-gray-500 uppercase">Alerts</span>
          </div>
          <div className="flex flex-col items-center px-4 border-r border-gray-800">
            <span className="text-3xl font-bold text-purple-400">{incident.affected_users?.length || 0}</span>
            <span className="text-xs text-gray-500 uppercase">Users</span>
          </div>
          <div className="flex flex-col items-center px-4">
            <span className="text-3xl font-bold text-green-400">{incident.source_ips?.length || 0}</span>
            <span className="text-xs text-gray-500 uppercase">IPs</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column (2/3) - Evidence & AI Summary */}
        <div className="lg:col-span-2 flex flex-col gap-8">
          
          {/* AI Investigation Brief */}
          <div className="bg-[#111827] border border-blue-900/40 rounded-xl p-6 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-purple-600" />
            <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2 mb-6">
              <span className="bg-blue-500/20 text-blue-400 p-1.5 rounded-md border border-blue-500/30">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
              </span>
              AI Investigation Brief
            </h2>
            
            <div className="prose prose-invert max-w-none">
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Summary</h3>
                <p className="text-gray-300 leading-relaxed text-lg">{incident.ai_summary || "No AI summary available."}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-800">
                  <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Key Evidence</h3>
                  <ul className="space-y-2 text-gray-300">
                    {(incident.ai_key_evidence || []).map((item: string, i: number) => (
                      <li key={i} className="flex gap-2 text-sm"><span className="text-blue-400">•</span> {item}</li>
                    ))}
                  </ul>
                </div>
                
                <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-800">
                  <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Possible Explanations</h3>
                  <p className="text-sm text-gray-300 leading-relaxed">{incident.ai_possible_explanation}</p>
                </div>
              </div>

              <div className="bg-blue-900/10 border border-blue-900/30 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-blue-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Search className="w-4 h-4" /> Recommended Investigation Steps
                </h3>
                <ul className="space-y-2 text-gray-300">
                  {(incident.ai_investigation_steps || []).map((step: string, i: number) => (
                    <li key={i} className="flex gap-2 text-sm"><span className="text-blue-400 font-bold">{i+1}.</span> {step}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Timeline & Entities */}
          <div className="bg-[#111827] border border-gray-800 rounded-xl p-6">
            <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2 mb-6">
              <Clock className="w-5 h-5 text-gray-400" /> Event Sequence
            </h2>
            
            <div className="relative pl-6 border-l-2 border-gray-800 space-y-6">
              {(incident.event_sequence || []).slice(0, 8).map((event: string, i: number) => (
                <div key={i} className="relative">
                  <div className="absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-gray-800 border-2 border-[#111827]" />
                  <div className="text-sm font-mono text-gray-400 mb-1">Step {i+1}</div>
                  <div className="text-gray-200 font-medium capitalize bg-gray-800/50 inline-block px-3 py-1 rounded border border-gray-700">{event.replace(/_/g, ' ')}</div>
                </div>
              ))}
              {(incident.event_sequence?.length || 0) > 8 && (
                <div className="relative">
                   <div className="absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-gray-800 border-2 border-[#111827]" />
                   <div className="text-gray-500 italic">+ {(incident.event_sequence.length - 8)} more events</div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column (1/3) - Analyst Review & Entities */}
        <div className="flex flex-col gap-6">
          
          {/* Analyst Review Panel */}
          <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden">
            <div className="bg-gray-800/50 p-4 border-b border-gray-800">
              <h2 className="text-base font-bold text-gray-100 uppercase tracking-wider">Human Analyst Review</h2>
            </div>
            
            <div className="p-5 flex flex-col gap-4">
              <textarea 
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="Add analyst notes and rationale for the decision..."
                className="w-full h-32 bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 resize-none"
              />
              
              <div className="grid grid-cols-2 gap-3">
                <button 
                  onClick={() => handleReview('confirmed')}
                  disabled={submitting}
                  className="flex items-center justify-center gap-2 py-2.5 bg-red-600/20 text-red-500 hover:bg-red-600/30 border border-red-900/50 rounded-lg text-sm font-bold transition-colors disabled:opacity-50"
                >
                  <ShieldCheck className="w-4 h-4" /> Confirm
                </button>
                <button 
                  onClick={() => handleReview('false_positive')}
                  disabled={submitting}
                  className="flex items-center justify-center gap-2 py-2.5 bg-gray-700 text-gray-300 hover:bg-gray-600 border border-gray-600 rounded-lg text-sm font-bold transition-colors disabled:opacity-50"
                >
                  <ThumbsDown className="w-4 h-4" /> False Positive
                </button>
                <button 
                  onClick={() => handleReview('investigating')}
                  disabled={submitting}
                  className="flex items-center justify-center gap-2 py-2.5 bg-blue-600/20 text-blue-500 hover:bg-blue-600/30 border border-blue-900/50 rounded-lg text-sm font-bold transition-colors disabled:opacity-50 col-span-2"
                >
                  <Search className="w-4 h-4" /> Investigate Further
                </button>
              </div>
            </div>
          </div>

          {/* Involved Entities */}
          <div className="bg-[#111827] border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Involved Entities</h3>
            
            <div className="flex flex-col gap-6">
              <div>
                <div className="text-xs font-semibold text-gray-500 mb-2 flex items-center gap-1"><Users className="w-3 h-3"/> USERS</div>
                <div className="flex flex-wrap gap-2">
                  {(incident.affected_users || []).map((u: string) => (
                    <Link key={u} href={`/users/${u}`} className="text-sm bg-gray-800 hover:bg-gray-700 text-blue-300 px-2.5 py-1 rounded transition-colors">
                      {u}
                    </Link>
                  ))}
                  {(!incident.affected_users || incident.affected_users.length === 0) && <span className="text-gray-600 text-sm">None</span>}
                </div>
              </div>
              
              <div>
                <div className="text-xs font-semibold text-gray-500 mb-2 flex items-center gap-1"><Target className="w-3 h-3"/> IP ADDRESSES</div>
                <div className="flex flex-wrap gap-2">
                  {(incident.source_ips || []).map((ip: string) => (
                    <Link key={ip} href={`/ips/${ip}`} className="text-sm bg-gray-800 hover:bg-gray-700 text-purple-300 px-2.5 py-1 rounded transition-colors font-mono">
                      {ip}
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
