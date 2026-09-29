const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

export async function fetchApi(endpoint: string, options: RequestInit = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const headers = {
    "Content-Type": "application/json",
    ...options.headers,
  };
  
  const response = await fetch(url, {
    ...options,
    headers,
  });
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `API Error: ${response.status} ${response.statusText}`);
  }
  
  return response.json();
}

export const api = {
  // Triage Pipeline
  runTriage: () => fetchApi("/triage/run", { method: "POST" }),
  getTriageStatus: (runId: string) => fetchApi(`/triage/${runId}`),
  
  // Alerts
  getAlerts: (skip = 0, limit = 50) => fetchApi(`/alerts?skip=${skip}&limit=${limit}`),
  uploadAlerts: () => fetchApi("/alerts/upload", { method: "POST" }),
  
  // Incidents
  getIncidents: () => fetchApi("/incidents"),
  getIncident: (id: string) => fetchApi(`/incidents/${id}`),
  reviewIncident: (id: string, decision: string, notes?: string) => 
    fetchApi(`/incidents/${id}/review`, {
      method: "POST",
      body: JSON.stringify({ decision, notes }),
    }),
    
  // Users & IPs
  getUsers: () => fetchApi("/users"),
  getUser: (username: string) => fetchApi(`/users/${username}`),
  getIps: () => fetchApi("/ips"),
  getIp: (ip: string) => fetchApi(`/ips/${ip}`),
  
  // Metrics & Graph
  getMetrics: () => fetchApi("/metrics"),
  getCorrelationGraph: () => fetchApi("/correlation-graph"),
};
