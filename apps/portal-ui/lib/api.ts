const API_BASE = process.env.NEXT_PUBLIC_PORTAL_API_URL || "http://localhost:8080";

export async function fetchSummary() {
  const res = await fetch(`${API_BASE}/api/summary`);
  if (!res.ok) throw new Error("Failed to load summary");
  return res.json();
}

export async function fetchDashboards() {
  const res = await fetch(`${API_BASE}/api/dashboards`);
  if (!res.ok) throw new Error("Failed to load dashboards");
  return res.json();
}