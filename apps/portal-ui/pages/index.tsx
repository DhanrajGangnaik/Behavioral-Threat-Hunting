import { useEffect, useState } from "react";
import EmbeddedGrafana from "../components/EmbeddedGrafana";
import KpiCard from "../components/KpiCard";
import { fetchDashboards, fetchSummary } from "../lib/api";

type Summary = {
  stats: {
    total_lines: number;
    total_alerts: number;
    active_incidents: number;
    top_incidents: Array<{ source_ip: string; category: string; path: string; count: number }>;
  };
  recent_alerts: Array<{ category: string; severity: string; path: string; source_ip: string }>;
};

type Dashboard = {
  id: number;
  title: string;
  grafana_uid: string;
  grafana_panel_id?: string | null;
};

const GRAFANA_PUBLIC = process.env.NEXT_PUBLIC_GRAFANA_URL || "http://localhost:3000";

function buildEmbed(d: Dashboard) {
  if (d.grafana_panel_id) {
    return `${GRAFANA_PUBLIC}/d-solo/${d.grafana_uid}?panelId=${d.grafana_panel_id}&theme=dark`;
  }
  return `${GRAFANA_PUBLIC}/d/${d.grafana_uid}`;
}

export default function HomePage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);

  useEffect(() => {
    fetchSummary().then(setSummary).catch(console.error);
    fetchDashboards().then(setDashboards).catch(console.error);
  }, []);

  return (
    <main className="container">
      <h1>Behavioral Threat Hunting Portal</h1>
      <p className="muted">
        Primary landing page abstracting Grafana, Prometheus, Loki and Sentinel.
      </p>

      <section className="grid">
        <KpiCard label="Processed Log Lines" value={summary?.stats.total_lines ?? 0} />
        <KpiCard label="Total Alerts" value={summary?.stats.total_alerts ?? 0} />
        <KpiCard label="Active Incidents" value={summary?.stats.active_incidents ?? 0} />
      </section>

      <section className="card">
        <h2>Recent Alerts</h2>
        <ul>
          {(summary?.recent_alerts ?? []).map((item, idx) => (
            <li key={idx}>
              <strong>{item.category}</strong> | {item.severity} | {item.source_ip} | {item.path}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Pinned Dashboards</h2>
        <div className="grid">
          {dashboards.map((d) => (
            <EmbeddedGrafana key={d.id} title={d.title} src={buildEmbed(d)} />
          ))}
        </div>
      </section>
    </main>
  );
}