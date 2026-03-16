import { useEffect, useState } from "react";
import { fetchDashboards } from "@/lib/api";

export default function DashboardsPage() {
  const [dashboards, setDashboards] = useState<any[]>([]);

  useEffect(() => {
    fetchDashboards().then(setDashboards).catch(console.error);
  }, []);

  return (
    <main className="container">
      <h1>Registered Dashboards</h1>
      <ul>
        {dashboards.map((item) => (
          <li key={item.id}>
            {item.title} | UID: {item.grafana_uid} | Panel: {item.grafana_panel_id || "full dashboard"}
          </li>
        ))}
      </ul>
    </main>
  );
}