import React from "react";
import { AIThreat } from "./useAIThreats";

const AIThreatsTable: React.FC<{ threats: AIThreat[], loading: boolean, onRefresh: () => void }> = ({ threats, loading, onRefresh }) => (
  <div className="table-card" style={{ marginTop: 32 }}>
    <h4>
      Recent AI-Detected Threats
      <button onClick={onRefresh} style={{ float: "right" }}>Refresh</button>
    </h4>
    <table style={{ width: "100%", borderCollapse: "collapse" }}>
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Risk Score</th>
          <th>File</th>
          <th>Line</th>
          <th>Title</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {loading ? (
          <tr><td colSpan={7}>Loading...</td></tr>
        ) : threats.length === 0 ? (
          <tr><td colSpan={7}>No AI threats detected.</td></tr>
        ) : (
          threats.map((t, i) => (
            <tr key={i}>
              <td>{t.event?.created_at?.replace('T', ' ').slice(0, 19) || "-"}</td>
              <td style={{ color: t.threat_level === "critical" ? "#e53935" : t.threat_level === "high" ? "#fb8c00" : t.threat_level === "medium" ? "#fbc02d" : "#43a047" }}>
                {t.threat_level}
              </td>
              <td>{t.risk_score}</td>
              <td>{t.event?.file_path || "-"}</td>
              <td>{t.event?.line_number || "-"}</td>
              <td>{t.event?.title || "-"}</td>
              <td>{t.details}</td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  </div>
);

export default AIThreatsTable;
