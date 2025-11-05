import React from "react";
import { AIThreatSummary } from "./useAIThreats";

const colors = { critical: "#e53935", high: "#fb8c00", medium: "#fbc02d", low: "#43a047" };

const AIThreatSummaryCards: React.FC<{ summary: AIThreatSummary | null, loading: boolean }> = ({ summary, loading }) => (
  <div className="summary-cards" style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
    {["count", "critical", "high", "medium", "low"].map((key) => (
      <div key={key} className="card" style={{ border: `2px solid ${colors[key as keyof typeof colors] || "#1976d2"}`, borderRadius: 8, padding: 16, minWidth: 100, textAlign: 'center' }}>
        <div className="card-title" style={{ fontWeight: 600, marginBottom: 8 }}>{key === "count" ? "Total" : key.charAt(0).toUpperCase() + key.slice(1)}</div>
        <div className="card-value" style={{ fontSize: 24 }}>{loading ? "..." : summary?.[key as keyof AIThreatSummary] ?? 0}</div>
      </div>
    ))}
  </div>
);

export default AIThreatSummaryCards;
