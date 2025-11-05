import React from "react";
import { useAIThreats } from "./useAIThreats";
import AIThreatSummaryCards from "./AIThreatSummaryCards";
import AIThreatTrendsChart from "./AIThreatTrendsChart";
import AIThreatSeverityPie from "./AIThreatSeverityPie";
import AIThreatsTable from "./AIThreatsTable";

const AIThreatDashboard: React.FC<{ pipelineId: number }> = ({ pipelineId }) => {
  const { threats, summary, loading, error, refetch } = useAIThreats(pipelineId);

  return (
    <section>
      <h2>AI-Detected Threats</h2>
      {error && <div className="error">{error}</div>}
      <AIThreatSummaryCards summary={summary} loading={loading} />
      <div className="dashboard-charts" style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        <AIThreatTrendsChart threats={threats} loading={loading} />
        <AIThreatSeverityPie threats={threats} loading={loading} />
      </div>
      <AIThreatsTable threats={threats} loading={loading} onRefresh={refetch} />
    </section>
  );
};

export default AIThreatDashboard;
