import React from "react";
import { AIThreat } from "./useAIThreats";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

const AIThreatTrendsChart: React.FC<{ threats: AIThreat[], loading: boolean }> = ({ threats, loading }) => {
  const data = threats.reduce((acc, t) => {
    const date = t.event?.created_at?.slice(0, 10) || "Unknown";
    acc[date] = (acc[date] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const chartData = Object.entries(data).map(([date, count]) => ({ date, count }));

  return (
    <div className="chart-card" style={{ flex: 1, minWidth: 300 }}>
      <h4>AI Threats Over Time</h4>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={chartData}>
          <XAxis dataKey="date" />
          <YAxis allowDecimals={false} />
          <Tooltip />
          <Line type="monotone" dataKey="count" stroke="#1976d2" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AIThreatTrendsChart;
