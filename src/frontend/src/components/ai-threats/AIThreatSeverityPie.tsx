import React from "react";
import { AIThreat } from "./useAIThreats";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const COLORS = ["#e53935", "#fb8c00", "#fbc02d", "#43a047"];
const LEVELS = ["critical", "high", "medium", "low"];

const AIThreatSeverityPie: React.FC<{ threats: AIThreat[], loading: boolean }> = ({ threats, loading }) => {
  const counts = LEVELS.map(level => ({
    name: level.charAt(0).toUpperCase() + level.slice(1),
    value: threats.filter(t => t.threat_level === level).length,
  }));

  return (
    <div className="chart-card" style={{ flex: 1, minWidth: 300 }}>
      <h4>Severity Distribution</h4>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={counts} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60}>
            {counts.map((entry, idx) => <Cell key={entry.name} fill={COLORS[idx]} />)}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AIThreatSeverityPie;
