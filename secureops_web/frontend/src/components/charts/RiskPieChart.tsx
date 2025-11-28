import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const data = [
  { name: 'High', value: 6 },
  { name: 'Medium', value: 10 },
  { name: 'Low', value: 14 },
];
const COLORS = ['#ef4444', '#facc15', '#22c55e'];

export const RiskPieChart: React.FC = () => (
  <div className="bg-white rounded-lg shadow p-4">
    <h3 className="font-semibold mb-2">Risk Distribution</h3>
    <ResponsiveContainer width="100%" height={250}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  </div>
);
