import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const data = [
  { time: '00:00', traffic: 120 },
  { time: '06:00', traffic: 200 },
  { time: '12:00', traffic: 150 },
  { time: '18:00', traffic: 300 },
  { time: '24:00', traffic: 250 },
];

export const TrafficLineChart: React.FC = () => (
  <div className="bg-white rounded-lg shadow p-4">
    <h3 className="font-semibold mb-2">Network Traffic</h3>
    <ResponsiveContainer width="100%" height={250}>
      <LineChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis />
        <Tooltip />
        <Line type="monotone" dataKey="traffic" stroke="#0f172a" strokeWidth={2} dot={{ r: 4 }} />
      </LineChart>
    </ResponsiveContainer>
  </div>
);
