import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const data = [
  { date: 'Mon', scans: 5 },
  { date: 'Tue', scans: 8 },
  { date: 'Wed', scans: 6 },
  { date: 'Thu', scans: 10 },
  { date: 'Fri', scans: 7 },
];

export const ScanHistoryAreaChart: React.FC = () => (
  <div className="bg-white rounded-lg shadow p-4">
    <h3 className="font-semibold mb-2">Scan History</h3>
    <ResponsiveContainer width="100%" height={250}>
      <AreaChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
        <defs>
          <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#38bdf8" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="date" />
        <YAxis />
        <Tooltip />
        <Area type="monotone" dataKey="scans" stroke="#38bdf8" fillOpacity={1} fill="url(#colorScans)" />
      </AreaChart>
    </ResponsiveContainer>
  </div>
);
