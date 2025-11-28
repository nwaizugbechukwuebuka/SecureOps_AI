import React from 'react';

const activities = [
  { time: '09:00', activity: 'Scan completed', status: 'success' },
  { time: '09:30', activity: 'Threat detected', status: 'danger' },
  { time: '10:00', activity: 'AI analysis run', status: 'accent' },
];

export const ActivityTimeline: React.FC = () => (
  <div className="bg-white rounded-lg shadow p-4">
    <h3 className="font-semibold mb-2">Activity Timeline</h3>
    <ul className="space-y-2">
      {activities.map((item, idx) => (
        <li key={idx} className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${item.status === 'success' ? 'bg-success' : item.status === 'danger' ? 'bg-danger' : 'bg-accent'}`}></span>
          <span className="text-xs text-gray-500">{item.time}</span>
          <span>{item.activity}</span>
        </li>
      ))}
    </ul>
  </div>
);
