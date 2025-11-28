import React from 'react';
import { Badge } from '../ui/Badge';

const feed = [
  { title: 'New Malware Variant', level: 'High', time: '2m ago' },
  { title: 'Phishing Campaign', level: 'Medium', time: '10m ago' },
  { title: 'DDoS Alert', level: 'Low', time: '1h ago' },
];

export const ThreatIntelFeed: React.FC = () => (
  <div className="bg-white rounded-lg shadow p-4">
    <h3 className="font-semibold mb-2">Threat Intel Feed</h3>
    <ul className="space-y-2">
      {feed.map((item, idx) => (
        <li key={idx} className="flex items-center justify-between">
          <span>{item.title}</span>
          <Badge color={item.level === 'High' ? 'danger' : item.level === 'Medium' ? 'warning' : 'accent'}>{item.level}</Badge>
          <span className="text-xs text-gray-400 ml-2">{item.time}</span>
        </li>
      ))}
    </ul>
  </div>
);
