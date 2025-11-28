import React from 'react';
import { Table } from '../ui/Table';

const columns = ['Target', 'Type', 'Status', 'Date'];
const data = [
  { Target: '192.168.1.1', Type: 'Basic', Status: 'Completed', Date: '2025-11-26' },
  { Target: '10.0.0.2', Type: 'AI', Status: 'Running', Date: '2025-11-27' },
  { Target: '172.16.0.3', Type: 'Advanced', Status: 'Failed', Date: '2025-11-25' },
];

export const RecentScansWidget: React.FC = () => (
  <div className="bg-white rounded-lg shadow p-4">
    <h3 className="font-semibold mb-2">Recent Scans</h3>
    <Table columns={columns} data={data} />
  </div>
);
