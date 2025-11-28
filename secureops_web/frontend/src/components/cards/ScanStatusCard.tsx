import React from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';

interface ScanStatusCardProps {
  status: 'Completed' | 'Running' | 'Failed';
  lastScan: string;
}

export const ScanStatusCard: React.FC<ScanStatusCardProps> = ({ status, lastScan }) => {
  const color = status === 'Completed' ? 'success' : status === 'Running' ? 'accent' : 'danger';
  return (
    <Card className="flex flex-col items-start gap-2">
      <span className="text-sm text-gray-500">Scan Status</span>
      <span className="text-2xl font-bold">{status}</span>
      <Badge color={color}>{lastScan}</Badge>
    </Card>
  );
};
