import React from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';

interface MetricCardProps {
  title: string;
  value: string | number;
  badge?: string;
  color?: 'primary' | 'accent' | 'danger' | 'success' | 'warning';
}

export const MetricCard: React.FC<MetricCardProps> = ({ title, value, badge, color = 'primary' }) => (
  <Card className="flex flex-col items-start gap-2">
    <span className="text-sm text-gray-500">{title}</span>
    <span className="text-2xl font-bold">{value}</span>
    {badge && <Badge color={color}>{badge}</Badge>}
  </Card>
);
