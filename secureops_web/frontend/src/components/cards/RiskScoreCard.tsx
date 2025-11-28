import React from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';

interface RiskScoreCardProps {
  score: number;
  level: 'High' | 'Medium' | 'Low';
}

export const RiskScoreCard: React.FC<RiskScoreCardProps> = ({ score, level }) => {
  const color = level === 'High' ? 'danger' : level === 'Medium' ? 'warning' : 'success';
  return (
    <Card className="flex flex-col items-start gap-2">
      <span className="text-sm text-gray-500">Risk Score</span>
      <span className="text-2xl font-bold">{score}</span>
      <Badge color={color}>{level}</Badge>
    </Card>
  );
};
