import React from 'react';
import { Card } from '../ui/Card';

const summary = {
  result: 'No threats detected',
  confidence: '98%',
  lastRun: '2025-11-27 10:00',
};

export const AIAnalysisSummary: React.FC = () => (
  <Card className="flex flex-col gap-2">
    <h3 className="font-semibold">AI Analysis Summary</h3>
    <span>Result: <span className="font-bold">{summary.result}</span></span>
    <span>Confidence: <span className="font-bold text-success">{summary.confidence}</span></span>
    <span>Last Run: <span className="text-xs text-gray-400">{summary.lastRun}</span></span>
  </Card>
);
