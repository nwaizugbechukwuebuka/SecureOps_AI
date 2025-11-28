import React from 'react';
import { DashboardLayout } from '../../components/layout/DashboardLayout';
import { AIAnalysisSummary } from '../../components/widgets/AIAnalysisSummary';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';

const AIAnalysis: React.FC = () => {
  const [data, setData] = React.useState('');
  const [result, setResult] = React.useState<string | null>(null);

  const handleAnalyze = async () => {
    // TODO: Integrate with aiService
    setResult('No threats detected (dummy result)');
  };

  return (
    <DashboardLayout>
      <h2 className="text-2xl font-bold mb-6">AI Analysis</h2>
      <div className="mb-4">
        <Input label="Data to Analyze" value={data} onChange={e => setData(e.target.value)} />
        <Button className="mt-2" onClick={handleAnalyze}>Run AI Analysis</Button>
      </div>
      {result && <div className="mb-4"><AIAnalysisSummary /></div>}
    </DashboardLayout>
  );
};

export default AIAnalysis;
