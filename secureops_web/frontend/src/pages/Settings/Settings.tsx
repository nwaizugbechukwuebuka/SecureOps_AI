import React from 'react';
import { DashboardLayout } from '../../components/layout/DashboardLayout';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { useTheme } from '../../hooks/useTheme';

const Settings: React.FC = () => {
  const { theme, setTheme } = useTheme();
  const [apiUrl, setApiUrl] = React.useState('http://localhost:8000');

  return (
    <DashboardLayout>
      <h2 className="text-2xl font-bold mb-6">Settings</h2>
      <div className="mb-4">
        <Input label="API URL" value={apiUrl} onChange={e => setApiUrl(e.target.value)} />
        <Button className="mt-2" onClick={() => alert('API URL saved!')}>Save</Button>
      </div>
      <div className="mb-4">
        <span className="font-semibold">Theme:</span>
        <select className="ml-2 px-2 py-1 border rounded" value={theme} onChange={e => setTheme(e.target.value)}>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
