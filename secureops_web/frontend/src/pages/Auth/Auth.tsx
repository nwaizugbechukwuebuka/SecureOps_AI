import React from 'react';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { useAuth } from '../../hooks/useAuth';
import { login } from '../../services/authService';

const Auth: React.FC = () => {
  const { user, setUser } = useAuth();
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);

  const handleLogin = async () => {
    try {
      const userData = await login(username, password);
      setUser(userData);
      setError(null);
    } catch (err: any) {
      setError('Invalid credentials');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-50">
      <div className="bg-white rounded-lg shadow p-8 w-full max-w-md">
        <h2 className="text-2xl font-bold mb-6 text-center">Sign In</h2>
        <Input label="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <Input label="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} className="mt-2" />
        {error && <div className="text-danger text-sm mt-2">{error}</div>}
        <Button className="mt-4 w-full" onClick={handleLogin}>Login</Button>
      </div>
    </div>
  );
};

export default Auth;
