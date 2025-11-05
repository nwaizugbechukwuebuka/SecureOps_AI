import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { initializeTheme } from './utils/theme';
import { useRealTimeNotifications } from './components/NotificationToast';

// Pages
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Settings from './pages/Settings';
import Alerts from './pages/Alerts';
import Users from './pages/Users';

// Components
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import NotificationToast from './components/NotificationToast';
import LoadingSpinner from './components/LoadingSpinner';

// Styles
import './styles/global.css';
import './styles/dashboard.css';

// Main App Layout Component
const AppLayout = () => {
  const { isAuthenticated, loading, user } = useAuth();
  const [sidebarOpen, setSidebarOpen] = React.useState(false);

  // Initialize real-time notifications for authenticated users
  useRealTimeNotifications();

  if (loading) {
    return (
      <LoadingSpinner 
        fullScreen 
        size="large" 
        text="Loading SecureOps AI..." 
      />
    );
  }

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Navbar 
        user={user}
        onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} 
      />
      
      <div className="flex">
        <Sidebar 
          isOpen={sidebarOpen} 
          onClose={() => setSidebarOpen(false)}
          user={user}
        />
        
        <main className="flex-1 min-h-screen">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/users" element={<Users />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
};

// Main App Component
export default function App() {
  useEffect(() => {
    // Initialize theme on app start
    initializeTheme();
  }, []);

  return (
    <AuthProvider>
      <Router>
        <AppLayout />
        <NotificationToast />
      </Router>
    </AuthProvider>
  );
}