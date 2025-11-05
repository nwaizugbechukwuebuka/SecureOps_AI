
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import { AuthProvider } from './context/AuthContext';
import { NotificationProvider } from './context/NotificationContext';
import ProtectedRoute, { AdminRoute, AnalystRoute, PermissionGate } from './components/ProtectedRoute';
import NotificationToast from './components/NotificationToast';
import MainLayout from './layout/MainLayout.jsx';
import Dashboard from './components/Dashboard.jsx';
import Login from './components/Login.jsx';
import SecurityAnalytics from './modules/SecurityAnalytics.jsx';
import UserManagement from './modules/UserManagement.jsx';
import SystemHealth from './modules/SystemHealth.jsx';
import AutomationAI from './modules/AutomationAI.jsx';
import LogsEvents from './modules/LogsEvents.jsx';
import Notifications from './modules/Notifications.jsx';

export default function App() {
  return (
    <NotificationProvider>
      <AuthProvider>
        <Router>
          <div className="app">
            <Routes>
              {/* Public Routes */}
              <Route path="/login" element={<PublicRoute />} />
              
              {/* Protected Routes with Role-Based Access */}
              <Route 
                path="/" 
                element={
                  <ProtectedRoute>
                    <MainLayoutWithAuth />
                  </ProtectedRoute>
                }
              >
                {/* Dashboard - All authenticated users */}
                <Route index element={<Dashboard />} />
                
                {/* Security Analytics - Analyst+ access */}
                <Route 
                  path="analytics" 
                  element={
                    <AnalystRoute>
                      <SecurityAnalytics />
                    </AnalystRoute>
                  } 
                />
                
                {/* User Management - Admin only */}
                <Route 
                  path="users" 
                  element={
                    <AdminRoute>
                      <UserManagement />
                    </AdminRoute>
                  } 
                />
                
                {/* System Health - Analyst+ access */}
                <Route 
                  path="system" 
                  element={
                    <AnalystRoute>
                      <SystemHealth />
                    </AnalystRoute>
                  } 
                />
                
                {/* Automation AI - Analyst+ access */}
                <Route 
                  path="tasks" 
                  element={
                    <AnalystRoute>
                      <AutomationAI />
                    </AnalystRoute>
                  } 
                />
                
                {/* Logs & Events - Analyst+ access */}
                <Route 
                  path="logs" 
                  element={
                    <AnalystRoute>
                      <LogsEvents />
                    </AnalystRoute>
                  } 
                />
                
                {/* Notifications - All authenticated users */}
                <Route path="notifications" element={<Notifications />} />
                
                {/* Admin Routes */}
                <Route path="admin/*" element={<AdminRoutes />} />
                
                {/* Analyst Routes */}
                <Route path="analyst/*" element={<AnalystRoutes />} />
                
                {/* Viewer Routes */}
                <Route path="viewer/*" element={<ViewerRoutes />} />
              </Route>
              
              {/* Catch all route */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
            
            {/* Global Notification Toast */}
            <NotificationToast />
          </div>
        </Router>
      </AuthProvider>
    </NotificationProvider>
  );
}

// Public Route Handler (Login)
const PublicRoute = () => {
  const { isAuthenticated, user } = useAuth();
  const location = useLocation();
  
  if (isAuthenticated && user) {
    // Redirect to appropriate dashboard based on role
    const returnTo = location.state?.from || getUserRoleDashboard(user.role);
    return <Navigate to={returnTo} replace />;
  }
  
  return <Login onLoginSuccess={(user) => {
    // Login success is handled by AuthContext
    console.log('Login successful for user:', user);
  }} />;
};

// Main Layout with Authentication
const MainLayoutWithAuth = () => {
  const { logout } = useAuth();
  
  return (
    <MainLayout onLogout={logout}>
      <Outlet />
    </MainLayout>
  );
};

// Role-based route groups
const AdminRoutes = () => (
  <Routes>
    <Route path="dashboard" element={<AdminDashboard />} />
    <Route path="users" element={<UserManagement />} />
    <Route path="system-config" element={<SystemConfiguration />} />
    <Route path="audit-logs" element={<AuditLogViewer />} />
    <Route path="security-settings" element={<SecuritySettings />} />
    <Route path="*" element={<Navigate to="/admin/dashboard" replace />} />
  </Routes>
);

const AnalystRoutes = () => (
  <Routes>
    <Route path="dashboard" element={<AnalystDashboard />} />
    <Route path="analytics" element={<SecurityAnalytics />} />
    <Route path="incidents" element={<IncidentManagement />} />
    <Route path="reports" element={<SecurityReports />} />
    <Route path="*" element={<Navigate to="/analyst/dashboard" replace />} />
  </Routes>
);

const ViewerRoutes = () => (
  <Routes>
    <Route path="dashboard" element={<ViewerDashboard />} />
    <Route path="reports" element={<ReadOnlyReports />} />
    <Route path="*" element={<Navigate to="/viewer/dashboard" replace />} />
  </Routes>
);

// Helper function to determine dashboard route based on role
const getUserRoleDashboard = (role) => {
  switch (role) {
    case 'admin':
      return '/admin/dashboard';
    case 'analyst':
      return '/analyst/dashboard';
    case 'viewer':
      return '/viewer/dashboard';
    default:
      return '/';
  }
};

// Placeholder components for role-specific dashboards
const AdminDashboard = () => <Dashboard adminMode={true} />;
const AnalystDashboard = () => <Dashboard analystMode={true} />;
const ViewerDashboard = () => <Dashboard viewerMode={true} />;
const SystemConfiguration = () => <div>System Configuration (Admin Only)</div>;
const AuditLogViewer = () => <div>Audit Log Viewer (Admin Only)</div>;
const SecuritySettings = () => <div>Security Settings (Admin Only)</div>;
const IncidentManagement = () => <div>Incident Management (Analyst+)</div>;
const SecurityReports = () => <div>Security Reports (Analyst+)</div>;
const ReadOnlyReports = () => <div>Read-Only Reports (Viewer)</div>;
