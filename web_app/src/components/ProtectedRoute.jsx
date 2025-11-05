/**
 * Protected Route Component with Role-Based Access Control
 * Controls access to routes based on user authentication and role permissions
 */

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useNotification } from '../context/NotificationContext';

const ProtectedRoute = ({ 
  children, 
  requiredRole = null, 
  requiredPermission = null, 
  fallbackPath = '/login',
  showUnauthorizedMessage = true 
}) => {
  const { isAuthenticated, user, loading, hasRole, hasPermission } = useAuth();
  const { showAuthError } = useNotification();
  const location = useLocation();

  // Show loading state while checking authentication
  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Verifying access...</p>
        </div>
      </div>
    );
  }

  // Check if user is authenticated
  if (!isAuthenticated || !user) {
    if (showUnauthorizedMessage) {
      showAuthError('Please log in to access this page');
    }
    
    // Redirect to login with return URL
    return (
      <Navigate 
        to={fallbackPath} 
        state={{ from: location.pathname }} 
        replace 
      />
    );
  }

  // Check role-based access
  if (requiredRole && !hasRole(requiredRole)) {
    if (showUnauthorizedMessage) {
      showAuthError(`Access denied. Required role: ${requiredRole.toUpperCase()}`);
    }
    
    // Redirect to appropriate dashboard based on user role
    const redirectPath = getUserRoleDashboard(user.role);
    return <Navigate to={redirectPath} replace />;
  }

  // Check permission-based access
  if (requiredPermission && !hasPermission(requiredPermission)) {
    if (showUnauthorizedMessage) {
      showAuthError(`Access denied. Missing permission: ${requiredPermission}`);
    }
    
    // Redirect to appropriate dashboard based on user role
    const redirectPath = getUserRoleDashboard(user.role);
    return <Navigate to={redirectPath} replace />;
  }

  // User has access, render the protected content
  return children;
};

// Helper function to get appropriate dashboard based on user role
const getUserRoleDashboard = (userRole) => {
  switch (userRole) {
    case 'admin':
      return '/admin/dashboard';
    case 'analyst':
      return '/analyst/dashboard';
    case 'viewer':
      return '/viewer/dashboard';
    default:
      return '/dashboard';
  }
};

// Higher-order component for role-based route protection
export const withRoleProtection = (Component, requiredRole, options = {}) => {
  return (props) => (
    <ProtectedRoute 
      requiredRole={requiredRole}
      {...options}
    >
      <Component {...props} />
    </ProtectedRoute>
  );
};

// Higher-order component for permission-based route protection
export const withPermissionProtection = (Component, requiredPermission, options = {}) => {
  return (props) => (
    <ProtectedRoute 
      requiredPermission={requiredPermission}
      {...options}
    >
      <Component {...props} />
    </ProtectedRoute>
  );
};

// Specialized components for different access levels
export const AdminRoute = ({ children, ...props }) => (
  <ProtectedRoute requiredRole="admin" {...props}>
    {children}
  </ProtectedRoute>
);

export const AnalystRoute = ({ children, ...props }) => (
  <ProtectedRoute requiredRole="analyst" {...props}>
    {children}
  </ProtectedRoute>
);

export const ViewerRoute = ({ children, ...props }) => (
  <ProtectedRoute requiredRole="viewer" {...props}>
    {children}
  </ProtectedRoute>
);

// Component for conditional rendering based on permissions
export const PermissionGate = ({ 
  children, 
  requiredRole = null, 
  requiredPermission = null,
  fallback = null,
  hideOnUnauthorized = true
}) => {
  const { isAuthenticated, user, hasRole, hasPermission } = useAuth();

  // Not authenticated
  if (!isAuthenticated || !user) {
    return hideOnUnauthorized ? null : fallback;
  }

  // Check role requirement
  if (requiredRole && !hasRole(requiredRole)) {
    return hideOnUnauthorized ? null : fallback;
  }

  // Check permission requirement
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return hideOnUnauthorized ? null : fallback;
  }

  // User has access
  return children;
};

// Hook for checking access in components
export const useAccessControl = () => {
  const { isAuthenticated, user, hasRole, hasPermission } = useAuth();

  const checkAccess = (requirements) => {
    if (!isAuthenticated || !user) {
      return false;
    }

    if (requirements.role && !hasRole(requirements.role)) {
      return false;
    }

    if (requirements.permission && !hasPermission(requirements.permission)) {
      return false;
    }

    if (requirements.userId && user.id !== requirements.userId) {
      return false;
    }

    return true;
  };

  const getAccessLevel = () => {
    if (!isAuthenticated || !user) return 'none';
    return user.role || 'viewer';
  };

  const canAccess = {
    adminPanel: () => hasRole('admin'),
    userManagement: () => hasRole('admin') || hasPermission('manage_users'),
    auditLogs: () => hasRole('analyst') || hasPermission('view_audit_logs'),
    securitySettings: () => hasRole('admin'),
    dashboard: () => isAuthenticated,
    profile: () => isAuthenticated
  };

  return {
    checkAccess,
    getAccessLevel,
    canAccess,
    isAuthenticated,
    user,
    hasRole,
    hasPermission
  };
};

export default ProtectedRoute;