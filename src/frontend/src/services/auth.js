import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { api, handleApiError } from './api';

// Initial state
const initialState = {
  user: null,
  isAuthenticated: false,
  loading: true,
  error: null,
  permissions: [],
  preferences: {},
};

// Action types
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  LOAD_USER_START: 'LOAD_USER_START',
  LOAD_USER_SUCCESS: 'LOAD_USER_SUCCESS',
  LOAD_USER_FAILURE: 'LOAD_USER_FAILURE',
  UPDATE_PROFILE: 'UPDATE_PROFILE',
  CLEAR_ERROR: 'CLEAR_ERROR',
  SET_PREFERENCES: 'SET_PREFERENCES',
};

// Reducer
const authReducer = (state, action) => {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
    case AUTH_ACTIONS.LOAD_USER_START:
      return {
        ...state,
        loading: true,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_SUCCESS:
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: true,
        loading: false,
        error: null,
        permissions: action.payload.permissions || [],
      };

    case AUTH_ACTIONS.LOAD_USER_SUCCESS:
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: true,
        loading: false,
        error: null,
        permissions: action.payload.permissions || [],
        preferences: action.payload.preferences || {},
      };

    case AUTH_ACTIONS.LOGIN_FAILURE:
    case AUTH_ACTIONS.LOAD_USER_FAILURE:
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        loading: false,
        error: action.payload.error,
        permissions: [],
        preferences: {},
      };

    case AUTH_ACTIONS.LOGOUT:
      return {
        ...initialState,
        loading: false,
      };

    case AUTH_ACTIONS.UPDATE_PROFILE:
      return {
        ...state,
        user: {
          ...state.user,
          ...action.payload,
        },
      };

    case AUTH_ACTIONS.SET_PREFERENCES:
      return {
        ...state,
        preferences: {
          ...state.preferences,
          ...action.payload,
        },
      };

    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null,
      };

    default:
      return state;
  }
};

// Create context
const AuthContext = createContext();

// Auth provider component
export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Check for existing authentication on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('access_token');
      const savedUser = localStorage.getItem('user');

      if (token && savedUser) {
        try {
          // Verify token is still valid by fetching user profile
          const response = await api.users.getProfile();
          
          dispatch({
            type: AUTH_ACTIONS.LOAD_USER_SUCCESS,
            payload: {
              user: response.data,
              permissions: response.data.permissions || [],
              preferences: response.data.preferences || {},
            },
          });
        } catch (error) {
          // Token is invalid, clear auth data
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('user');
          
          dispatch({
            type: AUTH_ACTIONS.LOAD_USER_FAILURE,
            payload: { error: 'Session expired' },
          });
        }
      } else {
        dispatch({
          type: AUTH_ACTIONS.LOAD_USER_FAILURE,
          payload: { error: null },
        });
      }
    };

    checkAuth();
  }, []);

  // Login function
  const login = async (credentials) => {
    try {
      dispatch({ type: AUTH_ACTIONS.LOGIN_START });

      const response = await api.auth.login(credentials);
      
      dispatch({
        type: AUTH_ACTIONS.LOGIN_SUCCESS,
        payload: {
          user: response.user,
          permissions: response.permissions || [],
        },
      });

      return { success: true, user: response.user };
    } catch (error) {
      const errorMessage = handleApiError(error, 'Login failed');
      
      dispatch({
        type: AUTH_ACTIONS.LOGIN_FAILURE,
        payload: { error: errorMessage },
      });

      return { success: false, error: errorMessage };
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await api.auth.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
    }
  };

  // Register function
  const register = async (userData) => {
    try {
      const response = await api.auth.register(userData);
      return { success: true, data: response.data };
    } catch (error) {
      const errorMessage = handleApiError(error, 'Registration failed');
      return { success: false, error: errorMessage };
    }
  };

  // Update profile function
  const updateProfile = async (profileData) => {
    try {
      const response = await api.users.updateProfile(profileData);
      
      dispatch({
        type: AUTH_ACTIONS.UPDATE_PROFILE,
        payload: response.data,
      });

      return { success: true, user: response.data };
    } catch (error) {
      const errorMessage = handleApiError(error, 'Profile update failed');
      return { success: false, error: errorMessage };
    }
  };

  // Change password function
  const changePassword = async (passwordData) => {
    try {
      await api.auth.changePassword(passwordData);
      return { success: true };
    } catch (error) {
      const errorMessage = handleApiError(error, 'Password change failed');
      return { success: false, error: errorMessage };
    }
  };

  // Reset password function
  const resetPassword = async (email) => {
    try {
      await api.auth.resetPassword(email);
      return { success: true };
    } catch (error) {
      const errorMessage = handleApiError(error, 'Password reset failed');
      return { success: false, error: errorMessage };
    }
  };

  // Verify email function
  const verifyEmail = async (token) => {
    try {
      await api.auth.verifyEmail(token);
      return { success: true };
    } catch (error) {
      const errorMessage = handleApiError(error, 'Email verification failed');
      return { success: false, error: errorMessage };
    }
  };

  // Update preferences function
  const updatePreferences = (preferences) => {
    dispatch({
      type: AUTH_ACTIONS.SET_PREFERENCES,
      payload: preferences,
    });

    // Persist preferences to localStorage
    localStorage.setItem('preferences', JSON.stringify(preferences));
  };

  // Clear error function
  const clearError = () => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR });
  };

  // Permission checking utilities
  const hasPermission = (permission) => {
    return state.permissions.includes(permission);
  };

  const hasAnyPermission = (permissions) => {
    return permissions.some(permission => state.permissions.includes(permission));
  };

  const hasAllPermissions = (permissions) => {
    return permissions.every(permission => state.permissions.includes(permission));
  };

  // Role checking utilities
  const hasRole = (role) => {
    return state.user?.roles?.includes(role) || false;
  };

  const isAdmin = () => {
    return hasRole('admin') || hasRole('superuser');
  };

  const isModerator = () => {
    return hasRole('moderator') || isAdmin();
  };

  // Context value
  const value = {
    // State
    ...state,
    
    // Actions
    login,
    logout,
    register,
    updateProfile,
    changePassword,
    resetPassword,
    verifyEmail,
    updatePreferences,
    clearError,
    
    // Utilities
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    hasRole,
    isAdmin,
    isModerator,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
};

// Higher-order component for protecting routes
export const withAuth = (Component, requiredPermissions = []) => {
  return (props) => {
    const { isAuthenticated, loading, hasAnyPermission } = useAuth();

    // Show loading while checking authentication
    if (loading) {
      return (
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh' 
        }}>
          Loading...
        </div>
      );
    }

    // Redirect to login if not authenticated
    if (!isAuthenticated) {
      window.location.href = '/login';
      return null;
    }

    // Check permissions if required
    if (requiredPermissions.length > 0 && !hasAnyPermission(requiredPermissions)) {
      return (
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh',
          flexDirection: 'column'
        }}>
          <h2>Access Denied</h2>
          <p>You don't have permission to access this resource.</p>
        </div>
      );
    }

    return <Component {...props} />;
  };
};

// Protected route component
export const ProtectedRoute = ({ 
  children, 
  requiredPermissions = [], 
  requiredRoles = [],
  fallback = null 
}) => {
  const { 
    isAuthenticated, 
    loading, 
    hasAnyPermission, 
    hasRole 
  } = useAuth();

  // Show loading while checking authentication
  if (loading) {
    return fallback || (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        Loading...
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    window.location.href = '/login';
    return null;
  }

  // Check permissions
  if (requiredPermissions.length > 0 && !hasAnyPermission(requiredPermissions)) {
    return fallback || (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        flexDirection: 'column'
      }}>
        <h2>Access Denied</h2>
        <p>You don't have the required permissions.</p>
      </div>
    );
  }

  // Check roles
  if (requiredRoles.length > 0 && !requiredRoles.some(role => hasRole(role))) {
    return fallback || (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        flexDirection: 'column'
      }}>
        <h2>Access Denied</h2>
        <p>You don't have the required role.</p>
      </div>
    );
  }

  return children;
};

// Login form component
export const LoginForm = ({ onSuccess, onError }) => {
  const { login, loading, error } = useAuth();
  const [credentials, setCredentials] = React.useState({
    email: '',
    password: '',
    remember: false,
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const result = await login(credentials);
    
    if (result.success) {
      if (onSuccess) onSuccess(result.user);
    } else {
      if (onError) onError(result.error);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setCredentials(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="email">Email:</label>
        <input
          type="email"
          id="email"
          name="email"
          value={credentials.email}
          onChange={handleChange}
          required
        />
      </div>
      
      <div>
        <label htmlFor="password">Password:</label>
        <input
          type="password"
          id="password"
          name="password"
          value={credentials.password}
          onChange={handleChange}
          required
        />
      </div>
      
      <div>
        <label>
          <input
            type="checkbox"
            name="remember"
            checked={credentials.remember}
            onChange={handleChange}
          />
          Remember me
        </label>
      </div>
      
      {error && <div style={{ color: 'red' }}>{error}</div>}
      
      <button type="submit" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
};

// User profile component
export const UserProfile = () => {
  const { user, updateProfile, loading } = useAuth();
  const [profile, setProfile] = React.useState({
    first_name: '',
    last_name: '',
    email: '',
    phone: '',
    timezone: '',
  });

  React.useEffect(() => {
    if (user) {
      setProfile({
        first_name: user.first_name || '',
        last_name: user.last_name || '',
        email: user.email || '',
        phone: user.phone || '',
        timezone: user.timezone || '',
      });
    }
  }, [user]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await updateProfile(profile);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setProfile(prev => ({
      ...prev,
      [name]: value,
    }));
  };

  if (!user) return null;

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="first_name">First Name:</label>
        <input
          type="text"
          id="first_name"
          name="first_name"
          value={profile.first_name}
          onChange={handleChange}
        />
      </div>
      
      <div>
        <label htmlFor="last_name">Last Name:</label>
        <input
          type="text"
          id="last_name"
          name="last_name"
          value={profile.last_name}
          onChange={handleChange}
        />
      </div>
      
      <div>
        <label htmlFor="email">Email:</label>
        <input
          type="email"
          id="email"
          name="email"
          value={profile.email}
          onChange={handleChange}
          disabled
        />
      </div>
      
      <div>
        <label htmlFor="phone">Phone:</label>
        <input
          type="tel"
          id="phone"
          name="phone"
          value={profile.phone}
          onChange={handleChange}
        />
      </div>
      
      <button type="submit" disabled={loading}>
        {loading ? 'Updating...' : 'Update Profile'}
      </button>
    </form>
  );
};

// Default export
export default {
  AuthProvider,
  useAuth,
  withAuth,
  ProtectedRoute,
  LoginForm,
  UserProfile,
};
