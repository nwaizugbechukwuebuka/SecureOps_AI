import React, { useEffect } from 'react';
import { Toaster, toast } from 'react-hot-toast';
import { useTheme } from '../utils/theme';
import { 
  CheckCircle, 
  AlertCircle, 
  XCircle, 
  Info, 
  X 
} from 'lucide-react';

// Custom toast component
const CustomToast = ({ type, message, onClose }) => {
  const { isDark } = useTheme();

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'warning':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      default:
        return <Info className="w-5 h-5 text-blue-500" />;
    }
  };

  const getBgColor = () => {
    if (isDark) {
      return 'bg-gray-800 border-gray-700';
    }
    return 'bg-white border-gray-200';
  };

  return (
    <div className={`
      flex items-center p-4 rounded-lg border shadow-lg max-w-sm
      ${getBgColor()}
      ${isDark ? 'text-white' : 'text-gray-900'}
    `}>
      <div className="flex-shrink-0 mr-3">
        {getIcon()}
      </div>
      
      <div className="flex-1 text-sm font-medium">
        {message}
      </div>
      
      {onClose && (
        <button
          onClick={onClose}
          className={`
            ml-3 flex-shrink-0 p-1 rounded-full transition-colors
            ${isDark ? 'hover:bg-gray-700' : 'hover:bg-gray-100'}
          `}
        >
          <X className="w-4 h-4" />
        </button>
      )}
    </div>
  );
};

// Main notification toast component
const NotificationToast = () => {
  const { isDark } = useTheme();

  return (
    <Toaster
      position="top-right"
      reverseOrder={false}
      gutter={8}
      containerClassName=""
      containerStyle={{}}
      toastOptions={{
        className: '',
        duration: 4000,
        style: {
          background: 'transparent',
          boxShadow: 'none',
          padding: 0,
          margin: 0,
        },
        success: {
          duration: 3000,
          iconTheme: {
            primary: '#10b981',
            secondary: '#ffffff',
          },
        },
        error: {
          duration: 5000,
          iconTheme: {
            primary: '#ef4444',
            secondary: '#ffffff',
          },
        },
      }}
    />
  );
};

// Utility functions for creating different types of toasts
export const showToast = {
  success: (message) => {
    toast.custom((t) => (
      <CustomToast
        type="success"
        message={message}
        onClose={() => toast.dismiss(t.id)}
      />
    ), {
      duration: 3000,
    });
  },

  error: (message) => {
    toast.custom((t) => (
      <CustomToast
        type="error"
        message={message}
        onClose={() => toast.dismiss(t.id)}
      />
    ), {
      duration: 5000,
    });
  },

  warning: (message) => {
    toast.custom((t) => (
      <CustomToast
        type="warning"
        message={message}
        onClose={() => toast.dismiss(t.id)}
      />
    ), {
      duration: 4000,
    });
  },

  info: (message) => {
    toast.custom((t) => (
      <CustomToast
        type="info"
        message={message}
        onClose={() => toast.dismiss(t.id)}
      />
    ), {
      duration: 4000,
    });
  },

  loading: (message) => {
    return toast.loading(message, {
      style: {
        background: 'var(--color-surface)',
        color: 'var(--color-text)',
        border: '1px solid var(--color-border)',
      },
    });
  },

  promise: (promise, { loading, success, error }) => {
    return toast.promise(promise, {
      loading,
      success,
      error,
    }, {
      style: {
        background: 'var(--color-surface)',
        color: 'var(--color-text)',
        border: '1px solid var(--color-border)',
      },
    });
  },

  dismiss: (toastId) => {
    toast.dismiss(toastId);
  },

  dismissAll: () => {
    toast.dismiss();
  },
};

// Security-specific toast notifications
export const securityToast = {
  threatDetected: (threatLevel, description) => {
    const message = `${threatLevel.toUpperCase()} threat detected: ${description}`;
    
    switch (threatLevel.toLowerCase()) {
      case 'critical':
        showToast.error(message);
        break;
      case 'high':
        showToast.warning(message);
        break;
      default:
        showToast.info(message);
    }
  },

  systemAlert: (message) => {
    showToast.warning(`System Alert: ${message}`);
  },

  userAction: (action, success = true) => {
    if (success) {
      showToast.success(`${action} completed successfully`);
    } else {
      showToast.error(`Failed to ${action.toLowerCase()}`);
    }
  },

  loginSuccess: (username) => {
    showToast.success(`Welcome back, ${username}!`);
  },

  loginFailed: (reason) => {
    showToast.error(`Login failed: ${reason}`);
  },

  sessionExpired: () => {
    showToast.warning('Your session has expired. Please log in again.');
  },

  permissionDenied: (action) => {
    showToast.error(`Permission denied: Cannot ${action}`);
  },
};

// Real-time notification handler
export const useRealTimeNotifications = () => {
  useEffect(() => {
    // Connect to WebSocket for real-time notifications
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/notifications`;
    
    let ws = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('Connected to notification WebSocket');
          reconnectAttempts = 0;
        };

        ws.onmessage = (event) => {
          try {
            const notification = JSON.parse(event.data);
            
            switch (notification.type) {
              case 'security_alert':
                securityToast.threatDetected(
                  notification.severity,
                  notification.message
                );
                break;
              
              case 'system_alert':
                securityToast.systemAlert(notification.message);
                break;
              
              case 'user_action':
                securityToast.userAction(notification.action, notification.success);
                break;
              
              default:
                showToast.info(notification.message);
            }
          } catch (error) {
            console.error('Error parsing notification:', error);
          }
        };

        ws.onclose = () => {
          console.log('Disconnected from notification WebSocket');
          
          // Attempt to reconnect
          if (reconnectAttempts < maxReconnectAttempts) {
            reconnectAttempts++;
            setTimeout(connect, 2000 * reconnectAttempts);
          }
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
        };

      } catch (error) {
        console.error('Failed to connect to WebSocket:', error);
      }
    };

    // Initial connection
    connect();

    // Cleanup on unmount
    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, []);
};

export default NotificationToast;