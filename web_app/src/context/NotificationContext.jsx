/**
 * Notification Context for SecureOps AI
 * Manages global notifications and alerts throughout the application
 */

import React, { createContext, useContext, useState, useCallback } from 'react';

const NotificationContext = createContext(null);

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};

export const NotificationProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([]);

  // Auto-increment ID for notifications
  const [nextId, setNextId] = useState(1);

  const showNotification = useCallback((message, type = 'info', duration = 5000, actions = null) => {
    const notification = {
      id: nextId,
      message,
      type, // 'success', 'error', 'warning', 'info'
      timestamp: new Date(),
      duration,
      actions,
      visible: true
    };

    setNotifications(prev => [...prev, notification]);
    setNextId(prev => prev + 1);

    // Auto-dismiss notification after duration
    if (duration > 0) {
      setTimeout(() => {
        dismissNotification(notification.id);
      }, duration);
    }

    return notification.id;
  }, [nextId]);

  const dismissNotification = useCallback((id) => {
    setNotifications(prev => 
      prev.map(notification => 
        notification.id === id 
          ? { ...notification, visible: false }
          : notification
      )
    );

    // Remove from array after animation completes
    setTimeout(() => {
      setNotifications(prev => prev.filter(notification => notification.id !== id));
    }, 300); // Match CSS transition duration
  }, []);

  const clearAllNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  // Security-specific notification helpers
  const showSecurityAlert = useCallback((message, severity = 'high', duration = 0) => {
    const type = severity === 'critical' ? 'error' : 
                severity === 'high' ? 'error' :
                severity === 'medium' ? 'warning' : 'info';
    
    return showNotification(
      `🔒 Security Alert: ${message}`,
      type,
      duration // Don't auto-dismiss security alerts by default
    );
  }, [showNotification]);

  const showAuthError = useCallback((message, duration = 8000) => {
    return showNotification(
      `🚫 Authentication Error: ${message}`,
      'error',
      duration
    );
  }, [showNotification]);

  const showSystemAlert = useCallback((message, type = 'warning', duration = 10000) => {
    return showNotification(
      `⚠️ System Alert: ${message}`,
      type,
      duration
    );
  }, [showNotification]);

  const showSuccessMessage = useCallback((message, duration = 4000) => {
    return showNotification(`✅ ${message}`, 'success', duration);
  }, [showNotification]);

  const showErrorMessage = useCallback((message, duration = 6000) => {
    return showNotification(`❌ ${message}`, 'error', duration);
  }, [showNotification]);

  const showInfoMessage = useCallback((message, duration = 5000) => {
    return showNotification(`ℹ️ ${message}`, 'info', duration);
  }, [showNotification]);

  const showWarningMessage = useCallback((message, duration = 7000) => {
    return showNotification(`⚠️ ${message}`, 'warning', duration);
  }, [showNotification]);

  // Batch operations for multiple notifications
  const showBatchNotifications = useCallback((notificationList) => {
    const ids = [];
    notificationList.forEach((notification, index) => {
      // Stagger notifications slightly to avoid overwhelming the user
      setTimeout(() => {
        const id = showNotification(
          notification.message,
          notification.type || 'info',
          notification.duration || 5000,
          notification.actions
        );
        ids.push(id);
      }, index * 100);
    });
    return ids;
  }, [showNotification]);

  // Utility to check if there are any visible notifications of a specific type
  const hasNotificationsOfType = useCallback((type) => {
    return notifications.some(notification => 
      notification.visible && notification.type === type
    );
  }, [notifications]);

  // Get count of visible notifications
  const getVisibleNotificationCount = useCallback(() => {
    return notifications.filter(notification => notification.visible).length;
  }, [notifications]);

  // Security audit notification (for security events)
  const showAuditNotification = useCallback((event, details = '') => {
    const message = `Audit: ${event}${details ? ` - ${details}` : ''}`;
    return showNotification(message, 'info', 3000);
  }, [showNotification]);

  const value = {
    // State
    notifications: notifications.filter(n => n.visible),
    allNotifications: notifications,
    
    // Basic notification methods
    showNotification,
    dismissNotification,
    clearAllNotifications,
    
    // Specialized notification methods
    showSecurityAlert,
    showAuthError,
    showSystemAlert,
    showSuccessMessage,
    showErrorMessage,
    showInfoMessage,
    showWarningMessage,
    showAuditNotification,
    
    // Batch operations
    showBatchNotifications,
    
    // Utility methods
    hasNotificationsOfType,
    getVisibleNotificationCount
  };

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
};

export default NotificationContext;