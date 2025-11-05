/**
 * Enhanced Notification Toast Component
 * Displays security alerts, system notifications, and user feedback
 */

import React, { useEffect, useState } from 'react';
import { useNotification } from '../context/NotificationContext';
import './NotificationToast.css';

const NotificationToast = () => {
  const { notifications, dismissNotification } = useNotification();
  const [visibleNotifications, setVisibleNotifications] = useState([]);

  useEffect(() => {
    setVisibleNotifications(notifications);
  }, [notifications]);

  const handleDismiss = (id) => {
    dismissNotification(id);
  };

  const getNotificationIcon = (type) => {
    switch (type) {
      case 'success':
        return '✅';
      case 'error':
        return '❌';
      case 'warning':
        return '⚠️';
      case 'info':
        return 'ℹ️';
      default:
        return 'ℹ️';
    }
  };

  const getNotificationTitle = (type) => {
    switch (type) {
      case 'success':
        return 'Success';
      case 'error':
        return 'Error';
      case 'warning':
        return 'Warning';
      case 'info':
        return 'Information';
      default:
        return 'Notification';
    }
  };

  const formatTimestamp = (timestamp) => {
    const now = new Date();
    const diff = now - new Date(timestamp);
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (seconds < 60) {
      return 'Just now';
    } else if (minutes < 60) {
      return `${minutes}m ago`;
    } else if (hours < 24) {
      return `${hours}h ago`;
    } else {
      return new Date(timestamp).toLocaleDateString();
    }
  };

  if (visibleNotifications.length === 0) {
    return null;
  }

  return (
    <div className="notification-container">
      {visibleNotifications.map((notification) => (
        <div
          key={notification.id}
          className={`notification-toast ${notification.type} ${
            notification.visible ? 'visible' : 'hidden'
          }`}
        >
          <div className="notification-content">
            <div className="notification-header">
              <div className="notification-icon">
                {getNotificationIcon(notification.type)}
              </div>
              <div className="notification-title">
                {getNotificationTitle(notification.type)}
              </div>
              <div className="notification-timestamp">
                {formatTimestamp(notification.timestamp)}
              </div>
              <button
                className="notification-close"
                onClick={() => handleDismiss(notification.id)}
                aria-label="Dismiss notification"
              >
                ✕
              </button>
            </div>
            
            <div className="notification-message">
              {notification.message}
            </div>

            {/* Action buttons if provided */}
            {notification.actions && notification.actions.length > 0 && (
              <div className="notification-actions">
                {notification.actions.map((action, index) => (
                  <button
                    key={index}
                    className={`notification-action ${action.style || 'primary'}`}
                    onClick={() => {
                      action.onClick();
                      if (action.dismissOnClick !== false) {
                        handleDismiss(notification.id);
                      }
                    }}
                  >
                    {action.label}
                  </button>
                ))}
              </div>
            )}

            {/* Progress bar for timed notifications */}
            {notification.duration > 0 && (
              <div className="notification-progress">
                <div
                  className="notification-progress-bar"
                  style={{
                    animationDuration: `${notification.duration}ms`,
                  }}
                />
              </div>
            )}
          </div>

          {/* Security indicator for security alerts */}
          {notification.message.includes('🔒 Security Alert') && (
            <div className="security-indicator">
              <div className="security-badge">SECURITY</div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default NotificationToast;