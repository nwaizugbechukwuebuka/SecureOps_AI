import React, { createContext, useContext, useEffect, useReducer, useCallback } from 'react';
import { api } from './api';

// WebSocket connection states
const WS_STATES = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
};

// Action types
const WS_ACTIONS = {
  SET_CONNECTION_STATE: 'SET_CONNECTION_STATE',
  SET_REAL_TIME_DATA: 'SET_REAL_TIME_DATA',
  UPDATE_ALERTS: 'UPDATE_ALERTS',
  UPDATE_PIPELINES: 'UPDATE_PIPELINES',
  UPDATE_VULNERABILITIES: 'UPDATE_VULNERABILITIES',
  UPDATE_COMPLIANCE: 'UPDATE_COMPLIANCE',
  UPDATE_ACTIVITY: 'UPDATE_ACTIVITY',
  ADD_NOTIFICATION: 'ADD_NOTIFICATION',
  REMOVE_NOTIFICATION: 'REMOVE_NOTIFICATION',
  CLEAR_NOTIFICATIONS: 'CLEAR_NOTIFICATIONS',
};

// Initial state
const initialState = {
  connectionState: WS_STATES.DISCONNECTED,
  realTimeAlerts: null,
  realTimePipelines: null,
  realTimeVulnerabilities: null,
  realTimeCompliance: null,
  realTimeActivity: null,
  notifications: [],
  lastHeartbeat: null,
  reconnectAttempts: 0,
};

// Reducer
const wsReducer = (state, action) => {
  switch (action.type) {
    case WS_ACTIONS.SET_CONNECTION_STATE:
      return {
        ...state,
        connectionState: action.payload.state,
        reconnectAttempts: action.payload.state === WS_STATES.CONNECTED ? 0 : state.reconnectAttempts,
        lastHeartbeat: action.payload.state === WS_STATES.CONNECTED ? Date.now() : state.lastHeartbeat,
      };

    case WS_ACTIONS.SET_REAL_TIME_DATA:
      return {
        ...state,
        [action.payload.type]: action.payload.data,
      };

    case WS_ACTIONS.UPDATE_ALERTS:
      return {
        ...state,
        realTimeAlerts: {
          ...state.realTimeAlerts,
          ...action.payload,
        },
      };

    case WS_ACTIONS.UPDATE_PIPELINES:
      return {
        ...state,
        realTimePipelines: {
          ...state.realTimePipelines,
          ...action.payload,
        },
      };

    case WS_ACTIONS.UPDATE_VULNERABILITIES:
      return {
        ...state,
        realTimeVulnerabilities: {
          ...state.realTimeVulnerabilities,
          ...action.payload,
        },
      };

    case WS_ACTIONS.UPDATE_COMPLIANCE:
      return {
        ...state,
        realTimeCompliance: {
          ...state.realTimeCompliance,
          ...action.payload,
        },
      };

    case WS_ACTIONS.UPDATE_ACTIVITY:
      return {
        ...state,
        realTimeActivity: action.payload,
      };

    case WS_ACTIONS.ADD_NOTIFICATION:
      return {
        ...state,
        notifications: [
          ...state.notifications,
          {
            ...action.payload,
            id: action.payload.id || Date.now(),
            timestamp: action.payload.timestamp || new Date().toISOString(),
          },
        ],
      };

    case WS_ACTIONS.REMOVE_NOTIFICATION:
      return {
        ...state,
        notifications: state.notifications.filter(n => n.id !== action.payload.id),
      };

    case WS_ACTIONS.CLEAR_NOTIFICATIONS:
      return {
        ...state,
        notifications: [],
      };

    default:
      return state;
  }
};

// Create context
const WebSocketContext = createContext();

// WebSocket provider component
export const WebSocketProvider = ({ children }) => {
  const [state, dispatch] = useReducer(wsReducer, initialState);
  const wsRef = React.useRef(null);
  const reconnectTimeoutRef = React.useRef(null);
  const heartbeatIntervalRef = React.useRef(null);

  // Connection configuration
  const config = {
    maxReconnectAttempts: 5,
    reconnectInterval: 1000, // Start with 1 second
    maxReconnectInterval: 30000, // Max 30 seconds
    heartbeatInterval: 30000, // 30 seconds
  };

  // Connect to WebSocket
  const connect = useCallback(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      console.warn('No auth token available for WebSocket connection');
      return;
    }

    dispatch({
      type: WS_ACTIONS.SET_CONNECTION_STATE,
      payload: { state: WS_STATES.CONNECTING },
    });

    const wsUrl = `${process.env.REACT_APP_WS_URL || 'ws://localhost:8000'}/ws/dashboard?token=${token}`;
    
    try {
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        console.log('WebSocket connected');
        dispatch({
          type: WS_ACTIONS.SET_CONNECTION_STATE,
          payload: { state: WS_STATES.CONNECTED },
        });

        // Start heartbeat
        startHeartbeat();

        // Send initial subscription
        sendMessage({
          type: 'subscribe',
          channels: ['alerts', 'pipelines', 'vulnerabilities', 'compliance', 'activity'],
        });
      };

      wsRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleMessage(data);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      wsRef.current.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        dispatch({
          type: WS_ACTIONS.SET_CONNECTION_STATE,
          payload: { state: WS_STATES.DISCONNECTED },
        });

        stopHeartbeat();

        // Attempt reconnection if not a clean close
        if (!event.wasClean && state.reconnectAttempts < config.maxReconnectAttempts) {
          scheduleReconnect();
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        dispatch({
          type: WS_ACTIONS.SET_CONNECTION_STATE,
          payload: { state: WS_STATES.ERROR },
        });
      };

    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
      dispatch({
        type: WS_ACTIONS.SET_CONNECTION_STATE,
        payload: { state: WS_STATES.ERROR },
      });
    }
  }, [state.reconnectAttempts]);

  // Disconnect WebSocket
  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnecting');
      wsRef.current = null;
    }

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    stopHeartbeat();

    dispatch({
      type: WS_ACTIONS.SET_CONNECTION_STATE,
      payload: { state: WS_STATES.DISCONNECTED },
    });
  }, []);

  // Send message through WebSocket
  const sendMessage = useCallback((message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
      return true;
    }
    return false;
  }, []);

  // Handle incoming messages
  const handleMessage = useCallback((data) => {
    const { type, payload, channel } = data;

    switch (type) {
      case 'heartbeat':
        // Update last heartbeat timestamp
        dispatch({
          type: WS_ACTIONS.SET_CONNECTION_STATE,
          payload: { 
            state: WS_STATES.CONNECTED,
            lastHeartbeat: Date.now(),
          },
        });
        break;

      case 'notification':
        dispatch({
          type: WS_ACTIONS.ADD_NOTIFICATION,
          payload: payload,
        });
        break;

      case 'data_update':
        if (channel === 'alerts') {
          dispatch({
            type: WS_ACTIONS.UPDATE_ALERTS,
            payload: payload,
          });
        } else if (channel === 'pipelines') {
          dispatch({
            type: WS_ACTIONS.UPDATE_PIPELINES,
            payload: payload,
          });
        } else if (channel === 'vulnerabilities') {
          dispatch({
            type: WS_ACTIONS.UPDATE_VULNERABILITIES,
            payload: payload,
          });
        } else if (channel === 'compliance') {
          dispatch({
            type: WS_ACTIONS.UPDATE_COMPLIANCE,
            payload: payload,
          });
        } else if (channel === 'activity') {
          dispatch({
            type: WS_ACTIONS.UPDATE_ACTIVITY,
            payload: payload,
          });
        }
        break;

      case 'pipeline_status':
        dispatch({
          type: WS_ACTIONS.UPDATE_PIPELINES,
          payload: {
            pipeline_updates: [payload],
          },
        });
        break;

      case 'alert_created':
      case 'alert_updated':
        dispatch({
          type: WS_ACTIONS.UPDATE_ALERTS,
          payload: {
            alert_updates: [payload],
          },
        });
        break;

      case 'scan_completed':
        dispatch({
          type: WS_ACTIONS.UPDATE_VULNERABILITIES,
          payload: {
            scan_results: [payload],
          },
        });
        break;

      case 'compliance_update':
        dispatch({
          type: WS_ACTIONS.UPDATE_COMPLIANCE,
          payload: payload,
        });
        break;

      default:
        console.log('Unknown WebSocket message type:', type);
    }
  }, []);

  // Schedule reconnection with exponential backoff
  const scheduleReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) return;

    const interval = Math.min(
      config.reconnectInterval * Math.pow(2, state.reconnectAttempts),
      config.maxReconnectInterval
    );

    console.log(`Scheduling reconnection in ${interval}ms (attempt ${state.reconnectAttempts + 1})`);

    reconnectTimeoutRef.current = setTimeout(() => {
      reconnectTimeoutRef.current = null;
      dispatch({
        type: WS_ACTIONS.SET_CONNECTION_STATE,
        payload: { 
          state: WS_STATES.CONNECTING,
          reconnectAttempts: state.reconnectAttempts + 1,
        },
      });
      connect();
    }, interval);
  }, [state.reconnectAttempts, connect]);

  // Start heartbeat monitoring
  const startHeartbeat = useCallback(() => {
    if (heartbeatIntervalRef.current) return;

    heartbeatIntervalRef.current = setInterval(() => {
      sendMessage({ type: 'ping' });
    }, config.heartbeatInterval);
  }, [sendMessage]);

  // Stop heartbeat monitoring
  const stopHeartbeat = useCallback(() => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }
  }, []);

  // Subscribe to specific channels
  const subscribe = useCallback((channels) => {
    sendMessage({
      type: 'subscribe',
      channels: Array.isArray(channels) ? channels : [channels],
    });
  }, [sendMessage]);

  // Unsubscribe from specific channels
  const unsubscribe = useCallback((channels) => {
    sendMessage({
      type: 'unsubscribe',
      channels: Array.isArray(channels) ? channels : [channels],
    });
  }, [sendMessage]);

  // Remove notification
  const removeNotification = useCallback((id) => {
    dispatch({
      type: WS_ACTIONS.REMOVE_NOTIFICATION,
      payload: { id },
    });
  }, []);

  // Clear all notifications
  const clearNotifications = useCallback(() => {
    dispatch({ type: WS_ACTIONS.CLEAR_NOTIFICATIONS });
  }, []);

  // Initialize connection on mount
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      connect();
    }

    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, []);

  // Reconnect when auth token changes
  useEffect(() => {
    const handleStorageChange = (e) => {
      if (e.key === 'access_token') {
        if (e.newValue) {
          // Token added/changed, reconnect
          disconnect();
          setTimeout(connect, 1000);
        } else {
          // Token removed, disconnect
          disconnect();
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [connect, disconnect]);

  // Context value
  const value = {
    // State
    ...state,
    isConnected: state.connectionState === WS_STATES.CONNECTED,
    isConnecting: state.connectionState === WS_STATES.CONNECTING,
    isDisconnected: state.connectionState === WS_STATES.DISCONNECTED,
    hasError: state.connectionState === WS_STATES.ERROR,

    // Actions
    connect,
    disconnect,
    sendMessage,
    subscribe,
    unsubscribe,
    removeNotification,
    clearNotifications,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

// Custom hook to use WebSocket context
export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  
  return context;
};

// Hook for specific real-time data
export const useRealTimeData = (dataType) => {
  const { 
    realTimeAlerts, 
    realTimePipelines, 
    realTimeVulnerabilities, 
    realTimeCompliance, 
    realTimeActivity 
  } = useWebSocket();

  const dataMap = {
    alerts: realTimeAlerts,
    pipelines: realTimePipelines,
    vulnerabilities: realTimeVulnerabilities,
    compliance: realTimeCompliance,
    activity: realTimeActivity,
  };

  return dataMap[dataType] || null;
};

// Hook for notifications
export const useNotifications = () => {
  const { notifications, removeNotification, clearNotifications } = useWebSocket();

  return {
    notifications,
    removeNotification,
    clearNotifications,
    unreadCount: notifications.filter(n => !n.read).length,
  };
};

// Connection status component
export const ConnectionStatus = ({ 
  showWhenConnected = false, 
  className = '',
  style = {} 
}) => {
  const { connectionState, reconnectAttempts } = useWebSocket();

  if (connectionState === WS_STATES.CONNECTED && !showWhenConnected) {
    return null;
  }

  const getStatusInfo = () => {
    switch (connectionState) {
      case WS_STATES.CONNECTING:
        return {
          text: reconnectAttempts > 0 ? `Reconnecting... (${reconnectAttempts})` : 'Connecting...',
          color: '#ff9800',
        };
      case WS_STATES.CONNECTED:
        return {
          text: 'Connected',
          color: '#4caf50',
        };
      case WS_STATES.DISCONNECTED:
        return {
          text: 'Disconnected',
          color: '#f44336',
        };
      case WS_STATES.ERROR:
        return {
          text: 'Connection Error',
          color: '#f44336',
        };
      default:
        return {
          text: 'Unknown',
          color: '#9e9e9e',
        };
    }
  };

  const { text, color } = getStatusInfo();

  return (
    <div 
      className={className}
      style={{
        display: 'flex',
        alignItems: 'center',
        padding: '4px 8px',
        borderRadius: '4px',
        backgroundColor: `${color}20`,
        border: `1px solid ${color}`,
        fontSize: '12px',
        color: color,
        ...style,
      }}
    >
      <div
        style={{
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          backgroundColor: color,
          marginRight: '6px',
          animation: connectionState === WS_STATES.CONNECTING ? 'pulse 1.5s infinite' : 'none',
        }}
      />
      {text}
    </div>
  );
};

// Default export
export default {
  WebSocketProvider,
  useWebSocket,
  useRealTimeData,
  useNotifications,
  ConnectionStatus,
};