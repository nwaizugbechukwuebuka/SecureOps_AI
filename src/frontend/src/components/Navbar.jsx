import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Avatar,
  Box,
  Badge,
  Tooltip,
  Switch,
  FormControlLabel,
  Divider,
  useTheme,
  alpha
} from '@mui/material';
import {
  Menu as MenuIcon,
  Notifications as NotificationsIcon,
  AccountCircle,
  Security as SecurityIcon,
  Brightness4,
  Brightness7,
  ExitToApp,
  Settings as SettingsIcon,
  Dashboard as DashboardIcon
} from '@mui/icons-material';
import { useAuth } from '../services/auth';
import { useWebSocket } from '../services/websocket';

const Navbar = ({ onToggleSidebar, onToggleTheme, darkMode }) => {
  const theme = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { notifications, unreadCount } = useWebSocket();
  
  const [anchorElUser, setAnchorElUser] = useState(null);
  const [anchorElNotifications, setAnchorElNotifications] = useState(null);
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);

  const handleOpenUserMenu = (event) => {
    setAnchorElUser(event.currentTarget);
  };

  const handleCloseUserMenu = () => {
    setAnchorElUser(null);
  };

  const handleOpenNotifications = (event) => {
    setAnchorElNotifications(event.currentTarget);
  };

  const handleCloseNotifications = () => {
    setAnchorElNotifications(null);
  };

  const handleLogout = () => {
    logout();
    handleCloseUserMenu();
    navigate('/login');
  };

  const getPageTitle = () => {
    const path = location.pathname;
    switch (path) {
      case '/':
        return 'Dashboard';
      case '/alerts':
        return 'Security Alerts';
      case '/pipelines':
        return 'CI/CD Pipelines';
      case '/compliance':
        return 'Compliance Dashboard';
      case '/settings':
        return 'Settings';
      default:
        return 'SecureOps';
    }
  };

  const formatNotificationTime = (timestamp) => {
    const now = new Date();
    const notificationTime = new Date(timestamp);
    const diffInMinutes = Math.floor((now - notificationTime) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours}h ago`;
    const diffInDays = Math.floor(diffInHours / 24);
    return `${diffInDays}d ago`;
  };

  const getNotificationIcon = (type) => {
    switch (type) {
      case 'critical':
        return '🚨';
      case 'warning':
        return '⚠️';
      case 'info':
        return 'ℹ️';
      case 'success':
        return '✅';
      default:
        return '🔔';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return theme.palette.error.main;
      case 'high':
        return theme.palette.warning.main;
      case 'medium':
        return theme.palette.info.main;
      case 'low':
        return theme.palette.success.main;
      default:
        return theme.palette.text.secondary;
    }
  };

  return (
    <AppBar 
      position="fixed" 
      sx={{ 
        zIndex: theme.zIndex.drawer + 1,
        backgroundColor: darkMode ? theme.palette.background.paper : theme.palette.primary.main,
        borderBottom: `1px solid ${alpha(theme.palette.divider, 0.12)}`
      }}
    >
      <Toolbar>
        {/* Menu Button */}
        <IconButton
          color="inherit"
          aria-label="open drawer"
          onClick={onToggleSidebar}
          edge="start"
          sx={{ mr: 2 }}
        >
          <MenuIcon />
        </IconButton>

        {/* Logo and Title */}
        <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
          <SecurityIcon sx={{ mr: 1, fontSize: 28 }} />
          <Typography 
            variant="h6" 
            component={Link} 
            to="/"
            sx={{ 
              textDecoration: 'none', 
              color: 'inherit',
              fontWeight: 600,
              mr: 3
            }}
          >
            SecureOps
          </Typography>
          
          {/* Current Page Title */}
          <Typography 
            variant="h6" 
            sx={{ 
              color: alpha(theme.palette.common.white, 0.8),
              fontWeight: 400
            }}
          >
            {getPageTitle()}
          </Typography>
        </Box>

        {/* Right Side Controls */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {/* Real-time Toggle */}
          <FormControlLabel
            control={
              <Switch
                checked={realTimeEnabled}
                onChange={(e) => setRealTimeEnabled(e.target.checked)}
                size="small"
                color="secondary"
              />
            }
            label={
              <Typography variant="caption" sx={{ color: 'inherit' }}>
                Real-time
              </Typography>
            }
            sx={{ mr: 1 }}
          />

          {/* Theme Toggle */}
          <Tooltip title={`Switch to ${darkMode ? 'light' : 'dark'} mode`}>
            <IconButton color="inherit" onClick={onToggleTheme}>
              {darkMode ? <Brightness7 /> : <Brightness4 />}
            </IconButton>
          </Tooltip>

          {/* Notifications */}
          <Tooltip title="Notifications">
            <IconButton color="inherit" onClick={handleOpenNotifications}>
              <Badge badgeContent={unreadCount} color="error">
                <NotificationsIcon />
              </Badge>
            </IconButton>
          </Tooltip>

          {/* Notifications Menu */}
          <Menu
            anchorEl={anchorElNotifications}
            open={Boolean(anchorElNotifications)}
            onClose={handleCloseNotifications}
            PaperProps={{
              sx: {
                width: 360,
                maxHeight: 400,
                overflow: 'auto'
              }
            }}
            transformOrigin={{ horizontal: 'right', vertical: 'top' }}
            anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
          >
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="h6">Notifications</Typography>
              <Typography variant="caption" color="text.secondary">
                {unreadCount} unread
              </Typography>
            </Box>
            
            {notifications.length === 0 ? (
              <MenuItem disabled>
                <Typography variant="body2" color="text.secondary">
                  No notifications
                </Typography>
              </MenuItem>
            ) : (
              notifications.slice(0, 10).map((notification) => (
                <MenuItem 
                  key={notification.id} 
                  onClick={handleCloseNotifications}
                  sx={{ 
                    borderLeft: 4, 
                    borderColor: getSeverityColor(notification.severity),
                    '&:hover': {
                      backgroundColor: alpha(getSeverityColor(notification.severity), 0.1)
                    }
                  }}
                >
                  <Box sx={{ width: '100%' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                      <Typography variant="body2" sx={{ mr: 1 }}>
                        {getNotificationIcon(notification.type)}
                      </Typography>
                      <Typography 
                        variant="subtitle2" 
                        sx={{ 
                          flexGrow: 1,
                          fontWeight: notification.read ? 400 : 600
                        }}
                      >
                        {notification.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {formatNotificationTime(notification.timestamp)}
                      </Typography>
                    </Box>
                    <Typography 
                      variant="body2" 
                      color="text.secondary"
                      sx={{ 
                        display: '-webkit-box',
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: 'vertical',
                        overflow: 'hidden'
                      }}
                    >
                      {notification.message}
                    </Typography>
                  </Box>
                </MenuItem>
              ))
            )}
            
            {notifications.length > 10 && (
              <>
                <Divider />
                <MenuItem 
                  onClick={() => {
                    handleCloseNotifications();
                    navigate('/alerts');
                  }}
                >
                  <Typography variant="body2" color="primary">
                    View all notifications
                  </Typography>
                </MenuItem>
              </>
            )}
          </Menu>

          {/* User Menu */}
          <Tooltip title="Account settings">
            <IconButton onClick={handleOpenUserMenu} sx={{ p: 0, ml: 1 }}>
              <Avatar 
                sx={{ 
                  width: 32, 
                  height: 32,
                  backgroundColor: theme.palette.secondary.main
                }}
              >
                {user?.firstName?.charAt(0) || user?.email?.charAt(0) || 'U'}
              </Avatar>
            </IconButton>
          </Tooltip>

          {/* User Menu Dropdown */}
          <Menu
            sx={{ mt: '45px' }}
            id="menu-appbar"
            anchorEl={anchorElUser}
            anchorOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
            keepMounted
            transformOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
            open={Boolean(anchorElUser)}
            onClose={handleCloseUserMenu}
          >
            {/* User Info */}
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                {user?.firstName} {user?.lastName}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {user?.email}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {user?.role}
              </Typography>
            </Box>

            <MenuItem 
              onClick={() => {
                handleCloseUserMenu();
                navigate('/');
              }}
            >
              <DashboardIcon sx={{ mr: 2 }} />
              Dashboard
            </MenuItem>
            
            <MenuItem 
              onClick={() => {
                handleCloseUserMenu();
                navigate('/settings');
              }}
            >
              <SettingsIcon sx={{ mr: 2 }} />
              Settings
            </MenuItem>
            
            <Divider />
            
            <MenuItem onClick={handleLogout}>
              <ExitToApp sx={{ mr: 2 }} />
              Logout
            </MenuItem>
          </Menu>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
