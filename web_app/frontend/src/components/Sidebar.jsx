import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: '📊' },
  { path: '/analytics', label: 'Security Analytics', icon: '🔒' },
  { path: '/users', label: 'User Management', icon: '👤' },
  { path: '/system', label: 'System Health', icon: '💻' },
  { path: '/tasks', label: 'AI Operations', icon: '🤖' },
  { path: '/logs', label: 'Logs & Events', icon: '📝' },
  { path: '/notifications', label: 'Notifications', icon: '🔔' },
  { path: '/settings', label: 'Settings', icon: '⚙️' }
];

export default function Sidebar({ isOpen }) {
  const location = useLocation();

  return (
    <aside className={`sidebar ${isOpen ? 'open' : ''}`}>
      <div className="sidebar-content">
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`sidebar-item ${location.pathname === item.path ? 'active' : ''}`}
            >
              <span className="sidebar-icon">{item.icon}</span>
              <span className="sidebar-label">{item.label}</span>
            </Link>
          ))}
        </nav>
      </div>
    </aside>
  );
}