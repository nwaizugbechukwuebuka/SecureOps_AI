import React from 'react';

export default function Navbar({ onLogout, onToggleSidebar }) {
  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <button className="sidebar-toggle" onClick={onToggleSidebar}>
          ☰
        </button>
        <h1>SecureOps AI</h1>
      </div>
      
      <div className="navbar-menu">
        <div className="navbar-status">
          <span className="status-indicator online"></span>
          <span>Online</span>
        </div>
        
        <div className="navbar-user">
          <span>Admin User</span>
          <button className="logout-btn" onClick={onLogout}>
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
}