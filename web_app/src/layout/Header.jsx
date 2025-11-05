import React, { useState, useEffect } from 'react';
import { getCurrentUser, logout } from '../auth';
import './Header.css';

export default function Header({ onLogout }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    getCurrentUser()
      .then(setUser)
      .catch(console.error);
  }, []);

  const handleLogout = async () => {
    try {
      await logout();
      onLogout?.();
    } catch (error) {
      console.error('Logout error:', error);
      onLogout?.(); // Force logout even if API call fails
    }
  };

  return (
    <header className="main-header">
      <div className="header-title">🔒 SecureOps AI Dashboard</div>
      <div className="header-actions">
        <span className="header-user">
          👤 {user?.full_name || user?.username || 'User'}
        </span>
        <span className="header-notifications">🔔</span>
        <button 
          className="logout-button" 
          onClick={handleLogout}
          title="Logout"
        >
          🚪 Logout
        </button>
      </div>
    </header>
  );
}
