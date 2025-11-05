import React from 'react';
import Sidebar from './Sidebar.jsx';
import Header from './Header.jsx';
import './MainLayout.css';

export default function MainLayout({ children, onLogout }) {
  return (
    <div className="main-layout">
      <Sidebar />
      <div className="main-content">
        <Header onLogout={onLogout} />
        <div className="main-body">{children}</div>
      </div>
    </div>
  );
}
