import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import secureopsMini from '../../assets/logos/secureops-mini.svg';

const sidebarLinks = [
  { name: 'Dashboard', path: '/' },
  { name: 'Threat Intel', path: '/threat-intel' },
  { name: 'Scan Reports', path: '/scan-reports' },
  { name: 'AI Analysis', path: '/ai-analysis' },
  { name: 'Settings', path: '/settings' },
];

export const Sidebar: React.FC = () => {
  const { pathname } = useLocation();
  return (
    <aside className="h-full w-56 bg-primary text-white flex flex-col py-6 shadow-lg">
      <div className="flex items-center gap-2 px-6 mb-8">
        <img src={secureopsMini} alt="Mini Logo" className="h-8" />
        <span className="font-bold text-lg">SecureOps</span>
      </div>
      <nav className="flex flex-col gap-2 px-6">
        {sidebarLinks.map((link) => (
          <Link
            key={link.name}
            to={link.path}
            className={`py-2 px-3 rounded transition-colors font-medium ${pathname === link.path ? 'bg-accent text-primary' : 'hover:bg-accent/80'}`}
          >
            {link.name}
          </Link>
        ))}
      </nav>
    </aside>
  );
};
