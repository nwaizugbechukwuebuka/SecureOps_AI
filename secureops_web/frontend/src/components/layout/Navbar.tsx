import React from "react";

const Navbar: React.FC = () => (
  <nav className="w-full bg-gray-200 py-4 px-6 mb-4">
    <span>Navbar Placeholder</span>
  </nav>
);

export default Navbar;
import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '../ui/Button';
import secureopsLogo from '../../assets/logos/secureops-logo.svg';

const navLinks = [
  { name: 'Dashboard', path: '/' },
  { name: 'Threat Intel', path: '/threat-intel' },
  { name: 'Scan Reports', path: '/scan-reports' },
  { name: 'AI Analysis', path: '/ai-analysis' },
  { name: 'Settings', path: '/settings' },
];

const Navbar: React.FC = () => (
  <nav className="flex items-center justify-between px-6 py-3 bg-white shadow">
    <Link to="/" className="flex items-center gap-2">
      <img src={secureopsLogo} alt="SecureOps Logo" className="h-8" />
      <span className="font-bold text-xl text-primary">SecureOps</span>
    </Link>
    <div className="flex gap-4">
      {navLinks.map((link) => (
        <Link key={link.name} to={link.path} className="text-gray-700 hover:text-accent font-medium">
          {link.name}
        </Link>
      ))}
    </div>
    <Button variant="accent">Sign Out</Button>
  </nav>
);

export default Navbar;
