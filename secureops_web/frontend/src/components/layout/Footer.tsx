import React from 'react';

export const Footer: React.FC = () => (
  <footer className="w-full py-4 px-6 bg-white border-t text-center text-gray-500 text-sm">
    &copy; {new Date().getFullYear()} SecureOps. All rights reserved.
  </footer>
);
