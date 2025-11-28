import React, { createContext, useState, ReactNode } from 'react';

interface ScanContextType {
  status: string;
  setStatus: (status: string) => void;
}

export const ScanContext = createContext<ScanContextType>({ status: '', setStatus: () => {} });

export const ScanProvider = ({ children }: { children: ReactNode }) => {
  const [status, setStatus] = useState('');

  return (
    <ScanContext.Provider value={{ status, setStatus }}>
      {children}
    </ScanContext.Provider>
  );
};
