import React, { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router';

interface AuthContextType {
  isAuthenticated: boolean;
  login: (email: string, password: string) => void;
  logout: () => void;
  user: { email: string; name: string } | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [user, setUser] = useState<{ email: string; name: string } | null>(null);

  // Check if user is already logged in on mount
  useEffect(() => {
    const storedAuth = localStorage.getItem('darkhook_auth');
    const storedUser = localStorage.getItem('darkhook_user');
    if (storedAuth === 'true' && storedUser) {
      setIsAuthenticated(true);
      setUser(JSON.parse(storedUser));
    }
  }, []);

  const login = (email: string, name: string) => {
    setIsAuthenticated(true);
    const userData = { email, name };
    setUser(userData);
    localStorage.setItem('darkhook_auth', 'true');
    localStorage.setItem('darkhook_user', JSON.stringify(userData));
  };

  const logout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem('darkhook_auth');
    localStorage.removeItem('darkhook_user');
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout, user }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
