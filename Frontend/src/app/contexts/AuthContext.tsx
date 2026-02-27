import React, { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { api } from '../services/api';

interface AuthContextType {
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  user: { email: string; name: string } | null;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [user, setUser] = useState<{ email: string; name: string } | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  // Check if user is already logged in on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('darkhook_token');
      const storedUser = localStorage.getItem('darkhook_user');
      
      if (token && storedUser) {
        try {
          // Try to get user info from API to verify token is still valid
          const userInfo = await api.getCurrentUser();
          setUser(userInfo);
          setIsAuthenticated(true);
        } catch (error) {
          // Token is invalid, clear storage
          localStorage.removeItem('darkhook_token');
          localStorage.removeItem('darkhook_user');
        }
      }
      setLoading(false);
    };
    
    checkAuth();
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const response = await api.login(email, password);
      
      // Store token
      localStorage.setItem('darkhook_token', response.access_token);
      
      // Get user info
      const userInfo = await api.getCurrentUser();
      setUser(userInfo);
      setIsAuthenticated(true);
      localStorage.setItem('darkhook_user', JSON.stringify(userInfo));
    } catch (error) {
      setLoading(false);
      throw error;
    }
    setLoading(false);
  };

  const register = async (name: string, email: string, password: string) => {
    setLoading(true);
    try {
      const response = await api.register(name, email, password);
      
      // Store token
      localStorage.setItem('darkhook_token', response.access_token);
      
      // Get user info
      const userInfo = await api.getCurrentUser();
      setUser(userInfo);
      setIsAuthenticated(true);
      localStorage.setItem('darkhook_user', JSON.stringify(userInfo));
    } catch (error) {
      setLoading(false);
      throw error;
    }
    setLoading(false);
  };

  const logout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem('darkhook_token');
    localStorage.removeItem('darkhook_user');
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, register, logout, user, loading }}>
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
