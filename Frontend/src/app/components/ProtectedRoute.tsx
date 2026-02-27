import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { useAuth } from '../contexts/AuthContext';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!isAuthenticated) {
      // Store the current path to redirect after login
      localStorage.setItem('darkhook_redirect', location.pathname);
      navigate('/login');
    }
  }, [isAuthenticated, navigate, location]);

  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
