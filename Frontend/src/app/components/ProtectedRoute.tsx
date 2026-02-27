import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { useAuth } from '../contexts/AuthContext';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // Only redirect if auth check is complete and user is not authenticated
    if (!loading && !isAuthenticated) {
      // Store the current path to redirect after login
      localStorage.setItem('darkhook_redirect', location.pathname);
      navigate('/login');
    }
  }, [isAuthenticated, loading, navigate, location]);

  // Show nothing while loading to prevent flash
  if (loading) {
    return (
      <div className="min-h-screen bg-[#060D1A] flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#00C2FF]"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
