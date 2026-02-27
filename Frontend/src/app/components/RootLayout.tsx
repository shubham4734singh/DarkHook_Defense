import { Outlet } from 'react-router';
import { AuthProvider } from '../contexts/AuthContext';

export function RootLayout() {
  return (
    <AuthProvider>
      <Outlet />
    </AuthProvider>
  );
}
