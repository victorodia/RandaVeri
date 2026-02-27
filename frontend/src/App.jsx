import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { BrandingProvider, useBranding } from './context/BrandingContext';
import { ThemeProvider } from './context/ThemeContext';
import ErrorBoundary from './components/ErrorBoundary';

const Login = React.lazy(() => import('./pages/Login'));
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const OrgEntrance = React.lazy(() => import('./pages/OrgEntrance'));
const ChangePassword = React.lazy(() => import('./pages/ChangePassword'));
const VerifyEmail = React.lazy(() => import('./pages/VerifyEmail'));
const ForgotPassword = React.lazy(() => import('./pages/ForgotPassword'));
const ResetPassword = React.lazy(() => import('./pages/ResetPassword'));

const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  const { branding } = useBranding();

  if (loading) return <LoadingFallback />;
  if (!branding.orgSlug) return <Navigate to="/" />;
  if (!user) return <Navigate to="/login" />;
  return children;
};

const LoadingFallback = () => (
  <div className="h-screen flex items-center justify-center bg-premium-bg text-premium-text">
    <div className="animate-spin h-8 w-8 border-4 border-premium-primary border-t-transparent rounded-full"></div>
  </div>
);

import { DialogProvider } from './context/DialogContext';
import CustomDialog from './components/CustomDialog';

function App() {
  return (
    <Router>
      <ThemeProvider>
        <DialogProvider>
          <BrandingProvider>
            <AuthProvider>
              <React.Suspense fallback={<LoadingFallback />}>
                <Routes>
                  <Route path="/" element={<OrgEntrance />} />
                  <Route path="/login" element={<Login />} />
                  <Route path="/forgot-password" element={<ForgotPassword />} />
                  <Route path="/reset-password" element={<ResetPassword />} />
                  <Route path="/verify-email" element={<VerifyEmail />} />
                  <Route path="/change-password" element={
                    <ProtectedRoute>
                      <ChangePassword />
                    </ProtectedRoute>
                  } />
                  <Route path="/dashboard" element={
                    <ErrorBoundary>
                      <ProtectedRoute>
                        <Dashboard />
                      </ProtectedRoute>
                    </ErrorBoundary>
                  } />
                  {/* Fallback */}
                  <Route path="*" element={<Navigate to="/" />} />
                </Routes>
                <CustomDialog />
              </React.Suspense>
            </AuthProvider>
          </BrandingProvider>
        </DialogProvider>
      </ThemeProvider>
    </Router>
  );
}

export default App;
