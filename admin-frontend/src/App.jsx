import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
const AdminDashboard = React.lazy(() => import('./pages/AdminDashboard'));
const ChangePassword = React.lazy(() => import('./pages/ChangePassword'));
const Login = React.lazy(() => import('./pages/Login'));
const ForgotPassword = React.lazy(() => import('./pages/ForgotPassword'));
const ResetPassword = React.lazy(() => import('./pages/ResetPassword'));
const VerifyEmail = React.lazy(() => import('./pages/VerifyEmail'));

const LoadingSpinner = () => (
    <div className="min-h-screen bg-premium-bg flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-4 border-premium-primary border-t-transparent rounded-full"></div>
    </div>
);

const ProtectedRoute = ({ children }) => {
    const { user, loading } = useAuth();

    if (loading) return <LoadingSpinner />;

    if (!user || !user.is_platform_user) return <Navigate to="/login" />;

    // Force Password Change Check
    if (user.is_password_change_required && window.location.pathname !== '/change-password') {
        return <Navigate to="/change-password" />;
    }

    return children;
};

function AppRoutes() {
    return (
        <React.Suspense fallback={<LoadingSpinner />}>
            <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                <Route path="/reset-password" element={<ResetPassword />} />
                <Route path="/verify-email" element={<VerifyEmail />} />
                <Route path="/change-password" element={
                    <ProtectedRoute>
                        <ChangePassword />
                    </ProtectedRoute>
                } />
                <Route path="/" element={
                    <ProtectedRoute>
                        <AdminDashboard />
                    </ProtectedRoute>
                } />
                <Route path="*" element={<Navigate to="/" />} />
            </Routes>
        </React.Suspense>
    );
}

import { DialogProvider } from './context/DialogContext';
import CustomDialog from './components/CustomDialog';

function App() {
    return (
        <ThemeProvider>
            <AuthProvider>
                <DialogProvider>
                    <Router>
                        <AppRoutes />
                        <CustomDialog />
                    </Router>
                </DialogProvider>
            </AuthProvider>
        </ThemeProvider>
    );
}

export default App;
